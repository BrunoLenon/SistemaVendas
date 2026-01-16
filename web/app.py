from flask import Flask, render_template, request, redirect, session, url_for, abort
import pandas as pd
from datetime import datetime
import os
import time

import tempfile
from typing import Optional, Tuple, List

from werkzeug.utils import secure_filename
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine


from dados_db import carregar_df as carregar_df_db
import json
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# =========================
# IMPORTAÇÃO (ADMIN) - conexão direta no DB (Supabase)
# =========================
_ENGINE: Optional[Engine] = None

def get_engine() -> Engine:
    """Cria (uma vez) o engine do SQLAlchemy a partir do DATABASE_URL do ambiente."""
    global _ENGINE
    if _ENGINE is not None:
        return _ENGINE

    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        # Compatibilidade: se você optar por usar variáveis separadas
        u = os.environ.get("DB_USER")
        p = os.environ.get("DB_PASSWORD")
        h = os.environ.get("DB_HOST")
        pt = os.environ.get("DB_PORT")
        n = os.environ.get("DB_NAME")
        if all([u, p, h, pt, n]):
            # db.py já costuma fazer o escaping/ssl, mas aqui garantimos o mínimo
            db_url = f"postgresql+psycopg2://{u}:{p}@{h}:{pt}/{n}"  # senha pode conter @, o ideal é usar DATABASE_URL
        else:
            raise RuntimeError("DATABASE_URL não está definida no ambiente.")

    # Garantir SSL no Supabase
    if "sslmode=" not in db_url:
        sep = "&" if "?" in db_url else "?"
        db_url = db_url + f"{sep}sslmode=require"

    _ENGINE = create_engine(db_url, pool_pre_ping=True)
    return _ENGINE

def _normalizar_texto(s: str) -> str:
    return (s or "").strip().upper()

def _ler_planilha_vendas(file_path: str) -> pd.DataFrame:
    """Lê Excel/CSV e devolve DataFrame com colunas esperadas."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext in [".xlsx", ".xlsm", ".xls"]:
        df = pd.read_excel(file_path)
    elif ext == ".csv":
        df = pd.read_csv(file_path, sep=None, engine="python")
    else:
        raise ValueError("Formato não suportado. Envie .xlsx ou .csv")

    # Padroniza nomes das colunas
    df.columns = [str(c).strip().upper() for c in df.columns]

    obrigatorias = {
        "MESTRE",
        "MARCA",
        "MOVIMENTO",
        "MOV_TIPO_MOVTO",
        "VENDEDOR",
        "NOTA",
        "EMP",
        "QTDADE_VENDIDA",
        "VALOR_TOTAL",
    }
    faltando = [c for c in sorted(obrigatorias) if c not in df.columns]
    if faltando:
        raise ValueError(f"Faltando coluna(s) obrigatória(s): {', '.join(faltando)}")

    # Normalizações
    df["VENDEDOR"] = df["VENDEDOR"].astype(str).map(_normalizar_texto)
    df["MESTRE"] = df["MESTRE"].astype(str).str.strip()
    df["MARCA"] = df["MARCA"].astype(str).str.strip()
    df["NOTA"] = df["NOTA"].astype(str).str.strip()
    df["EMP"] = df["EMP"].astype(str).str.strip()
    df["MOV_TIPO_MOVTO"] = df["MOV_TIPO_MOVTO"].astype(str).map(_normalizar_texto)

    # Datas / números
    df["MOVIMENTO"] = pd.to_datetime(df["MOVIMENTO"], errors="coerce")
    df["QTDADE_VENDIDA"] = pd.to_numeric(df["QTDADE_VENDIDA"], errors="coerce").fillna(0)
    df["VALOR_TOTAL"] = pd.to_numeric(df["VALOR_TOTAL"], errors="coerce").fillna(0)

    # UNIT e DES são opcionais, mas se vierem, guardamos
    if "UNIT" in df.columns:
        df["UNIT"] = pd.to_numeric(df["UNIT"], errors="coerce")
    else:
        df["UNIT"] = None
    if "DES" in df.columns:
        df["DES"] = pd.to_numeric(df["DES"], errors="coerce")
    else:
        df["DES"] = None

    # Remove linhas sem dados mínimos
    df = df.dropna(subset=["MOVIMENTO"])
    df = df[df["NOTA"].astype(str).str.len() > 0]
    df = df[df["VENDEDOR"].astype(str).str.len() > 0]
    df = df[df["MESTRE"].astype(str).str.len() > 0]

    return df

def inserir_vendas_no_banco(df: pd.DataFrame, chunk_size: int = 5000) -> Tuple[int, int]:
    """Insere no banco ignorando duplicados (mestre, vendedor, nota, emp). Retorna (inseridos, ignorados)."""
    engine = get_engine()

    # Monta tuplas para insert
    cols = [
        "MESTRE",
        "MARCA",
        "VENDEDOR",
        "MOVIMENTO",
        "MOV_TIPO_MOVTO",
        "QTDADE_VENDIDA",
        "VALOR_TOTAL",
        "NOTA",
        "EMP",
        "UNIT",
        "DES",
    ]
    df2 = df[cols].copy()

    # Converte data para date
    df2["MOVIMENTO"] = df2["MOVIMENTO"].dt.date

    total = len(df2)
    inseridos = 0

    insert_sql = text(
        """
        insert into public.vendas
            (mestre, marca, vendedor, data, mov_tipo_movto, qtda_vendida, valor_total, nota, emp, unit, des)
        values
            (:mestre, :marca, :vendedor, :data, :mov_tipo_movto, :qtda_vendida, :valor_total, :nota, :emp, :unit, :des)
        on conflict (mestre, vendedor, nota, emp) do nothing
        """
    )

    with engine.begin() as conn:
        for start in range(0, total, chunk_size):
            part = df2.iloc[start : start + chunk_size]
            params = [
                {
                    "mestre": str(r.MESTRE),
                    "marca": str(r.MARCA),
                    "vendedor": str(r.VENDEDOR),
                    "data": r.MOVIMENTO,
                    "mov_tipo_movto": str(r.MOV_TIPO_MOVTO),
                    "qtda_vendida": float(r.QTDADE_VENDIDA) if pd.notna(r.QTDADE_VENDIDA) else 0.0,
                    "valor_total": float(r.VALOR_TOTAL) if pd.notna(r.VALOR_TOTAL) else 0.0,
                    "nota": str(r.NOTA),
                    "emp": str(r.EMP),
                    "unit": None if pd.isna(r.UNIT) else float(r.UNIT),
                    "des": None if pd.isna(r.DES) else float(r.DES),
                }
                for r in part.itertuples(index=False)
            ]
            res = conn.execute(insert_sql, params)
            # res.rowcount é a quantidade inserida neste lote
            if res.rowcount is not None:
                inseridos += int(res.rowcount)

    ignorados = total - inseridos
    return inseridos, ignorados

app = Flask(__name__)
# Em produção, defina FLASK_SECRET_KEY no ambiente.
app.secret_key = os.environ.get("SECRET_KEY", "sistema-vendas-seguro")

# Limite de upload (ajuste se necessário)
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_MB", "30")) * 1024 * 1024

# =========================
# USUÁRIOS (persistência em JSON, com senha criptografada)
# =========================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
USUARIOS_JSON = os.environ.get("USUARIOS_JSON", os.path.join(BASE_DIR, "usuarios.json"))

def _normalizar_usuario(nome: str) -> str:
    return (nome or "").strip().upper()

def carregar_usuarios() -> dict:
    """Lê usuarios.json. Se não existir, cria um ADMIN padrão."""
    if not os.path.exists(USUARIOS_JSON):
        # ADMIN padrão: usuário ADMIN, senha admin123
        # (troque assim que entrar!)
        usuarios = {
            "ADMIN": {
                "senha_hash": generate_password_hash("admin123"),
                "role": "admin"
            }
        }
        salvar_usuarios(usuarios)
        return usuarios

    with open(USUARIOS_JSON, "r", encoding="utf-8") as f:
        return json.load(f)

def salvar_usuarios(usuarios: dict) -> None:
    os.makedirs(os.path.dirname(USUARIOS_JSON), exist_ok=True)
    with open(USUARIOS_JSON, "w", encoding="utf-8") as f:
        json.dump(usuarios, f, ensure_ascii=False, indent=2)

def validar_login(usuario: str, senha: str) -> tuple[bool, dict | None]:
    usuario = _normalizar_usuario(usuario)
    usuarios = carregar_usuarios()
    u = usuarios.get(usuario)
    if not u:
        return False, None
    if check_password_hash(u.get("senha_hash", ""), senha or ""):
        return True, u
    return False, None

def criar_ou_atualizar_usuario(usuario: str, senha: str, role: str = "vendedor") -> None:
    usuario = _normalizar_usuario(usuario)
    usuarios = carregar_usuarios()
    usuarios[usuario] = {
        "senha_hash": generate_password_hash(senha),
        "role": role
    }
    salvar_usuarios(usuarios)

def remover_usuario(usuario: str) -> None:
    usuario = _normalizar_usuario(usuario)
    usuarios = carregar_usuarios()
    if usuario in usuarios:
        usuarios.pop(usuario)
        salvar_usuarios(usuarios)

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "usuario" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "usuario" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


@app.errorhandler(403)
def forbidden(_e):
    return (
        "<h3>Acesso negado (403)</h3><p>Você não tem permissão para acessar esta página.</p>",
        403,
    )


# =========================
# CONFIG (caminhos)
# =========================
# Por padrão usa a pasta do projeto. No Windows local você pode manter o seu caminho fixo,
# ou deixar relativo (recomendado pra facilitar quando for para nuvem).
CAMINHO_PLANILHA = os.environ.get(
    "CAMINHO_PLANILHA",
    os.path.join(BASE_DIR, "planilha", "vendas.xlsx")
)
CAMINHO_PARQUET = os.environ.get(
    "CAMINHO_PARQUET",
    os.path.join(BASE_DIR, "planilha", "vendas.parquet")
)

# =========================
# BASE (Banco de Dados + cache)
# =========================
_df_cache = None
_cache_last_check = 0

def carregar_base():
    """
    Carrega a base a partir do BANCO (PostgreSQL).
    Usa cache em memória para acelerar acessos repetidos.
    (Atualiza no máximo a cada 2 segundos)
    """
    global _df_cache, _cache_last_check

    # Evita consultar o banco a cada request quando há muitos acessos.
    # (Checa no máximo a cada 2 segundos)
    now = time.time()
    if _df_cache is not None and (now - _cache_last_check) < 2:
        return _df_cache

    _cache_last_check = now
    df = carregar_df_db()
    _df_cache = df
    return df


# =========================
# FUNÇÃO DE CÁLCULO
# =========================
def calcular_dados(vendedor, ano_atual, mes_atual):
    df = carregar_base().copy()

    # Tipos e limpeza
    df["MOVIMENTO"] = pd.to_datetime(df["MOVIMENTO"], errors="coerce")
    df["VALOR_TOTAL"] = pd.to_numeric(df["VALOR_TOTAL"], errors="coerce").fillna(0)

    # =========================
    # MOVIMENTOS NEGATIVOS (DS/CA)
    # =========================
    if "MOV_TIPO_MOVTO" not in df.columns:
        df["MOV_TIPO_MOVTO"] = ""

    df["MOV_TIPO_MOVTO"] = df["MOV_TIPO_MOVTO"].astype(str).str.strip().str.upper()
    eh_negativo = df["MOV_TIPO_MOVTO"].isin(["DS", "CA"])
    df["VALOR_ASSINADO"] = df["VALOR_TOTAL"].where(~eh_negativo, -df["VALOR_TOTAL"])

    # =========================
    # FILTRO POR VENDEDOR
    # =========================
    vendedor_norm = _normalizar_usuario(vendedor)
    if 'VENDEDOR' not in df.columns:
        return None
    df['VENDEDOR'] = df['VENDEDOR'].astype(str).str.strip().str.upper()
    df_vend = df[df['VENDEDOR'] == vendedor_norm].copy()
    if df_vend.empty:
        return None

    # mês atual
    df_mes = df_vend[
        (df_vend["MOVIMENTO"].dt.year == ano_atual) &
        (df_vend["MOVIMENTO"].dt.month == mes_atual)
    ].copy()

    # mês anterior
    if mes_atual == 1:
        mes_ant = 12
        ano_ant = ano_atual - 1
    else:
        mes_ant = mes_atual - 1
        ano_ant = ano_atual

    df_mes_ant = df_vend[
        (df_vend["MOVIMENTO"].dt.year == ano_ant) &
        (df_vend["MOVIMENTO"].dt.month == mes_ant)
    ].copy()

    # mesmo mês ano passado
    df_mes_ano_passado = df_vend[
        (df_vend["MOVIMENTO"].dt.year == ano_atual - 1) &
        (df_vend["MOVIMENTO"].dt.month == mes_atual)
    ].copy()

    # =========================
    # CÁLCULOS
    # =========================

    # MIX: considerar apenas vendas (não DS/CA)
    df_mes_vendas = df_mes[~df_mes["MOV_TIPO_MOVTO"].isin(["DS", "CA"])]
    df_mes_ano_passado_vendas = df_mes_ano_passado[~df_mes_ano_passado["MOV_TIPO_MOVTO"].isin(["DS", "CA"])]

    mix_atual = df_mes_vendas["MESTRE"].nunique()
    mix_ano_passado = df_mes_ano_passado_vendas["MESTRE"].nunique()

    # VALOR líquido: considerar DS/CA como negativo
    valor_atual = df_mes["VALOR_ASSINADO"].sum()
    valor_ano_passado = df_mes_ano_passado["VALOR_ASSINADO"].sum()
    valor_mes_ant = df_mes_ant["VALOR_ASSINADO"].sum()

    # Crescimento vs mês anterior (líquido)
    if valor_mes_ant != 0:
        crescimento = ((valor_atual - valor_mes_ant) / abs(valor_mes_ant)) * 100
    else:
        crescimento = None

    # Valor por marca (líquido) - COMPLETO
    valor_por_marca = (
        df_mes
        .groupby("MARCA")["VALOR_ASSINADO"]
        .sum()
        .sort_values(ascending=False)
    )

    # Percentual por marca (líquido) - COMPLETO
    if valor_atual != 0:
        percentual_por_marca = (valor_por_marca / valor_atual) * 100
    else:
        percentual_por_marca = pd.Series(dtype="float64")


    # =========================
    # RANKING UNIFICADO (Valor + %)
    # =========================
    ranking_valor_pct = (
        pd.DataFrame({"valor": valor_por_marca, "pct": percentual_por_marca})
        .fillna(0)
        .sort_values("valor", ascending=False)
    )
    ranking_top15 = ranking_valor_pct.head(15)

    # Listas prontas para o HTML (mais rápido que iterrows no template)
    ranking_todos_list = [
        {"marca": str(marca), "valor": float(row["valor"]), "pct": float(row["pct"]) }
        for marca, row in ranking_valor_pct.iterrows()
    ]
    ranking_top15_list = ranking_todos_list[:15]

    # =========================
    # INDICADORES DS/CA (Devolução/Cancelamento)
    # =========================
    df_devol = df_mes[df_mes["MOV_TIPO_MOVTO"].isin(["DS", "CA"])]
    df_vendas = df_mes[~df_mes["MOV_TIPO_MOVTO"].isin(["DS", "CA"])]

    # Bruto = só vendas (positivo)
    valor_bruto = df_vendas["VALOR_TOTAL"].sum()

    # Devolvido/Cancelado = somatório DS/CA (mostrar positivo)
    valor_devolvido = df_devol["VALOR_TOTAL"].sum()

    if valor_bruto > 0:
        pct_devolucao = (valor_devolvido / valor_bruto) * 100
    else:
        pct_devolucao = None

    devolucao_por_marca = (
        df_devol
        .groupby("MARCA")["VALOR_TOTAL"]
        .sum()
        .sort_values(ascending=False)
    )

    return {
        "mix_atual": int(mix_atual),
        "mix_ano_passado": int(mix_ano_passado),

        # Valor líquido
        "valor_atual": float(valor_atual),
        "valor_ano_passado": float(valor_ano_passado),

        # DS/CA indicadores
        "valor_bruto": float(valor_bruto),
        "valor_devolvido": float(valor_devolvido),
        "pct_devolucao": None if pct_devolucao is None else float(pct_devolucao),
        "top10_devolucao_marcas": devolucao_por_marca.head(10),

        "crescimento": None if crescimento is None else float(crescimento),

        # Para o dashboard
        "top10_marcas": valor_por_marca.head(10),
        "ranking_top15_list": ranking_top15_list,
        "ranking_todos_list": ranking_todos_list,

        # Para as telas "Ver todas"
        "todas_marcas": valor_por_marca,
        "top15_percentual": percentual_por_marca.head(15) if not percentual_por_marca.empty else None,
        "todos_percentuais": percentual_por_marca,
    }



def _dados_vazios():
    # Estrutura padrão para quando não há dados no período ou vendedor não encontrado
    return {
        'mix_atual': 0,
        'mix_ano_passado': 0,
        'valor_atual': 0.0,
        'valor_ano_passado': 0.0,
        'valor_bruto': 0.0,
        'valor_devolvido': 0.0,
        'pct_devolucao': 0.0,
        'top10_devolucao_marcas': pd.Series(dtype='float64'),
        'crescimento': None,
        'top10_marcas': pd.Series(dtype='float64'),
        'ranking_top15_list': [],
        'ranking_todos_list': [],
        'todas_marcas': pd.Series(dtype='float64'),
        'top15_percentual': None,
        'todos_percentuais': pd.Series(dtype='float64'),
        'sem_dados': True,
        'mensagem': 'Nenhum dado encontrado para este vendedor no período selecionado.',
    }

# =========================
# ROTAS
# =========================
@app.route("/", methods=["GET", "POST"])
def login():
    erro = None

    if request.method == "POST":
        usuario = request.form.get("vendedor", "")
        senha = request.form.get("senha", "")

        ok, info = validar_login(usuario, senha)
        if ok:
            usuario = _normalizar_usuario(usuario)
            session.clear()
            session["usuario"] = usuario
            session["role"] = info.get("role", "vendedor")

            # Admin vai direto para o painel de administração
            if session["role"] == "admin":
                return redirect(url_for("admin_usuarios"))
            return redirect(url_for("dashboard"))

        erro = "Usuário ou senha inválidos."

    return render_template("login.html", erro=erro)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/dashboard")
@login_required
def dashboard():
    # vendedor = usuário logado (exceto admin)
    if session.get("role") == "admin":
        return redirect(url_for("admin_usuarios"))

    vendedor = session["usuario"]

    hoje = datetime.today()
    ano_padrao = hoje.year
    mes_padrao = hoje.month

    ano_atual = int(request.args.get("ano", ano_padrao))
    mes_atual = int(request.args.get("mes", mes_padrao))

    dados = calcular_dados(vendedor, ano_atual, mes_atual)
    if dados is None:
        dados = _dados_vazios()


    return render_template(
        "dashboard.html",
        vendedor=vendedor,
        dados=dados,
        mes=mes_atual,
        ano=ano_atual,
        role=session.get("role")
    )

@app.route("/marcas")
@login_required
def marcas():
    # Desativado: o ranking de marcas foi unificado em /percentuais (Valor + %)
    if session.get("role") == "admin":
        return redirect(url_for("admin_usuarios"))

    ano = request.args.get("ano")
    mes = request.args.get("mes")
    if ano and mes:
        return redirect(f"/percentuais?mes={mes}&ano={ano}")
    return redirect("/percentuais")

@app.route("/percentuais")
@login_required
def percentuais():
    if session.get("role") == "admin":
        return redirect(url_for("admin_usuarios"))

    vendedor = session["usuario"]
    hoje = datetime.today()
    ano = int(request.args.get("ano", hoje.year))
    mes = int(request.args.get("mes", hoje.month))

    dados = calcular_dados(vendedor, ano, mes)
    if dados is None:
        return render_template("percentuais.html", vendedor=vendedor, ranking_list=None, total=0, mes=mes, ano=ano)

    return render_template(
        "percentuais.html",
        vendedor=vendedor,
        ranking_list=dados.get("ranking_todos_list"),
        total=dados["valor_atual"],
        mes=mes,
        ano=ano,
        role=session.get("role")
    )
@app.route("/devolucoes")
@login_required
def devolucoes():
    if session.get("role") == "admin":
        return redirect(url_for("admin_usuarios"))

    vendedor = session["usuario"]
    hoje = datetime.today()
    ano = int(request.args.get("ano", hoje.year))
    mes = int(request.args.get("mes", hoje.month))

    dados = calcular_dados(vendedor, ano, mes)
    if dados is None:
        return render_template(
            "devolucoes.html",
            vendedor=vendedor,
            devolucoes=pd.Series(dtype="float64"),
            mes=mes,
            ano=ano
        )

    return render_template(
        "devolucoes.html",
        vendedor=vendedor,
        devolucoes=dados["top10_devolucao_marcas"] if dados.get("top10_devolucao_marcas") is not None else pd.Series(dtype="float64"),
        mes=mes,
        ano=ano,
        role=session.get("role")
    )


# =========================
# TROCAR SENHA (usuário logado)
# =========================
@app.route("/senha", methods=["GET", "POST"])
@login_required
def senha():
    if session.get("role") == "admin":
        # Admin também pode trocar a própria senha aqui
        pass

    usuario = session["usuario"]
    erro = None
    ok = None

    if request.method == "POST":
        senha_atual = request.form.get("senha_atual", "")
        nova_senha = request.form.get("nova_senha", "")
        confirmar = request.form.get("confirmar", "")

        if len(nova_senha) < 4:
            erro = "A nova senha precisa ter pelo menos 4 caracteres."
        elif nova_senha != confirmar:
            erro = "A confirmação não confere."
        else:
            ok_login, _ = validar_login(usuario, senha_atual)
            if not ok_login:
                erro = "Senha atual incorreta."
            else:
                # Atualiza no JSON
                usuarios = carregar_usuarios()
                info = usuarios.get(usuario, {})
                info["senha_hash"] = generate_password_hash(nova_senha)
                usuarios[usuario] = info
                salvar_usuarios(usuarios)
                ok = "Senha alterada com sucesso!"

    return render_template("senha.html", vendedor=usuario, erro=erro, ok=ok, role=session.get("role"))


# =========================
# ADMIN - GERENCIAR USUÁRIOS
# =========================
@app.route("/admin/usuarios", methods=["GET", "POST"])
@admin_required
def admin_usuarios():
    erro = None
    ok = None

    if request.method == "POST":
        acao = request.form.get("acao")

        if acao == "criar":
            novo_usuario = request.form.get("novo_usuario", "")
            nova_senha = request.form.get("nova_senha", "")
            role = request.form.get("role", "vendedor")

            if not novo_usuario.strip():
                erro = "Informe o nome do usuário."
            elif len(nova_senha) < 4:
                erro = "A senha precisa ter pelo menos 4 caracteres."
            else:
                criar_ou_atualizar_usuario(novo_usuario, nova_senha, role=role)
                ok = f"Usuário { _normalizar_usuario(novo_usuario) } criado/atualizado."

        elif acao == "reset":
            alvo = request.form.get("alvo", "")
            nova_senha = request.form.get("nova_senha", "")
            if _normalizar_usuario(alvo) == "ADMIN":
                erro = "Para segurança, use a tela de 'Trocar senha' para alterar a senha do ADMIN."
            elif len(nova_senha) < 4:
                erro = "A senha precisa ter pelo menos 4 caracteres."
            else:
                usuarios = carregar_usuarios()
                u = usuarios.get(_normalizar_usuario(alvo))
                if not u:
                    erro = "Usuário não encontrado."
                else:
                    u["senha_hash"] = generate_password_hash(nova_senha)
                    usuarios[_normalizar_usuario(alvo)] = u
                    salvar_usuarios(usuarios)
                    ok = f"Senha de { _normalizar_usuario(alvo) } atualizada."

        elif acao == "remover":
            alvo = request.form.get("alvo", "")
            if _normalizar_usuario(alvo) == "ADMIN":
                erro = "Não é permitido remover o ADMIN."
            else:
                remover_usuario(alvo)
                ok = f"Usuário { _normalizar_usuario(alvo) } removido."

    usuarios = carregar_usuarios()
    # Lista amigável pro template
    lista = [
        {"usuario": u, "role": info.get("role", "vendedor")}
        for u, info in sorted(usuarios.items(), key=lambda x: x[0])
    ]

    return render_template("admin_usuarios.html", usuarios=lista, erro=erro, ok=ok, usuario=session.get("usuario"))


# =========================
# ADMIN - IMPORTAR VENDAS (Excel/CSV)
# =========================
@app.route("/admin/importar", methods=["GET", "POST"])
@admin_required
def admin_importar():
    erro = None
    ok = None
    resumo = None

    if request.method == "POST":
        arq = request.files.get("arquivo")
        if not arq or not arq.filename:
            erro = "Selecione uma planilha (.xlsx) ou arquivo (.csv)."
        else:
            nome = secure_filename(arq.filename)
            ext = os.path.splitext(nome)[1].lower()
            if ext not in [".xlsx", ".xls", ".xlsm", ".csv"]:
                erro = "Formato inválido. Envie .xlsx ou .csv."
            else:
                # Salva temporariamente (Render permite /tmp)
                with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                    tmp_path = tmp.name
                    arq.save(tmp_path)

                try:
                    df = _ler_planilha_vendas(tmp_path)
                    total_linhas = len(df)
                    inseridos, ignorados = inserir_vendas_no_banco(df)

                    # limpa cache para refletir os dados imediatamente
                    global _df_cache, _cache_last_check
                    _df_cache = None
                    _cache_last_check = 0

                    resumo = {
                        "total": int(total_linhas),
                        "inseridos": int(inseridos),
                        "ignorados": int(ignorados),
                    }
                    ok = "Importação concluída com sucesso!"
                except Exception as e:
                    erro = f"Erro ao importar: {e}"
                finally:
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass

    return render_template(
        "admin_importar.html",
        erro=erro,
        ok=ok,
        resumo=resumo,
        usuario=session.get("usuario"),
    )


# =========================
# START
# =========================
if __name__ == "__main__":
    app.run(debug=True)
