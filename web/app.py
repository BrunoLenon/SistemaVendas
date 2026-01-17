import os
import logging
from datetime import date

import pandas as pd
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from dados_db import carregar_df
from db import SessionLocal, Usuario, Venda, criar_tabelas
from importar_excel import importar_planilha


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates")
    app.secret_key = os.getenv("SECRET_KEY", "dev")

    # Logs no stdout (Render captura automaticamente)
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

    # Garante tabelas
    try:
        criar_tabelas()
    except Exception:
        app.logger.exception("Falha ao criar/verificar tabelas")    # ------------- Helpers -------------
    def _usuario_logado() -> str | None:
        return session.get("usuario")

    def _role() -> str:
        """Role do usuário logado: admin | vendedor | supervisor"""
        return (session.get("role") or "vendedor").strip().lower()

    def _emp() -> int | None:
        """EMP (loja) associada ao usuário (ex.: supervisor)."""
        return session.get("emp")

    def _login_required():
        if not _usuario_logado():
            return redirect(url_for("login"))
        return None

    def _admin_required():
        if _role() != "admin":
            flash("Acesso restrito ao administrador.", "warning")
            return redirect(url_for("dashboard"))
        return None

    def _mes_ano_from_request():
        hoje = date.today()
        mes = int(request.args.get("mes", hoje.month))
        ano = int(request.args.get("ano", hoje.year))
        mes = max(1, min(12, mes))
        ano = max(2000, min(2100, ano))
        return mes, ano

    def _vendedores_por_emp(emp: int) -> list[str]:
        """Lista vendedores (USERNAME/coluna VENDEDOR) que possuem vendas na EMP informada."""
        if not emp:
            return []
        emp_str = str(emp)
        with SessionLocal() as db:
            rows = (
                db.query(Venda.vendedor)
                .filter(Venda.emp == emp_str)
                .distinct()
                .order_by(Venda.vendedor)
                .all()
            )
        return [r[0] for r in rows if r and r[0]]

    def _supervisor_pode_ver_vendedor(emp: int, vendedor: str) -> bool:
        if not emp or not vendedor:
            return False
        return vendedor.upper() in set(v.upper() for v in _vendedores_por_emp(emp))

    def _calcular_dados(df: pd.DataFrame, vendedor: str, mes: int, ano: int):
        """Calcula os números do dashboard a partir do DF carregado do banco."""
        if df is None or df.empty:
            return None

        # Normaliza
        df = df.copy()
        df["VENDEDOR"] = df["VENDEDOR"].astype(str).str.strip().str.upper()
        df["MARCA"] = df["MARCA"].astype(str).str.strip().str.upper()
        df["MESTRE"] = df["MESTRE"].astype(str).str.strip()
        df["MOV_TIPO_MOVTO"] = df["MOV_TIPO_MOVTO"].astype(str).str.strip().str.upper()
        df["MOVIMENTO"] = pd.to_datetime(df["MOVIMENTO"], errors="coerce")
        df["VALOR_TOTAL"] = pd.to_numeric(df["VALOR_TOTAL"], errors="coerce").fillna(0.0)

        df_v = df[df["VENDEDOR"] == vendedor.upper()].copy()
        if df_v.empty:
            return None

        # DS/CA entram como negativo no líquido
        neg = df_v["MOV_TIPO_MOVTO"].isin(["DS", "CA"])
        df_v["VALOR_ASSINADO"] = df_v["VALOR_TOTAL"].where(~neg, -df_v["VALOR_TOTAL"])

        # Filtra mês/ano
        df_mes = df_v[
            (df_v["MOVIMENTO"].dt.year == ano) & (df_v["MOVIMENTO"].dt.month == mes)
        ].copy()

        # Ano passado (mesmo mês)
        df_ano_passado = df_v[
            (df_v["MOVIMENTO"].dt.year == (ano - 1))
            & (df_v["MOVIMENTO"].dt.month == mes)
        ].copy()

        # Mês anterior
        if mes == 1:
            mes_ant, ano_ant = 12, ano - 1
        else:
            mes_ant, ano_ant = mes - 1, ano
        df_mes_ant = df_v[
            (df_v["MOVIMENTO"].dt.year == ano_ant) & (df_v["MOVIMENTO"].dt.month == mes_ant)
        ].copy()

        def _mix(df_in: pd.DataFrame) -> int:
            if df_in.empty:
                return 0
            vendas = df_in[~df_in["MOV_TIPO_MOVTO"].isin(["DS", "CA"])]
            return int(vendas["MESTRE"].nunique())

        def _valor_liquido(df_in: pd.DataFrame) -> float:
            if df_in.empty:
                return 0.0
            neg = df_in["MOV_TIPO_MOVTO"].isin(["DS", "CA"])
            return float(df_in["VALOR_TOTAL"].where(~neg, -df_in["VALOR_TOTAL"]).sum())

        def _valor_bruto(df_in: pd.DataFrame) -> float:
            if df_in.empty:
                return 0.0
            vendas = df_in[~df_in["MOV_TIPO_MOVTO"].isin(["DS", "CA"])]
            return float(vendas["VALOR_TOTAL"].sum())

        def _valor_devolvido(df_in: pd.DataFrame) -> float:
            if df_in.empty:
                return 0.0
            dev = df_in[df_in["MOV_TIPO_MOVTO"].isin(["DS", "CA"])]
            return float(dev["VALOR_TOTAL"].sum())

        valor_atual = _valor_liquido(df_mes)
        valor_ano_passado = _valor_liquido(df_ano_passado)
        valor_mes_anterior = _valor_liquido(df_mes_ant)

        mix_atual = _mix(df_mes)
        mix_ano_passado = _mix(df_ano_passado)

        valor_bruto = _valor_bruto(df_mes)
        valor_devolvido = _valor_devolvido(df_mes)
        pct_devolucao = (valor_devolvido / valor_bruto * 100.0) if valor_bruto else None

        if valor_mes_anterior:
            crescimento = ((valor_atual - valor_mes_anterior) / abs(valor_mes_anterior)) * 100.0
        else:
            crescimento = None

        # Ranking por marca (líquido)
        if df_mes.empty:
            ranking = pd.Series(dtype=float)
        else:
            neg = df_mes["MOV_TIPO_MOVTO"].isin(["DS", "CA"])
            df_mes = df_mes.copy()
            df_mes["VALOR_ASSINADO"] = df_mes["VALOR_TOTAL"].where(~neg, -df_mes["VALOR_TOTAL"])
            ranking = df_mes.groupby("MARCA")["VALOR_ASSINADO"].sum().sort_values(ascending=False)

        total = float(ranking.sum()) if not ranking.empty else 0.0
        ranking_list = [
            {
                "marca": str(m),
                "valor": float(v),
                "pct": (float(v) / total * 100.0) if total else 0.0,
            }
            for m, v in ranking.items()
        ]

        ranking_top15_list = ranking_list[:15]

        return {
            "valor_atual": valor_atual,
            "valor_ano_passado": valor_ano_passado,
            "valor_mes_anterior": valor_mes_anterior,
            "mix_atual": mix_atual,
            "mix_ano_passado": mix_ano_passado,
            "valor_bruto": valor_bruto,
            "valor_devolvido": valor_devolvido,
            "pct_devolucao": pct_devolucao,
            "crescimento": crescimento,
            "ranking_list": ranking_list,
            "ranking_top15_list": ranking_top15_list,
            "total_liquido_periodo": total,
        }

    def _bootstrap_admin_if_needed():
        """Cria o usuário ADMIN automaticamente se ainda não existir."""
        admin_user = os.getenv("BOOTSTRAP_ADMIN_USER", "ADMIN").strip().upper()
        admin_pass = os.getenv("BOOTSTRAP_ADMIN_PASSWORD")
        if not admin_pass:
            return

        with SessionLocal() as db:
            u = db.query(Usuario).filter(Usuario.username == admin_user).first()
            if u:
                return
            u = Usuario(
                username=admin_user,
                senha_hash=generate_password_hash(admin_pass),
                role="admin",
            )
            db.add(u)
            db.commit()
            app.logger.info("Usuario ADMIN criado automaticamente (%s)", admin_user)

    _bootstrap_admin_if_needed()

    # ------------- Rotas -------------
    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/")
    def home():
        return redirect(url_for("dashboard"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html", erro=None)

        vendedor = (request.form.get("vendedor") or "").strip().upper()
        senha = request.form.get("senha") or ""

        if not vendedor or not senha:
            return render_template("login.html", erro="Informe usuário e senha.")

        with SessionLocal() as db:
            u = db.query(Usuario).filter(Usuario.username == vendedor).first()
            if not u or not check_password_hash(u.senha_hash, senha):
                return render_template("login.html", erro="Usuário ou senha inválidos.")

            session["usuario"] = u.username
            session["role"] = u.role
            session["emp"] = getattr(u, 'emp', None)

        return redirect(url_for("dashboard"))

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/dashboard")
    def dashboard():
        red = _login_required()
        if red:
            return red

        mes, ano = _mes_ano_from_request()
        role = _role()
        emp = _emp()
        # Para supervisor, permitir escolher o vendedor e ver exatamente o que ele veria
        usuario_logado = _usuario_logado()
        vendedor_selecionado = request.args.get("vendedor", type=str)
        if vendedor_selecionado:
            vendedor_selecionado = vendedor_selecionado.strip().upper()

        try:
            df = carregar_df()

            vendedores_disponiveis = []
            dados = None

            if role == "supervisor":
                # supervisor enxerga APENAS vendedores da EMP dele (validação via BANCO)
                try:
                    emp_int = int(emp) if emp is not None else None
                except Exception:
                    emp_int = None

                if emp_int is not None:
                    vendedores_disponiveis = _vendedores_por_emp(emp_int)

                # também filtra o DF por EMP, se existir, para evitar misturas
                if emp_int is not None and "EMP" in df.columns:
                    try:
                        df["EMP"] = df["EMP"].astype("Int64")
                        df = df[df["EMP"] == emp_int].copy()
                    except Exception:
                        df = df[df["EMP"].astype(str) == str(emp_int)].copy()

                # Só calcula se o supervisor escolher um vendedor válido (mesma EMP)
                if vendedor_selecionado and vendedor_selecionado in vendedores_disponiveis:
                    dados = _calcular_dados(df, vendedor_selecionado, mes, ano)
                else:
                    vendedor_selecionado = None

                vendedor_titulo = usuario_logado
            else:
                vendedor_titulo = usuario_logado
                dados = _calcular_dados(df, usuario_logado, mes, ano)

        except Exception:
            app.logger.exception("Erro ao carregar/calcular dashboard")
            vendedores_disponiveis = []
            dados = None
            vendedor_titulo = _usuario_logado()
            vendedor_selecionado = None

        return render_template(
            "dashboard.html",
            vendedor=vendedor_titulo,
            vendedor_selecionado=vendedor_selecionado,
            mes=mes,
            ano=ano,
            dados=dados,
            role=role,
            emp=emp,
            vendedores_disponiveis=vendedores_disponiveis,
        )

    @app.get("/percentuais")
    def percentuais():
        red = _login_required()
        if red:
            return red

        mes, ano = _mes_ano_from_request()
        role = _role()
        emp = _emp()
        vendedor = _usuario_logado()
        vendedor_sel = None
        if role == "supervisor":
            vendedor_sel = request.args.get("vendedor", type=str)
            if not vendedor_sel:
                return redirect(url_for("dashboard"))
            vendedor_sel = vendedor_sel.strip().upper()
            vendedor = vendedor_sel

        try:
            df = carregar_df()
            if role == "supervisor" and emp is not None and "EMP" in df.columns:
                try:
                    emp_int = int(emp)
                    df["EMP"] = df["EMP"].astype("Int64")
                    df = df[df["EMP"] == emp_int].copy()
                except Exception:
                    df = df[df["EMP"].astype(str) == str(emp)].copy()
            if role == "supervisor" and emp is not None:
                allowed = set(_vendedores_por_emp(int(emp)))
                if vendedor.strip().upper() not in allowed:
                    return redirect(url_for("dashboard"))
            dados = _calcular_percentuais(df, vendedor, mes, ano)
        except Exception:
            app.logger.exception("Erro ao calcular percentuais")
            dados = None

        return render_template("percentuais.html", vendedor=vendedor, mes=mes, ano=ano, dados=dados, role=role, emp=emp)

    @app.get("/marcas")
    def marcas():
        red = _login_required()
        if red:
            return red

        mes, ano = _mes_ano_from_request()
        role = _role()
        emp = _emp()
        vendedor = _usuario_logado()
        vendedor_sel = None
        if role == "supervisor":
            vendedor_sel = request.args.get("vendedor", type=str)
            if not vendedor_sel:
                return redirect(url_for("dashboard"))
            vendedor_sel = vendedor_sel.strip().upper()
            vendedor = vendedor_sel

        try:
            df = carregar_df()
            if role == "supervisor" and emp is not None and "EMP" in df.columns:
                try:
                    emp_int = int(emp)
                    df["EMP"] = df["EMP"].astype("Int64")
                    df = df[df["EMP"] == emp_int].copy()
                except Exception:
                    df = df[df["EMP"].astype(str) == str(emp)].copy()
            if role == "supervisor" and emp is not None:
                allowed = set(_vendedores_por_emp(int(emp)))
                if vendedor.strip().upper() not in allowed:
                    return redirect(url_for("dashboard"))
            dados = _calcular_marcas(df, vendedor, mes, ano)
        except Exception:
            app.logger.exception("Erro ao calcular marcas")
            dados = None

        return render_template("marcas.html", vendedor=vendedor, mes=mes, ano=ano, dados=dados, role=role, emp=emp)

    @app.get("/devolucoes")
    def devolucoes():
        red = _login_required()
        if red:
            return red

        mes, ano = _mes_ano_from_request()
        role = _role()
        emp = _emp()
        vendedor = _usuario_logado()
        vendedor_sel = None
        if role == "supervisor":
            vendedor_sel = request.args.get("vendedor", type=str)
            if not vendedor_sel:
                return redirect(url_for("dashboard"))
            vendedor_sel = vendedor_sel.strip().upper()
            vendedor = vendedor_sel

        try:
            df = carregar_df()
            if role == "supervisor" and emp is not None and "EMP" in df.columns:
                try:
                    emp_int = int(emp)
                    df_emp = pd.to_numeric(df["EMP"], errors="coerce").astype("Int64")
                    df = df[df_emp == emp_int].copy()
                except Exception:
                    df = df.iloc[0:0].copy()
            # valida vendedor dentro da EMP do supervisor (também protege contra URL manual)
            if role == "supervisor" and emp is not None:
                vendedores_ok = _vendedores_por_emp(int(emp))
                if vendedor not in vendedores_ok:
                    flash("Vendedor inválido para sua EMP.", "warning")
                    return redirect(url_for("dashboard"))
            dados = _calcular_devolucoes(df, vendedor, mes, ano)
        except Exception:
            app.logger.exception("Erro ao calcular devolucoes")
            dados = None

        return render_template("devolucoes.html", vendedor=vendedor, mes=mes, ano=ano, dados=dados, role=role, emp=emp)


    @app.route("/senha", methods=["GET", "POST"])
    def senha():
        red = _login_required()
        if red:
            return red

        vendedor = _usuario_logado()
        if request.method == "GET":
            return render_template("senha.html", vendedor=vendedor, erro=None, ok=None)

        senha_atual = request.form.get("senha_atual") or ""
        nova_senha = request.form.get("nova_senha") or ""
        confirmar = request.form.get("confirmar") or ""

        if len(nova_senha) < 4:
            return render_template("senha.html", vendedor=vendedor, erro="Nova senha muito curta.", ok=None)
        if nova_senha != confirmar:
            return render_template("senha.html", vendedor=vendedor, erro="As senhas não conferem.", ok=None)

        with SessionLocal() as db:
            u = db.query(Usuario).filter(Usuario.username == vendedor).first()
            if not u or not check_password_hash(u.senha_hash, senha_atual):
                return render_template("senha.html", vendedor=vendedor, erro="Senha atual incorreta.", ok=None)

            u.senha_hash = generate_password_hash(nova_senha)
            db.commit()

        return render_template("senha.html", vendedor=vendedor, erro=None, ok="Senha atualizada com sucesso!")

    @app.route("/admin/usuarios", methods=["GET", "POST"])
    def admin_usuarios():
        red = _login_required()
        if red:
            return red
        red = _admin_required()
        if red:
            return red

        usuario = _usuario_logado()
        erro = None
        ok = None

        with SessionLocal() as db:
            if request.method == "POST":
                acao = request.form.get("acao")
                try:
                    if acao == "criar":
                        novo_usuario = (request.form.get("novo_usuario") or "").strip().upper()
                        nova_senha = request.form.get("nova_senha") or ""
                        role = (request.form.get("role") or "vendedor").strip().lower()
                        if len(nova_senha) < 4:
                            raise ValueError("Senha muito curta (mín. 4).")
                        if role not in {"admin", "vendedor"}:
                            role = "vendedor"
                        u = db.query(Usuario).filter(Usuario.username == novo_usuario).first()
                        if u:
                            u.senha_hash = generate_password_hash(nova_senha)
                            u.role = role
                            ok = f"Usuário {novo_usuario} atualizado."
                        else:
                            db.add(
                                Usuario(
                                    username=novo_usuario,
                                    senha_hash=generate_password_hash(nova_senha),
                                    role=role,
                                )
                            )
                            db.commit()
                            ok = f"Usuário {novo_usuario} criado."

                    elif acao == "reset":
                        alvo = (request.form.get("alvo") or "").strip().upper()
                        nova_senha = request.form.get("nova_senha") or ""
                        if alvo == "ADMIN":
                            raise ValueError("Para o ADMIN, use 'Trocar minha senha'.")
                        u = db.query(Usuario).filter(Usuario.username == alvo).first()
                        if not u:
                            raise ValueError("Usuário não encontrado.")
                        if len(nova_senha) < 4:
                            raise ValueError("Senha muito curta (mín. 4).")
                        u.senha_hash = generate_password_hash(nova_senha)
                        db.commit()
                        ok = f"Senha de {alvo} atualizada."

                    elif acao == "remover":
                        alvo = (request.form.get("alvo") or "").strip().upper()
                        if alvo == "ADMIN":
                            raise ValueError("O usuário ADMIN não pode ser removido.")
                        u = db.query(Usuario).filter(Usuario.username == alvo).first()
                        if not u:
                            raise ValueError("Usuário não encontrado.")
                        db.delete(u)
                        db.commit()
                        ok = f"Usuário {alvo} removido."
                    else:
                        raise ValueError("Ação inválida.")

                except Exception as e:
                    db.rollback()
                    erro = str(e)
                    app.logger.exception("Erro na admin/usuarios")

            usuarios = (
                db.query(Usuario).order_by(Usuario.role.desc(), Usuario.username.asc()).all()
            )
            usuarios_out = [{"usuario": u.username, "role": u.role} for u in usuarios]

        return render_template(
            "admin_usuarios.html",
            usuario=usuario,
            usuarios=usuarios_out,
            erro=erro,
            ok=ok,
        )

    @app.route("/admin/importar", methods=["GET", "POST"])
    def admin_importar():
        red = _login_required()
        if red:
            return red
        red = _admin_required()
        if red:
            return red

        if request.method == "GET":
            return render_template("admin_importar.html")

        arquivo = request.files.get("arquivo")
        if not arquivo or not arquivo.filename:
            flash("Selecione um arquivo .xlsx para importar.", "warning")
            return redirect(url_for("admin_importar"))

        if not arquivo.filename.lower().endswith(".xlsx"):
            flash("Formato inválido. Envie um arquivo .xlsx.", "danger")
            return redirect(url_for("admin_importar"))

        modo = request.form.get("modo", "ignorar_duplicados")
        chave = request.form.get("chave", "mestre_vendedor_nota_emp")

        # Salva temporariamente
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
            arquivo.save(tmp.name)
            tmp_path = tmp.name

        try:
            resumo = importar_planilha(tmp_path, modo=modo, chave=chave)
            if not resumo.get("ok"):
                faltando = resumo.get("faltando")
                if faltando:
                    flash("Colunas faltando: " + ", ".join(faltando), "danger")
                else:
                    flash(resumo.get("msg", "Falha ao importar."), "danger")
                return redirect(url_for("admin_importar"))

            flash(
                (
                    f"Importação concluída. Válidas: {resumo['validas']} | "
                    f"Inseridas: {resumo['inseridas']} | "
                    f"Ignoradas: {resumo['ignoradas']} | "
                    f"Erros: {resumo['erros_linha']}"
                ),
                "success",
            )
            return redirect(url_for("admin_importar"))

        except Exception:
            app.logger.exception("Erro ao importar planilha")
            flash("Erro ao importar. Veja os logs no Render.", "danger")
            return redirect(url_for("admin_importar"))
        finally:
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    # ------------- Erros -------------
    @app.errorhandler(500)
    def err_500(e):
        app.logger.exception("Erro 500: %s", e)
        return (
            "Erro interno. Verifique os logs no Render (ou fale com o admin).",
            500,
        )

    return app


app = create_app()
