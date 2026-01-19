import os
import logging
from datetime import date, datetime
import calendar

import pandas as pd
from sqlalchemy import and_
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
        app.logger.exception("Falha ao criar/verificar tabelas")

    # ------------- Helpers -------------
    def _usuario_logado() -> str | None:
        return session.get("usuario")

    def _role() -> str | None:
        return session.get("role")

    def _emp() -> str | None:
        """Retorna a EMP do usuário logado (quando existir)."""
        emp = session.get("emp")
        if emp is not None and emp != "":
            return str(emp)
        uid = session.get("user_id")
        if not uid:
            return None
        try:
            db = SessionLocal()
            u = db.query(Usuario).filter(Usuario.id == uid).first()
            if not u:
                return None
            emp_val = getattr(u, "emp", None)
            if emp_val is None or emp_val == "":
                return None
            session["emp"] = str(emp_val)
            return str(emp_val)
        except Exception:
            return None
        finally:
            try:
                db.close()
            except Exception:
                pass

    def _normalize_cols(df: pd.DataFrame) -> pd.DataFrame:
        """Normaliza nomes/tipos de colunas vindas do banco.

        Regras do app:
        - VENDEDOR (str, UPPER) e EMP (str)
        - MOVIMENTO (datetime) é usado para filtrar mês/ano
        """
        if df is None or df.empty:
            return df

        rename: dict[str, str] = {}
        for col in df.columns:
            low = str(col).strip().lower()
            if low == "vendedor":
                rename[col] = "VENDEDOR"
            elif low == "marca":
                rename[col] = "MARCA"
            elif low in ("data", "movimento"):
                # O app usa MOVIMENTO para filtros de período
                rename[col] = "MOVIMENTO"
            elif low in ("mov_tipo_movto", "mov_tipo_movimento", "mov_tipo_movto "):
                rename[col] = "MOV_TIPO_MOVTO"
            elif low in ("valor_total", "valor", "total"):
                rename[col] = "VALOR_TOTAL"
            elif low == "mestre":
                rename[col] = "MESTRE"
            elif low == "emp":
                rename[col] = "EMP"

        if rename:
            df = df.rename(columns=rename)

        # Tipos esperados
        if "MOVIMENTO" in df.columns:
            df["MOVIMENTO"] = pd.to_datetime(df["MOVIMENTO"], errors="coerce")
        if "VENDEDOR" in df.columns:
            df["VENDEDOR"] = df["VENDEDOR"].astype(str).str.strip().str.upper()
        if "EMP" in df.columns:
            df["EMP"] = df["EMP"].astype(str).str.strip()

        return df

    def _login_required():
        if not _usuario_logado():
            return redirect(url_for("login"))
        return None

    def _admin_required():
        if _role() != "admin":
            flash("Acesso restrito ao administrador.", "warning")
            return redirect(url_for("dashboard"))
        return None

    # NOTE: existe uma versão tipada desta função mais abaixo.
    # Mantemos apenas uma definição para evitar confusão/override.

    def _calcular_dados(df: pd.DataFrame, vendedor: str, mes: int, ano: int):
        """Calcula os números do dashboard a partir do DF carregado do banco."""
        if df is None or df.empty:
            return None

        # Normaliza colunas e tipos para suportar variações de schema (ex.: emp/EMP)
        df = _normalize_cols(df)

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
            """Mix de produtos (por MESTRE), abatendo DS/CA e sem ficar negativo.

            Regra:
            - Movimentos normais contam +1 por MESTRE
            - DS/CA contam -1 por MESTRE
            - O mix final é a quantidade de MESTRES com saldo > 0
            """
            if df_in.empty:
                return 0
            tmp = df_in[["MESTRE", "MOV_TIPO_MOVTO"]].copy()
            tmp["_s"] = 1
            tmp.loc[tmp["MOV_TIPO_MOVTO"].isin(["DS", "CA"]), "_s"] = -1
            saldo = tmp.groupby("MESTRE")["_s"].sum()
            return int((saldo > 0).sum())

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

    def _mes_ano_from_request() -> tuple[int, int]:
        mes = int(request.args.get("mes") or datetime.now().month)
        ano = int(request.args.get("ano") or datetime.now().year)
        mes = max(1, min(12, mes))
        ano = max(2000, min(2100, ano))
        return mes, ano

    def _resolver_vendedor_e_lista(df: pd.DataFrame) -> tuple[str | None, list[str], str | None, str | None]:
        """Resolve qual vendedor o usuário pode ver.

        Retorna: (vendedor_alvo, lista_vendedores, emp_usuario, aviso)
        - vendedor_alvo pode ser None quando ADMIN/SUPERVISOR ainda não selecionou.
        - lista_vendedores é usada no dropdown para ADMIN/SUPERVISOR.
        - emp_usuario é a EMP do supervisor (quando existir).
        - aviso é uma mensagem opcional para exibir na tela.
        """
        role = (session.get("role") or "").strip().lower()
        # No login o app grava session["usuario"].
        usuario_logado = (session.get("usuario") or "").strip().upper()
        df = _normalize_cols(df)

        # Lista base de vendedores (da tabela de vendas, pois a tabela usuarios pode não ter EMP preenchida)
        if df.empty or "VENDEDOR" not in df.columns:
            return None, [], _emp(), "Sem dados de vendas para montar a lista de vendedores."

        emp_usuario = _emp()
        if role == "supervisor":
            if not emp_usuario:
                return None, [], None, "Supervisor sem EMP cadastrada. Cadastre a EMP do supervisor na tabela usuarios."
            df_scope = df[df["EMP"] == str(emp_usuario)] if "EMP" in df.columns else df.iloc[0:0]
        elif role == "admin":
            df_scope = df
        else:
            # vendedor
            return usuario_logado, [], emp_usuario, None

        vendedores = (
            df_scope["VENDEDOR"].dropna().astype(str).str.strip().str.upper().unique().tolist()
            if not df_scope.empty
            else []
        )
        vendedores = sorted([v for v in vendedores if v])

        vendedor_req = (request.args.get("vendedor") or "").strip().upper() or None
        vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores) else None

        if not vendedores:
            # Ajuda a diagnosticar: existe EMP no df?
            if role == "supervisor" and emp_usuario:
                return None, [], emp_usuario, f"Nenhum vendedor encontrado para EMP {emp_usuario}. Verifique se a coluna EMP na tabela vendas está preenchida com {emp_usuario}."
            return None, [], emp_usuario, "Nenhum vendedor encontrado."

        return vendedor_alvo, vendedores, emp_usuario, None

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

            session["user_id"] = u.id
            session["usuario"] = u.username
            session["role"] = (u.role or "vendedor").strip().lower()
            # EMP pode não existir em versões antigas do schema
            session["emp"] = str(getattr(u, "emp", "")) if getattr(u, "emp", None) is not None else ""

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

        try:
            df = carregar_df()
            df = _normalize_cols(df)
        except Exception:
            app.logger.exception("Erro ao carregar dados")
            df = pd.DataFrame()

        vendedor_alvo, vendedores_lista, emp, msg = _resolver_vendedor_e_lista(df)

        dados = None
        if vendedor_alvo:
            try:
                dados = _calcular_dados(df, vendedor_alvo, mes, ano)
            except Exception:
                app.logger.exception("Erro ao carregar/calcular dashboard")
                dados = None

        return render_template(
            "dashboard.html",
            vendedor=vendedor_alvo or "",
            usuario=_usuario_logado(),
            role=_role(),
            emp=emp,
            vendedores=vendedores_lista,
            vendedor_selecionado=vendedor_alvo or "",
            mensagem_role=msg,
            mes=mes,
            ano=ano,
            dados=dados,
        )

    @app.get("/percentuais")
    def percentuais():
        red = _login_required()
        if red:
            return red

        mes, ano = _mes_ano_from_request()
        df = carregar_df()
        vendedor_alvo, vendedores_lista, emp, msg = _resolver_vendedor_e_lista(df)

        dados = {}
        if vendedor_alvo:
            dados = _calcular_dados(df, vendedor_alvo, mes, ano) or {}
        ranking_list = dados.get("ranking_list", [])
        total = float(dados.get("total_liquido_periodo", 0.0))
        return render_template(
            "percentuais.html",
            vendedor=vendedor_alvo or "",
            role=_role(),
            emp=emp,
            mes=mes,
            ano=ano,
            total=total,
            ranking_list=ranking_list,
        )

    @app.get("/marcas")
    def marcas():
        red = _login_required()
        if red:
            return red

        mes, ano = _mes_ano_from_request()
        df = carregar_df()
        vendedor_alvo, vendedores_lista, emp, msg = _resolver_vendedor_e_lista(df)

        # reaproveita cálculo do ranking (líquido por marca)
        dados = {}
        if vendedor_alvo:
            dados = _calcular_dados(df, vendedor_alvo, mes, ano) or {}
        marcas_map = {row["marca"]: row["valor"] for row in dados.get("ranking_list", [])}
        return render_template(
            "marcas.html",
            vendedor=vendedor_alvo or "",
            role=_role(),
            emp=emp,
            mes=mes,
            ano=ano,
            marcas=marcas_map,
        )

    @app.get("/devolucoes")
    def devolucoes():
        red = _login_required()
        if red:
            return red

        mes, ano = _mes_ano_from_request()
        df = carregar_df()
        vendedor_alvo, vendedores_lista, emp, msg = _resolver_vendedor_e_lista(df)

        if (not vendedor_alvo) or (df is None) or df.empty:
            devol = {}
        else:
            df = _normalize_cols(df)
            df = df[df["VENDEDOR"] == vendedor_alvo.upper()]
            df = df[(df["MOVIMENTO"].dt.year == ano) & (df["MOVIMENTO"].dt.month == mes)]
            df = df[df["MOV_TIPO_MOVTO"].isin(["DS", "CA"])]
            devol = (
                df.groupby("MARCA")["VALOR_TOTAL"].sum().sort_values(ascending=False).to_dict()
                if not df.empty
                else {}
            )

        return render_template(
            "devolucoes.html",
            vendedor=vendedor_alvo or "",
            role=_role(),
            emp=emp,
            mes=mes,
            ano=ano,
            devolucoes=devol,
        )

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
                        emp_sup = (request.form.get("emp_supervisor") or "").strip()
                        if len(nova_senha) < 4:
                            raise ValueError("Senha muito curta (mín. 4).")
                        if role not in {"admin", "supervisor", "vendedor"}:
                            role = "vendedor"
                        # Supervisor precisa de EMP
                        emp_val = None
                        if role == "supervisor":
                            if not emp_sup:
                                raise ValueError("Informe a EMP para o supervisor.")
                            emp_val = emp_sup
                        u = db.query(Usuario).filter(Usuario.username == novo_usuario).first()
                        if u:
                            u.senha_hash = generate_password_hash(nova_senha)
                            u.role = role
                            # Atualiza EMP quando aplicável
                            if role == "supervisor":
                                setattr(u, "emp", emp_val)
                            else:
                                setattr(u, "emp", None)
                            ok = f"Usuário {novo_usuario} atualizado."
                        else:
                            db.add(
                                Usuario(
                                    username=novo_usuario,
                                    senha_hash=generate_password_hash(nova_senha),
                                    role=role,
                                    emp=emp_val,
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

            usuarios = db.query(Usuario).order_by(Usuario.role.desc(), Usuario.username.asc()).all()
            usuarios_out = [
                {"usuario": u.username, "role": u.role, "emp": getattr(u, "emp", None)}
                for u in usuarios
            ]

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

    @app.route("/admin/apagar_vendas", methods=["POST"])
    def admin_apagar_vendas():
        """Apaga vendas por dia ou por mes.

        Usado pela tela /admin/importar (admin_importar.html).
        """
        red = _login_required()
        if red:
            return red
        red = _admin_required()
        if red:
            return red

        tipo = (request.form.get("tipo") or "").strip().lower()
        valor = (request.form.get("valor") or "").strip()
        if tipo not in {"dia", "mes"}:
            flash("Tipo invalido para apagar vendas.", "danger")
            return redirect(url_for("admin_importar"))
        if not valor:
            flash("Informe uma data/mes para apagar.", "warning")
            return redirect(url_for("admin_importar"))

        db = SessionLocal()
        try:
            if tipo == "dia":
                # valor: YYYY-MM-DD
                try:
                    dt = datetime.strptime(valor, "%Y-%m-%d").date()
                except Exception:
                    flash("Data invalida. Use o seletor de data.", "danger")
                    return redirect(url_for("admin_importar"))

                q = db.query(Venda).filter(Venda.movimento == dt)
                apagadas = q.delete(synchronize_session=False)
                db.commit()
                flash(f"Apagadas {apagadas} vendas do dia {dt.strftime('%d/%m/%Y')}.", "success")
                return redirect(url_for("admin_importar"))

            # tipo == "mes"  valor: YYYY-MM
            try:
                ano = int(valor[:4])
                mes = int(valor[5:7])
                if mes < 1 or mes > 12:
                    raise ValueError
            except Exception:
                flash("Mes invalido. Use o seletor de mes.", "danger")
                return redirect(url_for("admin_importar"))

            last_day = calendar.monthrange(ano, mes)[1]
            d_ini = date(ano, mes, 1)
            d_fim = date(ano, mes, last_day)

            q = db.query(Venda).filter(and_(Venda.movimento >= d_ini, Venda.movimento <= d_fim))
            apagadas = q.delete(synchronize_session=False)
            db.commit()
            flash(f"Apagadas {apagadas} vendas de {mes:02d}/{ano}.", "success")
            return redirect(url_for("admin_importar"))

        except Exception:
            db.rollback()
            app.logger.exception("Erro ao apagar vendas")
            flash("Erro ao apagar vendas. Veja os logs.", "danger")
            return redirect(url_for("admin_importar"))
        finally:
            try:
                db.close()
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
