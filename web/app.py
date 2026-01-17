import os
import logging
import tempfile
from datetime import date, datetime

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
from sqlalchemy import text

from dados_db import carregar_df
from db import SessionLocal, Usuario, criar_tabelas
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


    @app.route('/dashboard')
    def dashboard():
        if not session.get('usuario'):
            return redirect(url_for('login'))

        usuario_logado = session.get('usuario')
        role = (session.get('role') or 'vendedor').lower()
        emp_usuario = session.get('emp')  # pode ser None

        try:
            mes = int(request.args.get('mes', datetime.now().month))
            ano = int(request.args.get('ano', datetime.now().year))
        except Exception:
            mes = datetime.now().month
            ano = datetime.now().year

        df = carregar_df()

        # Normaliza EMP, se existir
        if df is not None and not df.empty and 'EMP' in df.columns:
            df['EMP'] = pd.to_numeric(df['EMP'], errors='coerce').astype('Int64')

        # Lista de vendedores para selects
        lista_vendedores = []
        if df is not None and not df.empty and 'VENDEDOR' in df.columns:
            if role == 'supervisor' and emp_usuario is not None and 'EMP' in df.columns:
                lista_vendedores = sorted(
                    [v for v in df.loc[df['EMP'] == int(emp_usuario), 'VENDEDOR'].dropna().unique().tolist()]
                )
            else:
                lista_vendedores = sorted([v for v in df['VENDEDOR'].dropna().unique().tolist()])

        # Determina alvo (vendedor visualizado)
        vendedor_alvo = None
        if role == 'vendedor':
            vendedor_alvo = usuario_logado
        elif role == 'supervisor':
            vendedor_alvo = request.args.get('vendedor') or None
            if vendedor_alvo:
                vendedor_alvo = vendedor_alvo.strip()
                # Restricao por EMP do supervisor
                if emp_usuario is not None and vendedor_alvo not in lista_vendedores:
                    flash('Este vendedor nao pertence a sua EMP.', 'warning')
                    vendedor_alvo = None
        else:  # admin
            vendedor_alvo = request.args.get('vendedor') or None
            if vendedor_alvo:
                vendedor_alvo = vendedor_alvo.strip()

        dados = None
        titulo_painel = None

        if df is None or df.empty:
            dados = None
        else:
            if role == 'admin' and not vendedor_alvo:
                # ADMIN sem vendedor selecionado => painel geral (todos)
                dados = _calcular_dados(df, None, mes, ano)
                titulo_painel = 'TODOS'
            elif vendedor_alvo:
                dados = _calcular_dados(df, vendedor_alvo, mes, ano)
                titulo_painel = vendedor_alvo

        return render_template(
            'dashboard.html',
            usuario=usuario_logado,
            vendedor=titulo_painel or vendedor_alvo or usuario_logado,
            vendedor_selecionado=vendedor_alvo,
            lista_vendedores=lista_vendedores,
            role=role,
            emp=emp_usuario,
            mes=mes,
            ano=ano,
            dados=dados,
        )


    @app.route('/percentuais')
    def percentuais():
        if not session.get('usuario'):
            return redirect(url_for('login'))

        usuario_logado = session.get('usuario')
        role = (session.get('role') or 'vendedor').lower()
        emp_usuario = session.get('emp')

        try:
            mes = int(request.args.get('mes', datetime.now().month))
            ano = int(request.args.get('ano', datetime.now().year))
        except Exception:
            mes = datetime.now().month
            ano = datetime.now().year

        df = carregar_df()
        if df is None or df.empty:
            return render_template('percentuais.html', vendedor=usuario_logado, mes=mes, ano=ano, ranking=[])

        if 'EMP' in df.columns:
            df['EMP'] = pd.to_numeric(df['EMP'], errors='coerce').astype('Int64')

        vendedor_alvo = None
        if role == 'vendedor':
            vendedor_alvo = usuario_logado
        elif role == 'supervisor':
            vendedor_alvo = request.args.get('vendedor') or None
            if vendedor_alvo and emp_usuario is not None and 'EMP' in df.columns:
                # valida se vendedor pertence a EMP
                if vendedor_alvo.strip() not in df.loc[df['EMP'] == int(emp_usuario), 'VENDEDOR'].dropna().unique().tolist():
                    flash('Este vendedor nao pertence a sua EMP.', 'warning')
                    vendedor_alvo = None
        else:  # admin
            vendedor_alvo = request.args.get('vendedor') or None

        df['DATA_DT'] = pd.to_datetime(df['DATA'], dayfirst=True, errors='coerce')
        df_mes = df[(df['DATA_DT'].dt.month == mes) & (df['DATA_DT'].dt.year == ano)]

        if role == 'supervisor' and emp_usuario is not None and 'EMP' in df_mes.columns:
            df_mes = df_mes[df_mes['EMP'] == int(emp_usuario)]

        if vendedor_alvo:
            df_mes = df_mes[df_mes['VENDEDOR'] == vendedor_alvo.upper()]
            titulo = vendedor_alvo.upper()
        else:
            titulo = 'TODOS' if role == 'admin' else usuario_logado

        # valor liquido considera DS/CA negativo
        df_mes['VALOR'] = pd.to_numeric(df_mes['VALOR_TOTAL'], errors='coerce').fillna(0.0)
        if 'MOV_TIPO_MOVTO' in df_mes.columns:
            mask_neg = df_mes['MOV_TIPO_MOVTO'].astype(str).str.upper().isin(['DS', 'CA'])
            df_mes.loc[mask_neg, 'VALOR'] = -df_mes.loc[mask_neg, 'VALOR'].abs()

        ranking = (
            df_mes.groupby('MARCA', dropna=False)['VALOR']
            .sum()
            .sort_values(ascending=False)
            .reset_index()
        )
        total = float(ranking['VALOR'].sum()) if len(ranking) else 0.0
        ranking['PCT'] = ranking['VALOR'].apply(lambda x: (float(x) / total * 100.0) if total else 0.0)

        rows = [
            {
                'marca': str(row['MARCA']) if pd.notna(row['MARCA']) else '-',
                'valor': float(row['VALOR']),
                'pct': float(row['PCT']),
            }
            for _, row in ranking.iterrows()
        ]

        return render_template(
            'percentuais.html',
            vendedor=titulo,
            mes=mes,
            ano=ano,
            ranking=rows,
            role=role,
            emp=emp_usuario,
        )


    @app.route('/admin/apagar_vendas', methods=['POST'])
    def admin_apagar_vendas():
        if not session.get('usuario'):
            return redirect(url_for('login'))
        if (session.get('role') or '').lower() != 'admin':
            flash('Acesso negado.', 'danger')
            return redirect(url_for('dashboard'))

        tipo = (request.form.get('tipo') or '').strip().lower()
        valor = (request.form.get('valor') or '').strip()
        if tipo not in ['dia', 'mes'] or not valor:
            flash('Informe o dia ou mes para apagar.', 'warning')
            return redirect(url_for('admin_importar'))

        # Parse data
        try:
            if tipo == 'dia':
                # esperado YYYY-MM-DD
                d = datetime.strptime(valor, '%Y-%m-%d').date()
                dt_ini = d
                dt_fim = d
                where_sql = 'data = :d'
                params = {'d': d}
                label = d.strftime('%d/%m/%Y')
            else:
                # esperado YYYY-MM
                dt_mes = datetime.strptime(valor + '-01', '%Y-%m-%d').date()
                dt_ini = dt_mes.replace(day=1)
                # proximo mes
                if dt_ini.month == 12:
                    dt_next = dt_ini.replace(year=dt_ini.year + 1, month=1)
                else:
                    dt_next = dt_ini.replace(month=dt_ini.month + 1)
                where_sql = 'data >= :ini AND data < :fim'
                params = {'ini': dt_ini, 'fim': dt_next}
                label = dt_ini.strftime('%m/%Y')
        except Exception:
            flash('Data invalida.', 'danger')
            return redirect(url_for('admin_importar'))

        sess = SessionLocal()
        try:
            res = sess.execute(text(f'DELETE FROM vendas WHERE {where_sql}'), params)
            sess.commit()
            apagadas = res.rowcount or 0
            flash(f'Apagadas {apagadas} vendas do periodo {label}.', 'success')
        except Exception as e:
            sess.rollback()
            flash(f'Erro ao apagar vendas: {e}', 'danger')
        finally:
            sess.close()

        return redirect(url_for('admin_importar'))


    # Mantem a rota de importacao como ja estava no arquivo (admin apenas)
    @app.route('/admin/importar', methods=['GET', 'POST'])
    def admin_importar():
        if not session.get('usuario'):
            return redirect(url_for('login'))

        if (session.get('role') or '').lower() != 'admin':
            flash('Acesso negado.', 'danger')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            f = request.files.get('arquivo')
            if not f or f.filename == '':
                flash('Selecione uma planilha.', 'warning')
                return redirect(url_for('admin_importar'))

            modo = request.form.get('modo', 'ignore')
            chave = request.form.get('chave', 'mestre_vendedor_nota_emp_movtipo')

            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx') as tmp:
                    f.save(tmp.name)
                    tmp_path = tmp.name

                resumo = importar_planilha(tmp_path, modo=modo, chave=chave)
                flash(
                    f"Importacao concluida. Validas: {resumo.get('validas', 0)} | Inseridas: {resumo.get('inseridas', 0)} | Ignoradas: {resumo.get('ignoradas', 0)} | Erros: {len(resumo.get('erros', []))}",
                    'success',
                )
            except Exception as e:
                logging.exception('Erro ao importar')
                flash(f'Erro ao importar: {e}', 'danger')
            finally:
                try:
                    if 'tmp_path' in locals() and os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    pass

            return redirect(url_for('admin_importar'))

        # GET
        return render_template('admin_importar.html')


    # Reaproveita /admin/usuarios do arquivo original (esta acima no head)

    return app
