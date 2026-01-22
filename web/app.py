import os
import logging
import json
from datetime import date, datetime
import calendar
from io import BytesIO

import pandas as pd
from sqlalchemy import and_, func, case, cast, String
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    send_file,
)
from werkzeug.security import check_password_hash, generate_password_hash

from dados_db import carregar_df
from db import (
    SessionLocal,
    Usuario,
    Venda,
    DashboardCache,
    ItemParado,
    CampanhaQtd,
    CampanhaQtdResultado,
    VendasResumoPeriodo,
    FechamentoMensal,
    criar_tabelas,
)
from importar_excel import importar_planilha


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates")
    app.secret_key = os.getenv("SECRET_KEY", "dev")

    # --------------------------
    # Filtro Jinja: formato brasileiro
    # --------------------------
    @app.template_filter("brl")
    def brl(value):
        """Formata números no padrão brasileiro (ex: 21.555.384,00).

        Retorna "0,00" para None/valores inválidos.
        """
        if value is None:
            return "0,00"
        try:
            num = float(value)
        except Exception:
            return "0,00"
        return f"{num:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")

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

    def _get_vendedores_db(role: str, emp_usuario: str | None) -> list[str]:
        """Lista de vendedores para dropdown sem carregar todas as vendas em memória."""
        role = (role or "").strip().lower()
        with SessionLocal() as db:
            q = db.query(func.distinct(Venda.vendedor))
            if role == "supervisor":
                if emp_usuario:
                    q = q.filter(Venda.emp == str(emp_usuario))
                else:
                    return []
            # admin vê tudo
            vendedores = [ (r[0] or "").strip().upper() for r in q.all() ]
        vendedores = sorted([v for v in vendedores if v])
        return vendedores

    def _get_emps_vendedor(username: str) -> list[str]:
        """Lista de EMPs em que o vendedor possui vendas (para vendedor multi-EMP).

        Regra do sistema: para vendedores, a EMP é inferida da tabela de vendas.
        """
        username = (username or "").strip().upper()
        if not username:
            return []
        with SessionLocal() as db:
            rows = (
                db.query(func.distinct(Venda.emp))
                .filter(Venda.vendedor == username)
                .all()
            )
        emps = sorted({str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip() != ""})
        return emps

    def _fetch_cache_row(vendedor: str, ano: int, mes: int, emp_scope: str | None) -> dict | None:
        """Busca dados do cache para o vendedor/período.

        - Se emp_scope for None (admin/vendedor), agrega across EMPs (somando valores e juntando ranking por marca).
        """
        vendedor = (vendedor or "").strip().upper()
        if not vendedor:
            return None

        with SessionLocal() as db:
            if emp_scope:
                row = (
                    db.query(DashboardCache)
                    .filter(DashboardCache.emp == str(emp_scope), DashboardCache.vendedor == vendedor, DashboardCache.ano == int(ano), DashboardCache.mes == int(mes))
                    .first()
                )
                if not row:
                    return None
                ranking_list = json.loads(row.ranking_json or "[]")
                ranking_top15 = json.loads(row.ranking_top15_json or "[]")
                return {
                    "emp": row.emp,
                    "vendedor": row.vendedor,
                    "valor_bruto": float(row.valor_bruto or 0.0),
                    "valor_atual": float(row.valor_liquido or 0.0),
                    "valor_devolvido": float((row.devolucoes or 0.0) + (row.cancelamentos or 0.0)),
                    "pct_devolucao": float(row.pct_devolucao or 0.0),
                    "mix_atual": int(row.mix_produtos or 0),
                    "mix_marcas": int(row.mix_marcas or 0),
                    "ranking_list": ranking_list,
                    "ranking_top15_list": ranking_top15,
                    "total_liquido_periodo": float(row.total_liquido_periodo or 0.0),
                }

            # Agrega várias EMPs
            rows = (
                db.query(DashboardCache)
                .filter(DashboardCache.vendedor == vendedor, DashboardCache.ano == int(ano), DashboardCache.mes == int(mes))
                .all()
            )
            if not rows:
                return None

            valor_bruto = sum(float(r.valor_bruto or 0.0) for r in rows)
            valor_atual = sum(float(r.valor_liquido or 0.0) for r in rows)
            devol = sum(float(r.devolucoes or 0.0) for r in rows)
            canc = sum(float(r.cancelamentos or 0.0) for r in rows)
            valor_devolvido = devol + canc
            pct_devolucao = (devol / valor_bruto * 100.0) if valor_bruto else 0.0
            mix_atual = sum(int(r.mix_produtos or 0) for r in rows)
            mix_marcas = sum(int(r.mix_marcas or 0) for r in rows)

            # junta ranking por marca (soma por marca)
            marca_sum = {}
            for r in rows:
                try:
                    lst = json.loads(r.ranking_json or "[]")
                except Exception:
                    lst = []
                for item in lst:
                    m = str(item.get("marca") or "").strip()
                    v = float(item.get("valor") or 0.0)
                    if not m:
                        continue
                    marca_sum[m] = marca_sum.get(m, 0.0) + v

            ranking_sorted = sorted(marca_sum.items(), key=lambda kv: kv[1], reverse=True)
            total = sum(marca_sum.values())
            ranking_list = [
                {"marca": m, "valor": float(v), "pct": (float(v)/total*100.0) if total else 0.0}
                for m, v in ranking_sorted
            ]
            ranking_top15 = ranking_list[:15]

            return {
                "emp": None,
                "vendedor": vendedor,
                "valor_bruto": valor_bruto,
                "valor_atual": valor_atual,
                "valor_devolvido": valor_devolvido,
                "pct_devolucao": pct_devolucao,
                "mix_atual": mix_atual,
                "mix_marcas": mix_marcas,
                "ranking_list": ranking_list,
                "ranking_top15_list": ranking_top15,
                "total_liquido_periodo": float(total),
            }

    def _fetch_cache_value(vendedor: str, ano: int, mes: int, emp_scope: str | None) -> float | None:
        row = _fetch_cache_row(vendedor, ano, mes, emp_scope)
        return float(row.get("valor_atual")) if row else None

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



    def _periodo_bounds(ano: int, mes: int):
        """Retorna (inicio, fim) do mês para filtro por intervalo (usa índice)."""
        mes = max(1, min(12, int(mes)))
        ano = int(ano)
        start = date(ano, mes, 1)
        if mes == 12:
            end = date(ano + 1, 1, 1)
        else:
            end = date(ano, mes + 1, 1)
        return start, end


    def _emp_norm(emp: str | None) -> str:
        """Normaliza EMP para armazenamento ('' quando nulo)."""
        return (emp or "").strip()


    def _mes_fechado(emp: str | None, ano: int, mes: int) -> bool:
        """Retorna True se o mês estiver marcado como fechado para a EMP."""
        emp_n = _emp_norm(emp)
        with SessionLocal() as db:
            row = (
                db.query(FechamentoMensal)
                .filter(FechamentoMensal.emp == emp_n, FechamentoMensal.ano == ano, FechamentoMensal.mes == mes)
                .first()
            )
            return bool(row and row.fechado)

    def _vendedores_from_db(role: str, emp_usuario: str | None):
        """Lista de vendedores disponível para dropdown (sem carregar dataframe inteiro)."""
        role = (role or '').strip().lower()
        usuario_logado = (session.get('usuario') or '').strip().upper()
        if role == 'vendedor':
            return [usuario_logado] if usuario_logado else []

        with SessionLocal() as db:
            q = db.query(Venda.vendedor).distinct()
            if role == 'supervisor':
                if not emp_usuario:
                    return []
                q = q.filter(Venda.emp == str(emp_usuario))
            vendedores = [ (v[0] or '').strip().upper() for v in q.all() ]
        vendedores = sorted([v for v in vendedores if v])
        return vendedores

    def _get_cache_row(vendedor: str, ano: int, mes: int, emp_scope: str | None):
        vendedor = (vendedor or '').strip().upper()
        if not vendedor:
            return None
        with SessionLocal() as db:
            if emp_scope:
                return db.query(DashboardCache).filter(
                    DashboardCache.emp == str(emp_scope),
                    DashboardCache.vendedor == vendedor,
                    DashboardCache.ano == int(ano),
                    DashboardCache.mes == int(mes),
                ).first()

            # ADMIN/VENDEDOR sem EMP: soma múltiplas EMPs
            rows = db.query(DashboardCache).filter(
                DashboardCache.vendedor == vendedor,
                DashboardCache.ano == int(ano),
                DashboardCache.mes == int(mes),
            ).all()
            if not rows:
                return None

            # cria um objeto "fake" com os totais somados
            agg = DashboardCache(emp='*', vendedor=vendedor, ano=int(ano), mes=int(mes))
            agg.valor_bruto = sum(r.valor_bruto or 0 for r in rows)
            agg.valor_liquido = sum(r.valor_liquido or 0 for r in rows)
            agg.devolucoes = sum(r.devolucoes or 0 for r in rows)
            agg.cancelamentos = sum(r.cancelamentos or 0 for r in rows)
            agg.pct_devolucao = (agg.devolucoes / agg.valor_bruto * 100.0) if agg.valor_bruto else 0.0
            agg.mix_produtos = sum(r.mix_produtos or 0 for r in rows)
            agg.mix_marcas = sum(r.mix_marcas or 0 for r in rows)

            # agrega ranking por marca somando valores
            marca_map = {}
            total = 0.0
            for r in rows:
                try:
                    lst = json.loads(r.ranking_json or '[]')
                except Exception:
                    lst = []
                for it in lst:
                    m = (it.get('marca') or '').strip()
                    v = float(it.get('valor') or 0.0)
                    marca_map[m] = marca_map.get(m, 0.0) + v
                    total += v
            ranking = sorted([
                {'marca': m, 'valor': val, 'pct': (val/total*100.0) if total else 0.0}
                for m, val in marca_map.items()
            ], key=lambda x: x['valor'], reverse=True)
            agg.ranking_json = json.dumps(ranking, ensure_ascii=False)
            agg.ranking_top15_json = json.dumps(ranking[:15], ensure_ascii=False)
            agg.total_liquido_periodo = total
            return agg


    def _dados_from_cache(vendedor_alvo, mes, ano, emp_scope):

        """Carrega o dashboard a partir do cache (dashboard_cache) e busca o

        *ano passado* na tabela vendas_resumo_periodo.


        Motivo: o valor de "Ano passado" pode vir de cadastro manual/importação

        (vendas_resumo_periodo) e não necessariamente do cache.

        """

        row = _get_cache_row(vendedor_alvo, mes, ano, emp_scope)

        if not row:

            return None


        # ---- valores atuais (do cache) ----

        valor_atual = float(getattr(row, 'valor_liquido', 0) or 0)

        valor_bruto = float(getattr(row, 'valor_bruto', 0) or 0)

        devolucoes = float(getattr(row, 'devolucoes', 0) or 0)

        cancelamentos = float(getattr(row, 'cancelamentos', 0) or 0)

        valor_devolvido = devolucoes + cancelamentos

        pct_devolucao = float(getattr(row, 'pct_devolucao', 0) or 0)

        mix_atual = int(getattr(row, 'mix_produtos', 0) or 0)


        total_liquido_periodo = float(getattr(row, 'total_liquido_periodo', None) or valor_atual)


        # ---- mês anterior (cache) ----

        if mes == 1:

            prev_mes, prev_ano = 12, ano - 1

        else:

            prev_mes, prev_ano = mes - 1, ano


        prev_row = _get_cache_row(vendedor_alvo, prev_mes, prev_ano, emp_scope)

        valor_mes_anterior = float(getattr(prev_row, 'valor_liquido', 0) or 0) if prev_row else 0.0


        crescimento_mes_anterior = None

        if prev_row and valor_mes_anterior != 0:

            crescimento_mes_anterior = ((valor_atual - valor_mes_anterior) / valor_mes_anterior) * 100.0


        # ---- ano passado (tabela de resumos) ----

        valor_ano_passado = 0.0

        mix_ano_passado = 0

        try:

            ano_passado = ano - 1

            vendedor_norm = (vendedor_alvo or '').strip().upper()

            emp_norm = (str(emp_scope).strip() if emp_scope is not None else '')


            with SessionLocal() as db:

                q = db.query(VendasResumoPeriodo).filter(

                    VendasResumoPeriodo.vendedor == vendedor_norm,

                    VendasResumoPeriodo.ano == ano_passado,

                    VendasResumoPeriodo.mes == mes,

                )

                # Se o vendedor tem EMP definida, usa a EMP. Caso contrário, soma tudo do vendedor.

                if emp_norm:

                    q = q.filter(VendasResumoPeriodo.emp == emp_norm)


                rows = q.all()

                if rows:

                    valor_ano_passado = float(sum((r.valor_venda or 0) for r in rows))

                    mix_ano_passado = int(sum((r.mix_produtos or 0) for r in rows))

        except Exception:

            # Não quebra o dashboard se der qualquer erro no lookup do ano passado

            valor_ano_passado = 0.0

            mix_ano_passado = 0


        ranking_list = []

        ranking_top15_list = []

        try:

            if getattr(row, 'ranking_json', None):

                import json

                ranking_list = json.loads(row.ranking_json) or []

        except Exception:

            ranking_list = []

        try:

            if getattr(row, 'ranking_top15_json', None):

                import json

                ranking_top15_list = json.loads(row.ranking_top15_json) or []

        except Exception:

            ranking_top15_list = []


        return dict(

            valor_atual=valor_atual,

            valor_bruto=valor_bruto,

            valor_devolvido=valor_devolvido,

            pct_devolucao=pct_devolucao,

            mix_atual=mix_atual,

            valor_mes_anterior=valor_mes_anterior,

            crescimento_mes_anterior=crescimento_mes_anterior,

            valor_ano_passado=valor_ano_passado,

            mix_ano_passado=mix_ano_passado,

            ranking_list=ranking_list,

            ranking_top15_list=ranking_top15_list,

            total_liquido_periodo=total_liquido_periodo,

        )

    def _dados_ao_vivo(vendedor: str, mes: int, ano: int, emp_scope: str | None):
        """Calcula o dashboard direto do banco (sem pandas).

        Usado apenas quando o cache ainda não existe para aquele período.
        """
        vendedor = (vendedor or '').strip().upper()
        if not vendedor:
            return None

        # intervalos
        start = date(ano, mes, 1)
        end = date(ano + 1, 1, 1) if mes == 12 else date(ano, mes + 1, 1)

        def _range(ay, mm):
            s = date(ay, mm, 1)
            e = date(ay + 1, 1, 1) if mm == 12 else date(ay, mm + 1, 1)
            return s, e

        if mes == 1:
            mes_ant, ano_ant = 12, ano - 1
        else:
            mes_ant, ano_ant = mes - 1, ano

        s_ant, e_ant = _range(ano_ant, mes_ant)
        s_ano_passado, e_ano_passado = _range(ano - 1, mes)

        with SessionLocal() as db:
            base = db.query(Venda).filter(Venda.vendedor == vendedor)
            if emp_scope:
                base = base.filter(Venda.emp == str(emp_scope))

            def sums(s, e):
                q = base.filter(Venda.movimento >= s, Venda.movimento < e)
                signed = case((Venda.mov_tipo_movto.in_(['DS','CA']), -Venda.valor_total), else_=Venda.valor_total)
                bruto = func.coalesce(func.sum(case((~Venda.mov_tipo_movto.in_(['DS','CA']), Venda.valor_total), else_=0.0)), 0.0)
                devol = func.coalesce(func.sum(case((Venda.mov_tipo_movto.in_(['DS','CA']), Venda.valor_total), else_=0.0)), 0.0)
                liquido = func.coalesce(func.sum(signed), 0.0)
                mix = func.count(func.distinct(case((~Venda.mov_tipo_movto.in_(['DS','CA']), Venda.mestre), else_=None)))
                row = db.query(bruto, devol, liquido, mix).select_from(Venda).filter(Venda.vendedor == vendedor)
                if emp_scope:
                    row = row.filter(Venda.emp == str(emp_scope))
                row = row.filter(Venda.movimento >= s, Venda.movimento < e).first()
                return float(row[0] or 0.0), float(row[1] or 0.0), float(row[2] or 0.0), int(row[3] or 0)

            bruto, devol, liquido, mix = sums(start, end)
            bruto_ant, devol_ant, liquido_ant, mix_ant = sums(s_ant, e_ant)
            bruto_ano_pass, devol_ano_pass, liquido_ano_pass, mix_ano_pass = sums(s_ano_passado, e_ano_passado)

            pct_devolucao = (devol / bruto * 100.0) if bruto else None
            crescimento = ((liquido - liquido_ant) / abs(liquido_ant) * 100.0) if liquido_ant else None

            # Se existir resumo manual do ano passado (vendas_resumo_periodo), ele tem prioridade
            # para alimentar os campos "Ano passado" (valor e mix). Isso permite carregar dados
            # do ano anterior sem precisar manter a base inteira de vendas.
            try:
                if emp_scope:
                    r = VendasResumoPeriodo.query.filter_by(
                        emp=str(emp_scope), vendedor=vendedor, ano=ano - 1, mes=mes
                    ).first()
                    if r:
                        liquido_ano_pass = float(r.valor_venda or 0.0)
                        mix_ano_pass = int(r.mix_produtos or 0)
                else:
                    rows_res = (
                        VendasResumoPeriodo.query
                        .filter_by(vendedor=vendedor, ano=ano - 1, mes=mes)
                        .all()
                    )
                    if rows_res:
                        rnull = next((x for x in rows_res if x.emp in (None, '')), None)
                        if rnull:
                            liquido_ano_pass = float(rnull.valor_venda or 0.0)
                            mix_ano_pass = int(rnull.mix_produtos or 0)
                        else:
                            liquido_ano_pass = float(sum(float(x.valor_venda or 0.0) for x in rows_res))
                            mix_ano_pass = int(sum(int(x.mix_produtos or 0) for x in rows_res))
            except Exception:
                pass

            # ranking por marca (liquido)
            signed = case((Venda.mov_tipo_movto.in_(['DS','CA']), -Venda.valor_total), else_=Venda.valor_total)
            q_rank = db.query(Venda.marca, func.coalesce(func.sum(signed), 0.0)).filter(Venda.vendedor == vendedor)
            if emp_scope:
                q_rank = q_rank.filter(Venda.emp == str(emp_scope))
            q_rank = q_rank.filter(Venda.movimento >= start, Venda.movimento < end).group_by(Venda.marca)
            rows = q_rank.all()
            ranking = sorted([(str(m or ''), float(v or 0.0)) for m,v in rows], key=lambda x: x[1], reverse=True)
            total = sum(v for _,v in ranking)
            ranking_list = [
                {'marca': m, 'valor': v, 'pct': (v/total*100.0) if total else 0.0}
                for m,v in ranking
            ]
            return {
                'valor_atual': liquido,
                'valor_ano_passado': liquido_ano_pass,
                'valor_mes_anterior': liquido_ant,
                'mix_atual': mix,
                'mix_ano_passado': mix_ano_pass,
                'valor_bruto': bruto,
                'valor_devolvido': devol,
                'pct_devolucao': pct_devolucao,
                'crescimento': crescimento,
                'ranking_list': ranking_list,
                'ranking_top15_list': ranking_list[:15],
                'total_liquido_periodo': total,
            }
    def _resolver_vendedor_e_lista(df: pd.DataFrame | None) -> tuple[str | None, list[str], str | None, str | None]:
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
        if df is None or df.empty or "VENDEDOR" not in df.columns:
            # fallback leve: busca direto do banco
            vendedores = _get_vendedores_db(role, _emp())
            if (role == 'vendedor'):
                return usuario_logado, [], _emp(), None
            if not vendedores:
                return None, [], _emp(), 'Sem dados de vendas para montar a lista de vendedores.'
            vendedor_req = (request.args.get('vendedor') or '').strip().upper() or None
            vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores) else None
            return vendedor_alvo, vendedores, _emp(), None

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

        role = _role() or ""
        emp_usuario = _emp()

        # Resolve vendedor alvo + lista para dropdown sem carregar toda a tabela em memória
        if role == "vendedor":
            vendedor_alvo = (_usuario_logado() or "").strip().upper()
            vendedores_lista = []
            msg = None
        else:
            vendedores_lista = _get_vendedores_db(role, emp_usuario)
            vendedor_req = (request.args.get("vendedor") or "").strip().upper() or None
            vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores_lista) else None
            msg = None
            if role == "supervisor" and not emp_usuario:
                msg = "Supervisor sem EMP cadastrada. Cadastre a EMP do supervisor na tabela usuarios."

        dados = None
        if vendedor_alvo:
            try:
                emp_scope = emp_usuario if role == "supervisor" else None
                dados = _dados_from_cache(vendedor_alvo, mes, ano, emp_scope)
            except Exception:
                app.logger.exception("Erro ao carregar dashboard do cache")
                dados = None

            # Fallback: calcula ao vivo (sem pandas) se cache ainda não existe
            if dados is None:
                try:
                    emp_scope = emp_usuario if role == "supervisor" else None
                    dados = _dados_ao_vivo(vendedor_alvo, mes, ano, emp_scope)
                except Exception:
                    app.logger.exception("Erro ao calcular dashboard ao vivo")
                    dados = None

        return render_template(
            "dashboard.html",
            vendedor=vendedor_alvo or "",
            usuario=_usuario_logado(),
            role=_role(),
            emp=emp_usuario,
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
        role = (_role() or '').lower()
        emp_scope = _emp() if role == 'supervisor' else None

        # resolve vendedor
        if role in {'admin', 'supervisor'}:
            vendedores = _get_vendedores_db(role, emp_scope)
            vendedor_req = (request.args.get('vendedor') or '').strip().upper() or None
            vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores) else None
        else:
            vendedor_alvo = (_usuario_logado() or '').strip().upper()

        dados = None
        if vendedor_alvo:
            dados = _dados_from_cache(vendedor_alvo, mes, ano, emp_scope)
            if dados is None:
                dados = _dados_ao_vivo(vendedor_alvo, mes, ano, emp_scope)
        dados = dados or {}

        ranking_list = dados.get('ranking_list', [])
        total = float(dados.get('total_liquido_periodo', 0.0))

        return render_template(
            'percentuais.html',
            vendedor=vendedor_alvo or '',
            role=_role(),
            emp=emp_scope,
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
        role = (_role() or '').lower()
        emp_scope = _emp() if role == 'supervisor' else None

        if role in {'admin','supervisor'}:
            vendedores = _get_vendedores_db(role, emp_scope)
            vendedor_req = (request.args.get('vendedor') or '').strip().upper() or None
            vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores) else None
        else:
            vendedor_alvo = (_usuario_logado() or '').strip().upper()

        dados = None
        if vendedor_alvo:
            dados = _dados_from_cache(vendedor_alvo, mes, ano, emp_scope)
            if dados is None:
                dados = _dados_ao_vivo(vendedor_alvo, mes, ano, emp_scope)
        dados = dados or {}

        marcas_map = {row.get('marca'): row.get('valor') for row in (dados.get('ranking_list') or [])}

        return render_template(
            'marcas.html',
            vendedor=vendedor_alvo or '',
            role=_role(),
            emp=emp_scope,
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
        role = (_role() or '').lower()
        emp_scope = _emp() if role == 'supervisor' else None

        # resolve vendedor
        if role in {'admin','supervisor'}:
            vendedores = _get_vendedores_db(role, emp_scope)
            vendedor_req = (request.args.get('vendedor') or '').strip().upper() or None
            vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores) else None
        else:
            vendedor_alvo = (_usuario_logado() or '').strip().upper()

        if not vendedor_alvo:
            devol = {}
        else:
            # Usa o helper padrão do sistema (intervalo [start, end))
            start, end = _periodo_bounds(ano, mes)
            with SessionLocal() as db:
                q = (
                    db.query(Venda.marca, func.coalesce(func.sum(Venda.valor_total), 0.0))
                    .filter(Venda.vendedor == vendedor_alvo)
                    .filter(Venda.movimento >= start)
                    .filter(Venda.movimento < end)
                    .filter(Venda.mov_tipo_movto.in_(['DS','CA']))
                )
                if emp_scope:
                    q = q.filter(Venda.emp == str(emp_scope))
                q = q.group_by(Venda.marca).order_by(func.sum(Venda.valor_total).desc())
                devol = {str(m or ''): float(v or 0.0) for m, v in q.all() if m}

        return render_template(
            'devolucoes.html',
            vendedor=vendedor_alvo or '',
            role=_role(),
            emp=emp_scope,
            mes=mes,
            ano=ano,
            devolucoes=devol,
        )


    @app.get("/itens_parados")
    def itens_parados():
        """Relatório de itens parados (liquidação) por EMP.

        Cadastro é feito pelo ADMIN por EMP.
        - ADMIN: pode visualizar todas as EMPs (e opcionalmente filtrar por EMP e/ou vendedor)
        - SUPERVISOR: visualiza somente a EMP cadastrada no usuário
        - VENDEDOR: a(s) EMP(s) é(são) derivada(s) de vendas.emp (pode ser multi-EMP)

        O campo "Valor" só aparece quando houver venda do código no período selecionado.
        """
        red = _login_required()
        if red:
            return red

        mes, ano = _mes_ano_from_request()
        role = (_role() or '').lower()

        # --- vendedor alvo (para cálculo do VALOR) ---
        vendedor_alvo = None
        vendedores_lista = []

        if role in {'admin', 'supervisor'}:
            emp_supervisor = _emp() if role == 'supervisor' else None
            if role == 'supervisor' and not emp_supervisor:
                flash('Seu usuário supervisor não possui EMP cadastrada. Solicite ao ADMIN para cadastrar.', 'warning')
                return redirect(url_for('dashboard'))

            vendedores_lista = _get_vendedores_db(role, emp_supervisor)
            vendedor_req = (request.args.get('vendedor') or '').strip().upper() or None
            if vendedor_req and vendedor_req in vendedores_lista:
                vendedor_alvo = vendedor_req
            else:
                vendedor_alvo = None  # admin/supervisor sem seleção = só lista

        else:
            vendedor_alvo = (_usuario_logado() or '').strip().upper()

        # --- EMP(s) visíveis para o usuário ---
        emp_param = (request.args.get('emp') or '').strip()
        emp_scopes = []

        if role == 'admin':
            if emp_param:
                emp_scopes = [str(emp_param)]
            else:
                # admin sem filtro: mostrar todas as EMPs que possuem itens cadastrados
                with SessionLocal() as db:
                    emp_scopes = [str(x[0]) for x in db.query(ItemParado.emp).filter(ItemParado.ativo == 1).distinct().all()]

        elif role == 'supervisor':
            emp_scopes = [str(_emp())]

        else:
            # vendedor: EMP(s) derivadas das vendas
            with SessionLocal() as db:
                emp_scopes = [str(x[0]) for x in db.query(Venda.emp).filter(Venda.vendedor == vendedor_alvo).distinct().all()]

        emp_scopes = sorted({e.strip() for e in emp_scopes if e and str(e).strip()})
        if not emp_scopes:
            flash('Não foi possível identificar a EMP para este usuário (sem vendas registradas).', 'warning')
            return redirect(url_for('dashboard'))

        # --- Buscar itens por EMP e agrupar ---
        with SessionLocal() as db:
            itens_all = (
                db.query(ItemParado)
                .filter(ItemParado.emp.in_(emp_scopes))
                .filter(ItemParado.ativo == 1)
                .order_by(ItemParado.emp.asc(), ItemParado.codigo.asc())
                .all()
            )

        itens_por_emp = {}
        for it in itens_all:
            e = str(it.emp).strip() if it.emp is not None else ''
            itens_por_emp.setdefault(e, []).append(it)

        # --- Calcular vendido_total por (emp, codigo) e recompensa ---
        vendido_total_map = {}
        recomp_map = {}

        if vendedor_alvo and itens_all:
            # lista de códigos (mestre) cadastrados nos itens
            codigos = [ (i.codigo or '').strip() for i in itens_all if (i.codigo or '').strip() ]
            codigos = sorted(set(codigos))
            if codigos:
                start, end = _periodo_bounds(ano, mes)
                with SessionLocal() as db:
                    q = (
                        db.query(Venda.emp, Venda.mestre, func.coalesce(func.sum(Venda.valor_total), 0.0))
                        .filter(Venda.emp.in_(emp_scopes))
                        .filter(Venda.vendedor == vendedor_alvo)
                        .filter(Venda.movimento >= start)
                        .filter(Venda.movimento < end)
                        .filter(Venda.mov_tipo_movto == 'OA')
                        .filter(Venda.mestre.in_(codigos))
                        .group_by(Venda.emp, Venda.mestre)
                    )
                    for emp_v, mestre, total in q.all():
                        k_emp = str(emp_v).strip() if emp_v is not None else ''
                        k_cod = (mestre or '').strip()
                        vendido_total_map[(k_emp, k_cod)] = float(total or 0.0)

                for it in itens_all:
                    emp_it = str(it.emp).strip() if it.emp is not None else ''
                    cod = (it.codigo or '').strip()
                    total = vendido_total_map.get((emp_it, cod), 0.0)
                    pct = float(it.recompensa_pct or 0.0)
                    valor = (total * (pct / 100.0)) if total > 0 and pct > 0 else 0.0
                    recomp_map[(emp_it, cod)] = valor

        return render_template(
            "itens_parados.html",
            role=role,
            mes=mes,
            ano=ano,
            emp_param=emp_param,
            emp_scopes=emp_scopes,
            itens_por_emp=itens_por_emp,
            vendedor=vendedor_alvo,
            vendedores_lista=vendedores_lista,
            vendido_total_map=vendido_total_map,
            recomp_map=recomp_map,
        )

    @app.get("/itens_parados/pdf")
    def itens_parados_pdf():
        """Exporta o relatório de itens parados em PDF (mes/ano e escopo do usuário)."""
        red = _login_required()
        if red:
            return red

        mes, ano = _mes_ano_from_request()
        role = (_role() or '').lower()

        # Reaproveita a lógica da tela para determinar vendedor/emp_scopes/itens e valores
        vendedor_alvo = None
        vendedores_lista = []

        if role in {'admin', 'supervisor'}:
            emp_supervisor = _emp() if role == 'supervisor' else None
            if role == 'supervisor' and not emp_supervisor:
                flash('Seu usuário supervisor não possui EMP cadastrada. Solicite ao ADMIN para cadastrar.', 'warning')
                return redirect(url_for('dashboard'))

            vendedores_lista = _get_vendedores_db(role, emp_supervisor)
            vendedor_req = (request.args.get('vendedor') or '').strip().upper() or None
            if vendedor_req and vendedor_req in vendedores_lista:
                vendedor_alvo = vendedor_req
            else:
                vendedor_alvo = None
        else:
            vendedor_alvo = (_usuario_logado() or '').strip().upper()

        emp_param = (request.args.get('emp') or '').strip()
        emp_scopes = []

        if role == 'admin':
            if emp_param:
                emp_scopes = [str(emp_param)]
            else:
                with SessionLocal() as db:
                    emp_scopes = [str(x[0]) for x in db.query(ItemParado.emp).filter(ItemParado.ativo == 1).distinct().all()]
        elif role == 'supervisor':
            emp_scopes = [str(_emp())]
        else:
            with SessionLocal() as db:
                emp_scopes = [str(x[0]) for x in db.query(Venda.emp).filter(Venda.vendedor == vendedor_alvo).distinct().all()]

        emp_scopes = sorted({e.strip() for e in emp_scopes if e and str(e).strip()})
        if not emp_scopes:
            flash('Não foi possível identificar a EMP para este usuário (sem vendas registradas).', 'warning')
            return redirect(url_for('dashboard'))

        with SessionLocal() as db:
            itens_all = (
                db.query(ItemParado)
                .filter(ItemParado.emp.in_(emp_scopes))
                .filter(ItemParado.ativo == 1)
                .order_by(ItemParado.emp.asc(), ItemParado.codigo.asc())
                .all()
            )

        itens_por_emp = {}
        for it in itens_all:
            e = str(it.emp).strip() if it.emp is not None else ''
            itens_por_emp.setdefault(e, []).append(it)

        vendido_total_map = {}
        recomp_map = {}

        if vendedor_alvo and itens_all:
            codigos = [ (i.codigo or '').strip() for i in itens_all if (i.codigo or '').strip() ]
            codigos = sorted(set(codigos))
            if codigos:
                start, end = _periodo_bounds(ano, mes)
                with SessionLocal() as db:
                    q = (
                        db.query(Venda.emp, Venda.mestre, func.coalesce(func.sum(Venda.valor_total), 0.0))
                        .filter(Venda.emp.in_(emp_scopes))
                        .filter(Venda.vendedor == vendedor_alvo)
                        .filter(Venda.movimento >= start)
                        .filter(Venda.movimento < end)
                        .filter(Venda.mov_tipo_movto == 'OA')
                        .filter(Venda.mestre.in_(codigos))
                        .group_by(Venda.emp, Venda.mestre)
                    )
                    for emp_v, mestre, total in q.all():
                        k_emp = str(emp_v).strip() if emp_v is not None else ''
                        k_cod = (mestre or '').strip()
                        vendido_total_map[(k_emp, k_cod)] = float(total or 0.0)

                for it in itens_all:
                    emp_it = str(it.emp).strip() if it.emp is not None else ''
                    cod = (it.codigo or '').strip()
                    total = vendido_total_map.get((emp_it, cod), 0.0)
                    pct = float(it.recompensa_pct or 0.0)
                    valor = (total * (pct / 100.0)) if total > 0 and pct > 0 else 0.0
                    recomp_map[(emp_it, cod)] = valor

        # --- Gerar PDF (ReportLab) ---
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import mm

        buf = BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        width, height = A4

        titulo = "Relatório - Itens Parados"
        periodo = f"Período: {mes:02d}/{ano}"
        vendedor_txt = f"Vendedor: {vendedor_alvo}" if vendedor_alvo else "Vendedor: (não selecionado)"
        agora = datetime.now().strftime("%d/%m/%Y %H:%M")

        def draw_header():
            y = height - 18*mm
            c.setFont("Helvetica-Bold", 14)
            c.drawString(18*mm, y, titulo)
            c.setFont("Helvetica", 10)
            c.drawString(18*mm, y-6*mm, periodo)
            c.drawString(18*mm, y-11*mm, vendedor_txt)
            c.drawRightString(width-18*mm, y-6*mm, f"Gerado em: {agora}")
            return y-18*mm

        y = draw_header()

        # tabela simples por EMP
        c.setFont("Helvetica", 9)

        for emp in emp_scopes:
            itens_emp = itens_por_emp.get(emp, [])
            if not itens_emp:
                continue

            # quebra página se necessário
            if y < 35*mm:
                c.showPage()
                y = draw_header()
                c.setFont("Helvetica", 9)

            c.setFont("Helvetica-Bold", 11)
            c.drawString(18*mm, y, f"EMP {emp}")
            y -= 6*mm
            c.setFont("Helvetica-Bold", 9)
            c.drawString(18*mm, y, "CÓDIGO")
            c.drawString(40*mm, y, "DESCRIÇÃO")
            c.drawRightString(width-55*mm, y, "QTD")
            c.drawRightString(width-35*mm, y, "%")
            c.drawRightString(width-18*mm, y, "VALOR")
            y -= 4*mm
            c.setLineWidth(0.5)
            c.line(18*mm, y, width-18*mm, y)
            y -= 5*mm
            c.setFont("Helvetica", 9)

            for it in itens_emp:
                cod = (it.codigo or '').strip()
                desc = (it.descricao or '').strip()
                qtd = it.quantidade or 0
                pct = float(it.recompensa_pct or 0.0)

                valor = recomp_map.get((emp, cod), 0.0)
                valor_txt = "" if valor <= 0 else f"R$ {valor:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")

                # quebra página
                if y < 20*mm:
                    c.showPage()
                    y = draw_header()
                    c.setFont("Helvetica", 9)

                c.drawString(18*mm, y, cod[:20])
                c.drawString(40*mm, y, desc[:55])
                c.drawRightString(width-55*mm, y, str(qtd))
                c.drawRightString(width-35*mm, y, f"{pct:.0f}%")
                c.drawRightString(width-18*mm, y, valor_txt)
                y -= 5*mm

            y -= 4*mm

        c.showPage()
        c.save()
        buf.seek(0)

        filename = f"itens_parados_{mes:02d}_{ano}.pdf"
        return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)

    # ---------------------------------------------------------------------
    # Campanhas de recompensa por quantidade (prefixo + marca)
    # ---------------------------------------------------------------------
    def _campanhas_mes_overlap(ano: int, mes: int, emp: str | None) -> list[CampanhaQtd]:
        """Retorna campanhas que intersectam o mês (e opcionalmente a EMP)."""
        inicio_mes, fim_mes = _periodo_bounds(int(ano), int(mes))
        with SessionLocal() as db:
            q = db.query(CampanhaQtd).filter(CampanhaQtd.ativo == 1)
            if emp:
                q = q.filter(CampanhaQtd.emp == str(emp))
            # overlap: inicio <= fim_mes AND fim >= inicio_mes
            q = q.filter(and_(CampanhaQtd.data_inicio <= fim_mes, CampanhaQtd.data_fim >= inicio_mes))
            return q.order_by(CampanhaQtd.emp.asc(), CampanhaQtd.data_inicio.asc()).all()

    def _upsert_resultado(
        db,
        campanha: CampanhaQtd,
        vendedor: str,
        emp: str,
        competencia_ano: int,
        competencia_mes: int,
        periodo_ini: date,
        periodo_fim: date,
    ) -> CampanhaQtdResultado:
        """Calcula e grava (upsert) o snapshot do resultado da campanha."""
        vendedor = (vendedor or "").strip().upper()
        emp = str(emp)

        # Campo usado para prefix match: por compatibilidade, usamos Venda.mestre
        # (em muitos cenários ele carrega descrição/identificador do item).
        prefix = (campanha.produto_prefixo or "").strip()
        prefix_up = prefix.upper()

        campo_item = func.upper(func.trim(cast(Venda.mestre, String)))
        cond_prefix = campo_item.like(prefix_up + "%")
        cond_marca = func.upper(func.trim(cast(Venda.marca, String))) == (campanha.marca or "").strip().upper()

        base = (
            db.query(
                func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd"),
                func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor"),
            )
            .filter(
                Venda.emp == emp,
                Venda.vendedor == vendedor,
                Venda.movimento >= periodo_ini,
                Venda.movimento <= periodo_fim,
                ~Venda.mov_tipo_movto.in_(["DS", "CA"]),
                cond_prefix,
                cond_marca,
            )
            .first()
        )
        qtd_vendida = float(base.qtd or 0.0)
        valor_vendido = float(base.valor or 0.0)

        minimo = campanha.qtd_minima
        atingiu = 1
        if minimo is not None and float(minimo) > 0:
            atingiu = 1 if qtd_vendida >= float(minimo) else 0
        valor_recomp = (qtd_vendida * float(campanha.recompensa_unit or 0.0)) if atingiu else 0.0

        # Upsert por chave única
        res = (
            db.query(CampanhaQtdResultado)
            .filter(
                CampanhaQtdResultado.campanha_id == campanha.id,
                CampanhaQtdResultado.emp == emp,
                CampanhaQtdResultado.vendedor == vendedor,
                CampanhaQtdResultado.competencia_ano == int(competencia_ano),
                CampanhaQtdResultado.competencia_mes == int(competencia_mes),
            )
            .first()
        )
        if not res:
            res = CampanhaQtdResultado(
                campanha_id=campanha.id,
                emp=emp,
                vendedor=vendedor,
                competencia_ano=int(competencia_ano),
                competencia_mes=int(competencia_mes),
                status_pagamento="PENDENTE",
            )
            db.add(res)

        # snapshot
        res.titulo = campanha.titulo
        res.produto_prefixo = prefix
        res.marca = (campanha.marca or "").strip()
        res.recompensa_unit = float(campanha.recompensa_unit or 0.0)
        res.qtd_minima = float(minimo) if minimo is not None else None
        res.data_inicio = campanha.data_inicio
        res.data_fim = campanha.data_fim

        res.qtd_vendida = qtd_vendida
        res.valor_vendido = valor_vendido
        res.atingiu_minimo = int(atingiu)
        res.valor_recompensa = float(valor_recomp)
        res.atualizado_em = datetime.utcnow()
        return res

    def _resolver_emp_scope_para_usuario(vendedor: str, role: str, emp_usuario: str | None) -> list[str]:
        """Retorna lista de EMPs que o usuário pode visualizar (para campanhas e relatórios)."""
        role = (role or "").strip().lower()
        if role == "admin":
            # Admin: se emp estiver definido via query param, filtra. Caso contrário, pode ver as EMPs do vendedor selecionado
            return []
        if role == "supervisor":
            return [str(emp_usuario)] if emp_usuario else []
        # vendedor
        return _get_emps_vendedor(vendedor)

    @app.get("/campanhas")
    def campanhas_qtd():
        """Relatório de campanhas de recompensa por quantidade.

        - Vendedor: vê por EMPs inferidas de vendas (multi-EMP)
        - Supervisor: vê apenas EMP dele
        - Admin: pode escolher vendedor/EMP
        """
        red = _login_required()
        if red:
            return red

        role = _role() or ""
        emp_usuario = _emp()

        # período
        hoje = date.today()
        mes = int(request.args.get("mes") or hoje.month)
        ano = int(request.args.get("ano") or hoje.year)

        # vendedor alvo
        vendedor_logado = (_usuario_logado() or "").strip().upper()
        vendedor_sel = (request.args.get("vendedor") or vendedor_logado).strip().upper()
        if role != "admin" and vendedor_sel != vendedor_logado and role != "supervisor":
            vendedor_sel = vendedor_logado

        # EMP scope
        emp_param = (request.args.get("emp") or "").strip()
        emps_scope: list[str] = []
        if (role or "").lower() == "admin":
            if emp_param:
                emps_scope = [emp_param]
            else:
                emps_scope = _get_emps_vendedor(vendedor_sel)
        else:
            emps_scope = _resolver_emp_scope_para_usuario(vendedor_sel, role, emp_usuario)

        # Se não temos EMP, não dá pra montar relatório
        if not emps_scope and (role or "").lower() != "admin":
            flash("Não foi possível identificar a EMP do vendedor pelas vendas. Verifique se já existem vendas importadas.", "warning")

        inicio_mes, fim_mes = _periodo_bounds(ano, mes)

        # Busca vendedores dropdown
        vendedores_dropdown = []
        try:
            vendedores_dropdown = _get_vendedores_db(role, emp_usuario)
        except Exception:
            vendedores_dropdown = []

        # Calcula resultados e agrupa por EMP
        blocos: list[dict] = []
        with SessionLocal() as db:
            for emp in emps_scope or ([emp_param] if emp_param else []):
                emp = str(emp)

                # campanhas relevantes (overlap do mês)
                campanhas = _campanhas_mes_overlap(ano, mes, emp)

                # aplica prioridade: regras do vendedor substituem regras gerais
                # chave: (produto_prefixo, marca)
                by_key: dict[tuple[str, str], CampanhaQtd] = {}
                for c in campanhas:
                    key = ((c.produto_prefixo or "").strip().upper(), (c.marca or "").strip().upper())
                    if c.vendedor and c.vendedor.strip().upper() == vendedor_sel:
                        by_key[key] = c
                    else:
                        by_key.setdefault(key, c)
                campanhas_final = list(by_key.values())

                linhas = []
                total_recomp = 0.0

                for c in campanhas_final:
                    # interseção do período
                    periodo_ini = max(c.data_inicio, inicio_mes)
                    periodo_fim = min(c.data_fim, fim_mes)
                    res = _upsert_resultado(db, c, vendedor_sel, emp, ano, mes, periodo_ini, periodo_fim)
                    linhas.append(res)
                    total_recomp += float(res.valor_recompensa or 0.0)

                db.commit()

                # Recarrega resultados (já persistidos)
                resultados = (
                    db.query(CampanhaQtdResultado)
                    .filter(
                        CampanhaQtdResultado.emp == emp,
                        CampanhaQtdResultado.vendedor == vendedor_sel,
                        CampanhaQtdResultado.competencia_ano == int(ano),
                        CampanhaQtdResultado.competencia_mes == int(mes),
                    )
                    .order_by(CampanhaQtdResultado.valor_recompensa.desc())
                    .all()
                )

                blocos.append({
                    "emp": emp,
                    "resultados": resultados,
                    "total": total_recomp,
                })

        return render_template(
            "campanhas_qtd.html",
            role=role,
            ano=ano,
            mes=mes,
            vendedor=vendedor_sel,
            vendedor_logado=vendedor_logado,
            vendedores=vendedores_dropdown,
            blocos=blocos,
            emp_param=emp_param,
        )

    @app.get("/campanhas/pdf")
    def campanhas_qtd_pdf():
        red = _login_required()
        if red:
            return red

        role = _role() or ""
        emp_usuario = _emp()
        hoje = date.today()
        mes = int(request.args.get("mes") or hoje.month)
        ano = int(request.args.get("ano") or hoje.year)

        vendedor_logado = (_usuario_logado() or "").strip().upper()
        vendedor_sel = (request.args.get("vendedor") or vendedor_logado).strip().upper()
        if role != "admin" and vendedor_sel != vendedor_logado and role != "supervisor":
            vendedor_sel = vendedor_logado

        emp_param = (request.args.get("emp") or "").strip()
        if (role or "").lower() == "admin":
            emps_scope = [emp_param] if emp_param else _get_emps_vendedor(vendedor_sel)
        else:
            emps_scope = _resolver_emp_scope_para_usuario(vendedor_sel, role, emp_usuario)

        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import mm

        buf = BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        width, height = A4

        def _money(v: float) -> str:
            return f"R$ {v:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")

        y = height - 18 * mm
        c.setFont("Helvetica-Bold", 14)
        c.drawString(18 * mm, y, "Campanhas - Recompensa por Quantidade")
        y -= 7 * mm
        c.setFont("Helvetica", 10)
        c.drawString(18 * mm, y, f"Vendedor: {vendedor_sel}   Período: {mes:02d}/{ano}")
        y -= 10 * mm

        with SessionLocal() as db:
            for emp in emps_scope:
                emp = str(emp)
                resultados = (
                    db.query(CampanhaQtdResultado)
                    .filter(
                        CampanhaQtdResultado.emp == emp,
                        CampanhaQtdResultado.vendedor == vendedor_sel,
                        CampanhaQtdResultado.competencia_ano == int(ano),
                        CampanhaQtdResultado.competencia_mes == int(mes),
                    )
                    .order_by(CampanhaQtdResultado.valor_recompensa.desc())
                    .all()
                )

                if y < 40 * mm:
                    c.showPage()
                    y = height - 18 * mm

                c.setFont("Helvetica-Bold", 12)
                c.drawString(18 * mm, y, f"EMP {emp}")
                y -= 6 * mm
                c.setFont("Helvetica-Bold", 9)
                c.drawString(18 * mm, y, "PRODUTO")
                c.drawString(65 * mm, y, "MARCA")
                c.drawRightString(width - 70 * mm, y, "QTD")
                c.drawRightString(width - 50 * mm, y, "MÍN")
                c.drawRightString(width - 18 * mm, y, "VALOR")
                y -= 4 * mm
                c.setLineWidth(0.5)
                c.line(18 * mm, y, width - 18 * mm, y)
                y -= 5 * mm
                c.setFont("Helvetica", 9)

                total_emp = 0.0
                for r in resultados:
                    if y < 25 * mm:
                        c.showPage()
                        y = height - 18 * mm
                        c.setFont("Helvetica", 9)
                    minimo_txt = "" if r.qtd_minima is None else f"{float(r.qtd_minima):.0f}"
                    valor_txt = _money(float(r.valor_recompensa or 0.0)) if float(r.valor_recompensa or 0.0) > 0 else "-"
                    c.drawString(18 * mm, y, (r.produto_prefixo or "")[:22])
                    c.drawString(65 * mm, y, (r.marca or "")[:14])
                    c.drawRightString(width - 70 * mm, y, f"{float(r.qtd_vendida or 0):.0f}")
                    c.drawRightString(width - 50 * mm, y, minimo_txt)
                    c.drawRightString(width - 18 * mm, y, valor_txt)
                    y -= 5 * mm
                    total_emp += float(r.valor_recompensa or 0.0)

                y -= 2 * mm
                c.setFont("Helvetica-Bold", 10)
                c.drawRightString(width - 18 * mm, y, f"Total EMP {emp}: {_money(total_emp)}")
                y -= 10 * mm

        c.showPage()
        c.save()
        buf.seek(0)
        filename = f"campanhas_{mes:02d}_{ano}.pdf"
        return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)

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
                            # Normaliza EMP como texto (ex.: "101")
                            emp_val = str(emp_sup).strip()
                            if not emp_val:
                                raise ValueError("Informe a EMP para o supervisor.")
                        u = db.query(Usuario).filter(Usuario.username == novo_usuario).first()
                        if u:
                            u.senha_hash = generate_password_hash(nova_senha)
                            u.role = role
                            # Atualiza EMP quando aplicável
                            if role == "supervisor":
                                setattr(u, "emp", emp_val)
                            else:
                                setattr(u, "emp", None)
                            # BUGFIX: sem commit, alterações não eram persistidas.
                            db.commit()
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
        # IMPORTANTISSIMO:
        # A chave de deduplicidade precisa bater com o indice/constraint UNIQUE do banco.
        # Seu banco foi padronizado com:
        #   (mestre, marca, vendedor, movimento, mov_tipo_movto, nota, emp)
        # Se a chave nao incluir MOVIMENTO e MOV_TIPO_MOVTO (DS/CA/OA), o Postgres
        # pode retornar erro de ON CONFLICT e/ou DS/CA pode ser ignorado.
        chave = request.form.get("chave", "mestre_movimento_vendedor_nota_tipo_emp")

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



    @app.route("/admin/itens_parados", methods=["GET", "POST"])
    def admin_itens_parados():
        """Cadastro de itens parados (liquidação) por EMP.

        Campos: EMP, Código, Descrição, Quantidade, Recompensa(%).
        """
        red = _login_required()
        if red:
            return red
        red = _admin_required()
        if red:
            return red

        erro = None
        ok = None

        with SessionLocal() as db:
            if request.method == 'POST':
                acao = (request.form.get('acao') or '').strip().lower()
                try:
                    if acao == 'criar':
                        emp = (request.form.get('emp') or '').strip()
                        codigo = (request.form.get('codigo') or '').strip()
                        descricao = (request.form.get('descricao') or '').strip()
                        quantidade_raw = (request.form.get('quantidade') or '').strip()
                        recompensa_raw = (request.form.get('recompensa_pct') or '').strip().replace(',', '.')

                        if not emp:
                            raise ValueError('Informe a EMP.')
                        if not codigo:
                            raise ValueError('Informe o CÓDIGO.')

                        quantidade = int(quantidade_raw) if quantidade_raw else None
                        recompensa_pct = float(recompensa_raw) if recompensa_raw else 0.0

                        db.add(ItemParado(
                            emp=str(emp),
                            codigo=str(codigo),
                            descricao=descricao or None,
                            quantidade=quantidade,
                            recompensa_pct=recompensa_pct,
                            ativo=1,
                        ))
                        db.commit()
                        ok = 'Item cadastrado com sucesso.'

                    elif acao == 'toggle':
                        item_id = int(request.form.get('item_id') or 0)
                        it = db.query(ItemParado).filter(ItemParado.id == item_id).first()
                        if not it:
                            raise ValueError('Item não encontrado.')
                        it.ativo = 0 if int(it.ativo or 0) == 1 else 1
                        it.atualizado_em = datetime.utcnow()
                        db.commit()
                        ok = 'Status do item atualizado.'

                    elif acao == 'remover':
                        item_id = int(request.form.get('item_id') or 0)
                        it = db.query(ItemParado).filter(ItemParado.id == item_id).first()
                        if not it:
                            raise ValueError('Item não encontrado.')
                        db.delete(it)
                        db.commit()
                        ok = 'Item removido.'

                    else:
                        raise ValueError('Ação inválida.')

                except Exception as e:
                    db.rollback()
                    erro = str(e)
                    app.logger.exception('Erro no cadastro de itens parados')

            itens = db.query(ItemParado).order_by(ItemParado.emp.asc(), ItemParado.codigo.asc()).all()

        return render_template(
            'admin_itens_parados.html',
            usuario=_usuario_logado(),
            itens=itens,
            erro=erro,
            ok=ok,
        )

    @app.route('/admin/resumos_periodo', methods=['GET', 'POST'])
    def admin_resumos_periodo():
        _admin_required()

        # filtros
        emp = _emp_norm(request.values.get('emp', ''))
        vendedor = (request.values.get('vendedor') or '').strip().upper()
        ano = int(request.values.get('ano') or datetime.now().year)
        mes = int(request.values.get('mes') or datetime.now().month)

        msgs: list[str] = []

        acao = (request.form.get('acao') or '').strip().lower()
        if request.method == 'POST' and acao:
            if acao in {'salvar', 'excluir'} and _mes_fechado(emp, ano, mes):
                msgs.append('⚠️ Mês fechado. Reabra o mês para editar os resumos.')
            else:
                with SessionLocal() as db:
                    if acao == 'fechar':
                        rec = (
                            db.query(FechamentoMensal)
                            .filter(
                                FechamentoMensal.emp == emp,
                                FechamentoMensal.ano == ano,
                                FechamentoMensal.mes == mes,
                            )
                            .one_or_none()
                        )
                        if rec is None:
                            rec = FechamentoMensal(emp=emp, ano=ano, mes=mes, fechado=True, fechado_em=datetime.utcnow())
                            db.add(rec)
                        else:
                            rec.fechado = True
                            rec.fechado_em = datetime.utcnow()
                        db.commit()
                        msgs.append('✅ Mês fechado. Edição travada.')

                    elif acao == 'reabrir':
                        rec = (
                            db.query(FechamentoMensal)
                            .filter(
                                FechamentoMensal.emp == emp,
                                FechamentoMensal.ano == ano,
                                FechamentoMensal.mes == mes,
                            )
                            .one_or_none()
                        )
                        if rec is None:
                            rec = FechamentoMensal(emp=emp, ano=ano, mes=mes, fechado=False)
                            db.add(rec)
                        else:
                            rec.fechado = False
                        db.commit()
                        msgs.append('✅ Mês reaberto. Edição liberada.')

                    elif acao == 'salvar':
                        vend = (request.form.get('vendedor_edit') or '').strip().upper()
                        if not vend:
                            msgs.append('⚠️ Informe o vendedor.')
                        else:
                            try:
                                valor_venda = float((request.form.get('valor_venda') or '0').replace(',', '.'))
                            except Exception:
                                valor_venda = 0.0
                            try:
                                mix_produtos = int(request.form.get('mix_produtos') or 0)
                            except Exception:
                                mix_produtos = 0

                            rec = (
                                db.query(VendasResumoPeriodo)
                                .filter(
                                    VendasResumoPeriodo.emp == emp,
                                    VendasResumoPeriodo.vendedor == vend,
                                    VendasResumoPeriodo.ano == ano,
                                    VendasResumoPeriodo.mes == mes,
                                )
                                .one_or_none()
                            )
                            if rec is None:
                                rec = VendasResumoPeriodo(
                                    emp=emp,
                                    vendedor=vend,
                                    ano=ano,
                                    mes=mes,
                                    valor_venda=valor_venda,
                                    mix_produtos=mix_produtos,
                                    created_at=datetime.utcnow(),
                                    updated_at=datetime.utcnow(),
                                )
                                db.add(rec)
                            else:
                                rec.valor_venda = valor_venda
                                rec.mix_produtos = mix_produtos
                                rec.updated_at = datetime.utcnow()
                            db.commit()
                            msgs.append('✅ Resumo salvo.')

                    elif acao == 'excluir':
                        vend = (request.form.get('vendedor_edit') or '').strip().upper()
                        if not vend:
                            msgs.append('⚠️ Informe o vendedor para excluir.')
                        else:
                            rec = (
                                db.query(VendasResumoPeriodo)
                                .filter(
                                    VendasResumoPeriodo.emp == emp,
                                    VendasResumoPeriodo.vendedor == vend,
                                    VendasResumoPeriodo.ano == ano,
                                    VendasResumoPeriodo.mes == mes,
                                )
                                .one_or_none()
                            )
                            if rec is None:
                                msgs.append('⚠️ Não encontrei esse resumo para excluir.')
                            else:
                                db.delete(rec)
                                db.commit()
                                msgs.append('✅ Resumo excluído.')

        # carregar lista e status de fechamento
        fechado = _mes_fechado(emp, ano, mes)
        with SessionLocal() as db:
            # EMP e vendedor são opcionais: quando vierem em branco, listamos TODOS.
            q = db.query(VendasResumoPeriodo).filter(
                VendasResumoPeriodo.ano == ano,
                VendasResumoPeriodo.mes == mes,
            )
            if emp:
                q = q.filter(VendasResumoPeriodo.emp == emp)
            if vendedor:
                q = q.filter(VendasResumoPeriodo.vendedor == vendedor)
            registros = q.order_by(VendasResumoPeriodo.vendedor.asc()).all()

            # Sugestão rápida de vendedores (com base em vendas do período)
            # Ajuda o admin a não digitar errado
            start, end = _periodo_bounds(ano, mes)
            vs_q = db.query(Venda.vendedor).filter(Venda.movimento >= start, Venda.movimento < end)
            if emp:
                vs_q = vs_q.filter(Venda.emp == emp)
            vendedores_sugeridos = (
                vs_q.distinct().order_by(Venda.vendedor.asc()).all()
            )
            vendedores_sugeridos = [v[0] for v in vendedores_sugeridos if v and v[0]]

        return render_template(
            'admin_resumos_periodo.html',
            emp=emp,
            ano=ano,
            mes=mes,
            vendedor_filtro=vendedor,
            registros=registros,
            fechado=fechado,
            vendedores_sugeridos=vendedores_sugeridos,
            msgs=msgs,
        )

    # Compatibilidade: algumas telas/atalhos antigos apontavam para /admin/fechamento.
    # O fechamento mensal hoje é feito dentro da tela de resumos por período.
    @app.get('/admin/fechamento')
    def admin_fechamento_redirect():
        _admin_required()
        return redirect(url_for('admin_resumos_periodo'))


    @app.route("/admin/campanhas", methods=["GET", "POST"])
    def admin_campanhas_qtd():
        """Cadastro de campanhas de recompensa por quantidade.

        Campos:
        - EMP (obrigatório)
        - Vendedor (opcional; vazio = todos da EMP)
        - Produto prefixo (obrigatório)
        - Marca (obrigatório)
        - Recompensa (R$/un)
        - Quantidade mínima (opcional)
        - Período (data início/fim)
        """
        red = _login_required()
        if red:
            return red
        red = _admin_required()
        if red:
            return red

        erro = None
        ok = None

        hoje = date.today()
        mes = int(request.values.get("mes") or hoje.month)
        ano = int(request.values.get("ano") or hoje.year)

        with SessionLocal() as db:
            if request.method == "POST":
                acao = (request.form.get("acao") or "").strip().lower()
                try:
                    if acao == "criar":
                        emp = (request.form.get("emp") or "").strip()
                        vendedor = (request.form.get("vendedor") or "").strip().upper() or None
                        titulo = (request.form.get("titulo") or "").strip() or None
                        produto_prefixo = (request.form.get("produto_prefixo") or "").strip()
                        marca = (request.form.get("marca") or "").strip()
                        recompensa_raw = (request.form.get("recompensa_unit") or "").strip().replace(",", ".")
                        qtd_min_raw = (request.form.get("qtd_minima") or "").strip().replace(",", ".")
                        data_ini_raw = (request.form.get("data_inicio") or "").strip()
                        data_fim_raw = (request.form.get("data_fim") or "").strip()

                        if not emp:
                            raise ValueError("Informe a EMP.")
                        if not produto_prefixo:
                            raise ValueError("Informe o produto (prefixo).")
                        if not marca:
                            raise ValueError("Informe a marca.")
                        if not recompensa_raw:
                            raise ValueError("Informe a recompensa (R$/un).")
                        if not data_ini_raw or not data_fim_raw:
                            raise ValueError("Informe data início e fim.")

                        recompensa_unit = float(recompensa_raw)
                        qtd_minima = float(qtd_min_raw) if qtd_min_raw else None
                        data_inicio = datetime.strptime(data_ini_raw, "%Y-%m-%d").date()
                        data_fim = datetime.strptime(data_fim_raw, "%Y-%m-%d").date()
                        if data_fim < data_inicio:
                            raise ValueError("Data fim não pode ser menor que data início.")

                        db.add(
                            CampanhaQtd(
                                emp=str(emp),
                                vendedor=vendedor,
                                titulo=titulo,
                                produto_prefixo=produto_prefixo.upper(),
                                marca=marca.upper(),
                                recompensa_unit=recompensa_unit,
                                qtd_minima=qtd_minima,
                                data_inicio=data_inicio,
                                data_fim=data_fim,
                                ativo=1,
                            )
                        )
                        db.commit()
                        ok = "Campanha cadastrada com sucesso."

                    elif acao == "toggle":
                        cid = int(request.form.get("campanha_id") or 0)
                        c = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                        if not c:
                            raise ValueError("Campanha não encontrada.")
                        c.ativo = 0 if int(c.ativo or 0) == 1 else 1
                        c.atualizado_em = datetime.utcnow()
                        db.commit()
                        ok = "Status da campanha atualizado."

                    elif acao == "remover":
                        cid = int(request.form.get("campanha_id") or 0)
                        c = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                        if not c:
                            raise ValueError("Campanha não encontrada.")
                        db.delete(c)
                        db.commit()
                        ok = "Campanha removida."

                    elif acao == "pagar":
                        rid = int(request.form.get("resultado_id") or 0)
                        r = db.query(CampanhaQtdResultado).filter(CampanhaQtdResultado.id == rid).first()
                        if not r:
                            raise ValueError("Resultado não encontrado.")
                        if (r.status_pagamento or "PENDENTE") == "PAGO":
                            r.status_pagamento = "PENDENTE"
                            r.pago_em = None
                        else:
                            r.status_pagamento = "PAGO"
                            r.pago_em = datetime.utcnow()
                        r.atualizado_em = datetime.utcnow()
                        db.commit()
                        ok = "Status de pagamento atualizado."

                    else:
                        raise ValueError("Ação inválida.")

                except Exception as e:
                    db.rollback()
                    erro = str(e)
                    app.logger.exception("Erro ao gerenciar campanhas")

            campanhas = db.query(CampanhaQtd).order_by(CampanhaQtd.emp.asc(), CampanhaQtd.data_inicio.desc()).all()
            resultados = (
                db.query(CampanhaQtdResultado)
                .filter(
                    CampanhaQtdResultado.competencia_ano == int(ano),
                    CampanhaQtdResultado.competencia_mes == int(mes),
                )
                .order_by(CampanhaQtdResultado.valor_recompensa.desc())
                .all()
            )

        return render_template(
            "admin_campanhas_qtd.html",
            usuario=_usuario_logado(),
            campanhas=campanhas,
            resultados=resultados,
            ano=ano,
            mes=mes,
            erro=erro,
            ok=ok,
        )

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
