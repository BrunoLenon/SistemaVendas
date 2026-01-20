import os
import logging
import json
from datetime import date, datetime
import calendar

import pandas as pd
from sqlalchemy import and_, func
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
from db import SessionLocal, Usuario, Venda, DashboardCache, criar_tabelas
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

    def _dados_from_cache(vendedor: str, mes: int, ano: int, emp_scope: str | None):
        """Monta o dict usado no template a partir do cache (e cache de meses relacionados)."""
        row = _get_cache_row(vendedor, ano, mes, emp_scope)
        if not row:
            return None

        # comparações via cache (se existir)
        if mes == 1:
            mes_ant, ano_ant = 12, ano - 1
        else:
            mes_ant, ano_ant = mes - 1, ano

        prev_row = _get_cache_row(vendedor, ano_ant, mes_ant, emp_scope)
        last_year_row = _get_cache_row(vendedor, ano - 1, mes, emp_scope)

        valor_atual = float(row.valor_liquido or 0.0)
        valor_mes_anterior = float(prev_row.valor_liquido or 0.0) if prev_row else None
        valor_ano_passado = float(last_year_row.valor_liquido or 0.0) if last_year_row else None

        crescimento = None
        if valor_mes_anterior not in (None, 0):
            crescimento = ((valor_atual - valor_mes_anterior) / abs(valor_mes_anterior)) * 100.0

        try:
            ranking_list = json.loads(row.ranking_json or '[]')
        except Exception:
            ranking_list = []
        try:
            ranking_top15_list = json.loads(row.ranking_top15_json or '[]')
        except Exception:
            ranking_top15_list = ranking_list[:15]

        valor_bruto = float(row.valor_bruto or 0.0)
        valor_devolvido = float((row.devolucoes or 0.0) + (row.cancelamentos or 0.0))
        pct_devolucao = (valor_devolvido / valor_bruto * 100.0) if valor_bruto else None

        mix_atual = int(row.mix_produtos or 0)
        mix_ano_passado = int(last_year_row.mix_produtos or 0) if last_year_row else None

        return {
            'valor_atual': valor_atual,
            'valor_ano_passado': valor_ano_passado,
            'valor_mes_anterior': valor_mes_anterior,
            'mix_atual': mix_atual,
            'mix_ano_passado': mix_ano_passado or 0,
            'valor_bruto': valor_bruto,
            'valor_devolvido': valor_devolvido,
            'pct_devolucao': pct_devolucao,
            'crescimento': crescimento,
            'ranking_list': ranking_list,
            'ranking_top15_list': ranking_top15_list,
            'total_liquido_periodo': float(getattr(row, 'total_liquido_periodo', 0.0) or 0.0),
        }


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
            start, end = _month_bounds(ano, mes)
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
