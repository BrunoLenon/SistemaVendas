"""Rotas do Dashboard (extraído do app.py).

Refatoração pura: mantém endpoints, templates e comportamento externo.
"""

from __future__ import annotations

from typing import Callable, Optional, Any
from datetime import date

from flask import (
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from sqlalchemy import func, case

from db import SessionLocal, Venda, Usuario, UsuarioEmp, Emp
from sv_utils import _periodo_bounds


def _meses_referencia(ano: int, mes: int, quantidade: int = 3) -> list[tuple[int, int]]:
    refs: list[tuple[int, int]] = []
    a = int(ano)
    m = int(mes)
    for _ in range(max(1, int(quantidade))):
        refs.append((a, m))
        if m == 1:
            a -= 1
            m = 12
        else:
            m -= 1
    refs.reverse()
    return refs


def _qtd_positiva_expr():
    return func.coalesce(Venda.qtdade_vendida, 0.0) > 0


def _signed_valor_expr():
    qtd_ok = _qtd_positiva_expr()
    valor = func.coalesce(Venda.valor_total, 0.0)
    return case((qtd_ok & Venda.mov_tipo_movto.in_(["DS", "CA"]), -valor), (qtd_ok, valor), else_=0.0)


def _signed_qtd_expr():
    qtd = func.coalesce(Venda.qtdade_vendida, 0.0)
    qtd_ok = qtd > 0
    return case((qtd_ok & Venda.mov_tipo_movto.in_(["DS", "CA"]), -qtd), (qtd_ok, qtd), else_=0.0)




def _query_periodo(db, ano: int, mes: int, emp: str | None = None):
    start, end = _periodo_bounds(int(ano), int(mes))
    q = db.query(Venda).filter(Venda.movimento >= start, Venda.movimento < end)
    if emp:
        q = q.filter(Venda.emp == str(emp))
    return q


def _build_global_sales_analysis(ano: int, mes: int) -> dict:
    signed_valor = _signed_valor_expr()
    signed_qtd = _signed_qtd_expr()
    with SessionLocal() as db:
        base = _query_periodo(db, ano, mes)

        top_produtos_rows = (
            base.with_entities(
                Venda.mestre.label("codigo"),
                func.coalesce(func.max(func.nullif(Venda.descricao, "")), func.max(func.nullif(Venda.descricao_norm, "")), Venda.mestre).label("descricao"),
                func.coalesce(func.sum(signed_valor), 0.0).label("valor"),
                func.coalesce(func.sum(signed_qtd), 0.0).label("qtd"),
                func.count(func.distinct(Venda.emp)).label("emps"),
            )
            .group_by(Venda.mestre)
            .order_by(func.sum(signed_valor).desc())
            .limit(12)
            .all()
        )
        top_produtos = [{
            "codigo": (r.codigo or "").strip(),
            "descricao": (r.descricao or r.codigo or "—").strip(),
            "valor": float(r.valor or 0.0),
            "qtd": float(r.qtd or 0.0),
            "emps": int(r.emps or 0),
        } for r in top_produtos_rows]

        top_marcas_rows = (
            base.with_entities(
                func.coalesce(func.nullif(Venda.marca, ""), "SEM MARCA").label("marca"),
                func.coalesce(func.sum(signed_valor), 0.0).label("valor"),
                func.coalesce(func.sum(signed_qtd), 0.0).label("qtd"),
            )
            .group_by(func.coalesce(func.nullif(Venda.marca, ""), "SEM MARCA"))
            .order_by(func.sum(signed_valor).desc())
            .limit(8)
            .all()
        )
        total_marcas = sum(float(r.valor or 0.0) for r in top_marcas_rows) or 0.0
        top_marcas = [{
            "marca": (r.marca or "SEM MARCA").strip(),
            "valor": float(r.valor or 0.0),
            "qtd": float(r.qtd or 0.0),
            "pct": ((float(r.valor or 0.0) / total_marcas) * 100.0) if total_marcas else 0.0,
        } for r in top_marcas_rows]

        clientes_total = int(base.with_entities(func.coalesce(func.count(func.distinct(Venda.cliente_id_norm)), 0)).scalar() or 0)

    return {
        "top_produtos": top_produtos,
        "top_marcas": top_marcas,
        "clientes_total": clientes_total,
    }

def _build_emp_dashboard(ano: int, mes: int, emp: str | None) -> Optional[dict]:
    emp = (emp or "").strip()
    if not emp:
        return None

    signed_valor = _signed_valor_expr()
    signed_qtd = _signed_qtd_expr()
    refs = _meses_referencia(ano, mes, 3)
    meses: list[dict] = []

    with SessionLocal() as db:
        emp_nome = db.query(Emp.nome).filter(Emp.codigo == emp).scalar()

        for a, m in refs:
            start, end = _periodo_bounds(int(a), int(m))
            base = db.query(Venda).filter(
                Venda.movimento >= start,
                Venda.movimento < end,
                Venda.emp == emp,
            )
            row = base.with_entities(
                func.coalesce(func.sum(case((_qtd_positiva_expr() & ~Venda.mov_tipo_movto.in_(["DS", "CA"]), func.coalesce(Venda.valor_total, 0.0)), else_=0.0)), 0.0),
                func.coalesce(func.sum(case((_qtd_positiva_expr() & Venda.mov_tipo_movto.in_(["DS", "CA"]), func.coalesce(Venda.valor_total, 0.0)), else_=0.0)), 0.0),
                func.coalesce(func.sum(signed_valor), 0.0),
                func.coalesce(func.sum(case((_qtd_positiva_expr() & ~Venda.mov_tipo_movto.in_(["DS", "CA"]), func.coalesce(Venda.qtdade_vendida, 0.0)), else_=0.0)), 0.0),
                func.coalesce(func.count(func.distinct(Venda.cliente_id_norm)), 0),
            ).first()
            bruto = float(row[0] or 0.0)
            devol = float(row[1] or 0.0)
            liquido = float(row[2] or 0.0)
            itens = float(row[3] or 0.0)
            clientes = int(row[4] or 0)
            ticket = (liquido / clientes) if clientes else 0.0
            meses.append({
                "ano": int(a),
                "mes": int(m),
                "label": f"{int(m):02d}/{int(a)}",
                "bruto": bruto,
                "devolvido": devol,
                "liquido": liquido,
                "mix": itens,
                "clientes": clientes,
                "ticket_medio": ticket,
            })

        base_atual = _query_periodo(db, ano, mes, emp)

        top_produtos_rows = (
            base_atual.with_entities(
                Venda.mestre.label("codigo"),
                func.coalesce(func.max(func.nullif(Venda.descricao, "")), func.max(func.nullif(Venda.descricao_norm, "")), Venda.mestre).label("descricao"),
                func.coalesce(func.sum(signed_valor), 0.0).label("valor"),
                func.coalesce(func.sum(signed_qtd), 0.0).label("qtd"),
            )
            .group_by(Venda.mestre)
            .order_by(func.sum(signed_valor).desc())
            .limit(12)
            .all()
        )
        top_produtos = [
            {
                "codigo": (r.codigo or "").strip(),
                "descricao": (r.descricao or r.codigo or "—").strip(),
                "valor": float(r.valor or 0.0),
                "qtd": float(r.qtd or 0.0),
            }
            for r in top_produtos_rows
        ]

        top_linhas_rows = (
            base_atual.with_entities(
                func.coalesce(func.nullif(Venda.marca, ""), "SEM MARCA").label("linha"),
                func.coalesce(func.sum(signed_valor), 0.0).label("valor"),
                func.coalesce(func.sum(signed_qtd), 0.0).label("qtd"),
            )
            .group_by(func.coalesce(func.nullif(Venda.marca, ""), "SEM MARCA"))
            .order_by(func.sum(signed_valor).desc())
            .limit(8)
            .all()
        )
        total_linhas = sum(float(r.valor or 0.0) for r in top_linhas_rows) or 0.0
        top_linhas = [
            {
                "linha": (r.linha or "SEM MARCA").strip(),
                "valor": float(r.valor or 0.0),
                "qtd": float(r.qtd or 0.0),
                "pct": ((float(r.valor or 0.0) / total_linhas) * 100.0) if total_linhas else 0.0,
            }
            for r in top_linhas_rows
        ]

        vendedores_venda_rows = (
            base_atual.with_entities(
                func.coalesce(func.nullif(Venda.vendedor, ""), "SEM VENDEDOR").label("vendedor"),
                func.coalesce(func.sum(signed_valor), 0.0).label("valor"),
                func.coalesce(func.sum(signed_qtd), 0.0).label("qtd"),
                func.coalesce(func.count(func.distinct(Venda.cliente_id_norm)), 0).label("clientes"),
            )
            .group_by(func.coalesce(func.nullif(Venda.vendedor, ""), "SEM VENDEDOR"))
            .order_by(func.sum(signed_valor).desc())
            .all()
        )
        vendedores_com_venda = [
            {
                "vendedor": (r.vendedor or "SEM VENDEDOR").strip().upper(),
                "valor": float(r.valor or 0.0),
                "qtd": float(r.qtd or 0.0),
                "clientes": int(r.clientes or 0),
            }
            for r in vendedores_venda_rows if float(r.valor or 0.0) > 0
        ]
        top_vendedores = vendedores_com_venda[:10]

        vendedores_cadastrados_rows = (
            db.query(Usuario.username)
            .join(UsuarioEmp, Usuario.id == UsuarioEmp.usuario_id)
            .filter(func.lower(Usuario.role) == "vendedor", UsuarioEmp.emp == emp, UsuarioEmp.ativo.is_(True))
            .all()
        )
        vendedores_cadastrados = sorted({(r[0] or "").strip().upper() for r in vendedores_cadastrados_rows if (r[0] or "").strip()})
        if not vendedores_cadastrados:
            vendedores_cadastrados = sorted({(r.get("vendedor") or "").strip().upper() for r in vendedores_com_venda if (r.get("vendedor") or "").strip()})

        venderam_set = {r["vendedor"] for r in vendedores_com_venda}
        vendedores_sem_venda = [v for v in vendedores_cadastrados if v not in venderam_set]

        top_clientes_rows = (
            base_atual.with_entities(
                func.coalesce(func.nullif(Venda.razao, ""), func.nullif(Venda.razao_norm, ""), "SEM CLIENTE").label("cliente"),
                func.coalesce(func.sum(signed_valor), 0.0).label("valor"),
                func.coalesce(func.sum(signed_qtd), 0.0).label("qtd"),
            )
            .group_by(func.coalesce(func.nullif(Venda.razao, ""), func.nullif(Venda.razao_norm, ""), "SEM CLIENTE"))
            .order_by(func.sum(signed_valor).desc())
            .limit(8)
            .all()
        )
        top_clientes = [{
            "cliente": (r.cliente or "SEM CLIENTE").strip(),
            "valor": float(r.valor or 0.0),
            "qtd": float(r.qtd or 0.0),
        } for r in top_clientes_rows]

        clientes_total = int(base_atual.with_entities(func.coalesce(func.count(func.distinct(Venda.cliente_id_norm)), 0)).scalar() or 0)

    atual = meses[-1] if meses else None
    anterior = meses[-2] if len(meses) >= 2 else None
    acumulado_3m = sum(float(m["liquido"] or 0.0) for m in meses)
    crescimento_pct = None
    if atual and anterior and float(anterior["liquido"] or 0.0) != 0.0:
        crescimento_pct = ((float(atual["liquido"] or 0.0) - float(anterior["liquido"] or 0.0)) / float(anterior["liquido"] or 0.0)) * 100.0

    return {
        "emp": emp,
        "emp_nome": (emp_nome or "").strip(),
        "meses": meses,
        "atual": atual,
        "anterior": anterior,
        "acumulado_3m": acumulado_3m,
        "crescimento_pct": crescimento_pct,
        "top_produtos": top_produtos,
        "top_linhas": top_linhas,
        "top_vendedores": top_vendedores,
        "vendedores_sem_venda": vendedores_sem_venda[:15],
        "total_vendedores_sem_venda": len(vendedores_sem_venda),
        "total_vendedores_com_venda": len(vendedores_com_venda),
        "clientes_total": clientes_total,
        "top_clientes": top_clientes,
    }


def register_dashboard_routes(
    app,
    *,
    login_required_fn: Callable[[], Any],
    mes_ano_from_request_fn: Callable[[], tuple[int, int]],
    role_fn: Callable[[], str],
    emp_fn: Callable[[], Optional[str]],
    allowed_emps_fn: Callable[[], list[str]],
    usuario_logado_fn: Callable[[], Optional[str]],
    get_vendedores_db_fn: Callable[[str, Optional[str]], list[str]],
    dados_from_cache_fn: Callable[[str, int, int, Any], Optional[dict]],
    dados_ao_vivo_fn: Callable[[str, int, int, Any], Optional[dict]],
    dashboard_insights_fn: Callable[[str, int, int, Any], Optional[dict]],
    dados_admin_geral_fn: Callable[[int, int], Optional[dict]],
) -> None:
    """Registra rotas relacionadas ao Dashboard.

    Importante: **não** usa Blueprint para não alterar nomes de endpoints (url_for).
    """

    @app.get("/dashboard")
    def dashboard():
        red = login_required_fn()
        if red:
            return red

        mes, ano = mes_ano_from_request_fn()

        role = role_fn() or ""
        emp_usuario = emp_fn()
        allowed_emps = allowed_emps_fn()

        # Resolve vendedor alvo + lista para dropdown sem carregar toda a tabela em memória
        if role == "vendedor":
            vendedor_alvo = (usuario_logado_fn() or "").strip().upper()
            vendedores_lista = []
            msg = None
        else:
            vendedores_lista = get_vendedores_db_fn(role, emp_usuario)
            vendedor_req = (request.args.get("vendedor") or "").strip().upper() or None
            vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores_lista) else None
            msg = None
            if role in ("supervisor", "gerente") and not allowed_emps:
                msg = "Supervisor/Gerente sem EMP vinculada. Cadastre EMPs do usuário em usuario_emps."

        dados = None
        if vendedor_alvo:
            try:
                emp_scope = (allowed_emps if (role or "").lower() in ["supervisor", "gerente", "vendedor"] else None)
                dados = dados_from_cache_fn(vendedor_alvo, mes, ano, emp_scope)
            except Exception:
                app.logger.exception("Erro ao carregar dashboard do cache")
                dados = None

            # Fallback: calcula ao vivo (sem pandas) se cache ainda não existe
            if dados is None:
                try:
                    emp_scope = (allowed_emps if (role or "").lower() in ["supervisor", "gerente", "vendedor"] else None)
                    dados = dados_ao_vivo_fn(vendedor_alvo, mes, ano, emp_scope)
                except Exception:
                    app.logger.exception("Erro ao calcular dashboard ao vivo")
                    dados = None

        insights = None
        if vendedor_alvo:
            try:
                emp_scope = (allowed_emps if (role or "").lower() in ["supervisor", "gerente", "vendedor"] else None)
                insights = dashboard_insights_fn(vendedor_alvo, ano=ano, mes=mes, emp_scope=emp_scope)
            except Exception:
                app.logger.exception("Erro ao calcular insights do dashboard")
                insights = None

        dados_admin = None
        dashboard_emp = None
        global_analysis = None
        emp_selecionada = None
        emp_options = []
        if (role or "").lower() == "admin" and not vendedor_alvo:
            emp_selecionada = (request.args.get("emp") or "").strip() or None
            try:
                dados_admin = dados_admin_geral_fn(mes=mes, ano=ano)
                global_analysis = _build_global_sales_analysis(ano=ano, mes=mes)
            except Exception:
                app.logger.exception("Erro ao carregar dashboard geral do admin")
                dados_admin = None
                global_analysis = None
            emp_options = [str((row or {}).get("emp") or "").strip() for row in (dados_admin or {}).get("ranking_emp_list", []) if str((row or {}).get("emp") or "").strip()]
            if emp_selecionada:
                try:
                    dashboard_emp = _build_emp_dashboard(ano=ano, mes=mes, emp=emp_selecionada)
                except Exception:
                    app.logger.exception("Erro ao carregar dashboard detalhado por EMP")
                    dashboard_emp = None
        elif (role or "").lower() in ("supervisor", "gerente") and not vendedor_alvo and allowed_emps:
            emp_selecionada = ((request.args.get("emp") or "").strip() or allowed_emps[0])
            if emp_selecionada not in allowed_emps:
                emp_selecionada = allowed_emps[0]
            emp_options = list(allowed_emps)
            try:
                dashboard_emp = _build_emp_dashboard(ano=ano, mes=mes, emp=emp_selecionada)
            except Exception:
                app.logger.exception("Erro ao carregar dashboard detalhado por EMP do supervisor")
                dashboard_emp = None

        return render_template(
            "dashboard.html",
            insights=insights,
            vendedor=vendedor_alvo or "",
            usuario=usuario_logado_fn(),
            role=role_fn(),
            emp=(" / ".join(allowed_emps) if (role or "").lower() in ("supervisor", "gerente") and allowed_emps else emp_usuario),
            vendedores=vendedores_lista,
            vendedor_selecionado=vendedor_alvo or "",
            mensagem_role=msg,
            mes=mes,
            ano=ano,
            dados=dados,
            dados_admin=dados_admin,
            global_analysis=global_analysis,
            dashboard_emp=dashboard_emp,
            emp_options=emp_options,
            emp_selecionada=emp_selecionada or "",
            admin_geral=(bool(dados_admin) and not (vendedor_alvo or "").strip()),
        )

    @app.get("/percentuais")
    def percentuais():
        red = login_required_fn()
        if red:
            return red

        mes, ano = mes_ano_from_request_fn()
        role = (role_fn() or "").lower()
        emp_scope = emp_fn() if role in ("supervisor", "gerente") else None

        # resolve vendedor
        if role in {"admin", "supervisor", "gerente"}:
            vendedores = get_vendedores_db_fn(role, emp_scope)
            vendedor_req = (request.args.get("vendedor") or "").strip().upper() or None
            vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores) else None
        else:
            vendedor_alvo = (usuario_logado_fn() or "").strip().upper()

        dados = None
        if vendedor_alvo:
            dados = dados_from_cache_fn(vendedor_alvo, mes, ano, emp_scope)
            if dados is None:
                dados = dados_ao_vivo_fn(vendedor_alvo, mes, ano, emp_scope)
        dados = dados or {}

        ranking_list = dados.get("ranking_list", [])
        total = float(dados.get("total_liquido_periodo", 0.0))

        return render_template(
            "percentuais.html",
            vendedor=vendedor_alvo or "",
            role=role_fn(),
            emp=emp_scope,
            mes=mes,
            ano=ano,
            total=total,
            ranking_list=ranking_list,
        )

    @app.get("/marcas")
    def marcas():
        red = login_required_fn()
        if red:
            return red

        mes, ano = mes_ano_from_request_fn()
        role = (role_fn() or "").lower()
        emp_scope = emp_fn() if role in ("supervisor", "gerente") else None

        if role in {"admin", "supervisor", "gerente"}:
            vendedores = get_vendedores_db_fn(role, emp_scope)
            vendedor_req = (request.args.get("vendedor") or "").strip().upper() or None
            vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores) else None
        else:
            vendedor_alvo = (usuario_logado_fn() or "").strip().upper()

        dados = None
        if vendedor_alvo:
            dados = dados_from_cache_fn(vendedor_alvo, mes, ano, emp_scope)
            if dados is None:
                dados = dados_ao_vivo_fn(vendedor_alvo, mes, ano, emp_scope)
        dados = dados or {}

        marcas_map = {row.get("marca"): row.get("valor") for row in (dados.get("ranking_list") or [])}

        return render_template(
            "marcas.html",
            vendedor=vendedor_alvo or "",
            role=role_fn(),
            emp=emp_scope,
            mes=mes,
            ano=ano,
            marcas=marcas_map,
        )

    @app.get("/devolucoes")
    def devolucoes():
        red = login_required_fn()
        if red:
            return red

        mes, ano = mes_ano_from_request_fn()
        role = (role_fn() or "").lower()
        emp_scope = emp_fn() if role in ("supervisor", "gerente") else None

        # resolve vendedor
        if role in {"admin", "supervisor", "gerente"}:
            vendedores = get_vendedores_db_fn(role, emp_scope)
            vendedor_req = (request.args.get("vendedor") or "").strip().upper() or None
            vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores) else None
        else:
            vendedor_alvo = (usuario_logado_fn() or "").strip().upper()

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
                    .filter(Venda.mov_tipo_movto.in_(["DS", "CA"]))
                )
                if emp_scope:
                    q = q.filter(Venda.emp == str(emp_scope))
                q = q.group_by(Venda.marca).order_by(func.sum(Venda.valor_total).desc())
                devol = {str(m or ""): float(v or 0.0) for m, v in q.all() if m}

        return render_template(
            "devolucoes.html",
            vendedor=vendedor_alvo or "",
            role=role_fn(),
            emp=emp_scope,
            mes=mes,
            ano=ano,
            devolucoes=devol,
        )
