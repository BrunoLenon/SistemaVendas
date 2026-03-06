"""Rotas do Dashboard (extraído do app.py).

Refatoração pura: mantém endpoints, templates e comportamento externo.
"""

from __future__ import annotations

from typing import Callable, Optional, Any

from flask import (
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from sqlalchemy import func

from db import SessionLocal, Venda
from sv_utils import _periodo_bounds


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
            if role == "supervisor" and not allowed_emps:
                msg = "Supervisor sem EMP vinculada. Cadastre EMPs do supervisor em usuario_emps."

        dados = None
        if vendedor_alvo:
            try:
                emp_scope = (allowed_emps if (role or "").lower() in ["supervisor", "vendedor"] else None)
                dados = dados_from_cache_fn(vendedor_alvo, mes, ano, emp_scope)
            except Exception:
                app.logger.exception("Erro ao carregar dashboard do cache")
                dados = None

            # Fallback: calcula ao vivo (sem pandas) se cache ainda não existe
            if dados is None:
                try:
                    emp_scope = (allowed_emps if (role or "").lower() in ["supervisor", "vendedor"] else None)
                    dados = dados_ao_vivo_fn(vendedor_alvo, mes, ano, emp_scope)
                except Exception:
                    app.logger.exception("Erro ao calcular dashboard ao vivo")
                    dados = None

        insights = None
        if vendedor_alvo:
            try:
                emp_scope = (allowed_emps if (role or "").lower() in ["supervisor", "vendedor"] else None)
                insights = dashboard_insights_fn(vendedor_alvo, ano=ano, mes=mes, emp_scope=emp_scope)
            except Exception:
                app.logger.exception("Erro ao calcular insights do dashboard")
                insights = None

        dados_admin = None
        if (role or "").lower() == "admin" and not vendedor_alvo:
            try:
                dados_admin = dados_admin_geral_fn(mes=mes, ano=ano)
            except Exception:
                app.logger.exception("Erro ao carregar dashboard geral do admin")
                dados_admin = None

        return render_template(
            "dashboard.html",
            insights=insights,
            vendedor=vendedor_alvo or "",
            usuario=usuario_logado_fn(),
            role=role_fn(),
            emp=(" / ".join(allowed_emps) if (role or "").lower() == "supervisor" and allowed_emps else emp_usuario),
            vendedores=vendedores_lista,
            vendedor_selecionado=vendedor_alvo or "",
            mensagem_role=msg,
            mes=mes,
            ano=ano,
            dados=dados,
            dados_admin=dados_admin,
            admin_geral=(bool(dados_admin) and not (vendedor_alvo or "").strip()),
        )

    @app.get("/percentuais")
    def percentuais():
        red = login_required_fn()
        if red:
            return red

        mes, ano = mes_ano_from_request_fn()
        role = (role_fn() or "").lower()
        emp_scope = emp_fn() if role == "supervisor" else None

        # resolve vendedor
        if role in {"admin", "supervisor"}:
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
        emp_scope = emp_fn() if role == "supervisor" else None

        if role in {"admin", "supervisor"}:
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
        emp_scope = emp_fn() if role == "supervisor" else None

        # resolve vendedor
        if role in {"admin", "supervisor"}:
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
