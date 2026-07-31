# -*- coding: utf-8 -*-
"""Consulta leve do saldo mensal importado de itens parados."""

from __future__ import annotations

import calendar
from datetime import date
from decimal import Decimal
from io import BytesIO
from typing import Callable

from flask import render_template, request, send_file

from db import (
    ItemParado,
    ItensParadosVendaUsuario,
    SessionLocal,
    ensure_itens_parados_snapshot_schema,
)
from itens_parados_snapshot import norm_emp, norm_username, period_options
from security_utils import normalize_role
from sv_utils import emp_sort_key


_login_required: Callable[[], object] | None = None
_role: Callable[[], str | None] | None = None
_allowed_emps: Callable[[], list[str]] | None = None
_usuario_logado: Callable[[], str | None] | None = None


def _safe_int(value, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(str(value).strip())
    except Exception:
        return default
    return max(minimum, min(maximum, parsed))


def _load_view_data():
    red = _login_required() if _login_required else None
    if red:
        return {"redirect": red}

    ensure_itens_parados_snapshot_schema()
    role = normalize_role(_role() if _role else "")
    username = norm_username(_usuario_logado() if _usuario_logado else "")
    today = date.today()

    with SessionLocal() as db:
        periods = period_options(db)
        default_year, default_month = periods[0] if periods else (today.year, today.month)
        ano = _safe_int(request.args.get("ano"), default_year, 2000, 2100)
        mes = _safe_int(request.args.get("mes"), default_month, 1, 12)

        base_query = db.query(ItensParadosVendaUsuario).filter(
            ItensParadosVendaUsuario.ano == ano,
            ItensParadosVendaUsuario.mes == mes,
        )
        emp_filter = norm_emp(request.args.get("emp"))
        user_filter = norm_username(request.args.get("usuario"))
        product_scope_emps: list[str] | None = None

        if role == "admin":
            all_rows = base_query.all()
            query = base_query
            if emp_filter:
                query = query.filter(ItensParadosVendaUsuario.emp == emp_filter)
                product_scope_emps = [emp_filter]
            if user_filter:
                query = query.filter(
                    ItensParadosVendaUsuario.usuario_nome == user_filter
                )
            rows = query.all()
            emp_options = sorted(
                {row.emp for row in all_rows if row.emp}, key=emp_sort_key
            )
            user_options = sorted(
                {row.usuario_nome for row in all_rows if row.usuario_nome}
            )
        elif role in {"gerente", "supervisor"}:
            allowed = sorted(
                {
                    norm_emp(emp)
                    for emp in ((_allowed_emps() if _allowed_emps else []) or [])
                    if norm_emp(emp)
                },
                key=emp_sort_key,
            )
            query = base_query
            if allowed:
                query = query.filter(ItensParadosVendaUsuario.emp.in_(allowed))
                product_scope_emps = list(allowed)
                if emp_filter and emp_filter in allowed:
                    query = query.filter(ItensParadosVendaUsuario.emp == emp_filter)
                    product_scope_emps = [emp_filter]
            else:
                query = query.filter(
                    ItensParadosVendaUsuario.usuario_nome == username
                )
                product_scope_emps = []
            if user_filter:
                query = query.filter(
                    ItensParadosVendaUsuario.usuario_nome == user_filter
                )
            rows = query.all()
            emp_options = allowed
            user_options = sorted({row.usuario_nome for row in rows})
        else:
            rows = base_query.filter(
                ItensParadosVendaUsuario.usuario_nome == username
            ).all()
            allowed = sorted(
                {
                    norm_emp(emp)
                    for emp in ((_allowed_emps() if _allowed_emps else []) or [])
                    if norm_emp(emp)
                },
                key=emp_sort_key,
            )
            # O vendedor enxerga os produtos ativos de todas as lojas vinculadas,
            # mesmo quando ainda não possui venda de item parado na competência.
            product_scope_emps = allowed or sorted(
                {norm_emp(row.emp) for row in rows if norm_emp(row.emp)},
                key=emp_sort_key,
            )
            emp_options = []
            user_options = []
            emp_filter = ""
            user_filter = ""

        rows.sort(key=lambda row: (emp_sort_key(row.emp), row.usuario_nome))
        visible_emps = sorted({row.emp for row in rows if row.emp}, key=emp_sort_key)
        period_start = date(ano, mes, 1)
        period_end = date(ano, mes, calendar.monthrange(ano, mes)[1])

        product_query = db.query(ItemParado).filter(
            ItemParado.ativo.is_(True),
            ItemParado.data_inicio.isnot(None),
            ItemParado.data_fim.isnot(None),
            ItemParado.data_inicio <= period_end,
            ItemParado.data_fim >= period_start,
        )
        if product_scope_emps is not None:
            product_query = product_query.filter(
                ItemParado.emp.in_(product_scope_emps or ["__none__"])
            )
        active_products_raw = product_query.all()

    # Evita duplicar um mesmo código na mesma EMP caso exista resíduo de uma
    # importação anterior, sem ocultar o produto de lojas diferentes.
    product_map: dict[tuple[str, str], ItemParado] = {}
    for item in active_products_raw:
        key = (norm_emp(item.emp), str(item.codigo or "").strip().upper())
        current = product_map.get(key)
        if current is None or (item.data_fim or date.min) > (current.data_fim or date.min):
            product_map[key] = item
    active_products = sorted(
        product_map.values(),
        key=lambda item: (
            emp_sort_key(norm_emp(item.emp)),
            str(item.descricao or "").strip().upper(),
            str(item.codigo or "").strip().upper(),
        ),
    )
    active_counts: dict[str, int] = {}
    for item in active_products:
        emp_key = norm_emp(item.emp)
        active_counts[emp_key] = active_counts.get(emp_key, 0) + 1

    by_emp: dict[str, dict] = {}
    total_vendido = Decimal("0")
    total_bonus = Decimal("0")
    total_pontos = 0
    for row in rows:
        vendido = Decimal(str(row.valor_total or 0))
        bonus = Decimal(str(row.bonus_total or 0))
        pontos = int(row.pontos or 0)
        total_vendido += vendido
        total_bonus += bonus
        total_pontos += pontos
        card = by_emp.setdefault(
            row.emp,
            {
                "emp": row.emp,
                "valor_vendido": Decimal("0"),
                "pontos": 0,
                "bonus_total": Decimal("0"),
                "usuarios": 0,
                "linhas": 0,
                "itens_distintos": 0,
                "itens_ativos": int(active_counts.get(norm_emp(row.emp), 0) or 0),
            },
        )
        card["valor_vendido"] += vendido
        card["pontos"] += pontos
        card["bonus_total"] += bonus
        card["usuarios"] += 1
        card["linhas"] += int(row.qtd_linhas or 0)
        card["itens_distintos"] += int(row.qtd_itens or 0)

    emp_cards = sorted(by_emp.values(), key=lambda item: emp_sort_key(item["emp"]))
    product_emps = sorted(
        {norm_emp(item.emp) for item in active_products if norm_emp(item.emp)},
        key=emp_sort_key,
    )
    if role == "admin":
        emp_options = sorted(set(emp_options) | set(product_emps), key=emp_sort_key)
    summary = {
        "valor_vendido": total_vendido,
        "pontos": total_pontos,
        "bonus_total": total_bonus,
        "usuarios": len(rows),
        "emps": len(visible_emps or product_emps),
        "linhas": sum(int(row.qtd_linhas or 0) for row in rows),
        "produtos_ativos": len(active_products),
    }
    return {
        "role": role,
        "ano": ano,
        "mes": mes,
        "rows": rows,
        "periods": periods,
        "emp_options": emp_options,
        "user_options": user_options,
        "emp_filter": emp_filter,
        "user_filter": user_filter,
        "emp_cards": emp_cards,
        "active_products": active_products,
        "summary": summary,
    }


def itens_parados():
    data = _load_view_data()
    if data.get("redirect"):
        return data["redirect"]
    return render_template("itens_parados.html", **data)


def itens_parados_pdf():
    data = _load_view_data()
    if data.get("redirect"):
        return data["redirect"]

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.pdfgen import canvas
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("ReportLab não está disponível para gerar o PDF.") from exc

    bio = BytesIO()
    c = canvas.Canvas(bio, pagesize=A4)
    width, height = A4
    y = height - 18 * mm
    c.setFont("Helvetica-Bold", 15)
    c.drawString(15 * mm, y, "Itens Parados")
    y -= 7 * mm
    c.setFont("Helvetica", 9)
    c.drawString(15 * mm, y, f"Competência: {data['mes']:02d}/{data['ano']}")
    y -= 8 * mm

    def brl(value):
        raw = f"{Decimal(str(value or 0)):,.2f}"
        return "R$ " + raw.replace(",", "X").replace(".", ",").replace("X", ".")

    c.setFont("Helvetica-Bold", 10)
    c.drawString(
        15 * mm,
        y,
        f"Vendas elegíveis: {brl(data['summary']['valor_vendido'])} | "
        f"Pontos: {data['summary']['pontos']} | "
        f"Bônus: {brl(data['summary']['bonus_total'])}",
    )
    y -= 9 * mm
    c.setFont("Helvetica-Bold", 8)
    c.drawString(15 * mm, y, "EMP")
    c.drawString(30 * mm, y, "Funcionário")
    c.drawRightString(width - 75 * mm, y, "Venda")
    c.drawRightString(width - 45 * mm, y, "Pontos")
    c.drawRightString(width - 15 * mm, y, "Bônus")
    y -= 5 * mm
    c.setFont("Helvetica", 8)
    for row in data["rows"]:
        if y < 18 * mm:
            c.showPage()
            y = height - 18 * mm
            c.setFont("Helvetica", 8)
        c.drawString(15 * mm, y, str(row.emp or ""))
        c.drawString(30 * mm, y, str(row.usuario_nome or "")[:34])
        c.drawRightString(width - 75 * mm, y, brl(row.valor_total))
        c.drawRightString(width - 45 * mm, y, str(int(row.pontos or 0)))
        c.drawRightString(width - 15 * mm, y, brl(row.bonus_total))
        y -= 5 * mm
    c.save()
    bio.seek(0)
    return send_file(
        bio,
        as_attachment=True,
        download_name=f"itens_parados_{data['ano']}_{data['mes']:02d}.pdf",
        mimetype="application/pdf",
    )


def register_itens_parados_routes(
    app,
    *,
    login_required_fn,
    mes_ano_from_request_fn=None,
    role_fn,
    emp_fn=None,
    allowed_emps_fn,
    usuario_logado_fn,
    get_vendedores_db_fn=None,
    periodo_bounds_fn=None,
):
    global _login_required, _role, _allowed_emps, _usuario_logado
    _login_required = login_required_fn
    _role = role_fn
    _allowed_emps = allowed_emps_fn
    _usuario_logado = usuario_logado_fn

    app.add_url_rule(
        "/itens_parados",
        endpoint="itens_parados",
        view_func=itens_parados,
        methods=["GET"],
    )
    app.add_url_rule(
        "/itens_parados/pdf",
        endpoint="itens_parados_pdf",
        view_func=itens_parados_pdf,
        methods=["GET"],
    )
