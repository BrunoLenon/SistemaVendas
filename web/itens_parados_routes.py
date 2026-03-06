from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import Callable, Iterable

from flask import flash, redirect, render_template, request, send_file, url_for
from sqlalchemy import func

from db import ItemParado, SessionLocal, Venda

# ---------------------------------------------------------------------
# Injeção de dependências (refatoração pura)
# ---------------------------------------------------------------------

_login_required: Callable[[], object] | None = None
_mes_ano_from_request: Callable[[], tuple[int, int]] | None = None
_role: Callable[[], str | None] | None = None
_emp: Callable[[], str | None] | None = None
_allowed_emps: Callable[[], list[str]] | None = None
_usuario_logado: Callable[[], str | None] | None = None
_get_vendedores_db: Callable[..., list[str]] | None = None
_periodo_bounds: Callable[[int, int], tuple[object, object]] | None = None


def register_itens_parados_routes(
    app,
    *,
    login_required_fn: Callable[[], object],
    mes_ano_from_request_fn: Callable[[], tuple[int, int]],
    role_fn: Callable[[], str | None],
    emp_fn: Callable[[], str | None],
    allowed_emps_fn: Callable[[], list[str]],
    usuario_logado_fn: Callable[[], str | None],
    get_vendedores_db_fn: Callable[..., list[str]],
    periodo_bounds_fn: Callable[[int, int], tuple[object, object]],
):
    """Registra rotas de Itens Parados sem alterar nomes de endpoint (backward-compatible)."""
    global _login_required, _mes_ano_from_request, _role, _emp, _allowed_emps
    global _usuario_logado, _get_vendedores_db, _periodo_bounds

    _login_required = login_required_fn
    _mes_ano_from_request = mes_ano_from_request_fn
    _role = role_fn
    _emp = emp_fn
    _allowed_emps = allowed_emps_fn
    _usuario_logado = usuario_logado_fn
    _get_vendedores_db = get_vendedores_db_fn
    _periodo_bounds = periodo_bounds_fn

    # Mantém os mesmos endpoints usados no sistema
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


# ---------------------------------------------------------------------
# Rotas (código movido do app.py sem mudança de lógica)
# ---------------------------------------------------------------------


def itens_parados():
    """Relatório de itens parados (liquidação) por EMP.

    Cadastro é feito pelo ADMIN por EMP.
    - ADMIN: pode visualizar todas as EMPs (e opcionalmente filtrar por EMP e/ou vendedor)
    - SUPERVISOR: visualiza somente a EMP cadastrada no usuário
    - VENDEDOR: a(s) EMP(s) é(são) derivada(s) de vendas.emp (pode ser multi-EMP)

    O campo "Valor" só aparece quando houver venda do código no período selecionado.
    """
    red = _login_required() if _login_required else None
    if red:
        return red

    mes, ano = _mes_ano_from_request() if _mes_ano_from_request else (0, 0)
    role = ((_role() or "") if _role else "").lower()

    # --- vendedor alvo (para cálculo do VALOR) ---
    vendedor_alvo = None
    vendedores_lista: list[str] = []

    if role in {"admin", "supervisor"}:
        emp_supervisor = (_emp() if _emp else None) if role == "supervisor" else None
        if role == "supervisor" and not emp_supervisor:
            flash(
                "Seu usuário supervisor não possui EMP cadastrada. Solicite ao ADMIN para cadastrar.",
                "warning",
            )
            return redirect(url_for("dashboard"))

        vendedores_lista = _get_vendedores_db(role, emp_supervisor) if _get_vendedores_db else []
        vendedor_req = (request.args.get("vendedor") or "").strip().upper() or None
        if vendedor_req and vendedor_req in vendedores_lista:
            vendedor_alvo = vendedor_req
        else:
            vendedor_alvo = None  # admin/supervisor sem seleção = só lista

    else:
        vendedor_alvo = ((_usuario_logado() or "") if _usuario_logado else "").strip().upper()

    # --- EMP(s) visíveis para o usuário ---
    emp_param = (request.args.get("emp") or "").strip()
    emp_scopes: list[str] = []

    if role == "admin":
        if emp_param:
            emp_scopes = [str(emp_param)]
        else:
            # admin sem filtro: mostrar todas as EMPs que possuem itens cadastrados
            with SessionLocal() as db:
                # `itens_parados.ativo` is boolean in the database (TRUE/FALSE)
                emp_scopes = [
                    str(x[0])
                    for x in db.query(ItemParado.emp)
                    .filter(ItemParado.ativo.is_(True))
                    .distinct()
                    .all()
                ]

    elif role == "supervisor":
        emps = _allowed_emps() if _allowed_emps else []
        emp_scopes = emps if emps else ([str(_emp())] if (_emp and _emp()) else [])

    else:
        # vendedor: EMP(s) via usuario_emps (recomendado); fallback = derivadas das vendas
        emps = _allowed_emps() if _allowed_emps else []
        if emps:
            emp_scopes = emps
        else:
            with SessionLocal() as db:
                emp_scopes = [
                    str(x[0])
                    for x in db.query(Venda.emp)
                    .filter(Venda.vendedor == vendedor_alvo)
                    .distinct()
                    .all()
                ]

    emp_scopes = sorted({e.strip() for e in emp_scopes if e and str(e).strip()})
    if not emp_scopes:
        flash(
            "Não foi possível identificar a EMP para este usuário (sem vendas registradas).", "warning"
        )
        return redirect(url_for("dashboard"))

    # --- Buscar itens por EMP e agrupar ---
    with SessionLocal() as db:
        itens_all = (
            db.query(ItemParado)
            .filter(ItemParado.emp.in_(emp_scopes))
            .filter(ItemParado.ativo.is_(True))
            .order_by(ItemParado.emp.asc(), ItemParado.codigo.asc())
            .all()
        )

    itens_por_emp: dict[str, list[ItemParado]] = {}
    for it in itens_all:
        e = str(it.emp).strip() if it.emp is not None else ""
        itens_por_emp.setdefault(e, []).append(it)

    # --- Calcular vendido_total por (emp, codigo) e recompensa ---
    vendido_total_map: dict[tuple[str, str], float] = {}
    recomp_map: dict[tuple[str, str], float] = {}

    if vendedor_alvo and itens_all:
        # lista de códigos (mestre) cadastrados nos itens
        codigos = [(i.codigo or "").strip() for i in itens_all if (i.codigo or "").strip()]
        codigos = sorted(set(codigos))
        if codigos:
            start, end = _periodo_bounds(int(ano), int(mes)) if _periodo_bounds else (None, None)
            with SessionLocal() as db:
                q = (
                    db.query(Venda.emp, Venda.mestre, func.coalesce(func.sum(Venda.valor_total), 0.0))
                    .filter(Venda.emp.in_(emp_scopes))
                    .filter(Venda.vendedor == vendedor_alvo)
                    .filter(Venda.movimento >= start)
                    .filter(Venda.movimento < end)
                    .filter(Venda.mov_tipo_movto == "OA")
                    .filter(Venda.mestre.in_(codigos))
                    .group_by(Venda.emp, Venda.mestre)
                )
                for emp_v, mestre, total in q.all():
                    k_emp = str(emp_v).strip() if emp_v is not None else ""
                    k_cod = (mestre or "").strip()
                    vendido_total_map[(k_emp, k_cod)] = float(total or 0.0)

            for it in itens_all:
                emp_it = str(it.emp).strip() if it.emp is not None else ""
                cod = (it.codigo or "").strip()
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


def itens_parados_pdf():
    """Exporta o relatório de itens parados em PDF (mes/ano e escopo do usuário)."""
    red = _login_required() if _login_required else None
    if red:
        return red

    mes, ano = _mes_ano_from_request() if _mes_ano_from_request else (0, 0)
    role = ((_role() or "") if _role else "").lower()

    # Reaproveita a lógica da tela para determinar vendedor/emp_scopes/itens e valores
    vendedor_alvo = None
    vendedores_lista: list[str] = []

    if role in {"admin", "supervisor"}:
        emp_supervisor = (_emp() if _emp else None) if role == "supervisor" else None
        if role == "supervisor" and not emp_supervisor:
            flash(
                "Seu usuário supervisor não possui EMP cadastrada. Solicite ao ADMIN para cadastrar.",
                "warning",
            )
            return redirect(url_for("dashboard"))

        vendedores_lista = _get_vendedores_db(role, emp_supervisor) if _get_vendedores_db else []
        vendedor_req = (request.args.get("vendedor") or "").strip().upper() or None
        if vendedor_req and vendedor_req in vendedores_lista:
            vendedor_alvo = vendedor_req
        else:
            vendedor_alvo = None
    else:
        vendedor_alvo = ((_usuario_logado() or "") if _usuario_logado else "").strip().upper()

    emp_param = (request.args.get("emp") or "").strip()
    emp_scopes: list[str] = []

    if role == "admin":
        if emp_param:
            emp_scopes = [str(emp_param)]
        else:
            with SessionLocal() as db:
                # `itens_parados.ativo` is boolean in the database (TRUE/FALSE)
                emp_scopes = [
                    str(x[0])
                    for x in db.query(ItemParado.emp)
                    .filter(ItemParado.ativo.is_(True))
                    .distinct()
                    .all()
                ]
    elif role == "supervisor":
        emps = _allowed_emps() if _allowed_emps else []
        emp_scopes = emps if emps else ([str(_emp())] if (_emp and _emp()) else [])
    else:
        with SessionLocal() as db:
            emp_scopes = [
                str(x[0])
                for x in db.query(Venda.emp)
                .filter(Venda.vendedor == vendedor_alvo)
                .distinct()
                .all()
            ]

    emp_scopes = sorted({e.strip() for e in emp_scopes if e and str(e).strip()})
    if not emp_scopes:
        flash(
            "Não foi possível identificar a EMP para este usuário (sem vendas registradas).", "warning"
        )
        return redirect(url_for("dashboard"))

    with SessionLocal() as db:
        itens_all = (
            db.query(ItemParado)
            .filter(ItemParado.emp.in_(emp_scopes))
            .filter(ItemParado.ativo.is_(True))
            .order_by(ItemParado.emp.asc(), ItemParado.codigo.asc())
            .all()
        )

    itens_por_emp: dict[str, list[ItemParado]] = {}
    for it in itens_all:
        e = str(it.emp).strip() if it.emp is not None else ""
        itens_por_emp.setdefault(e, []).append(it)

    vendido_total_map: dict[tuple[str, str], float] = {}
    recomp_map: dict[tuple[str, str], float] = {}

    if vendedor_alvo and itens_all:
        codigos = [(i.codigo or "").strip() for i in itens_all if (i.codigo or "").strip()]
        codigos = sorted(set(codigos))
        if codigos:
            start, end = _periodo_bounds(int(ano), int(mes)) if _periodo_bounds else (None, None)
            with SessionLocal() as db:
                q = (
                    db.query(Venda.emp, Venda.mestre, func.coalesce(func.sum(Venda.valor_total), 0.0))
                    .filter(Venda.emp.in_(emp_scopes))
                    .filter(Venda.vendedor == vendedor_alvo)
                    .filter(Venda.movimento >= start)
                    .filter(Venda.movimento < end)
                    .filter(Venda.mov_tipo_movto == "OA")
                    .filter(Venda.mestre.in_(codigos))
                    .group_by(Venda.emp, Venda.mestre)
                )
                for emp_v, mestre, total in q.all():
                    k_emp = str(emp_v).strip() if emp_v is not None else ""
                    k_cod = (mestre or "").strip()
                    vendido_total_map[(k_emp, k_cod)] = float(total or 0.0)

            for it in itens_all:
                emp_it = str(it.emp).strip() if it.emp is not None else ""
                cod = (it.codigo or "").strip()
                total = vendido_total_map.get((emp_it, cod), 0.0)
                pct = float(it.recompensa_pct or 0.0)
                valor = (total * (pct / 100.0)) if total > 0 and pct > 0 else 0.0
                recomp_map[(emp_it, cod)] = valor

    # --- Gerar PDF (ReportLab) ---
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4

    titulo = "Relatório - Itens Parados"
    periodo = f"Período: {mes:02d}/{ano}"
    vendedor_txt = (
        f"Vendedor: {vendedor_alvo}" if vendedor_alvo else "Vendedor: (não selecionado)"
    )
    agora = datetime.now().strftime("%d/%m/%Y %H:%M")

    def draw_header():
        y = height - 18 * mm
        c.setFont("Helvetica-Bold", 14)
        c.drawString(18 * mm, y, titulo)
        c.setFont("Helvetica", 10)
        c.drawString(18 * mm, y - 6 * mm, periodo)
        c.drawString(18 * mm, y - 11 * mm, vendedor_txt)
        c.drawRightString(width - 18 * mm, y - 6 * mm, f"Gerado em: {agora}")
        return y - 18 * mm

    y = draw_header()

    # tabela simples por EMP
    c.setFont("Helvetica", 9)

    for emp in emp_scopes:
        itens_emp = itens_por_emp.get(emp, [])
        if not itens_emp:
            continue

        # quebra página se necessário
        if y < 35 * mm:
            c.showPage()
            y = draw_header()
            c.setFont("Helvetica", 9)

        c.setFont("Helvetica-Bold", 11)
        c.drawString(18 * mm, y, f"EMP {emp}")
        y -= 6 * mm
        c.setFont("Helvetica-Bold", 9)
        c.drawString(18 * mm, y, "CÓDIGO")
        c.drawString(40 * mm, y, "DESCRIÇÃO")
        c.drawRightString(width - 55 * mm, y, "QTD")
        c.drawRightString(width - 35 * mm, y, "%")
        c.drawRightString(width - 18 * mm, y, "VALOR")
        y -= 4 * mm
        c.setLineWidth(0.5)
        c.line(18 * mm, y, width - 18 * mm, y)
        y -= 5 * mm
        c.setFont("Helvetica", 9)

        for it in itens_emp:
            cod = (it.codigo or "").strip()
            desc = (it.descricao or "").strip()
            qtd = it.quantidade or 0
            pct = float(it.recompensa_pct or 0.0)

            valor = recomp_map.get((emp, cod), 0.0)
            valor_txt = (
                ""
                if valor <= 0
                else f"R$ {valor:,.2f}"
                .replace(",", "X")
                .replace(".", ",")
                .replace("X", ".")
            )

            # quebra página
            if y < 20 * mm:
                c.showPage()
                y = draw_header()
                c.setFont("Helvetica", 9)

            c.drawString(18 * mm, y, cod[:20])
            c.drawString(40 * mm, y, desc[:55])
            c.drawRightString(width - 55 * mm, y, str(qtd))
            c.drawRightString(width - 35 * mm, y, f"{pct:.0f}%")
            c.drawRightString(width - 18 * mm, y, valor_txt)
            y -= 5 * mm

        y -= 4 * mm

    c.showPage()
    c.save()
    buf.seek(0)

    filename = f"itens_parados_{mes:02d}_{ano}.pdf"
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)
