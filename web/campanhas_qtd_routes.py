from __future__ import annotations

from datetime import date
from io import BytesIO
from typing import Callable, Any

from flask import render_template, request, send_file

from services.campanhas_service import build_campanhas_page_context


def register_campanhas_qtd_routes(
    app,
    *,
    deps: Any,
    SessionLocal,
    CampanhaQtdResultado,
    login_required_fn: Callable[[], Any],
    role_fn: Callable[[], str | None],
    emp_fn: Callable[[], str | None],
    usuario_logado_fn: Callable[[], str | None],
    get_vendedores_db_fn: Callable[[str, str | None], list[str]],
    get_emps_vendedor_fn: Callable[[str], list[str]],
    resolver_emp_scope_fn: Callable[[str, str, str | None], list[str]],
) -> None:
    """Registra rotas de Campanhas QTD (recompensa por quantidade).

    Refatoração pura: mantém paths, endpoints e comportamento.
    """

    def campanhas_qtd():
        """Relatório de campanhas de recompensa por quantidade.

        - Vendedor: vê por EMPs inferidas de vendas (multi-EMP)
        - Supervisor: vê apenas EMP dele
        - Admin: pode escolher vendedor/EMP
        """
        red = login_required_fn()
        if red:
            return red

        role = role_fn() or ""
        emp_usuario = emp_fn()
        vendedor_logado = (usuario_logado_fn() or "").strip().upper()

        # Flags de permissão para a UI (templates)
        ctx_role = role
        ctx_is_admin = (ctx_role == "admin")
        ctx_is_supervisor = (ctx_role == "supervisor")
        ctx_is_vendedor = (ctx_role == "vendedor")
        ctx_is_financeiro = (ctx_role == "financeiro")

        # (ctx_* são utilizados indiretamente no contexto do template, mantidos por compatibilidade)
        _ = (ctx_is_admin, ctx_is_supervisor, ctx_is_vendedor, ctx_is_financeiro)

        ctx = build_campanhas_page_context(
            deps,
            role=role,
            emp_usuario=emp_usuario,
            vendedor_logado=vendedor_logado,
            args=request.args,
        )
        return render_template("campanhas_qtd.html", **ctx)

    def campanhas_qtd_pdf():
        red = login_required_fn()
        if red:
            return red

        role = role_fn() or ""
        emp_usuario = emp_fn()
        hoje = date.today()
        mes = int(request.args.get("mes") or hoje.month)
        ano = int(request.args.get("ano") or hoje.year)

        vendedor_logado = (usuario_logado_fn() or "").strip().upper()
        if (role or "").lower() == "supervisor":
            vendedor_sel = (request.args.get("vendedor") or "__ALL__").strip().upper()
            if vendedor_sel == "__ALL__":
                try:
                    vs = get_vendedores_db_fn(role, emp_usuario)
                    vendedor_sel = (vs[0] if vs else vendedor_logado).strip().upper()
                except Exception:
                    vendedor_sel = vendedor_logado
        else:
            vendedor_sel = (request.args.get("vendedor") or vendedor_logado).strip().upper()
            if (role or "").lower() != "admin" and vendedor_sel != vendedor_logado:
                vendedor_sel = vendedor_logado

        emp_param = (request.args.get("emp") or "").strip()
        if (role or "").lower() == "admin":
            emps_scope = [emp_param] if emp_param else get_emps_vendedor_fn(vendedor_sel)
        else:
            emps_scope = resolver_emp_scope_fn(vendedor_sel, role, emp_usuario)

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

    # Endpoints preservados explicitamente (compatibilidade total com url_for)
    app.add_url_rule("/campanhas", endpoint="campanhas_qtd", view_func=campanhas_qtd, methods=["GET"])
    app.add_url_rule("/campanhas/pdf", endpoint="campanhas_qtd_pdf", view_func=campanhas_qtd_pdf, methods=["GET"])
