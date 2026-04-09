# -*- coding: utf-8 -*-
"""Rotas do Relatório de Campanhas (unificado).

Extraído do app.py como refatoração pura (sem alterar comportamento externo).
- Mantém os mesmos paths
- Mantém os mesmos nomes de endpoint usados em url_for(...)
"""

from __future__ import annotations

from io import BytesIO
from typing import Callable, Any

from flask import flash, jsonify, render_template, request, send_file, url_for

from services.campanhas_service import build_relatorio_campanhas_scope
from services.relatorio_campanhas_service import build_relatorio_campanhas_unificado_context
from services.relatorio_unificado_service import load_combo_item_details


def _pick(obj, *keys):
    for k in keys:
        try:
            v = obj.get(k) if isinstance(obj, dict) else getattr(obj, k, None)
            if v is None:
                continue
            if isinstance(v, str) and not v.strip():
                continue
            return v
        except Exception:
            continue
    return None


def _to_float(x):
    try:
        return float(x or 0)
    except Exception:
        return 0.0


def _norm_status(s: str) -> str:
    s = (s or "PENDENTE").strip().upper()
    if s in ("A PAGAR", "A_PAGAR", "APAGAR"):
        return "A_PAGAR"
    if s == "PAGO":
        return "PAGO"
    if s == "PENDENTE":
        return "PENDENTE"
    return s


def _agg_status(counts: dict[str, int]) -> str:
    if counts.get("PENDENTE"):
        return "PENDENTE"
    if counts.get("A_PAGAR"):
        return "A_PAGAR"
    if counts.get("PAGO"):
        return "PAGO"
    return "OUTROS"


def _build_group_summaries(rows, *, ano: int, mes: int):
    groups_map: dict[tuple[str, str], dict[str, Any]] = {}
    for r in (rows or []):
        emp_r = str(_pick(r, "emp", "EMP") or "").strip() or "—"
        vend_r = str(_pick(r, "vendedor", "VENDEDOR") or "").strip() or "—"
        valor = _to_float(_pick(r, "valor_recompensa", "valor", "VALOR_RECOMPENSA") or 0)
        st = _norm_status(_pick(r, "status_pagamento", "status", "STATUS_PAGAMENTO") or "PENDENTE")

        key = (emp_r, vend_r)
        g = groups_map.get(key)
        if not g:
            g = {
                "emp": emp_r,
                "vendedor": vend_r,
                "total": 0.0,
                "status_counts": {"PENDENTE": 0, "A_PAGAR": 0, "PAGO": 0, "OUTROS": 0},
                "campanhas_count": 0,
                "detail_url": url_for(
                    "relatorio_campanhas_detalhes",
                    ano=ano,
                    mes=mes,
                    emp=emp_r,
                    vendedor=vend_r,
                ),
            }
            groups_map[key] = g

        g["total"] += valor
        g["campanhas_count"] += 1
        g["status_counts"][st if st in g["status_counts"] else "OUTROS"] += 1

    rows_grouped = list(groups_map.values())
    for g in rows_grouped:
        g["status"] = _agg_status(g["status_counts"])

    rows_grouped.sort(key=lambda gg: (-gg["total"], gg["emp"], gg["vendedor"]))
    return rows_grouped


def _build_group_detail(rows, *, ano: int, mes: int, emp: str, vendedor: str):
    campanhas = []
    total = 0.0
    status_counts = {"PENDENTE": 0, "A_PAGAR": 0, "PAGO": 0, "OUTROS": 0}

    for r in (rows or []):
        emp_r = str(_pick(r, "emp", "EMP") or "").strip() or "—"
        vendedor_r = str(_pick(r, "vendedor", "VENDEDOR") or "").strip() or "—"
        if emp_r != emp or vendedor_r != vendedor:
            continue

        titulo = str(_pick(r, "titulo", "campanha", "CAMPANHA") or "").strip() or "—"
        valor = _to_float(_pick(r, "valor_recompensa", "valor", "VALOR_RECOMPENSA") or 0)
        st = _norm_status(_pick(r, "status_pagamento", "status", "STATUS_PAGAMENTO") or "PENDENTE")
        tipo_camp = str(getattr(r, "tipo", "") or "").strip().upper()
        origem_id = int(getattr(r, "origem_id", 0) or 0)

        detail_url = None
        if tipo_camp == "COMBO" and origem_id > 0:
            detail_url = url_for(
                "relatorio_campanhas_combo_itens",
                ano=ano,
                mes=mes,
                emp=emp,
                vendedor=vendedor,
                combo_id=origem_id,
            )

        campanhas.append({
            "titulo": titulo,
            "item_codigo": getattr(r, "item_codigo", None),
            "qtd_minima": getattr(r, "qtd_minima", None),
            "recompensa_unit": getattr(r, "recompensa_unit", None),
            "qtd_vendida": float(getattr(r, "qtd_base", 0) or 0),
            "vendeu_rs": float(getattr(r, "valor_vendido", 0) or 0),
            "valor": valor,
            "status": st,
            "atingiu": bool(getattr(r, "atingiu", False)),
            "tipo": "COMBO_CARD" if tipo_camp == "COMBO" else tipo_camp,
            "origem_id": origem_id,
            "detail_url": detail_url,
            "itens": [],
        })
        total += valor
        status_counts[st if st in status_counts else "OUTROS"] += 1

    def _camp_sort_key(c):
        tipo = str(c.get("tipo") or "").strip().upper()
        tipo_ord = 9 if tipo == "PARADO" else (5 if tipo == "COMBO_CARD" else 1)
        status_ord = {"PENDENTE": 0, "A_PAGAR": 1, "PAGO": 2}.get(c.get("status"), 9)
        return (tipo_ord, status_ord, -float(c.get("valor") or 0), str(c.get("titulo") or ""))

    campanhas.sort(key=_camp_sort_key)
    return {
        "emp": emp,
        "vendedor": vendedor,
        "total": total,
        "status": _agg_status(status_counts),
        "campanhas_count": len(campanhas),
        "campanhas": campanhas,
    }


def _calc_resumo_financeiro(rows):
    resumo = {
        "linhas": 0,
        "total_valor": 0.0,
        "status": {"PENDENTE": 0.0, "A_PAGAR": 0.0, "PAGO": 0.0, "OUTROS": 0.0},
        "por_emp": {},
    }
    for r in (rows or []):
        emp = str(_pick(r, "emp", "EMP") or "").strip() or "—"
        vendedor = str(_pick(r, "vendedor", "VENDEDOR") or "").strip() or "—"
        valor = _to_float(_pick(r, "valor_recompensa", "valor", "VALOR_RECOMPENSA") or 0)
        st = _norm_status(_pick(r, "status_pagamento", "status", "STATUS_PAGAMENTO") or "PENDENTE")
        st_key = st if st in ("PENDENTE", "A_PAGAR", "PAGO") else "OUTROS"
        resumo["linhas"] += 1
        resumo["total_valor"] += valor
        resumo["status"][st_key] += valor
        empd = resumo["por_emp"].setdefault(emp, {"total": 0.0, "status": {"PENDENTE": 0.0, "A_PAGAR": 0.0, "PAGO": 0.0, "OUTROS": 0.0}, "vendedores": {}})
        empd["total"] += valor
        empd["status"][st_key] += valor
        vd = empd["vendedores"].setdefault(vendedor, {"total": 0.0, "status": {"PENDENTE": 0.0, "A_PAGAR": 0.0, "PAGO": 0.0, "OUTROS": 0.0}, "linhas": 0})
        vd["linhas"] += 1
        vd["total"] += valor
        vd["status"][st_key] += valor
    resumo["por_emp_ordenado"] = sorted(resumo["por_emp"].items(), key=lambda kv: kv[1].get("total", 0.0), reverse=True)
    return resumo


def register_relatorio_campanhas_routes(
    app,
    *,
    deps: Any,
    login_required_fn: Callable[[], Any],
    role_fn: Callable[[], str | None],
    emp_fn: Callable[[], str | None],
    usuario_logado_fn: Callable[[], str | None],
) -> None:
    """Registra rotas do relatório unificado de campanhas.

    Importante: não usa Blueprint para não alterar nomes de endpoints.
    Endpoints são fixados explicitamente para 100% backward compatibility.
    """

    def relatorio_campanhas():
        """Relatório gerencial de campanhas por EMP -> vendedores -> campanhas (mês/ano)."""
        red = login_required_fn()
        if red:
            return red

        role = (role_fn() or "").strip().lower()
        ctx_is_admin = (role == "admin")
        ctx_is_supervisor = (role == "supervisor")
        ctx_is_vendedor = (role == "vendedor")
        ctx_is_financeiro = (role == "financeiro")

        emp_usuario = emp_fn()
        vendedor_logado = (usuario_logado_fn() or "").strip().upper()

        scope = build_relatorio_campanhas_scope(
            deps,
            role=role,
            emp_usuario=emp_usuario,
            vendedor_logado=vendedor_logado,
            args=request.args,
            flash=flash,
        )
        ano = int(scope["ano"])
        mes = int(scope["mes"])
        emps_sel = scope["emps_sel"]
        vendedores_sel = scope["vendedores_sel"]
        emps_scope = scope["emps_scope"]
        vendedores_por_emp = scope["vendedores_por_emp"]

        ctx = build_relatorio_campanhas_unificado_context(
            deps,
            role=role,
            vendedor_logado=vendedor_logado,
            ano=ano,
            mes=mes,
            emps_scope=emps_scope,
            emps_sel=emps_sel,
            vendedores_sel=vendedores_sel,
            vendedores_por_emp=vendedores_por_emp,
            recalc=str(request.args.get("recalc") or "").strip() in ("1", "true", "True", "sim", "SIM"),
            flash=flash,
            include_combo_itens=False,
            use_cache=True,
        )

        ctx["role"] = role
        ctx["is_admin"] = ctx_is_admin
        ctx["is_supervisor"] = ctx_is_supervisor
        ctx["is_vendedor"] = ctx_is_vendedor
        ctx["is_financeiro"] = ctx_is_financeiro
        try:
            vendedores_scope = sorted({str(v or '').strip().upper() for vs in (vendedores_por_emp or {}).values() for v in (vs or []) if str(v or '').strip()})
        except Exception:
            vendedores_scope = []
        if role == 'vendedor' and vendedor_logado:
            vendedores_scope = [vendedor_logado]
        ctx["vendedores_scope"] = vendedores_scope

        try:
            default_per_page = 100 if role in ("admin", "supervisor") else 50
            page = int(request.args.get("page") or 1)
            per_page = int(request.args.get("per_page") or default_per_page)
            page = max(page, 1)
            per_page = max(25, min(per_page, 500))
        except Exception:
            page, per_page = 1, (100 if role in ("admin", "supervisor") else 50)

        rows = ctx.get("rows") or []
        rows_grouped = _build_group_summaries(rows, ano=ano, mes=mes)

        total_rows = len(rows_grouped)
        start = (page - 1) * per_page
        end = start + per_page
        ctx["rows_grouped"] = rows_grouped
        ctx["rows_grouped_page"] = rows_grouped[start:end]
        ctx["rows_page"] = ctx["rows_grouped_page"]
        ctx["page"] = page
        ctx["per_page"] = per_page
        ctx["total_rows"] = total_rows
        ctx["total_pages"] = (total_rows + per_page - 1) // per_page if per_page else 1
        ctx["resumo"] = _calc_resumo_financeiro(rows)

        from urllib.parse import urlencode
        base_args = request.args.to_dict(flat=False) if request.args else {}

        def _make_url(endpoint: str, **updates):
            d = dict(base_args)
            for k, v in updates.items():
                if v is None:
                    d.pop(k, None)
                else:
                    d[k] = str(v)
            qs = urlencode(d, doseq=True)
            return url_for(endpoint) + (("?" + qs) if qs else "")

        ctx["recalc_url"] = _make_url("relatorio_campanhas", recalc=1, page=1)
        ctx["export_url"] = _make_url("relatorio_campanhas_export_csv", page=None, per_page=None)
        per_page_opts = [50, 100, 200, 500]
        ctx["per_page_opts"] = per_page_opts
        ctx["per_page_urls"] = {opt: _make_url("relatorio_campanhas", per_page=opt, page=1) for opt in per_page_opts}
        ctx["prev_url"] = _make_url("relatorio_campanhas", page=max(1, page - 1))
        ctx["next_url"] = _make_url("relatorio_campanhas", page=min(ctx["total_pages"], page + 1))

        return render_template("relatorio_campanhas.html", ctx=ctx, **ctx)

    def relatorio_campanhas_detalhes():
        """Carrega o detalhe de um vendedor sob demanda para reduzir HTML inicial."""
        red = login_required_fn()
        if red:
            return red

        role = (role_fn() or "").strip().lower()
        emp_usuario = emp_fn()
        vendedor_logado = (usuario_logado_fn() or "").strip().upper()

        scope = build_relatorio_campanhas_scope(
            deps,
            role=role,
            emp_usuario=emp_usuario,
            vendedor_logado=vendedor_logado,
            args=request.args,
            flash=flash,
        )

        ano = int(scope["ano"])
        mes = int(scope["mes"])
        emps_sel = scope["emps_sel"]
        vendedores_sel = scope["vendedores_sel"]
        emps_scope = {str(e) for e in (scope.get("emps_scope") or []) if str(e).strip()}
        vendedores_por_emp = scope.get("vendedores_por_emp") or {}

        emp_req = str(request.args.get("emp") or "").strip()
        vendedor_req = str(request.args.get("vendedor") or "").strip().upper()
        if not emp_req or not vendedor_req:
            return "Parâmetros inválidos.", 400

        if emp_req not in emps_scope:
            return "EMP fora do escopo.", 403

        vendedores_emp = {str(v or '').strip().upper() for v in (vendedores_por_emp.get(emp_req) or []) if str(v or '').strip()}
        if role == 'vendedor':
            vendedores_emp = {vendedor_logado} if vendedor_logado else set()
        if vendedor_req not in vendedores_emp:
            return "Vendedor fora do escopo.", 403

        ctx = build_relatorio_campanhas_unificado_context(
            deps,
            role=role,
            vendedor_logado=vendedor_logado,
            ano=ano,
            mes=mes,
            emps_scope=list(emps_scope),
            emps_sel=emps_sel,
            vendedores_sel=vendedores_sel,
            vendedores_por_emp=vendedores_por_emp,
            recalc=False,
            flash=flash,
            include_combo_itens=False,
            use_cache=True,
        )

        group_detail = _build_group_detail(ctx.get("rows") or [], ano=ano, mes=mes, emp=emp_req, vendedor=vendedor_req)
        return render_template("_relatorio_campanhas_detalhes.html", g=group_detail)

    def relatorio_campanhas_combo_itens():
        """Carrega itens de um combo sob demanda para reduzir payload inicial da página."""
        red = login_required_fn()
        if red:
            return red

        role = (role_fn() or "").strip().lower()
        emp_usuario = emp_fn()
        vendedor_logado = (usuario_logado_fn() or "").strip().upper()

        scope = build_relatorio_campanhas_scope(
            deps,
            role=role,
            emp_usuario=emp_usuario,
            vendedor_logado=vendedor_logado,
            args=request.args,
            flash=flash,
        )

        ano = int(scope["ano"])
        mes = int(scope["mes"])
        emps_scope = {str(e) for e in (scope.get("emps_scope") or []) if str(e).strip()}
        vendedores_por_emp = scope.get("vendedores_por_emp") or {}

        emp_req = str(request.args.get("emp") or "").strip()
        vendedor_req = str(request.args.get("vendedor") or "").strip().upper()
        combo_id = int(request.args.get("combo_id") or 0)

        if not emp_req or not vendedor_req or combo_id <= 0:
            return jsonify({"ok": False, "message": "Parâmetros inválidos."}), 400

        if emp_req not in emps_scope:
            return jsonify({"ok": False, "message": "EMP fora do escopo."}), 403

        vendedores_emp = {str(v or '').strip().upper() for v in (vendedores_por_emp.get(emp_req) or []) if str(v or '').strip()}
        if role == 'vendedor':
            vendedores_emp = {vendedor_logado} if vendedor_logado else set()
        if vendedor_req not in vendedores_emp:
            return jsonify({"ok": False, "message": "Vendedor fora do escopo."}), 403

        payload = load_combo_item_details(
            ano=ano,
            mes=mes,
            emp=emp_req,
            vendedor=vendedor_req,
            combo_id=combo_id,
        )
        return jsonify(payload)

    def relatorio_campanhas_export_csv():
        """Exporta o relatório unificado (mes/ano/filtros) em CSV."""
        red = login_required_fn()
        if red:
            return red

        role = (role_fn() or "").strip().lower()
        emp_usuario = emp_fn()
        vendedor_logado = (usuario_logado_fn() or "").strip().upper()

        scope = build_relatorio_campanhas_scope(
            deps,
            role=role,
            emp_usuario=emp_usuario,
            vendedor_logado=vendedor_logado,
            args=request.args,
            flash=flash,
        )
        ano = int(scope["ano"])
        mes = int(scope["mes"])
        emps_sel = scope["emps_sel"]
        vendedores_sel = scope["vendedores_sel"]
        emps_scope = scope["emps_scope"]
        vendedores_por_emp = scope["vendedores_por_emp"]

        ctx = build_relatorio_campanhas_unificado_context(
            deps,
            role=role,
            vendedor_logado=vendedor_logado,
            ano=ano,
            mes=mes,
            emps_scope=emps_scope,
            emps_sel=emps_sel,
            vendedores_sel=vendedores_sel,
            vendedores_por_emp=vendedores_por_emp,
            recalc=False,
            flash=flash,
            include_combo_itens=True,
            use_cache=True,
        )

        import csv
        from io import StringIO
        sio = StringIO()
        w = csv.writer(sio, delimiter=";")
        w.writerow(["tipo", "competencia", "emp", "vendedor", "titulo", "atingiu_gate", "qtd_base", "qtd_premiada", "valor_recompensa", "status_pagamento", "pago_em"])
        for r in (ctx.get("rows") or []):
            comp = f"{getattr(r, 'competencia_mes', mes):02d}/{getattr(r, 'competencia_ano', ano)}"
            w.writerow([
                getattr(r, "tipo", ""),
                comp,
                getattr(r, "emp", ""),
                getattr(r, "vendedor", ""),
                getattr(r, "titulo", ""),
                "SIM" if getattr(r, "atingiu_gate", None) else "NÃO" if getattr(r, "atingiu_gate", None) is not None else "",
                getattr(r, "qtd_base", "") if getattr(r, "qtd_base", None) is not None else "",
                getattr(r, "qtd_premiada", "") if getattr(r, "qtd_premiada", None) is not None else "",
                getattr(r, "valor_recompensa", 0.0),
                getattr(r, "status_pagamento", "PENDENTE"),
                getattr(r, "pago_em", "") or "",
            ])

        out = sio.getvalue().encode("utf-8")
        filename = f"relatorio_campanhas_{ano}_{mes:02d}.csv"
        return send_file(
            BytesIO(out),
            mimetype="text/csv",
            as_attachment=True,
            download_name=filename,
        )

    app.add_url_rule("/relatorios/campanhas", endpoint="relatorio_campanhas", view_func=relatorio_campanhas, methods=["GET"])
    app.add_url_rule("/relatorios/campanhas/detalhes", endpoint="relatorio_campanhas_detalhes", view_func=relatorio_campanhas_detalhes, methods=["GET"])
    app.add_url_rule("/relatorios/campanhas/combo-itens", endpoint="relatorio_campanhas_combo_itens", view_func=relatorio_campanhas_combo_itens, methods=["GET"])
    app.add_url_rule("/relatorios/campanhas/export.csv", endpoint="relatorio_campanhas_export_csv", view_func=relatorio_campanhas_export_csv, methods=["GET"])
