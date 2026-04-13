# -*- coding: utf-8 -*-
"""Rotas do Financeiro (Campanhas / Fechamento V2).

Evolução segura:
- mantém os endpoints legados /financeiro/campanhas_v2 e /financeiro/fechamento_v2
- passa a implementar /financeiro/campanhas como cockpit financeiro do relatório unificado
- status do Financeiro é controlado em `financeiro_pagamentos`, evitando alterar cada
  tabela de resultado neste primeiro passo.
"""

from __future__ import annotations

from datetime import date
from urllib.parse import urlencode, parse_qs
from typing import Any, Callable

from flask import flash, redirect, render_template, request, url_for
from werkzeug.datastructures import MultiDict

from db import CampanhaV2Master, CampanhaV2Resultado, SessionLocal
from services.campanhas_service import build_relatorio_campanhas_scope
from services.financeiro_service import (
    apply_bulk_status_from_relatorio,
    build_financeiro_campanhas_context,
    ensure_pagamento_from_row,
)


def register_financeiro_campanhas_routes(
    app,
    *,
    deps: Any,
    login_required_fn: Callable[[], Any],
    financeiro_required_fn: Callable[[Callable[..., Any]], Callable[..., Any]],
    role_fn: Callable[[], str | None],
    emp_fn: Callable[[], str | None],
    usuario_logado_fn: Callable[[], str | None],
) -> None:
    """Registra rotas do Financeiro no app Flask."""

    def _redirect_back(default_endpoint: str = "financeiro_campanhas"):
        qs = (request.form.get("return_qs") or "").strip()
        base = url_for(default_endpoint)
        return redirect(f"{base}?{qs}" if qs else base)

    def _args_from_qs(qs: str):
        data = parse_qs(qs or '', keep_blank_values=True)
        args = MultiDict()
        for key, values in data.items():
            for value in values:
                args.add(key, value)
        return args

    def financeiro_campanhas_v2():
        # por enquanto, redireciona para o fechamento (mesma visão legada)
        return redirect(url_for("financeiro_fechamento_v2"))

    app.add_url_rule(
        "/financeiro/campanhas_v2",
        endpoint="financeiro_campanhas_v2",
        view_func=financeiro_required_fn(financeiro_campanhas_v2),
        methods=["GET"],
    )

    def financeiro_fechamento_v2():
        ano = int(request.args.get("ano") or date.today().year)
        mes = int(request.args.get("mes") or date.today().month)
        db = SessionLocal()
        try:
            rows = (
                db.query(CampanhaV2Resultado, CampanhaV2Master.titulo)
                .join(CampanhaV2Master, CampanhaV2Master.id == CampanhaV2Resultado.campanha_id)
                .filter(CampanhaV2Resultado.ano == ano, CampanhaV2Resultado.mes == mes)
                .order_by(
                    CampanhaV2Resultado.status_financeiro.asc(),
                    CampanhaV2Resultado.recompensa.desc(),
                )
                .all()
            )
            resultados = []
            for r, titulo in rows:
                resultados.append(
                    {
                        "id": r.id,
                        "campanha_titulo": titulo,
                        "emp": r.emp,
                        "vendedor": r.vendedor,
                        "valor_base": r.valor_base,
                        "recompensa": r.recompensa,
                        "status_financeiro": r.status_financeiro,
                    }
                )
            return render_template(
                "financeiro_fechamento_v2.html", resultados=resultados, ano=ano, mes=mes
            )
        finally:
            db.close()

    app.add_url_rule(
        "/financeiro/fechamento_v2",
        endpoint="financeiro_fechamento_v2",
        view_func=financeiro_required_fn(financeiro_fechamento_v2),
        methods=["GET"],
    )

    def financeiro_fechamento_v2_status():
        rid = int(request.form.get("resultado_id") or 0)
        status = (request.form.get("status_financeiro") or "PENDENTE").strip().upper()
        if status not in ("PENDENTE", "A_PAGAR", "PAGO"):
            status = "PENDENTE"
        db = SessionLocal()
        try:
            r = db.query(CampanhaV2Resultado).filter(CampanhaV2Resultado.id == rid).first()
            if not r:
                flash("Resultado não encontrado.", "danger")
                return redirect(url_for("financeiro_fechamento_v2"))
            r.status_financeiro = status
            db.commit()
            flash("Status atualizado.", "success")
        except Exception as e:
            db.rollback()
            flash(f"Erro ao atualizar status: {e}", "danger")
        finally:
            db.close()
        return redirect(url_for("financeiro_fechamento_v2"))

    app.add_url_rule(
        "/financeiro/fechamento_v2/status",
        endpoint="financeiro_fechamento_v2_status",
        view_func=financeiro_required_fn(financeiro_fechamento_v2_status),
        methods=["POST"],
    )

    def financeiro_campanhas():
        red = login_required_fn()
        if red:
            return red

        role = (role_fn() or "").strip().lower()
        if role not in ("financeiro", "admin"):
            flash("Acesso restrito ao Financeiro.", "warning")
            return redirect(url_for("dashboard"))

        emp_usuario = emp_fn()
        vendedor_logado = (usuario_logado_fn() or "").strip().upper()

        if request.method == "POST":
            novo_status = (request.form.get("novo_status") or "PENDENTE").strip().upper()
            if novo_status not in ("PENDENTE", "A_PAGAR", "PAGO"):
                novo_status = "PENDENTE"

            batch_scope = (request.form.get("batch_scope") or "").strip().lower()

            try:
                db = SessionLocal()
                try:
                    if batch_scope:
                        args_post = _args_from_qs(request.form.get("return_qs") or "")
                        scope_post = build_relatorio_campanhas_scope(
                            deps,
                            role=role,
                            emp_usuario=emp_usuario,
                            vendedor_logado=vendedor_logado,
                            args=args_post,
                            flash=flash,
                        )
                        ctx_post = build_financeiro_campanhas_context(
                            deps,
                            role=role,
                            vendedor_logado=vendedor_logado,
                            ano=int(scope_post["ano"]),
                            mes=int(scope_post["mes"]),
                            emps_scope=scope_post["emps_scope"],
                            emps_sel=scope_post["emps_sel"],
                            vendedores_sel=scope_post["vendedores_sel"],
                            vendedores_por_emp=scope_post["vendedores_por_emp"],
                            recalc=False,
                            status_sel=(args_post.get("status") or "").strip(),
                            tipo_sel=(args_post.get("tipo") or "").strip(),
                            flash=flash,
                        )
                        changed, total = apply_bulk_status_from_relatorio(
                            db,
                            ano=int(scope_post["ano"]),
                            mes=int(scope_post["mes"]),
                            relatorio=ctx_post.get("relatorio") or [],
                            novo_status=novo_status,
                            actor=vendedor_logado,
                            emp=request.form.get("emp_scope") or None,
                            vendedor=request.form.get("vendedor_scope") or None,
                        )
                        db.commit()
                        if total <= 0:
                            flash("Nenhuma campanha encontrada para a ação em lote nos filtros atuais.", "warning")
                        elif changed <= 0:
                            flash(f"Nenhuma linha precisou ser alterada para {novo_status}.", "info")
                        else:
                            alvo = (
                                f"loja EMP {request.form.get('emp_scope')}" if batch_scope == "emp"
                                else (f"vendedor {request.form.get('vendedor_scope')}" if batch_scope == "vendedor" else "filtros atuais")
                            )
                            flash(f"{changed} linha(s) atualizadas para {novo_status} em {alvo}.", "success")
                    else:
                        ensure_pagamento_from_row(
                            db,
                            ano=int(request.form.get("ano") or date.today().year),
                            mes=int(request.form.get("mes") or date.today().month),
                            tipo=request.form.get("tipo") or "",
                            origem_id=int(request.form.get("origem_id") or 0),
                            emp=request.form.get("emp") or 0,
                            vendedor=request.form.get("vendedor") or "",
                            campanha_nome=request.form.get("titulo") or "",
                            valor_premio=float(request.form.get("valor") or 0),
                            actor=vendedor_logado,
                            novo_status=novo_status,
                        )
                        db.commit()
                        flash(f"Status atualizado para {novo_status}.", "success")
                except Exception as e:
                    db.rollback()
                    flash(f"Erro ao atualizar status financeiro: {e}", "danger")
                finally:
                    db.close()
            except Exception as e:
                flash(f"Erro ao abrir sessão do financeiro: {e}", "danger")
            return _redirect_back()

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

        ctx = build_financeiro_campanhas_context(
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
            status_sel=(request.args.get("status") or "").strip(),
            tipo_sel=(request.args.get("tipo") or "").strip(),
            flash=flash,
        )
        ctx["role"] = role
        ctx["return_qs"] = urlencode(request.args, doseq=True)
        return render_template("financeiro_campanhas.html", **ctx)

    app.add_url_rule(
        "/financeiro/campanhas",
        endpoint="financeiro_campanhas",
        view_func=financeiro_campanhas,
        methods=["GET", "POST"],
    )
