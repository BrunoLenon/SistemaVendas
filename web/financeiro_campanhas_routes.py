# -*- coding: utf-8 -*-
"""Rotas do Financeiro (Campanhas / Fechamento V2).

Extraído do web/app.py como refatoração pura (sem alterar comportamento externo).
- Mantém os mesmos paths e os mesmos nomes de endpoint usados em url_for(...)

Observação:
- Registramos explicitamente o 'endpoint' para garantir backward compatibility.
"""

from __future__ import annotations

from flask import flash, redirect, render_template, request, url_for

from auth_helpers import financeiro_required, login_required
from db import CampanhaV2Master, CampanhaV2Resultado, SessionLocal


def register_financeiro_campanhas_routes(app) -> None:
    """Registra rotas do Financeiro no app Flask."""

    def financeiro_campanhas_v2():
        # por enquanto, redireciona para o fechamento (mesma visão)
        return redirect(url_for("financeiro_fechamento_v2"))

    app.add_url_rule(
        "/financeiro/campanhas_v2",
        endpoint="financeiro_campanhas_v2",
        view_func=financeiro_required(financeiro_campanhas_v2),
        methods=["GET"],
    )

    def financeiro_fechamento_v2():
        from datetime import date

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
        view_func=financeiro_required(financeiro_fechamento_v2),
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
        view_func=financeiro_required(financeiro_fechamento_v2_status),
        methods=["POST"],
    )

    def financeiro_campanhas():
        """Endpoint compatível com o menu lateral (sidebar).

        Caso a implementação atual esteja em /financeiro/campanhas_v2, redireciona para lá.
        """

        try:
            return redirect(url_for("financeiro_campanhas_v2"))
        except Exception:
            # fallback: se não existir v2, renderiza página simples informativa
            return redirect("/financeiro/campanhas_v2")

    app.add_url_rule(
        "/financeiro/campanhas",
        endpoint="financeiro_campanhas",
        view_func=login_required(financeiro_campanhas),
        methods=["GET"],
    )
