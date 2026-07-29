from __future__ import annotations

"""Estrutura inicial do módulo Bônus Atacado.

A página já respeita autenticação e está pronta para receber o importador quando
a planilha definitiva do atacado for concluída. Nenhuma tabela ou cálculo é
criado nesta etapa.
"""

from flask import render_template, session

from auth_helpers import _login_required


def register_bonus_atacado_routes(app) -> None:
    def bonus_atacado():
        red = _login_required()
        if red:
            return red
        return render_template(
            "bonus_atacado.html",
            role=str(session.get("role") or "").strip().lower(),
        )

    app.add_url_rule(
        "/bonus-atacado",
        endpoint="bonus_atacado",
        view_func=bonus_atacado,
        methods=["GET"],
    )
