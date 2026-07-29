from __future__ import annotations

"""Dashboard inicial leve.

Esta versão não consulta vendas, campanhas, metas ou relatórios. Ela funciona
como central de acesso aos poucos módulos mantidos no sistema. Os indicadores
definitivos serão reconstruídos em uma etapa posterior.
"""

from datetime import datetime
from typing import Any, Callable

from flask import render_template, session


def register_dashboard_routes(
    app,
    *,
    login_required_fn: Callable[[], Any],
    **_unused,
) -> None:
    def dashboard():
        red = login_required_fn()
        if red:
            return red

        role = str(session.get("role") or "").strip().lower()
        emp = str(session.get("emp") or "").strip()
        return render_template(
            "dashboard.html",
            role=role,
            emp=emp,
            usuario=session.get("usuario") or session.get("vendedor") or "",
            agora=datetime.now(),
        )

    app.add_url_rule("/dashboard", endpoint="dashboard", view_func=dashboard, methods=["GET"])
