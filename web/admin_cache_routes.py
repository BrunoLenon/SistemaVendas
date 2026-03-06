from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

from flask import jsonify, request


def register_admin_cache_routes(
    app,
    *,
    login_required_fn: Callable[[], Any],
    admin_required_fn: Callable[[], Any],
) -> None:
    """Registra a rota de refresh de cache do dashboard.

    Refatoração pura: mantém URL, endpoint e payload externo.
    """

    def admin_cache_refresh():
        """Recalcula o cache do dashboard para um EMP/mês/ano (ADMIN).

        Exemplo:
          /admin/cache/refresh?emp=101&ano=2026&mes=1
        """
        red = login_required_fn()
        if red:
            return red
        red2 = admin_required_fn()
        if red2:
            return red2

        emp = (request.args.get("emp") or "").strip()
        ano = int(request.args.get("ano") or datetime.now().year)
        mes = int(request.args.get("mes") or datetime.now().month)

        if not emp:
            return jsonify({"ok": False, "error": "Parâmetro 'emp' é obrigatório."}), 400

        try:
            from dashboard_cache import refresh_dashboard_cache

            info = refresh_dashboard_cache(emp, ano, mes)
            return jsonify({"ok": True, "emp": emp, "ano": ano, "mes": mes, **info})
        except Exception as e:
            try:
                app.logger.exception("Falha ao atualizar cache")
            except Exception:
                pass
            return jsonify({"ok": False, "error": str(e)}), 500

    app.add_url_rule(
        "/admin/cache/refresh",
        endpoint="admin_cache_refresh",
        view_func=admin_cache_refresh,
        methods=["GET"],
    )
