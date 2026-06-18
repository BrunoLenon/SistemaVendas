from __future__ import annotations

from datetime import datetime, date
from typing import Any, Callable
import threading

from flask import jsonify, request, current_app


def _month_bounds(ano: int, mes: int) -> tuple[date, date]:
    ano = int(ano)
    mes = max(1, min(12, int(mes)))
    start = date(ano, mes, 1)
    end = date(ano + 1, 1, 1) if mes == 12 else date(ano, mes + 1, 1)
    return start, end


def register_admin_cache_routes(
    app,
    *,
    login_required_fn: Callable[[], Any],
    admin_required_fn: Callable[[], Any],
) -> None:
    """Registra rotas de refresh de cache do dashboard."""

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

    def admin_cache_refresh_competencia():
        """Dispara refresh de cache em segundo plano para uma competência.

        Uso seguro após importação:
          /admin/cache/refresh-competencia?ano=2026&mes=6&emp=1001&emp=101

        Se nenhum emp for informado, tenta descobrir EMPs com venda no mês.
        A resposta é imediata para não bloquear o worker HTTP.
        """
        red = login_required_fn()
        if red:
            return red
        red2 = admin_required_fn()
        if red2:
            return red2

        ano = int(request.args.get("ano") or datetime.now().year)
        mes = int(request.args.get("mes") or datetime.now().month)
        emps = [str(e).strip() for e in request.args.getlist("emp") if str(e).strip()]
        logger = current_app.logger

        def _job():
            try:
                from sqlalchemy import func
                from db import SessionLocal, Venda
                from dashboard_cache import refresh_dashboard_cache

                emps_job = list(emps)
                if not emps_job:
                    start, end = _month_bounds(ano, mes)
                    with SessionLocal() as db:
                        emps_job = sorted({
                            str(r[0]).strip()
                            for r in db.query(func.distinct(Venda.emp)).filter(Venda.movimento >= start, Venda.movimento < end).all()
                            if r[0] is not None and str(r[0]).strip()
                        })

                logger.warning("[CACHE_REFRESH_BG] inicio ano=%s mes=%s emps=%s", ano, mes, len(emps_job))
                for emp in emps_job:
                    try:
                        info = refresh_dashboard_cache(emp, ano, mes)
                        logger.warning("[CACHE_REFRESH_BG] ok emp=%s ano=%s mes=%s info=%s", emp, ano, mes, info)
                    except Exception:
                        logger.exception("[CACHE_REFRESH_BG] falha emp=%s ano=%s mes=%s", emp, ano, mes)
                logger.warning("[CACHE_REFRESH_BG] fim ano=%s mes=%s", ano, mes)
            except Exception:
                logger.exception("[CACHE_REFRESH_BG] falha geral ano=%s mes=%s", ano, mes)

        t = threading.Thread(target=_job, name=f"cache-refresh-{ano}-{mes}", daemon=True)
        t.start()
        return jsonify({
            "ok": True,
            "status": "agendado",
            "ano": ano,
            "mes": mes,
            "emps_informadas": emps,
            "msg": "Refresh de cache iniciado em segundo plano. Confira os logs do Render.",
        })

    app.add_url_rule(
        "/admin/cache/refresh",
        endpoint="admin_cache_refresh",
        view_func=admin_cache_refresh,
        methods=["GET"],
    )
    app.add_url_rule(
        "/admin/cache/refresh-competencia",
        endpoint="admin_cache_refresh_competencia",
        view_func=admin_cache_refresh_competencia,
        methods=["GET"],
    )
