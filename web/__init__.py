from __future__ import annotations

import os
import sys
from pathlib import Path

from flask import Flask


def _ensure_sys_path() -> None:
    """Keep compatibility with legacy imports like `from db import ...` or `from services...`"""
    root_dir = Path(__file__).resolve().parent.parent  # project root (..../src)
    web_dir = Path(__file__).resolve().parent          # .../web
    # Insert at front so it wins over site-packages similarly to the old bootstrap.
    for p in (str(root_dir), str(web_dir)):
        if p not in sys.path:
            sys.path.insert(0, p)


def create_app() -> Flask:
    """App factory (SaaS-style) that reuses the legacy app and guarantees blueprint registration.

    This is intentionally minimal/safe: it does NOT change routes/logic; it only ensures the app
    boots reliably and that the `auth` blueprint exists so url_for('auth.login') works.
    """
    _ensure_sys_path()

    # Import legacy Flask app (all existing routes/handlers live there)
    import web.app as legacy_app_module  # noqa: WPS433

    app: Flask = legacy_app_module.app

    # Ensure blueprints are registered (idempotent).
    # Some patches may have replaced __init__.py and accidentally stopped registering auth.
    try:
        from web.blueprints.auth import bp as auth_bp  # noqa: WPS433
        if "auth" not in app.blueprints:
            app.register_blueprint(auth_bp)
    except Exception as exc:  # pragma: no cover
        # If auth blueprint import fails, we still want the process to start for debugging.
        app.logger.exception("Falha ao registrar blueprint auth: %s", exc)

    # Keep compatibility with existing wrapper blueprints (admin/mensagens), if present.
    for name, modpath in (
        ("admin", "web.blueprints.admin"),
        ("mensagens", "web.blueprints.mensagens"),
    ):
        try:
            module = __import__(modpath, fromlist=["bp"])
            bp = getattr(module, "bp", None)
            if bp is not None and name not in app.blueprints:
                app.register_blueprint(bp)
        except Exception:
            # Optional: these may not exist in older bases. Don't block boot.
            pass

    return app
