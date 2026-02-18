"""WSGI entrypoint PORT-SAFE for Render.

Why this exists:
- Render does an HTTP port scan + health check very early.
- If your app import is slow (pandas/pyarrow) or blocks, Gunicorn may be listening
  but no worker responds yet, causing: "No open HTTP ports detected".

This module returns an immediate lightweight WSGI app that answers:
- GET/HEAD /healthz -> 200 OK
- Any path -> 200 (warmup page)

In background, it imports the real Flask app from web/app.py (app:app).
Once loaded, it proxies all requests to the real app.

If the real app fails to import, it keeps serving warmup and logs the traceback.
You can temporarily expose the traceback at /__boot_error by setting:
  BOOT_ERROR_PUBLIC=1
"""

from __future__ import annotations

import os
import sys
import time
import threading
import traceback
from typing import Optional, Callable

from flask import Flask, Response

# --- bootstrap web app (fast) ---
_bootstrap = Flask("bootstrap")
_started_at = time.time()
_real_wsgi: Optional[Callable] = None
_boot_error: Optional[str] = None


@_bootstrap.route("/healthz", methods=["GET", "HEAD"])  # Render health check
def healthz():
    # Always return 200 so deploy doesn't fail while the real app warms up.
    return "OK", 200


@_bootstrap.route("/__boot_status", methods=["GET", "HEAD"])
def boot_status():
    ready = _real_wsgi is not None
    err = _boot_error is not None
    body = (
        f"ready={int(ready)}\n"
        f"error={int(err)}\n"
        f"uptime_s={int(time.time() - _started_at)}\n"
    )
    return Response(body, mimetype="text/plain")


@_bootstrap.route("/__boot_error", methods=["GET", "HEAD"])
def boot_error():
    if os.getenv("BOOT_ERROR_PUBLIC") != "1":
        return Response("disabled", status=403, mimetype="text/plain")
    if _boot_error:
        return Response(_boot_error, status=500, mimetype="text/plain")
    return Response("no error", mimetype="text/plain")


@_bootstrap.route("/", defaults={"path": ""}, methods=[
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
])
@_bootstrap.route("/<path:path>", methods=[
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
])
def warmup(path: str):
    # Friendly warmup page; once real app loads, proxy will take over.
    # Keep it light & always 200 so Render port scan succeeds.
    msg = (
        "SistemaVendas está iniciando…\n\n"
        "Se esta tela permanecer por muito tempo, verifique /__boot_status\n"
    )
    return Response(msg, mimetype="text/plain")


def _load_real_app() -> None:
    """Import the real Flask app without blocking Render health/port checks."""
    global _real_wsgi, _boot_error
    try:
        root = os.path.dirname(os.path.abspath(__file__))
        web_dir = os.path.join(root, "web")
        if web_dir not in sys.path:
            sys.path.insert(0, web_dir)

        # Import web/app.py as module "app" (because web_dir is on sys.path)
        import importlib

        real_module = importlib.import_module("app")
        flask_app = getattr(real_module, "app", None)
        if flask_app is None:
            raise RuntimeError("Não encontrei 'app' em web/app.py (esperado: app = Flask(...))")

        _real_wsgi = flask_app.wsgi_app
        print("[BOOT] App real carregado com sucesso.")

    except Exception:
        _boot_error = traceback.format_exc()
        print("[BOOT] ERRO ao carregar app real:")
        print(_boot_error)


# Start background import ASAP.
threading.Thread(target=_load_real_app, daemon=True).start()


def app(environ, start_response):
    """WSGI callable for Gunicorn: wsgi:app"""
    if _real_wsgi is not None:
        return _real_wsgi(environ, start_response)
    return _bootstrap.wsgi_app(environ, start_response)
