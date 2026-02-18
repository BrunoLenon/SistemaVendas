"""WSGI entrypoint PORT-SAFE for Render.

Motivo:
- O Render faz um *port scan* e um *health check* muito cedo.
- Se o import do seu app for lento (pandas/pyarrow) ou travar, o Gunicorn pode
  estar "listening" mas nenhum worker responde a HTTP ainda, e o Render acusa:
  "No open HTTP ports detected".

O que este arquivo faz:
- Sobe um WSGI bem leve que responde imediatamente:
  - GET/HEAD /healthz -> 200 OK
  - /__boot_status -> status do boot (ready/error/phase)
  - /__threads -> dump de stack das threads (debug quando travar)
- Em background, ele importa o app real (web/app.py -> app).
- Quando carregar, ele passa a proxyar tudo para o app real.

Se o app real falhar no import, ele continua servindo a tela de warmup.
Para expor o traceback publicamente (temporário), set:
  BOOT_ERROR_PUBLIC=1
"""

from __future__ import annotations

import os
import sys
import time
import threading
import traceback
import sys as _sys
from typing import Optional, Callable

from flask import Flask, Response

# --- bootstrap web app (fast) ---
_bootstrap = Flask("bootstrap")
_started_at = time.time()
_real_wsgi: Optional[Callable] = None
_boot_error: Optional[str] = None
_boot_phase: str = "starting"
_boot_log: list[str] = []
_BOOT_LOG_MAX = 80


def _log(msg: str) -> None:
    global _boot_log
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    line = f"[BOOT {stamp}] {msg}"
    print(line)
    _boot_log.append(line)
    if len(_boot_log) > _BOOT_LOG_MAX:
        _boot_log = _boot_log[-_BOOT_LOG_MAX:]


@_bootstrap.route("/healthz", methods=["GET", "HEAD"])  # Render health check
def healthz():
    # Retorna 200 sempre para o deploy não falhar durante o warmup.
    return "OK", 200


@_bootstrap.route("/__boot_status", methods=["GET", "HEAD"])
def boot_status():
    ready = _real_wsgi is not None
    err = _boot_error is not None
    last = _boot_log[-1] if _boot_log else ""
    body = (
        f"ready={int(ready)}\n"
        f"error={int(err)}\n"
        f"phase={_boot_phase}\n"
        f"uptime_s={int(time.time() - _started_at)}\n"
        f"last={last}\n"
    )
    return Response(body, mimetype="text/plain")


@_bootstrap.route("/__boot_log", methods=["GET", "HEAD"])
def boot_log():
    return Response("\n".join(_boot_log) + "\n", mimetype="text/plain")


@_bootstrap.route("/__boot_error", methods=["GET", "HEAD"])
def boot_error():
    if os.getenv("BOOT_ERROR_PUBLIC") != "1":
        return Response("disabled", status=403, mimetype="text/plain")
    if _boot_error:
        return Response(_boot_error, status=500, mimetype="text/plain")
    return Response("no error", mimetype="text/plain")


@_bootstrap.route("/__threads", methods=["GET", "HEAD"])
def threads_dump():
    """Dump stacks de todas as threads (útil quando ready=0 por muito tempo)."""
    frames = _sys._current_frames()  # noqa: SLF001
    out = []
    for th in threading.enumerate():
        out.append(f"\n=== thread: {th.name} (ident={th.ident}) daemon={th.daemon} ===")
        fr = frames.get(th.ident)
        if fr is None:
            out.append("<no frame>")
            continue
        out.extend(traceback.format_stack(fr))
    return Response("\n".join(out), mimetype="text/plain")


@_bootstrap.route("/", defaults={"path": ""}, methods=[
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
])
@_bootstrap.route("/<path:path>", methods=[
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
])
def warmup(path: str):
    # Tela amigável enquanto o app real carrega.
    msg = (
        "SistemaVendas está iniciando…\n\n"
        "Status: /__boot_status\n"
        "Log:    /__boot_log\n"
    )
    return Response(msg, mimetype="text/plain")


def _load_real_app() -> None:
    """Importa o app real sem bloquear o health/port check do Render."""
    global _real_wsgi, _boot_error, _boot_phase

    try:
        _boot_phase = "importing"
        _log("iniciando import do app real")

        root = os.path.dirname(os.path.abspath(__file__))
        web_dir = os.path.join(root, "web")
        if web_dir not in sys.path:
            sys.path.insert(0, web_dir)

        import importlib

        real_module = importlib.import_module("app")
        flask_app = getattr(real_module, "app", None)
        if flask_app is None:
            raise RuntimeError("Não encontrei 'app' em web/app.py (esperado: app = Flask(...))")

        _real_wsgi = flask_app.wsgi_app
        _boot_phase = "ready"
        _log("app real carregado com sucesso")

    except Exception:
        _boot_error = traceback.format_exc()
        _boot_phase = "error"
        _log("ERRO ao carregar app real")
        _log(_boot_error)


# Start background import ASAP.
threading.Thread(target=_load_real_app, daemon=True, name="boot-loader").start()


def app(environ, start_response):
    """WSGI callable for Gunicorn: wsgi:app"""
    if _real_wsgi is not None:
        return _real_wsgi(environ, start_response)
    return _bootstrap.wsgi_app(environ, start_response)
