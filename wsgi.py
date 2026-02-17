from __future__ import annotations

"""WSGI entrypoint (Render-friendly).

Por que existe este arquivo:
- Em plataformas como Render, o healthcheck/port-scan precisa receber resposta HTTP rápido.
- Imports pesados (ex.: pandas) ou módulos grandes podem atrasar o boot do worker e causar:
  "No open HTTP ports detected" / timeout de /healthz.

Estratégia:
- Expor imediatamente um app mínimo que responde /healthz (e / durante warmup).
- Carregar o app real em background.
- Quando o app real estiver pronto, encaminhar todo tráfego para ele.

Start command recomendado no Render:
  gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 2 --timeout 180 \
    --access-logfile - --error-logfile - --log-level info --capture-output wsgi:app
"""

import os
import sys
import threading
import traceback
from typing import Callable, Optional

from flask import Flask

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")

# Garante que os imports do app encontrem os módulos dentro de web/
if WEB_DIR not in sys.path:
    sys.path.insert(0, WEB_DIR)

_boot = Flask("bootstrap")


@_boot.route("/healthz", methods=["GET", "HEAD"])
def _healthz():
    return ("OK", 200)


@_boot.route("/", methods=["GET", "HEAD"])
def _root_warmup():
    # Durante warmup, retorna 200 no / (alguns port-scanners usam /)
    return ("OK", 200)


_real_wsgi: Optional[Callable] = None
_real_err: Optional[str] = None
_real_loaded = threading.Event()


def _load_real_app() -> None:
    global _real_wsgi, _real_err
    try:
        # Import do app real (pode ser pesado)
        from app import app as real_app  # type: ignore

        _real_wsgi = real_app.wsgi_app
    except Exception:
        _real_err = traceback.format_exc()
    finally:
        _real_loaded.set()


# Carrega em background para não bloquear o primeiro response do healthcheck
threading.Thread(target=_load_real_app, daemon=True).start()


class _AppProxy:
    """Encaminha requests para o app real quando pronto."""

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO") or "/"

        # /healthz sempre ultra-leve
        if path == "/healthz" or path == "/favicon.ico":
            return _boot.wsgi_app(environ, start_response)

        # Enquanto carrega, responda / rapidamente para satisfazer o port-scan
        if _real_wsgi is None:
            if path == "/":
                return _boot.wsgi_app(environ, start_response)

            if _real_err:
                # Loga o traceback no stdout (Render logs) e responde sem expor detalhes
                try:
                    print(_real_err)
                except Exception:
                    pass
                body = b"Erro ao iniciar a aplicacao. Verifique os logs do Render."
                start_response(
                    "500 INTERNAL SERVER ERROR",
                    [
                        ("Content-Type", "text/plain; charset=utf-8"),
                        ("Content-Length", str(len(body))),
                    ],
                )
                return [body]

            body = b"Warming up..."
            start_response(
                "503 SERVICE UNAVAILABLE",
                [
                    ("Content-Type", "text/plain; charset=utf-8"),
                    ("Content-Length", str(len(body))),
                    ("Retry-After", "5"),
                ],
            )
            return [body]

        # App real pronto
        return _real_wsgi(environ, start_response)


# Gunicorn vai expor esta variável
app = _AppProxy()
