"""WSGI entrypoint (Render-safe) for SistemaVendas.

Objetivo:
- Abrir a porta rapidamente (Render health check / port scan) mesmo que o app Flask demore para importar.
- Importar o Flask app em background e trocar automaticamente para o app real quando estiver pronto.
- Expor endpoints de diagnóstico simples (boot_status / boot_log / threads).

Rotas de diagnóstico (funcionam com 1 ou 2 underscores para compatibilidade):
- /healthz
- /_boot_status  | /__boot_status
- /_boot_log     | /__boot_log
- /_threads      | /__threads
"""

from __future__ import annotations

import importlib
import io
import os
import sys
import threading
import time
import traceback
from typing import Callable, Optional

# -----------------------------
# Boot state / logging
# -----------------------------

_boot_lock = threading.Lock()
_boot_started_at = time.time()
_boot_started = False
_boot_ready = False
_boot_error = False
_boot_phase = "init"  # init | starting | importing | ready | error
_boot_exc: Optional[str] = None
_boot_log: list[str] = []


def _log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    with _boot_lock:
        _boot_log.append(line)
        # evita log infinito em memória
        if len(_boot_log) > 400:
            del _boot_log[:200]
    # também vai pro stdout do Render
    print(line, flush=True)


def _set_phase(phase: str) -> None:
    global _boot_phase
    with _boot_lock:
        _boot_phase = phase


# -----------------------------
# Import / swap
# -----------------------------

_real_wsgi: Optional[Callable] = None


def _import_real_app() -> Callable:
    """Importa o Flask app real.

    Regras:
    - Em repo com pasta 'web/', importamos 'app' depois de inserir web/ no sys.path.
    - Retorna o .wsgi_app do Flask.
    """
    base_dir = os.path.dirname(__file__)
    web_dir = os.path.join(base_dir, "web")

    if os.path.isdir(web_dir) and web_dir not in sys.path:
        sys.path.insert(0, web_dir)
        _log(f"BOOT sys.path += {web_dir}")

    # tenta importar 'app' (web/app.py)
    mod = importlib.import_module("app")

    flask_app = getattr(mod, "app", None)
    if flask_app is None:
        raise RuntimeError("Módulo 'app' foi importado, mas não encontrou variável global 'app' (Flask).")

    # Garante que existe wsgi_app
    wsgi_app = getattr(flask_app, "wsgi_app", None)
    if wsgi_app is None:
        raise RuntimeError("Flask app não possui 'wsgi_app'.")

    return wsgi_app


def _boot_worker() -> None:
    global _boot_ready, _boot_error, _boot_exc, _real_wsgi

    _set_phase("starting")
    _log("BOOT thread started")

    try:
        _set_phase("importing")
        _log("BOOT importing Flask app (app.py)")

        # watchdog simples: se ficar preso, teremos /_threads
        wsgi_app = _import_real_app()

        _real_wsgi = wsgi_app
        _boot_ready = True
        _set_phase("ready")
        _log("BOOT ready (delegating to real app)")

    except Exception:
        _boot_error = True
        _set_phase("error")
        _boot_exc = traceback.format_exc()
        _log("BOOT ERROR during import")
        _log(_boot_exc)


def _start_boot_once() -> None:
    global _boot_started
    with _boot_lock:
        if _boot_started:
            return
        _boot_started = True

    t = threading.Thread(target=_boot_worker, name="sv-boot", daemon=True)
    t.start()


# inicia boot imediatamente ao importar wsgi.py
_start_boot_once()


# -----------------------------
# Tiny WSGI helpers
# -----------------------------


def _plain(status: str, body: str, content_type: str = "text/plain; charset=utf-8"):
    def _app(environ, start_response):
        data = body.encode("utf-8", errors="replace")
        headers = [("Content-Type", content_type), ("Content-Length", str(len(data)))]
        start_response(status, headers)
        return [data]

    return _app


def _html(status: str, html: str):
    return _plain(status, html, content_type="text/html; charset=utf-8")


def _get_path(environ) -> str:
    return (environ.get("PATH_INFO") or "/")


def _boot_status_text() -> str:
    with _boot_lock:
        uptime = int(time.time() - _boot_started_at)
        lines = [
            f"ready={1 if _boot_ready else 0}",
            f"error={1 if _boot_error else 0}",
            f"phase={_boot_phase}",
            f"uptime_s={uptime}",
        ]
    return "\n".join(lines) + "\n"


def _boot_log_text() -> str:
    with _boot_lock:
        tail = _boot_log[-200:]
        exc = _boot_exc
    out = []
    out.append("\n".join(tail))
    if exc:
        out.append("\n--- TRACEBACK ---\n")
        out.append(exc)
    return "\n".join(out).rstrip() + "\n"


def _threads_text() -> str:
    buf = io.StringIO()
    frames = sys._current_frames()
    for th in threading.enumerate():
        buf.write(f"\n=== Thread: {th.name} (ident={th.ident}) ===\n")
        fr = frames.get(th.ident)
        if fr is None:
            buf.write("<no frame>\n")
            continue
        buf.write("".join(traceback.format_stack(fr)))
    return buf.getvalue()


def _warmup_page() -> str:
    # página HTML com auto-refresh/redirect
    return f"""<!doctype html>
<html lang=\"pt-br\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>SistemaVendas iniciando…</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; background:#0b0b0b; color:#eaeaea; margin:0; padding:24px; }}
    a {{ color:#8bd5ff; }}
    .box {{ max-width: 920px; }}
    .muted {{ color:#b0b0b0; }}
    pre {{ background:#151515; padding:16px; border-radius:10px; overflow:auto; }}
  </style>
</head>
<body>
  <div class=\"box\">
    <h2>SistemaVendas está iniciando…</h2>
    <p class=\"muted\">Assim que o boot finalizar, esta página redireciona automaticamente.</p>

    <p>
      Status: <a href=\"/_boot_status\">/_boot_status</a> | <a href=\"/__boot_status\">/__boot_status</a><br>
      Log: <a href=\"/_boot_log\">/_boot_log</a> | <a href=\"/__boot_log\">/__boot_log</a><br>
      Threads: <a href=\"/_threads\">/_threads</a>
    </p>

    <pre id=\"status\">carregando status…</pre>
    <pre id=\"log\" class=\"muted\">carregando logs…</pre>
  </div>

<script>
async function tick() {{
  try {{
    const st = await fetch('/_boot_status', {{cache:'no-store'}}).then(r=>r.text());
    document.getElementById('status').textContent = st.trim();

    if (/ready=1/.test(st)) {{
      window.location.href = '/';
      return;
    }}

    const lg = await fetch('/_boot_log', {{cache:'no-store'}}).then(r=>r.text());
    // mostra só o final para não pesar
    const lines = lg.split(/\n/);
    const tail = lines.slice(-40).join('\n');
    document.getElementById('log').textContent = tail;
  }} catch (e) {{
    document.getElementById('log').textContent = 'Falha ao ler boot status/log: ' + e;
  }}
  setTimeout(tick, 1200);
}}

tick();
</script>
</body>
</html>"""


# -----------------------------
# Public WSGI callable
# -----------------------------


def app(environ, start_response):
    path = _get_path(environ)

    # aliases compatíveis (1 ou 2 underscores)
    if path in ("/healthz", "/_healthz"):
        body = f"ok\nboot_ready={1 if _boot_ready else 0}\nboot_phase={_boot_phase}\n"
        return _plain("200 OK", body)(environ, start_response)

    if path in ("/_boot_status", "/__boot_status"):
        return _plain("200 OK", _boot_status_text())(environ, start_response)

    if path in ("/_boot_log", "/__boot_log"):
        return _plain("200 OK", _boot_log_text())(environ, start_response)

    if path in ("/_threads", "/__threads"):
        return _plain("200 OK", _threads_text())(environ, start_response)

    # Se o app real já está pronto, delega.
    if _real_wsgi is not None and _boot_ready and not _boot_error:
        return _real_wsgi(environ, start_response)

    # Caso tenha dado erro no boot, mostra log/trace no body (para evitar tela em branco)
    if _boot_error:
        return _plain(
            "500 Internal Server Error",
            "BOOT ERROR\n\n" + _boot_status_text() + "\n" + _boot_log_text(),
        )(environ, start_response)

    # Ainda inicializando
    if path == "/":
        return _html("200 OK", _warmup_page())(environ, start_response)

    # Para qualquer outra rota enquanto ainda não pronto, responde warmup simples
    # (ajuda o browser a não ficar só em branco)
    return _html("503 Service Unavailable", _warmup_page())(environ, start_response)
