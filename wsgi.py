"""WSGI bootstrap for Render.

This module serves a lightweight boot UI while importing the real Flask app (web/app.py).
It avoids Render port-scan timeouts and surfaces import errors clearly.

Start command (Render):
  gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 2 --timeout 95 --access-logfile - --error-logfile - --log-level info --capture-output wsgi:app
"""
from __future__ import annotations

import os
import sys
import time
import traceback
import threading
import importlib
from typing import Optional, Any, Dict

from flask import Flask, Response, request
from werkzeug.wrappers import Response as WResponse

BOOT: Dict[str, Any] = {
    "ready": False,
    "error": None,
    "phase": "starting",
    "started_at": time.time(),
    "log": [],
}

def _log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    BOOT["log"].append(f"[{ts}] {msg}")
    # keep last 300 lines
    if len(BOOT["log"]) > 300:
        BOOT["log"] = BOOT["log"][-300:]

def _boot_worker() -> None:
    try:
        BOOT["phase"] = "importing"
        _log("BOOT thread started")
        # Ensure 'web' is on sys.path so import app works in Render root
        web_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
        if web_dir not in sys.path:
            sys.path.insert(0, web_dir)
        _log(f"BOOT sys.path[0] = {sys.path[0]}")
        _log("BOOT importing Flask app (app.py)")
        mod = importlib.import_module("app")  # web/app.py as module 'app'
        real_app = getattr(mod, "app", None)
        if real_app is None:
            raise RuntimeError("app.py foi importado mas não encontrei variável global 'app' (Flask instance).")
        BOOT["real_app"] = real_app
        BOOT["ready"] = True
        BOOT["phase"] = "ready"
        _log("BOOT ready: real Flask app carregado")
    except Exception as e:
        BOOT["ready"] = False
        BOOT["phase"] = "error"
        BOOT["error"] = f"{type(e).__name__}: {e}"
        _log("BOOT ERROR during import")
        _log(traceback.format_exc())

_boot_thread = threading.Thread(target=_boot_worker, daemon=True)
_boot_thread.start()

boot_app = Flask("boot_ui")

@boot_app.get("/healthz")
def healthz():
    # Render healthcheck should pass fast even during boot.
    return ("ok", 200)

@boot_app.get("/_boot_status")
@boot_app.get("/__boot_status")
def boot_status():
    uptime = int(time.time() - BOOT["started_at"])
    return Response(f"ready={1 if BOOT['ready'] else 0}\nerror={BOOT['error'] or 0}\nphase={BOOT['phase']}\nuptime_s={uptime}\n", mimetype="text/plain")

@boot_app.get("/_boot_log")
@boot_app.get("/__boot_log")
def boot_log():
    return Response("\n".join(BOOT["log"]) + "\n", mimetype="text/plain")

@boot_app.get("/_threads")
@boot_app.get("/__threads")
def threads_dump():
    import faulthandler, io
    buf = io.StringIO()
    faulthandler.dump_traceback(file=buf, all_threads=True)
    return Response(buf.getvalue(), mimetype="text/plain")

@boot_app.get("/")
def index():
    # If ready, delegate to real app immediately.
    if BOOT.get("ready") and BOOT.get("real_app"):
        real_app = BOOT["real_app"]
        return WResponse.from_app(real_app.wsgi_app, request.environ)

    # Simple HTML (NO regex in JS).
    html = f"""<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SistemaVendas iniciando…</title>
<style>
body{{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,"Liberation Mono","Courier New", monospace;background:#0b0b0f;color:#eaeaf2;margin:0;padding:24px}}
a{{color:#9bd1ff}}
.box{{background:#131321;border:1px solid #2a2a44;border-radius:10px;padding:14px;margin:14px 0;}}
pre{{white-space:pre-wrap;word-break:break-word;margin:0;}}
.small{{opacity:.8;font-size:12px}}
</style>
</head>
<body>
<h2>SistemaVendas está iniciando…</h2>
<div class="small">Assim que o boot finalizar, esta página redireciona automaticamente.</div>
<div class="box">
<div>Status: <a href="/_boot_status">/_boot_status</a> | <a href="/__boot_status">/__boot_status</a></div>
<div>Log: <a href="/_boot_log">/_boot_log</a> | <a href="/__boot_log">/__boot_log</a></div>
<div>Threads: <a href="/_threads">/_threads</a></div>
</div>

<div class="box"><pre id="status">carregando status…</pre></div>
<div class="box"><pre id="log">carregando logs…</pre></div>

<script>
async function pull(){{
  try {{
    const s = await fetch('/_boot_status', {{cache:'no-store'}});
    document.getElementById('status').textContent = await s.text();
  }} catch(e) {{
    document.getElementById('status').textContent = 'erro ao carregar status: ' + e;
  }}
  try {{
    const l = await fetch('/_boot_log', {{cache:'no-store'}});
    document.getElementById('log').textContent = await l.text();
  }} catch(e) {{
    document.getElementById('log').textContent = 'erro ao carregar log: ' + e;
  }}
  // if ready -> reload home to enter the real app
  if(document.getElementById('status').textContent.includes('ready=1')) {{
    location.reload();
  }}
}}
pull();
setInterval(pull, 2000);
</script>
</body>
</html>"""
    return Response(html, mimetype="text/html")

@boot_app.route("/<path:path>", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"])
def passthrough(path: str):
    # When ready, proxy all other requests to real app.
    if BOOT.get("ready") and BOOT.get("real_app"):
        real_app = BOOT["real_app"]
        return WResponse.from_app(real_app.wsgi_app, request.environ)
    return ("SistemaVendas está iniciando… (aguarde)\n", 503)

# Exposed WSGI callable
def app(environ, start_response):
    if BOOT.get("ready") and BOOT.get("real_app"):
        return BOOT["real_app"].wsgi_app(environ, start_response)  # type: ignore
    return boot_app.wsgi_app(environ, start_response)
