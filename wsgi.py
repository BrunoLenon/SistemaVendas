import os
import sys
import threading
import traceback
import importlib

# -----------------------------------------------------------------------------
# Render-safe WSGI bootstrap
# - Responde imediatamente em /healthz e / para o port-scan/healthcheck do Render.
# - Carrega o app real (web/app.py -> variavel 'app') em background.
# - Evita travar o boot por imports pesados no startup.
# -----------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")

# Garante que `import app` encontre SistemaVendas/web/app.py
if WEB_DIR not in sys.path:
    sys.path.insert(0, WEB_DIR)

_real_app = None
_real_app_error = None
_loader_started = False
_loader_lock = threading.Lock()


def _load_real_app():
    global _real_app, _real_app_error
    try:
        mod = importlib.import_module("app")
        flask_app = getattr(mod, "app", None)
        if flask_app is None:
            raise RuntimeError("Nao encontrei a variavel 'app' dentro de web/app.py")
        _real_app = flask_app
    except Exception:
        _real_app_error = traceback.format_exc()


def _start_loader():
    global _loader_started
    if _loader_started:
        return
    with _loader_lock:
        if _loader_started:
            return
        _loader_started = True
        t = threading.Thread(target=_load_real_app, daemon=True)
        t.start()


def _respond(start_response, status: str, body: bytes, headers=None):
    headers = headers or []
    if not any(h[0].lower() == "content-type" for h in headers):
        headers.append(("Content-Type", "text/plain; charset=utf-8"))
    headers.append(("Content-Length", str(len(body))))
    start_response(status, headers)
    return [body]


def _warmup_html() -> bytes:
    return (
        "<!doctype html>\n"
        "<html lang='pt-br'>\n"
        "<head>\n"
        "  <meta charset='utf-8'/>\n"
        "  <meta name='viewport' content='width=device-width, initial-scale=1'/>\n"
        "  <meta http-equiv='refresh' content='2;url=/login'/>\n"
        "  <title>SistemaVendas - Iniciando</title>\n"
        "  <style>body{font-family:system-ui,Segoe UI,Arial;margin:40px} .box{max-width:760px} code{background:#f2f2f2;padding:2px 6px;border-radius:6px}</style>\n"
        "</head>\n"
        "<body>\n"
        "  <div class='box'>\n"
        "    <h2>SistemaVendas está iniciando…</h2>\n"
        "    <p>O servidor já está no ar. Estou carregando o aplicativo. Em instantes você será redirecionado para <code>/login</code>.</p>\n"
        "    <p>Se não redirecionar automaticamente, aperte F5.</p>\n"
        "  </div>\n"
        "</body>\n"
        "</html>\n"
    ).encode("utf-8")


# WSGI callable
def app(environ, start_response):
    path = environ.get("PATH_INFO") or "/"

    # Healthcheck do Render
    if path == "/healthz":
        return _respond(start_response, "200 OK", b"OK")

    # Inicia loader em background sem bloquear
    _start_loader()

    # Se o app real carregou, delega
    if _real_app is not None:
        return _real_app(environ, start_response)

    # Se o app real deu erro, exponha o traceback (facilita corrigir)
    if _real_app_error:
        body = ("ERRO AO INICIAR APLICACAO\n\n" + _real_app_error).encode("utf-8")
        return _respond(start_response, "500 Internal Server Error", body)

    # Enquanto carrega, responda rapido para o port-scan do Render
    if path == "/" or path == "":
        body = _warmup_html()
        return _respond(
            start_response,
            "200 OK",
            body,
            headers=[("Content-Type", "text/html; charset=utf-8")],
        )

    return _respond(
        start_response,
        "503 Service Unavailable",
        b"Warming up...",
        headers=[("Retry-After", "3")],
    )
