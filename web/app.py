from __future__ import annotations

"""Bootstrap enxuto do SistemaVendas.

A aplicação mantém somente os módulos em uso:
- Dashboard leve;
- Bônus Varejo;
- Bônus Atacado (estrutura inicial);
- Itens Parados;
- Itens Parados (Admin);
- Usuários;
- Configurações;
- Promoções QR;
- Troca de senha.

As antigas rotas de campanhas, metas, importações gerais, financeiro, mensagens,
rankings e relatórios não são importadas nem registradas. Portanto, elas não
executam consultas nem participam do ciclo de requisição.
"""

import logging
import os
import sys
import time
from datetime import date, datetime, timedelta

from flask import Flask, flash, redirect, render_template, request, session, url_for
from sqlalchemy import func
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from auth_helpers import (  # noqa: E402
    _admin_required,
    _allowed_emps,
    _emp,
    _login_required,
    _role,
    _usuario_logado,
)
from branding import _get_setting, register_branding  # noqa: E402
from db import ItemParado, SessionLocal, Usuario, UsuarioEmp  # noqa: E402
from errors import register_error_handlers  # noqa: E402
from jinja_filters import register_template_filters  # noqa: E402
from security_utils import audit, rate_limit  # noqa: E402


app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY", "dev")
app.permanent_session_lifetime = timedelta(hours=1)

IS_PROD = bool(os.getenv("RENDER")) or os.getenv("FLASK_ENV") == "production"
STATIC_CACHE_SECONDS = int(os.getenv("STATIC_CACHE_SECONDS", "86400") or 86400)
STATIC_VERSIONED_CACHE_SECONDS = int(
    os.getenv("STATIC_VERSIONED_CACHE_SECONDS", "31536000") or 31536000
)
SLOW_REQUEST_MS = int(os.getenv("SLOW_REQUEST_MS", "1200") or 1200)
MAINTENANCE_CACHE_SECONDS = int(os.getenv("MAINTENANCE_CACHE_SECONDS", "30") or 30)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PROD,
    SEND_FILE_MAX_AGE_DEFAULT=STATIC_CACHE_SECONDS,
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,
)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
register_template_filters(app)
register_branding(app, SessionLocal)


# ---------------------------------------------------------------------------
# Hooks globais mínimos
# ---------------------------------------------------------------------------
@app.before_request
def _mark_request_start():
    request.environ["sv_started_at"] = time.perf_counter()


@app.before_request
def _security_rate_limits():
    if request.path == "/login" and request.method == "POST":
        if not rate_limit("login", limit=8, window_sec=60):
            audit("login_rate_limited")
            return (
                render_template(
                    "login.html",
                    erro="Muitas tentativas. Aguarde 1 minuto e tente novamente.",
                ),
                429,
            )
    return None


@app.before_request
def _idle_timeout():
    if request.endpoint == "static" or not session.get("usuario"):
        return None

    now = datetime.utcnow()
    last = session.get("last_activity")
    if last:
        try:
            if now - datetime.fromisoformat(last) > timedelta(hours=1):
                session.clear()
                flash(
                    "Sua sessão expirou por inatividade. Faça login novamente.",
                    "warning",
                )
                return redirect(url_for("auth.login"))
        except Exception:
            pass

    session["last_activity"] = now.isoformat()
    return None


_maintenance_cache: tuple[float, str] | None = None


def _maintenance_flag() -> str:
    global _maintenance_cache

    env_flag = (os.getenv("MAINTENANCE_MODE") or "").strip().lower()
    if env_flag:
        return env_flag

    now = time.time()
    if _maintenance_cache and _maintenance_cache[0] > now:
        return _maintenance_cache[1]

    flag = "off"
    try:
        with SessionLocal() as db:
            flag = (_get_setting(db, "maintenance_mode", "off") or "off").strip().lower()
    except Exception:
        # Falha aberta: indisponibilidade da configuração não derruba o sistema.
        flag = "off"

    _maintenance_cache = (now + MAINTENANCE_CACHE_SECONDS, flag)
    return flag


@app.before_request
def _maintenance_guard():
    if request.endpoint == "static" or request.path.startswith("/static"):
        return None
    if request.path.startswith(("/healthz", "/login", "/logout")):
        return None

    if _maintenance_flag() in {"1", "true", "on", "yes", "y", "sim"}:
        if (_role() or "") != "admin":
            return render_template("maintenance.html"), 503
    return None


@app.after_request
def _security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; "
        "form-action 'self'; img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "connect-src 'self' https:; font-src 'self' https://cdn.jsdelivr.net data:;",
    )
    if IS_PROD:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )

    if request.endpoint == "static" or request.path.startswith("/static/"):
        max_age = (
            STATIC_VERSIONED_CACHE_SECONDS
            if request.query_string
            else STATIC_CACHE_SECONDS
        )
        response.headers["Cache-Control"] = (
            f"public, max-age={max_age}"
            + (", immutable" if request.query_string else "")
        )

    started_at = request.environ.get("sv_started_at")
    if started_at is not None:
        try:
            elapsed_ms = int((time.perf_counter() - float(started_at)) * 1000)
            response.headers["Server-Timing"] = f"app;dur={elapsed_ms}"
            if request.endpoint != "static" and elapsed_ms >= SLOW_REQUEST_MS:
                app.logger.warning(
                    "SLOW_REQUEST path=%s method=%s status=%s duration_ms=%s",
                    request.path,
                    request.method,
                    response.status_code,
                    elapsed_ms,
                )
        except Exception:
            pass

    return response


# ---------------------------------------------------------------------------
# Helpers usados somente por Itens Parados
# ---------------------------------------------------------------------------
def _mes_ano_from_request() -> tuple[int, int]:
    try:
        mes = int(request.args.get("mes") or datetime.now().month)
    except (TypeError, ValueError):
        mes = datetime.now().month
    try:
        ano = int(request.args.get("ano") or datetime.now().year)
    except (TypeError, ValueError):
        ano = datetime.now().year
    return max(1, min(12, mes)), max(2000, min(2100, ano))


def _periodo_bounds(ano: int, mes: int) -> tuple[date, date]:
    mes = max(1, min(12, int(mes)))
    ano = int(ano)
    inicio = date(ano, mes, 1)
    fim = date(ano + 1, 1, 1) if mes == 12 else date(ano, mes + 1, 1)
    return inicio, fim


def _get_vendedores_db(role: str, emp_usuario: str | None) -> list[str]:
    """Lista vendedores pela base de usuários, sem varrer a tabela de vendas."""
    role = (role or "").strip().lower()
    try:
        with SessionLocal() as db:
            q = db.query(Usuario.username).filter(func.lower(Usuario.role) == "vendedor")

            if role in {"supervisor", "gerente"}:
                emps = [str(emp) for emp in (_allowed_emps() or []) if str(emp).strip()]
                if not emps and emp_usuario:
                    emps = [str(emp_usuario)]
                if not emps:
                    return []
                q = (
                    q.join(UsuarioEmp, Usuario.id == UsuarioEmp.usuario_id)
                    .filter(UsuarioEmp.ativo.is_(True))
                    .filter(UsuarioEmp.emp.in_(emps))
                )
            elif emp_usuario:
                q = (
                    q.join(UsuarioEmp, Usuario.id == UsuarioEmp.usuario_id)
                    .filter(UsuarioEmp.ativo.is_(True))
                    .filter(UsuarioEmp.emp == str(emp_usuario))
                )

            return sorted(
                {
                    str(row[0]).strip().upper()
                    for row in q.distinct().all()
                    if row and row[0] and str(row[0]).strip()
                }
            )
    except Exception:
        app.logger.exception("Falha ao listar vendedores para Itens Parados")
        return []


# ---------------------------------------------------------------------------
# Registro exclusivo dos módulos mantidos
# ---------------------------------------------------------------------------
from blueprints.auth import bp as auth_bp  # noqa: E402
from admin_config_routes import register_admin_config_routes  # noqa: E402
from admin_itens_parados_routes import register_admin_itens_parados_routes  # noqa: E402
from admin_usuarios_routes import register_admin_usuarios_routes  # noqa: E402
from bonus_atacado_routes import register_bonus_atacado_routes  # noqa: E402
from bonus_importados_routes import register_bonus_importados_routes  # noqa: E402
from core_routes import register_core_routes  # noqa: E402
from dashboard_routes import register_dashboard_routes  # noqa: E402
from itens_parados_routes import register_itens_parados_routes  # noqa: E402
from itens_parados_snapshot import register_itens_parados_snapshot_routes  # noqa: E402
from promocoes_qr_routes import register_promocoes_qr_routes  # noqa: E402

app.register_blueprint(auth_bp)

register_core_routes(
    app,
    login_required_fn=_login_required,
    usuario_logado_fn=_usuario_logado,
    session_local_factory=SessionLocal,
    usuario_model=Usuario,
    render_template_fn=render_template,
    check_password_hash_fn=check_password_hash,
    generate_password_hash_fn=generate_password_hash,
)
register_dashboard_routes(app, login_required_fn=_login_required)
register_bonus_importados_routes(app)
register_bonus_atacado_routes(app)
register_itens_parados_snapshot_routes(app)
register_itens_parados_routes(
    app,
    login_required_fn=_login_required,
    mes_ano_from_request_fn=_mes_ano_from_request,
    role_fn=_role,
    emp_fn=_emp,
    allowed_emps_fn=_allowed_emps,
    usuario_logado_fn=_usuario_logado,
    get_vendedores_db_fn=_get_vendedores_db,
    periodo_bounds_fn=_periodo_bounds,
)
register_admin_itens_parados_routes(
    app,
    SessionLocal=SessionLocal,
    ItemParado=ItemParado,
    login_required_fn=_login_required,
    admin_required_fn=_admin_required,
    usuario_logado_fn=_usuario_logado,
)
register_admin_usuarios_routes(
    app,
    login_required_fn=_login_required,
    admin_required_fn=_admin_required,
    usuario_logado_fn=_usuario_logado,
)
register_admin_config_routes(app)
register_promocoes_qr_routes(app)
register_error_handlers(app)
