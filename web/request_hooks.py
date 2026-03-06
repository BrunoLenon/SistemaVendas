import os
import logging
from datetime import datetime, timedelta

from flask import (
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


def register_request_hooks(
    app,
    *,
    audit,
    rate_limit,
    SessionLocal,
    get_setting,
    role_fn,
    find_pending_blocking_message,
    IS_PROD: bool,
):
    """Registra hooks globais (before_request / after_request) no app Flask.

    Regras:
    - Refatoração pura: mantém o mesmo comportamento externo.
    - Ordem de registro importa (Flask executa before_request na ordem registrada).
    """

    # --------------------------
    # Segurança (rate limits) + headers
    # --------------------------
    @app.before_request
    def _security_rate_limits():
        # limita tentativas de login (POST)
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

        # limita endpoints de relatórios (evita abuso e picos)
        if request.path.startswith("/relatorios/"):
            if not rate_limit("reports", limit=120, window_sec=60):
                audit("reports_rate_limited", path=request.path)
                return ("Muitas requisições. Aguarde um pouco e tente novamente.", 429)

    @app.after_request
    def _security_headers(resp):
        # headers de segurança básicos
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )

        # CSP simples (compatível com Bootstrap CDN + inline styles/scripts existentes)
        csp = (
            "default-src 'self'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "img-src 'self' data: https:; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "connect-src 'self' https:; "
            "font-src 'self' https://cdn.jsdelivr.net data:;"
        )
        resp.headers.setdefault("Content-Security-Policy", csp)

        # HSTS somente em produção
        if IS_PROD:
            resp.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return resp

    # --------------------------
    # Sessão: expiração por inatividade
    # --------------------------
    @app.before_request
    def _idle_timeout():
        # Ignora arquivos estáticos
        if request.endpoint == "static":
            return None
        # Se não está logado, segue normal
        if not session.get("usuario"):
            return None
        now = datetime.utcnow()
        last = session.get("last_activity")
        if last:
            try:
                last_dt = datetime.fromisoformat(last)
                if now - last_dt > timedelta(hours=1):
                    session.clear()
                    flash(
                        "Sua sessão expirou por inatividade. Faça login novamente.",
                        "warning",
                    )
                    return redirect(url_for("auth.login"))
            except Exception:
                # Se estiver inválido, reseta
                pass
        session["last_activity"] = now.isoformat()
        return None

    # --------------------------
    # Modo manutenção (admin bypass)
    # --------------------------
    @app.before_request
    def _maintenance_guard():
        # Permite assets e healthz
        if request.endpoint == "static" or request.path.startswith("/static"):
            return None
        if request.path.startswith("/healthz"):
            return None

        # Sempre permitir login/logout
        if request.path.startswith("/login") or request.path.startswith("/logout"):
            return None

        # Flag via ENV tem prioridade; senão, usa AppSetting
        flag = (os.getenv("MAINTENANCE_MODE") or "").strip().lower()

        if not flag:
            try:
                with SessionLocal() as db:
                    flag = (get_setting(db, "maintenance_mode", "off") or "off").strip().lower()
            except Exception:
                # Se falhar leitura, não bloqueia (fail-open)
                return None

        if flag in ("1", "true", "on", "yes", "y"):
            r = (role_fn() or "")
            if r != "admin":
                return render_template("maintenance.html"), 503

        return None

    # --------------------------
    # Guard de mensagens bloqueantes
    # --------------------------
    @app.before_request
    def _mensagens_bloqueantes_guard():
        # Ignora assets e healthz
        if request.endpoint == "static" or request.path.startswith("/static"):
            return None
        if request.path.startswith("/healthz"):
            return None

        # Sem login, não bloqueia
        if not session.get("usuario"):
            return None

        # Permitir rotas de auth e rotas de mensagens (para o usuário conseguir ler)
        if (
            request.path.startswith("/login")
            or request.path.startswith("/logout")
            or request.path.startswith("/senha")
        ):
            return None
        if request.path.startswith("/mensagens"):
            return None

        try:
            with SessionLocal() as db:
                pendente = find_pending_blocking_message(db)
                if pendente:
                    # salva a rota desejada para retornar depois de marcar como lida
                    if request.method == "GET":
                        session["after_block_redirect"] = (
                            request.full_path if request.query_string else request.path
                        )
                    else:
                        session["after_block_redirect"] = (
                            request.referrer or url_for("dashboard")
                        )
                    return redirect(
                        url_for("mensagens_bloqueio", mensagem_id=pendente.id)
                    )
        except Exception as e:
            # nunca derrubar o app por causa do módulo de mensagens
            logging.exception("Erro no guard de mensagens bloqueantes: %s", e)

        return None
