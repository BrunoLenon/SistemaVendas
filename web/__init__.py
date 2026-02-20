from __future__ import annotations

"""Application factory (bootstrap) para o SistemaVendas/Veipeças.

Objetivo: manter o boot estável no Render/Gunicorn e garantir que rotas críticas
(como /login) existam mesmo quando o app legado (web/app.py) falhar em registrar
blueprints por causa de path/import.

Este módulo NÃO altera regras de negócio; só garante inicialização previsível.
"""

import os
import sys
from flask import Flask


def _ensure_web_on_path() -> None:
    # /.../src/web
    web_dir = os.path.dirname(__file__)
    # /.../src
    base_dir = os.path.dirname(web_dir)

    # Compat: seus imports históricos usam `from db import ...` e `from services...`
    # então precisamos colocar WEB_DIR no sys.path.
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)


def _safe_register_blueprint(app: Flask, bp, name: str) -> None:
    # Evita duplicar registro em múltiplos boots/imports.
    if name in app.blueprints:
        return
    app.register_blueprint(bp)


def create_app() -> Flask:
    _ensure_web_on_path()

    # Importa o app legado (monolito) que já contém todas as rotas existentes.
    # Ele pode falhar em registrar o auth blueprint dependendo de sys.path,
    # então garantimos isso aqui também.
    import web.app as legacy_app_module  # noqa

    app: Flask = legacy_app_module.app

    # GARANTIA CRÍTICA: auth.login precisa existir (home redireciona para ele).
    try:
        from web.blueprints.auth import bp as auth_bp  # noqa
        _safe_register_blueprint(app, auth_bp, "auth")
    except Exception:
        # último fallback: tenta import antigo (quando WEB_DIR está no path)
        try:
            from blueprints.auth import bp as auth_bp  # type: ignore
            _safe_register_blueprint(app, auth_bp, "auth")
        except Exception:
            # aqui a gente NÃO estoura o boot (pra não derrubar o deploy),
            # mas registra um log bem explícito.
            try:
                app.logger.exception("Falha ao registrar blueprint 'auth' no create_app()")
            except Exception:
                pass


    # GARANTIA: cadastro de campanhas V2 (admin) precisa existir (rota /admin/campanhas_v2).
    # Este blueprint é independente do monolito e mantém o cadastro/ações V2 estáveis.
    try:
        from web.blueprints.campanhas_v2_admin import bp as campanhas_v2_admin_bp  # noqa
        _safe_register_blueprint(app, campanhas_v2_admin_bp, "campanhas_v2_admin")
    except Exception:
        try:
            from blueprints.campanhas_v2_admin import bp as campanhas_v2_admin_bp  # type: ignore
            _safe_register_blueprint(app, campanhas_v2_admin_bp, "campanhas_v2_admin")
        except Exception:
            try:
                app.logger.exception("Falha ao registrar blueprint 'campanhas_v2_admin' no create_app()")
            except Exception:
                pass

    return app
