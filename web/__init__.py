from __future__ import annotations

import os
import sys
from pathlib import Path

from flask import Flask


def _ensure_paths() -> None:
    """Garante compatibilidade com imports antigos do projeto.

    O código legado usa imports do tipo: `from db import ...`, `from services import ...`
    (assumindo que a pasta `web/` está no PYTHONPATH). Em produção, isso nem sempre é verdade.
    """
    base_dir = Path(__file__).resolve().parent.parent  # raiz do repo
    web_dir = Path(__file__).resolve().parent          # .../web

    for p in (str(base_dir), str(web_dir)):
        if p not in sys.path:
            sys.path.insert(0, p)


def create_app() -> Flask:
    """App Factory (padrão SaaS).

    Neste passo (PASSO 3), mantemos a lógica do app legado em `web/app.py`,
    porém registramos as rotas de módulos via Blueprints para reduzir riscos
    e permitir evolução sem regressões.
    """
    _ensure_paths()

    # Importa o app legado
    import web.app as legacy_app_module  # noqa: WPS433

    app = getattr(legacy_app_module, "app", None)
    if app is None:
        raise RuntimeError("Não foi encontrado `app` em web/app.py")

    # Registra blueprints (auth já existia; admin/mensagens entram agora)
    try:
        from web.blueprints import auth_bp, admin_bp, mensagens_bp  # noqa: WPS433
        # Evita re-registro em reload
        already = set(app.blueprints.keys())
        if auth_bp.name not in already:
            app.register_blueprint(auth_bp)
        if admin_bp.name not in already:
            app.register_blueprint(admin_bp)
        if mensagens_bp.name not in already:
            app.register_blueprint(mensagens_bp)
    except Exception as e:  # pragma: no cover
        # Em caso de erro, melhor falhar com mensagem clara.
        raise RuntimeError(f"Falha ao registrar blueprints: {e}") from e

    return app
