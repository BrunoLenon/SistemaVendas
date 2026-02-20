import os
import sys
from pathlib import Path


def _ensure_paths():
    """Mantém compatibilidade com imports legados: `from db import ...`, `from services...`."""
    base_dir = Path(__file__).resolve().parent.parent  # .../SistemaVendas
    web_dir = base_dir / "web"
    for p in (str(base_dir), str(web_dir)):
        if p not in sys.path:
            sys.path.insert(0, p)


def create_app():
    _ensure_paths()

    # Importa o app legado (mantém comportamento atual)
    import web.app as legacy_app_module  # noqa

    app = getattr(legacy_app_module, "app", None)
    if app is None:
        raise RuntimeError("Não foi possível localizar `app` em web/app.py")

    # Registra blueprints (se existirem)
    try:
        from web.blueprints.auth import bp as auth_bp  # noqa
        app.register_blueprint(auth_bp)
    except Exception:
        pass

    try:
        from web.blueprints.admin import bp as admin_bp  # noqa
        app.register_blueprint(admin_bp)
    except Exception:
        pass

    try:
        from web.blueprints.mensagens import bp as msg_bp  # noqa
        app.register_blueprint(msg_bp)
    except Exception:
        pass

    # Novo: Campanhas V2 (cadastro enterprise) – fonte da verdade do V2
    try:
        from web.blueprints.campanhas_v2_admin import bp as campv2_bp  # noqa
        app.register_blueprint(campv2_bp)
    except Exception:
        # Não derruba o app se o arquivo não estiver presente em algum deploy intermediário
        pass

    return app
