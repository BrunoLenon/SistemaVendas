from __future__ import annotations

from datetime import date, datetime

from db import AppSetting, BrandingTheme


def _get_setting(db, key: str, default: str | None = None) -> str | None:
    s = db.query(AppSetting).filter(AppSetting.key == key).first()
    return s.value if s and s.value is not None else default


def _set_setting(db, key: str, value: str | None):
    s = db.query(AppSetting).filter(AppSetting.key == key).first()
    if not s:
        s = AppSetting(key=key, value=value)
        db.add(s)
    else:
        s.value = value


def _current_branding(db) -> dict:
    """Retorna branding atual (tema sazonal ativo ou padrão)."""
    today = date.today()
    theme = (
        db.query(BrandingTheme)
          .filter(BrandingTheme.is_active == True)
          .filter(BrandingTheme.start_date <= today)
          .filter(BrandingTheme.end_date >= today)
          .order_by(BrandingTheme.start_date.desc(), BrandingTheme.updated_at.desc())
          .first()
    )
    if theme:
        ver = theme.updated_at.isoformat() if theme.updated_at else ""
        return {
            "logo_url": theme.logo_url,
            "favicon_url": theme.favicon_url,
            "theme_name": theme.name,
            "version": ver,
        }
    # Padrão
    logo = _get_setting(db, "branding.default_logo_url")
    favicon = _get_setting(db, "branding.default_favicon_url")
    ver = _get_setting(db, "branding.default_version", "")
    return {"logo_url": logo, "favicon_url": favicon, "theme_name": "default", "version": ver}


def register_branding(app, SessionLocal):
    """Registra context processors de branding e variáveis globais do Jinja.

    Mantém comportamento externo (mesmas chaves disponíveis no template):
      - branding: {logo_url, favicon_url, theme_name, version}
      - today / now
    """

    @app.context_processor
    def inject_branding():
        try:
            with SessionLocal() as db:
                b = _current_branding(db)
        except Exception:
            b = {"logo_url": None, "favicon_url": None, "theme_name": "default", "version": ""}
        return {"branding": b}

    @app.context_processor
    def inject_globals():
        """Variáveis globais disponíveis em todos os templates Jinja (evita UndefinedError)."""
        try:
            return {"today": date.today(), "now": datetime.now()}
        except Exception:
            # fallback ultra-defensivo
            return {"today": date.today()}

    return inject_branding, inject_globals
