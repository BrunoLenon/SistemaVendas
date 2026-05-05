from __future__ import annotations

from datetime import date, datetime
import os
import time

from db import AppSetting, BrandingTheme


BRANDING_CACHE_SECONDS = int(os.getenv("BRANDING_CACHE_SECONDS", "60") or 60)
GLOBAL_SETTING_CACHE_SECONDS = int(os.getenv("GLOBAL_SETTING_CACHE_SECONDS", "30") or 30)
_BRANDING_CACHE: dict[str, tuple[float, object]] = {}
_CACHE_MISS = object()


def _cache_get(key: str):
    item = _BRANDING_CACHE.get(key)
    if not item:
        return _CACHE_MISS
    expires_at, value = item
    if expires_at <= time.time():
        _BRANDING_CACHE.pop(key, None)
        return _CACHE_MISS
    return value


def _cache_set(key: str, value, ttl_seconds: int):
    ttl = max(0, int(ttl_seconds or 0))
    if ttl <= 0:
        _BRANDING_CACHE.pop(key, None)
        return value
    _BRANDING_CACHE[key] = (time.time() + ttl, value)
    return value


def _cache_clear_prefix(prefix: str):
    for k in list(_BRANDING_CACHE.keys()):
        if k.startswith(prefix):
            _BRANDING_CACHE.pop(k, None)


def clear_branding_cache():
    """Limpa cache local de branding/configurações usado por este worker."""
    _cache_clear_prefix("branding:")
    _cache_clear_prefix("setting:branding.")


def _get_setting(db, key: str, default: str | None = None) -> str | None:
    s = db.query(AppSetting).filter(AppSetting.key == key).first()
    return s.value if s and s.value is not None else default


def _get_setting_cached(db, key: str, default: str | None = None) -> str | None:
    cache_key = f"setting:{key}"
    cached = _cache_get(cache_key)
    if cached is not _CACHE_MISS:
        return cached  # type: ignore[return-value]
    value = _get_setting(db, key, default)
    return _cache_set(cache_key, value, GLOBAL_SETTING_CACHE_SECONDS)  # type: ignore[return-value]


def _set_setting(db, key: str, value: str | None):
    s = db.query(AppSetting).filter(AppSetting.key == key).first()
    if not s:
        s = AppSetting(key=key, value=value)
        db.add(s)
    else:
        s.value = value
    _cache_clear_prefix(f"setting:{key}")
    if key.startswith("branding."):
        _cache_clear_prefix("branding:")


def _current_branding(db) -> dict:
    """Retorna branding atual (tema sazonal ativo ou padrão)."""
    cached = _cache_get("branding:current")
    if isinstance(cached, dict):
        return dict(cached)

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
        b = {
            "logo_url": theme.logo_url,
            "login_logo_left_url": _get_setting_cached(db, "branding.login_logo_left_url", theme.logo_url),
            "login_logo_right_url": _get_setting_cached(db, "branding.login_logo_right_url", theme.logo_url),
            "favicon_url": theme.favicon_url,
            "theme_name": theme.name,
            "version": ver,
        }
        return dict(_cache_set("branding:current", b, BRANDING_CACHE_SECONDS))

    # Padrão
    logo = _get_setting_cached(db, "branding.default_logo_url")
    favicon = _get_setting_cached(db, "branding.default_favicon_url")
    login_logo_left = _get_setting_cached(db, "branding.login_logo_left_url", logo)
    login_logo_right = _get_setting_cached(db, "branding.login_logo_right_url", logo)
    ver = _get_setting_cached(db, "branding.default_version", "")
    b = {
        "logo_url": logo,
        "login_logo_left_url": login_logo_left,
        "login_logo_right_url": login_logo_right,
        "favicon_url": favicon,
        "theme_name": "default",
        "version": ver,
    }
    return dict(_cache_set("branding:current", b, BRANDING_CACHE_SECONDS))


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
