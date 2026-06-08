from __future__ import annotations

from datetime import date, datetime
import os
import sys
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


def _clear_prefix_everywhere(prefix: str):
    """Limpa caches locais também quando app.py possui cache próprio.

    O projeto passou por uma refatoração em que branding.py e app.py podem existir
    com caches em memória separados. Sem essa limpeza cruzada, uploads/temas ficam
    salvos no banco, mas a tela pode continuar exibindo a logo antiga até o TTL expirar.
    """
    _cache_clear_prefix(prefix)
    for mod in list(sys.modules.values()):
        for attr in ("_BRANDING_CACHE", "_PERF_CACHE"):
            cache = getattr(mod, attr, None)
            if not isinstance(cache, dict) or cache is _BRANDING_CACHE:
                continue
            for k in list(cache.keys()):
                if isinstance(k, str) and k.startswith(prefix):
                    cache.pop(k, None)


def clear_branding_cache():
    """Limpa cache local de branding/configurações usado pelos workers."""
    _clear_prefix_everywhere("branding:")
    _clear_prefix_everywhere("setting:branding.")


def _is_data_url(value: str | None) -> bool:
    return bool(value and str(value).strip().lower().startswith("data:"))


def _version_for_urls(version: str | None, *urls: str | None) -> str:
    """Evita anexar ?v= em data URLs, pois isso quebra imagens base64."""
    if any(_is_data_url(u) for u in urls):
        return ""
    return version or ""


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

    _clear_prefix_everywhere(f"setting:{key}")
    if key.startswith("branding."):
        _clear_prefix_everywhere("branding:")
        _clear_prefix_everywhere("setting:branding.")


def _current_branding(db) -> dict:
    """Retorna branding atual (tema sazonal ativo ou padrão).

    Regra profissional:
    - tema sazonal ativo substitui apenas o que ele tiver configurado;
    - se o tema não tiver logo/favicon, usa fallback do branding padrão;
    - data URL nunca recebe ?v= para não quebrar a imagem.
    """
    cached = _cache_get("branding:current")
    if isinstance(cached, dict):
        return dict(cached)

    default_logo = _get_setting_cached(db, "branding.default_logo_url")
    default_favicon = _get_setting_cached(db, "branding.default_favicon_url")
    default_login_left = _get_setting_cached(db, "branding.login_logo_left_url", default_logo)
    default_login_right = _get_setting_cached(db, "branding.login_logo_right_url", default_logo)
    default_version = _get_setting_cached(db, "branding.default_version", "")

    today = date.today()
    theme = (
        db.query(BrandingTheme)
          .filter(BrandingTheme.is_active == True)
          .filter(BrandingTheme.start_date <= today)
          .filter(BrandingTheme.end_date >= today)
          .order_by(BrandingTheme.start_date.desc(), BrandingTheme.updated_at.desc(), BrandingTheme.id.desc())
          .first()
    )
    if theme:
        logo = theme.logo_url or default_logo
        favicon = theme.favicon_url or default_favicon
        login_left = default_login_left or logo
        login_right = default_login_right or logo
        raw_version = theme.updated_at.isoformat() if theme.updated_at else default_version
        b = {
            "logo_url": logo,
            "login_logo_left_url": login_left,
            "login_logo_right_url": login_right,
            "favicon_url": favicon,
            "theme_name": theme.name,
            "theme_id": theme.id,
            "is_seasonal": True,
            "version": _version_for_urls(raw_version, logo, favicon, login_left, login_right),
        }
        return dict(_cache_set("branding:current", b, BRANDING_CACHE_SECONDS))

    b = {
        "logo_url": default_logo,
        "login_logo_left_url": default_login_left,
        "login_logo_right_url": default_login_right,
        "favicon_url": default_favicon,
        "theme_name": "default",
        "theme_id": None,
        "is_seasonal": False,
        "version": _version_for_urls(default_version, default_logo, default_favicon, default_login_left, default_login_right),
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
