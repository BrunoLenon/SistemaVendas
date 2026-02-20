import os
import sys

# --- Path shim: permite rodar tanto como 'app:app' (--chdir web) quanto 'web.app:app' ---
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from services.scope import get_session_emps, refresh_session_emps, set_session_emps
from services.campanhas_service import (
    CampanhasDeps,
    build_campanhas_page_context,
    build_relatorio_campanhas_scope,
)
from services.relatorio_campanhas_service import build_relatorio_campanhas_context, build_relatorio_campanhas_unificado_context
from services.campanhas_v2_engine import recalc_v2_competencia
import os
import re
import mimetypes
import logging
import json
from datetime import date, datetime, timedelta
import calendar
from io import BytesIO

from decimal import Decimal, ROUND_HALF_UP

import pandas as pd
import requests
from sqlalchemy import and_, or_, func, case, cast, String, text, extract
# ---------------------------------------------------------------------------
# Helpers de compatibilidade para "rows" que podem vir como dict, SQLAlchemy Row,
# dataclass (ex.: UnifiedRow), ou objetos simples.
# ---------------------------------------------------------------------------
def _obj_get(obj, key, default=None):
    """Acesso seguro estilo dict: tenta dict, RowMapping, atributos e chaves."""
    if obj is None:
        return default
    try:
        # dict
        if isinstance(obj, dict):
            return obj.get(key, default)
        # SQLAlchemy Row: possui _mapping
        mapping = getattr(obj, "_mapping", None)
        if mapping is not None:
            return mapping.get(key, default)
        # dataclass/objeto: atributo
        if hasattr(obj, key):
            return getattr(obj, key)
        # tenta variações de caixa
        k = str(key)
        for kk in (k.lower(), k.upper()):
            if hasattr(obj, kk):
                return getattr(obj, kk)
        # fallback: __getitem__
        try:
            return obj[key]  # type: ignore[index]
        except Exception:
            return default
    except Exception:
        return default

def _obj_get_any(obj, keys, default=None):
    for k in keys:
        v = _obj_get(obj, k, None)
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        return v
    return default


from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    send_file,
    jsonify,
)
from werkzeug.security import check_password_hash, generate_password_hash

from dados_db import carregar_df, limpar_cache_df
from db import (
    CampanhaV2Master, CampanhaV2ScopeEMP, CampanhaV2Resultado,

    SessionLocal,
    Usuario,
    UsuarioEmp,
    Emp,
    Mensagem,
    MensagemEmpresa,
    MensagemUsuario,
    MensagemLidaDiaria,
    Venda,
    DashboardCache,
    ItemParado,
    CampanhaQtd,
    CampanhaQtdResultado,
    CampanhaCombo,
    CampanhaComboItem,
    CampanhaComboResultado,
    VendasResumoPeriodo,
    MetaPrograma,
    MetaProgramaEmp,
    MetaEscala,
    MetaMarca,
    MetaBaseManual,
    MetaResultado,
    FechamentoMensal,
    AppSetting,
    BrandingTheme,
    criar_tabelas,
)
from importar_excel import importar_planilha

# Flask app (Render/Gunicorn expects `app` at module level: web/app.py -> app:app)
app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY", "dev")
# Sessão expira após 1h sem atividade
app.permanent_session_lifetime = timedelta(hours=1)

# ==============================
# Segurança & Performance (base)
# ==============================
# Detecta produção (Render/FLASK_ENV)
IS_PROD = bool(os.getenv("RENDER")) or (os.getenv("FLASK_ENV") == "production")

# Cache TTL (horas) - se o cache estiver mais velho que isso, recalcula ao vivo
CACHE_TTL_HOURS = float(os.getenv("CACHE_TTL_HOURS", "12") or 12)


# Respeitar X-Forwarded-* (https/ip real) atrás do Render
try:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
except Exception:
    pass

# Cookies de sessão mais seguros
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PROD,  # em dev/local pode ser False
)

from security_utils import audit, rate_limit, normalize_role

@app.before_request
def _security_rate_limits():
    # limita tentativas de login (POST)
    if request.path == "/login" and request.method == "POST":
        if not rate_limit("login", limit=8, window_sec=60):
            audit("login_rate_limited")
            return render_template("login.html", erro="Muitas tentativas. Aguarde 1 minuto e tente novamente."), 429

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
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

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
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return resp

# --------------------------
# Filtro Jinja: formato brasileiro
# --------------------------
@app.template_filter("brl")
def brl(value):
    """Formata números no padrão brasileiro (ex: 21.555.384,00).

    Retorna "0,00" para None/valores inválidos.
    """
    if value is None:
        return "0,00"
    try:
        num = float(value)
    except Exception:
        return "0,00"
    return f"{num:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
@app.template_filter("brl")
def brl(value):
    """Formata números no padrão brasileiro (ex: 21.555.384,00).

    Retorna "0,00" para None/valores inválidos.
    """
    if value is None:
        return "0,00"
    try:
        num = float(value)
    except Exception:
        return "0,00"
    return f"{num:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")

# --------------------------
# Filtro Jinja: moeda brasileira (com R$)
# --------------------------
@app.template_filter("brl_rs")
def brl_rs(value):
    """Formata valores monetários no padrão brasileiro com prefixo 'R$' (ex: R$12.345,67)."""
    s = brl(value)
    # brl() já devolve '0,00' em erro
    if s.startswith("-"):
        return "R$-" + s[1:]
    return "R$" + s


# Logs no stdout (Render captura automaticamente)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

@app.before_request
def _idle_timeout():
    # Ignora arquivos estáticos
    if request.endpoint == 'static':
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
                flash("Sua sessão expirou por inatividade. Faça login novamente.", "warning")
                return redirect(url_for("auth.login"))
        except Exception:
            # Se estiver inválido, reseta
            pass
    session["last_activity"] = now.isoformat()
    return None


# Schema / migrações
# IMPORTANTE:
# - Evite executar alterações de schema automaticamente no startup do app (request path).
# - Para ambientes de DEV/primeiro deploy, habilite explicitamente via env var.
#
# Como usar:
#   AUTO_MIGRATE=1  -> executa criar_tabelas() na inicialização
#
# Em produção, mantenha AUTO_MIGRATE=0 e rode migrações de forma controlada.
if os.getenv("AUTO_MIGRATE", "0") == "1":
    try:
        criar_tabelas()
        app.logger.info("AUTO_MIGRATE=1 -> criar_tabelas() executado com sucesso")
    except Exception:
        app.logger.exception("Falha ao criar/verificar tabelas (AUTO_MIGRATE=1)")
# Blueprints (organização do app)
try:
    from blueprints.auth import bp as auth_bp
    app.register_blueprint(auth_bp)
except Exception:
    app.logger.exception("Falha ao registrar blueprint de auth")


# -------------------- Modo Manutenção (bloqueia não-admin) --------------------
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
                flag = (_get_setting(db, "maintenance_mode", "off") or "off").strip().lower()
        except Exception:
            # Se falhar leitura, não bloqueia (fail-open)
            return None

    if flag in ("1", "true", "on", "yes", "y"):
        r = _role() or ""
        if r != "admin":
            return render_template("maintenance.html"), 503

    return None


# ------------- Helpers -------------
def _normalize_role(r: str | None) -> str:
    # Compatibilidade: o sistema historicamente usa `_normalize_role`.
    # A lógica agora vive em `security_utils.normalize_role`.
    return normalize_role(r)


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

@app.context_processor
def inject_branding():
    try:
        with SessionLocal() as db:
            b = _current_branding(db)
    except Exception:
        b = {"logo_url": None, "favicon_url": None, "theme_name": "default", "version": ""}
    return {"branding": b}

# -------------------- Configurações / Branding (ADMIN) --------------------

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
    if request.path.startswith("/login") or request.path.startswith("/logout") or request.path.startswith("/senha"):
        return None
    if request.path.startswith("/mensagens"):
        return None

    try:
        with SessionLocal() as db:
            pendente = _find_pending_blocking_message(db)
            if pendente:
                # salva a rota desejada para retornar depois de marcar como lida
                if request.method == "GET":
                    session["after_block_redirect"] = request.full_path if request.query_string else request.path
                else:
                    session["after_block_redirect"] = request.referrer or url_for("dashboard")
                return redirect(url_for("mensagens_bloqueio", mensagem_id=pendente.id))
    except Exception as e:
        # nunca derrubar o app por causa do módulo de mensagens
        logging.exception("Erro no guard de mensagens bloqueantes: %s", e)

    return None


@app.route('/admin/configuracoes', methods=['GET', 'POST'])
def admin_configuracoes():
    red = _admin_required()
    if red:
        return red

    msgs: list[str] = []
    today = date.today()

    with SessionLocal() as db:

        # Modo manutenção (admin-only)
        maintenance_mode = (_get_setting(db, "maintenance_mode", "off") or "off").strip().lower()

        if request.method == 'POST':
            acao = (request.form.get('acao') or '').strip()

            if acao in ('toggle_maintenance', 'maintenance_on', 'maintenance_off'):
                try:
                    if acao == 'maintenance_on':
                        new_val = 'on'
                    elif acao == 'maintenance_off':
                        new_val = 'off'
                    else:
                        # toggle on/off (compatibilidade)
                        new_val = (request.form.get('maintenance_mode') or '').strip().lower()
                        if new_val not in ('on', 'off'):
                            new_val = 'off'

                    _set_setting(db, 'maintenance_mode', new_val)
                    db.commit()
                    maintenance_mode = new_val
                    msgs.append(f"Modo manutenção {'ativado' if new_val == 'on' else 'desativado'}.")
                except Exception:
                    db.rollback()
                    msgs.append('Falha ao atualizar modo manutenção.')
        # Upload padrão (sempre disponível)
        if request.method == 'POST' and (request.form.get('acao') or '') == 'upload_default':
            try:
                logo_file = request.files.get('default_logo')
                fav_file = request.files.get('default_favicon')

                def _read_file(f, max_bytes: int, allowed_ext: set[str]):
                    if not f or not getattr(f, 'filename', ''):
                        return None
                    filename = f.filename
                    ext = (os.path.splitext(filename)[1] or '').lower()
                    if ext and ext not in allowed_ext:
                        raise ValueError(f"Arquivo inválido ({ext}). Permitidos: {', '.join(sorted(allowed_ext))}")
                    data = f.read()
                    if len(data) > max_bytes:
                        raise ValueError("Arquivo muito grande.")
                    ctype = f.mimetype or mimetypes.guess_type(filename)[0] or "application/octet-stream"
                    return filename, data, ctype

                logo = _read_file(logo_file, max_bytes=2_000_000, allowed_ext={'.png', '.jpg', '.jpeg', '.webp', '.svg'})
                fav = _read_file(fav_file, max_bytes=400_000, allowed_ext={'.png', '.ico', '.jpg', '.jpeg', '.webp', '.svg'})

                if not logo and not fav:
                    raise ValueError("Envie uma logo e/ou um favicon.")

                if logo:
                    url = _supabase_storage_upload(logo[0], logo[1], logo[2], folder="default")
                    _set_setting(db, "branding.default_logo_url", url)
                if fav:
                    url = _supabase_storage_upload(fav[0], fav[1], fav[2], folder="default")
                    _set_setting(db, "branding.default_favicon_url", url)

                # bump version para cache bust
                _set_setting(db, "branding.default_version", datetime.utcnow().isoformat())
                db.commit()
                msgs.append("Arquivos padrão atualizados com sucesso.")
            except Exception as e:
                db.rollback()
                msgs.append(f"Erro ao salvar: {e}")

        # Criar tema sazonal
        if request.method == 'POST' and (request.form.get('acao') or '') == 'create_theme':
            try:
                name = (request.form.get('name') or '').strip()
                sd = request.form.get('start_date')
                ed = request.form.get('end_date')
                if not name or not sd or not ed:
                    raise ValueError("Informe nome, data início e data fim.")
                start_date = datetime.fromisoformat(sd).date()
                end_date = datetime.fromisoformat(ed).date()
                if end_date < start_date:
                    raise ValueError("Data fim precisa ser >= data início.")

                logo_file = request.files.get('theme_logo')
                fav_file = request.files.get('theme_favicon')
                logo_url = None
                fav_url = None
                if logo_file and logo_file.filename:
                    data = logo_file.read()
                    if len(data) > 2_000_000:
                        raise ValueError("Logo do tema muito grande.")
                    ctype = logo_file.mimetype or mimetypes.guess_type(logo_file.filename)[0] or "application/octet-stream"
                    logo_url = _supabase_storage_upload(logo_file.filename, data, ctype, folder="themes")
                if fav_file and fav_file.filename:
                    data = fav_file.read()
                    if len(data) > 400_000:
                        raise ValueError("Favicon do tema muito grande.")
                    ctype = fav_file.mimetype or mimetypes.guess_type(fav_file.filename)[0] or "application/octet-stream"
                    fav_url = _supabase_storage_upload(fav_file.filename, data, ctype, folder="themes")

                t = BrandingTheme(
                    name=name,
                    start_date=start_date,
                    end_date=end_date,
                    logo_url=logo_url,
                    favicon_url=fav_url,
                    is_active=True,
                )
                db.add(t)
                db.commit()
                msgs.append("Tema criado com sucesso.")
            except Exception as e:
                db.rollback()
                msgs.append(f"Erro ao criar tema: {e}")

        # Ações em tema existente
        if request.method == 'POST' and (request.form.get('acao') or '').startswith('theme_'):
            try:
                theme_id = int(request.form.get('theme_id') or '0')
                t = db.query(BrandingTheme).filter(BrandingTheme.id == theme_id).first()
                if not t:
                    raise ValueError("Tema não encontrado.")
                acao = request.form.get('acao')

                if acao == 'theme_toggle':
                    t.is_active = not bool(t.is_active)
                    db.commit()
                    msgs.append("Status do tema atualizado.")

                elif acao == 'theme_update':
                    name = (request.form.get('name') or '').strip()
                    sd = request.form.get('start_date')
                    ed = request.form.get('end_date')
                    if name:
                        t.name = name
                    if sd:
                        t.start_date = datetime.fromisoformat(sd).date()
                    if ed:
                        t.end_date = datetime.fromisoformat(ed).date()
                    if t.end_date < t.start_date:
                        raise ValueError("Data fim precisa ser >= data início.")

                    logo_file = request.files.get('theme_logo')
                    fav_file = request.files.get('theme_favicon')
                    if logo_file and logo_file.filename:
                        data = logo_file.read()
                        if len(data) > 2_000_000:
                            raise ValueError("Logo do tema muito grande.")
                        ctype = logo_file.mimetype or mimetypes.guess_type(logo_file.filename)[0] or "application/octet-stream"
                        t.logo_url = _supabase_storage_upload(logo_file.filename, data, ctype, folder="themes")
                    if fav_file and fav_file.filename:
                        data = fav_file.read()
                        if len(data) > 400_000:
                            raise ValueError("Favicon do tema muito grande.")
                        ctype = fav_file.mimetype or mimetypes.guess_type(fav_file.filename)[0] or "application/octet-stream"
                        t.favicon_url = _supabase_storage_upload(fav_file.filename, data, ctype, folder="themes")

                    db.commit()
                    msgs.append("Tema atualizado com sucesso.")

                elif acao == 'theme_delete':
                    db.delete(t)
                    db.commit()
                    msgs.append("Tema removido.")

                elif acao == "alterar_emp":
                    # Atualiza o campo EMP "legado/padrão" do usuário (util para supervisor e como EMP padrão para multi-EMP)
                    alvo = (request.form.get("alvo") or "").strip().upper()
                    emp_novo = (request.form.get("emp_novo") or "").strip()
                    if not alvo:
                        raise ValueError("Informe o usuário para alterar EMP.")
                    u = db.query(Usuario).filter(Usuario.username == alvo).first()
                    if not u:
                        raise ValueError("Usuário não encontrado.")
                    # Admin pode alterar EMP de qualquer role (inclusive limpar)
                    if emp_novo == "":
                        setattr(u, "emp", None)
                        db.commit()
                        ok = f"EMP do usuário {alvo} removida."
                    else:
                        setattr(u, "emp", str(emp_novo))
                        db.commit()
                        ok = f"EMP do usuário {alvo} atualizada para {emp_novo}."
                else:
                    raise ValueError("Ação inválida.")
            except Exception as e:
                db.rollback()
                msgs.append(f"Erro: {e}")

        # Dados para tela
        branding = _current_branding(db)
        default_logo = _get_setting(db, "branding.default_logo_url")
        default_favicon = _get_setting(db, "branding.default_favicon_url")
        themes = db.query(BrandingTheme).order_by(BrandingTheme.start_date.desc(), BrandingTheme.id.desc()).all()

    return render_template(
        "admin_configuracoes.html",
        msgs=msgs,
        branding=branding,
        default_logo=default_logo,
        default_favicon=default_favicon,
        themes=themes,
        today=today.isoformat(),
    )

def _supabase_storage_upload(filename: str, content: bytes, content_type: str, folder: str) -> str:
    """Faz upload no Supabase Storage e retorna URL pública.
    Requer SUPABASE_URL e uma key (preferencialmente service role).
    """
    supa_url = (os.getenv("SUPABASE_URL") or "").rstrip("/")
    key = (
        os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        or os.getenv("SUPABASE_SERVICE_KEY")
        or os.getenv("SUPABASE_KEY")
        or os.getenv("SUPABASE_ANON_KEY")
        or ""
    )
    if not supa_url or not key:
        raise RuntimeError("SUPABASE_URL/SUPABASE_KEY não configurados no ambiente.")

    bucket = os.getenv("SUPABASE_STORAGE_BUCKET", "branding")
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    path = f"{folder}/{ts}_{safe_name}"
    endpoint = f"{supa_url}/storage/v1/object/{bucket}/{path}"

    headers = {
        "Authorization": f"Bearer {key}",
        "apikey": key,
        "Content-Type": content_type or "application/octet-stream",
        "x-upsert": "true",
    }
    r = requests.put(endpoint, headers=headers, data=content, timeout=30)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Falha upload storage: {r.status_code} {r.text[:200]}")
    public_url = f"{supa_url}/storage/v1/object/public/{bucket}/{path}"
    return public_url
def _usuario_logado() -> str | None:
    return session.get("usuario")

def _role() -> str | None:
    return _normalize_role(session.get("role"))

def _emp() -> str | None:
    """Retorna a EMP do usuário logado (quando existir)."""
    emp = session.get("emp")
    if emp is not None and emp != "":
        return str(emp)
    uid = session.get("user_id")
    if not uid:
        return None
    try:
        db = SessionLocal()
        u = db.query(Usuario).filter(Usuario.id == uid).first()
        if not u:
            return None
        emp_val = getattr(u, "emp", None)
        if emp_val is None or emp_val == "":
            return None
        session["emp"] = str(emp_val)
        return str(emp_val)
    except Exception:
        return None
    finally:
        try:
            db.close()
        except Exception:
            pass



def _allowed_emps() -> list[str]:
    """Lista de EMPs permitidas para o usuário logado via tabela usuario_emps.

    Compat:
      - session['emps'] (novo / recomendado)
      - session['allowed_emps'] (legado)
    """
    role = (_role() or "").lower()
    if role == "admin" and session.get("admin_all_emps"):
        return []

    emps_int = get_session_emps()
    if emps_int:
        return _filter_emps_cadastradas([str(e) for e in emps_int], apenas_ativas=True)

    uid = session.get("user_id")
    if not uid:
        return []

    try:
        with SessionLocal() as db:
            refresh_session_emps(db, usuario_id=int(uid), fallback_emp=_emp())
            emps_int = get_session_emps()
            return _filter_emps_cadastradas([str(e) for e in emps_int], apenas_ativas=True)
    except Exception:
        return []
def _is_date_in_range(today: date, inicio: date | None, fim: date | None) -> bool:
    if inicio and today < inicio:
        return False
    if fim and today > fim:
        return False
    return True


def _find_pending_blocking_message(db) -> Mensagem | None:
    """Retorna a primeira mensagem bloqueante pendente para o usuário (hoje)."""
    role = (_role() or "").lower()
    user_id = session.get("user_id")
    if not user_id:
        return None

    today = date.today()
    allowed_emps = _allowed_emps()  # [] significa "todas" para admin_all_emps

    # Busca candidatas recentes primeiro (id desc) para mostrar a mais nova
    candidatas = (
        db.query(Mensagem)
        .filter(Mensagem.ativo.is_(True))
        .filter(Mensagem.bloqueante.is_(True))
        .order_by(Mensagem.id.desc())
        .limit(50)
        .all()
    )

    for msg in candidatas:
        if not _is_date_in_range(today, msg.inicio_em, msg.fim_em):
            continue

        # Destino: usuário específico (admin pode mandar)
        targeted_user = (
            db.query(MensagemUsuario)
            .filter(MensagemUsuario.mensagem_id == msg.id)
            .filter(MensagemUsuario.usuario_id == int(user_id))
            .first()
            is not None
        )

        # Destino: empresas
        targeted_emp = False
        if role == "admin" and session.get("admin_all_emps"):
            # Admin "todas as EMPs": se a mensagem tiver qualquer empresa destino, conta.
            targeted_emp = (
                db.query(MensagemEmpresa)
                .filter(MensagemEmpresa.mensagem_id == msg.id)
                .first()
                is not None
            )
        else:
            if allowed_emps:
                targeted_emp = (
                    db.query(MensagemEmpresa)
                    .filter(MensagemEmpresa.mensagem_id == msg.id)
                    .filter(MensagemEmpresa.emp.in_(allowed_emps))
                    .first()
                    is not None
                )

        if not (targeted_user or targeted_emp):
            continue

        # Já leu hoje?
        ja_leu = (
            db.query(MensagemLidaDiaria)
            .filter(MensagemLidaDiaria.mensagem_id == msg.id)
            .filter(MensagemLidaDiaria.usuario_id == int(user_id))
            .filter(MensagemLidaDiaria.data == today)
            .first()
            is not None
        )
        if ja_leu:
            continue

        return msg

    return None



def _normalize_cols(df: pd.DataFrame) -> pd.DataFrame:
    """Normaliza nomes/tipos de colunas vindas do banco.

    Regras do app:
    - VENDEDOR (str, UPPER) e EMP (str)
    - MOVIMENTO (datetime) é usado para filtrar mês/ano
    """
    if df is None or df.empty:
        return df

    rename: dict[str, str] = {}
    for col in df.columns:
        low = str(col).strip().lower()
        if low == "vendedor":
            rename[col] = "VENDEDOR"
        elif low == "marca":
            rename[col] = "MARCA"
        elif low in ("data", "movimento"):
            # O app usa MOVIMENTO para filtros de período
            rename[col] = "MOVIMENTO"
        elif low in ("mov_tipo_movto", "mov_tipo_movimento", "mov_tipo_movto "):
            rename[col] = "MOV_TIPO_MOVTO"
        elif low in ("valor_total", "valor", "total"):
            rename[col] = "VALOR_TOTAL"
        elif low == "mestre":
            rename[col] = "MESTRE"
        elif low == "emp":
            rename[col] = "EMP"

    if rename:
        df = df.rename(columns=rename)

    # Tipos esperados
    if "MOVIMENTO" in df.columns:
        df["MOVIMENTO"] = pd.to_datetime(df["MOVIMENTO"], errors="coerce")
    if "VENDEDOR" in df.columns:
        df["VENDEDOR"] = df["VENDEDOR"].astype(str).str.strip().str.upper()
    if "EMP" in df.columns:
        df["EMP"] = df["EMP"].astype(str).str.strip()

    return df


# =========================
# Auth helpers / decorators
# =========================
from functools import wraps

def _role():
    """Retorna o papel/perfil normalizado do usuário logado (admin/supervisor/vendedor/financeiro)."""
    try:
        return normalize_role(session.get("role"))
    except Exception:
        # fallback defensivo
        val = session.get("role") or session.get("perfil") or ""
        return str(val).strip().lower()

def login_required(view_func):
    """Decorator: exige usuário logado."""
    @wraps(view_func)
    def _wrapped(*args, **kwargs):
        red = _login_required()
        if red:
            return red
        return view_func(*args, **kwargs)
    return _wrapped

def admin_required(view_func):
    """Decorator: exige ADMIN."""
    @wraps(view_func)
    def _wrapped(*args, **kwargs):
        red = _admin_required()
        if red:
            return red
        return view_func(*args, **kwargs)
    return _wrapped

def financeiro_required(view_func):
    """Decorator: exige FINANCEIRO (ou ADMIN)."""
    @wraps(view_func)
    def _wrapped(*args, **kwargs):
        if _role() not in ("financeiro", "admin"):
            flash("Acesso restrito ao Financeiro.", "warning")
            return redirect(url_for("dashboard"))
        return view_func(*args, **kwargs)
    return _wrapped

def _login_required():
    if not _usuario_logado():
        return redirect(url_for("auth.login"))
    return None

def _admin_required():
    """Garante acesso ADMIN.

    Retorna um redirect quando não for admin; caso contrário retorna None.
    """
    if _role() != "admin":
        flash("Acesso restrito ao administrador.", "warning")
        audit("admin_forbidden")
        return redirect(url_for("dashboard"))
    return None

def _admin_or_supervisor_required():
    """Garante acesso ADMIN ou SUPERVISOR."""
    if (_role() or "").lower() not in ["admin", "supervisor"]:
        flash("Acesso restrito.", "warning")
        audit("forbidden", path=request.path)
        return redirect(url_for("dashboard"))
    return None

def _get_vendedores_db(role: str, emp_usuario: str | None) -> list[str]:
    """Lista de vendedores para dropdown sem carregar todas as vendas em memória."""
    role = (role or "").strip().lower()
    with SessionLocal() as db:
        # Opcional (recomendado): mostrar/filtrar apenas vendedores cadastrados no sistema.
        # Isso evita aparecer vendedor "fantasma" que existe nas vendas importadas mas não tem usuário.
        try:
            vendedores_cadastrados = {
                (r[0] or "").strip().upper()
                for r in db.query(Usuario.username).filter(func.lower(Usuario.role) == "vendedor").all()
            }
        except Exception:
            vendedores_cadastrados = set()

        q = db.query(func.distinct(Venda.vendedor))
        if role == "supervisor":
            emps = _allowed_emps()
            if emps:
                q = q.filter(Venda.emp.in_(emps))
            elif emp_usuario:
                q = q.filter(Venda.emp == str(emp_usuario))
            else:
                return []
        # admin vê tudo; vendedor usa o próprio (não usa dropdown normalmente)
        vendedores = [(r[0] or "").strip().upper() for r in q.all()]

    vendedores = [v for v in vendedores if v]

    # Se houver cadastro, restringe a ele.
    # (Mantém compatibilidade: se a base de usuários ainda não estiver completa, não zera a lista.)
    if vendedores_cadastrados:
        vendedores = [v for v in vendedores if v in vendedores_cadastrados]

    vendedores = sorted(vendedores)
    return vendedores

def _get_emps_vendedor(username: str) -> list[str]:
    """Lista de EMPs que o vendedor pode acessar.

    Regra nova (recomendada): usa tabela usuario_emps para controlar permissão.
    Fallback (para não travar migração): se não houver vínculo ainda, infere pelas vendas.
    """
    username = (username or "").strip().upper()
    if not username:
        return []

    # Primeiro tenta permissão via usuário_emps (quando o vendedor está logado)
    if (_usuario_logado() or "").strip().upper() == username:
        emps = _allowed_emps()
        if emps:
            return _filter_emps_cadastradas(sorted({str(e).strip() for e in emps if e is not None and str(e).strip()}), apenas_ativas=True)

    # Fallback: inferir pelas vendas (compatibilidade)
    with SessionLocal() as db:
        rows = (
            db.query(func.distinct(Venda.emp))
            .filter(Venda.vendedor == username)
            .all()
        )
    emps = sorted({str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip() != ""})
    return _filter_emps_cadastradas(emps, apenas_ativas=True)

def _fetch_cache_row(vendedor: str, ano: int, mes: int, emp_scope: str | None) -> dict | None:
    """Busca dados do cache para o vendedor/período.

    - Se emp_scope for None (admin/vendedor), agrega across EMPs (somando valores e juntando ranking por marca).
    """
    vendedor = (vendedor or "").strip().upper()
    if not vendedor:
        return None

    with SessionLocal() as db:
        if emp_scope:
            row = (
                db.query(DashboardCache)
                .filter(DashboardCache.emp == str(emp_scope), DashboardCache.vendedor == vendedor, DashboardCache.ano == int(ano), DashboardCache.mes == int(mes))
                .first()
            )
            if not row:
                return None
            ranking_list = json.loads(row.ranking_json or "[]")
            ranking_top15 = json.loads(row.ranking_top15_json or "[]")
            return {
                "emp": row.emp,
                "vendedor": row.vendedor,
                "valor_bruto": float(row.valor_bruto or 0.0),
                "valor_atual": float(row.valor_liquido or 0.0),
                "valor_devolvido": float((row.devolucoes or 0.0) + (row.cancelamentos or 0.0)),
                "pct_devolucao": float(row.pct_devolucao or 0.0),
                "mix_atual": int(row.mix_produtos or 0),
                "mix_marcas": int(row.mix_marcas or 0),
                "ranking_list": ranking_list,
                "ranking_top15_list": ranking_top15,
                "total_liquido_periodo": float(row.total_liquido_periodo or 0.0),
            }

        # Agrega várias EMPs
        rows = (
            db.query(DashboardCache)
            .filter(DashboardCache.vendedor == vendedor, DashboardCache.ano == int(ano), DashboardCache.mes == int(mes))
            .all()
        )
        if not rows:
            return None
        # se qualquer linha do período estiver expirada, força recálculo ao vivo
        if any((not _cache_is_fresh(r)) for r in rows):
            return None

        valor_bruto = sum(float(r.valor_bruto or 0.0) for r in rows)
        valor_atual = sum(float(r.valor_liquido or 0.0) for r in rows)
        devol = sum(float(r.devolucoes or 0.0) for r in rows)
        canc = sum(float(r.cancelamentos or 0.0) for r in rows)
        valor_devolvido = devol + canc
        pct_devolucao = (devol / valor_bruto * 100.0) if valor_bruto else 0.0
        mix_atual = sum(int(r.mix_produtos or 0) for r in rows)
        mix_marcas = sum(int(r.mix_marcas or 0) for r in rows)

        # junta ranking por marca (soma por marca)
        marca_sum = {}
        for r in rows:
            try:
                lst = json.loads(r.ranking_json or "[]")
            except Exception:
                lst = []
            for item in lst:
                m = str(item.get("marca") or "").strip()
                v = float(item.get("valor") or 0.0)
                if not m:
                    continue
                marca_sum[m] = marca_sum.get(m, 0.0) + v

        ranking_sorted = sorted(marca_sum.items(), key=lambda kv: kv[1], reverse=True)
        total = sum(marca_sum.values())
        ranking_list = [
            {"marca": m, "valor": float(v), "pct": (float(v)/total*100.0) if total else 0.0}
            for m, v in ranking_sorted
        ]
        ranking_top15 = ranking_list[:15]

        return {
            "emp": None,
            "vendedor": vendedor,
            "valor_bruto": valor_bruto,
            "valor_atual": valor_atual,
            "valor_devolvido": valor_devolvido,
            "pct_devolucao": pct_devolucao,
            "mix_atual": mix_atual,
            "mix_marcas": mix_marcas,
            "ranking_list": ranking_list,
            "ranking_top15_list": ranking_top15,
            "total_liquido_periodo": float(total),
        }

def _fetch_cache_value(vendedor: str, ano: int, mes: int, emp_scope: str | None) -> float | None:
    row = _fetch_cache_row(vendedor, ano, mes, emp_scope)
    return float(row.get("valor_atual")) if row else None

# NOTE: existe uma versão tipada desta função mais abaixo.
# Mantemos apenas uma definição para evitar confusão/override.

def _calcular_dados(df: pd.DataFrame, vendedor: str, mes: int, ano: int):
    """Calcula os números do dashboard a partir do DF carregado do banco."""
    if df is None or df.empty:
        return None

    # Normaliza colunas e tipos para suportar variações de schema (ex.: emp/EMP)
    df = _normalize_cols(df)

    df_v = df[df["VENDEDOR"] == vendedor.upper()].copy()
    if df_v.empty:
        return None

    # DS/CA entram como negativo no líquido
    neg = df_v["MOV_TIPO_MOVTO"].isin(["DS", "CA"])
    df_v["VALOR_ASSINADO"] = df_v["VALOR_TOTAL"].where(~neg, -df_v["VALOR_TOTAL"])

    # Filtra mês/ano
    df_mes = df_v[
        (df_v["MOVIMENTO"].dt.year == ano) & (df_v["MOVIMENTO"].dt.month == mes)
    ].copy()

    # Ano passado (mesmo mês)
    df_ano_passado = df_v[
        (df_v["MOVIMENTO"].dt.year == (ano - 1))
        & (df_v["MOVIMENTO"].dt.month == mes)
    ].copy()

    # Mês anterior
    if mes == 1:
        mes_ant, ano_ant = 12, ano - 1
    else:
        mes_ant, ano_ant = mes - 1, ano
    df_mes_ant = df_v[
        (df_v["MOVIMENTO"].dt.year == ano_ant) & (df_v["MOVIMENTO"].dt.month == mes_ant)
    ].copy()

    def _mix(df_in: pd.DataFrame) -> int:
        """Mix de produtos (por MESTRE), abatendo DS/CA e sem ficar negativo.

        Regra:
        - Movimentos normais contam +1 por MESTRE
        - DS/CA contam -1 por MESTRE
        - O mix final é a quantidade de MESTRES com saldo > 0
        """
        if df_in.empty:
            return 0
        tmp = df_in[["MESTRE", "MOV_TIPO_MOVTO"]].copy()
        tmp["_s"] = 1
        tmp.loc[tmp["MOV_TIPO_MOVTO"].isin(["DS", "CA"]), "_s"] = -1
        saldo = tmp.groupby("MESTRE")["_s"].sum()
        return int((saldo > 0).sum())

    def _valor_liquido(df_in: pd.DataFrame) -> float:
        if df_in.empty:
            return 0.0
        neg = df_in["MOV_TIPO_MOVTO"].isin(["DS", "CA"])
        return float(df_in["VALOR_TOTAL"].where(~neg, -df_in["VALOR_TOTAL"]).sum())

    def _valor_bruto(df_in: pd.DataFrame) -> float:
        if df_in.empty:
            return 0.0
        vendas = df_in[~df_in["MOV_TIPO_MOVTO"].isin(["DS", "CA"])]
        return float(vendas["VALOR_TOTAL"].sum())

    def _valor_devolvido(df_in: pd.DataFrame) -> float:
        if df_in.empty:
            return 0.0
        dev = df_in[df_in["MOV_TIPO_MOVTO"].isin(["DS", "CA"])]
        return float(dev["VALOR_TOTAL"].sum())

    valor_atual = _valor_liquido(df_mes)
    valor_ano_passado = _valor_liquido(df_ano_passado)
    valor_mes_anterior = _valor_liquido(df_mes_ant)

    mix_atual = _mix(df_mes)
    mix_ano_passado = _mix(df_ano_passado)

    valor_bruto = _valor_bruto(df_mes)
    valor_devolvido = _valor_devolvido(df_mes)
    pct_devolucao = (valor_devolvido / valor_bruto * 100.0) if valor_bruto else None

    if valor_mes_anterior:
        crescimento = ((valor_atual - valor_mes_anterior) / abs(valor_mes_anterior)) * 100.0
    else:
        crescimento = None

    # Ranking por marca (líquido)
    if df_mes.empty:
        ranking = pd.Series(dtype=float)
    else:
        neg = df_mes["MOV_TIPO_MOVTO"].isin(["DS", "CA"])
        df_mes = df_mes.copy()
        df_mes["VALOR_ASSINADO"] = df_mes["VALOR_TOTAL"].where(~neg, -df_mes["VALOR_TOTAL"])
        ranking = df_mes.groupby("MARCA")["VALOR_ASSINADO"].sum().sort_values(ascending=False)

    total = float(ranking.sum()) if not ranking.empty else 0.0
    ranking_list = [
        {
            "marca": str(m),
            "valor": float(v),
            "pct": (float(v) / total * 100.0) if total else 0.0,
        }
        for m, v in ranking.items()
    ]

    ranking_top15_list = ranking_list[:15]

    return {
        "valor_atual": valor_atual,
        "valor_ano_passado": valor_ano_passado,
        "valor_mes_anterior": valor_mes_anterior,
        "mix_atual": mix_atual,
        "mix_ano_passado": mix_ano_passado,
        "valor_bruto": valor_bruto,
        "valor_devolvido": valor_devolvido,
        "pct_devolucao": pct_devolucao,
        "crescimento": crescimento,
        "ranking_list": ranking_list,
        "ranking_top15_list": ranking_top15_list,
        "total_liquido_periodo": total,
    }

def _bootstrap_admin_if_needed():
    """Cria o usuário ADMIN automaticamente se ainda não existir."""
    admin_user = os.getenv("BOOTSTRAP_ADMIN_USER", "ADMIN").strip().upper()
    admin_pass = os.getenv("BOOTSTRAP_ADMIN_PASSWORD")
    if not admin_pass:
        return

    with SessionLocal() as db:
        u = db.query(Usuario).filter(Usuario.username == admin_user).first()
        if u:
            return
        u = Usuario(
            username=admin_user,
            senha_hash=generate_password_hash(admin_pass),
            role="admin",
        )
        db.add(u)
        db.commit()
        app.logger.info("Usuario ADMIN criado automaticamente (%s)", admin_user)

_bootstrap_admin_if_needed()

def _mes_ano_from_request() -> tuple[int, int]:
    mes = int(request.args.get("mes") or datetime.now().month)
    ano = int(request.args.get("ano") or datetime.now().year)
    mes = max(1, min(12, mes))
    ano = max(2000, min(2100, ano))
    return mes, ano



def _periodo_bounds(ano: int, mes: int):
    """Retorna (inicio, fim) do mês para filtro por intervalo (usa índice)."""
    mes = max(1, min(12, int(mes)))
    ano = int(ano)
    start = date(ano, mes, 1)
    if mes == 12:
        end = date(ano + 1, 1, 1)
    else:
        end = date(ano, mes + 1, 1)
    return start, end



def _parse_num_ptbr(val: str | None) -> float:
    """Parseia número em formatos comuns PT-BR:
    - '118589,72'
    - '118.589,72'
    - '118589.72'
    - 'R$ 118.589,72'
    """
    if val is None:
        return 0.0
    s = str(val).strip()
    if not s:
        return 0.0
    # remove moeda e espaços
    s = re.sub(r'[^0-9,\.-]', '', s)
    if not s:
        return 0.0

    # Se tiver vírgula e ponto, assume ponto milhar e vírgula decimal (PT-BR)
    if ',' in s and '.' in s:
        # remove separador de milhar
        s = s.replace('.', '')
        s = s.replace(',', '.')
    elif ',' in s:
        s = s.replace(',', '.')
    # senão: já está em formato com ponto decimal ou inteiro
    try:
        return float(s)
    except Exception:
        return 0.0


def _emp_norm(emp: str | None) -> str:
    """Normaliza EMP para armazenamento ('' quando nulo)."""
    return (emp or "").strip()


def _parse_multi_args(name: str) -> list[str]:
    """Lê parâmetros repetidos via querystring (?emp=101&emp=102).
    Mantém compatibilidade com padrão antigo (?emp=101).
    """
    vals = []
    try:
        vals = request.args.getlist(name)
    except Exception:
        vals = []
    # Compat: alguns formulários antigos mandam apenas 1 valor em get()
    if not vals:
        v = (request.args.get(name) or "").strip()
        if v:
            vals = [v]
    # Aceita CSV (caso alguém copie/cole)
    out: list[str] = []
    for v in vals:
        for part in str(v).split(","):
            p = part.strip()
            if p:
                out.append(p)
    # unique mantendo ordem
    seen=set()
    res=[]
    for v in out:
        if v not in seen:
            seen.add(v); res.append(v)
    return res


def _parse_multi_args_from(args, name: str) -> list[str]:
    """Versão sem dependência direta de `request`, para uso em services."""
    vals = []
    try:
        if hasattr(args, "getlist"):
            vals = list(args.getlist(name))
        else:
            v = args.get(name) if hasattr(args, "get") else None
            vals = [v] if v else []
    except Exception:
        vals = []

    if not vals:
        try:
            v = (args.get(name) or "").strip()
        except Exception:
            v = ""
        if v:
            vals = [v]

    out: list[str] = []
    for v in vals:
        for part in str(v).split(","):
            p = part.strip()
            if p:
                out.append(p)

    seen = set()
    res = []
    for v in out:
        if v not in seen:
            seen.add(v)
            res.append(v)
    return res

def _competencia_fechada(db, emp: str, ano: int, mes: int) -> bool:
    """Retorna True se a competência (EMP+ano+mes) estiver marcada como FECHADA."""
    emp = _emp_norm(emp)
    if not emp:
        return False
    try:
        rec = (
            db.query(FechamentoMensal)
            .filter(
                FechamentoMensal.emp == emp,
                FechamentoMensal.ano == int(ano),
                FechamentoMensal.mes == int(mes),
                FechamentoMensal.fechado.is_(True),
            )
            .first()
        )
        return bool(rec)
    except Exception:
        return False




def _emp_to_int_safe(emp: str) -> int | str:
    """Regra crítica: EMP é numérico na base de vendas.
    Sempre converte antes de comparar/filtrar para não zerar totais.
    """
    s = str(emp).strip()
    return int(s) if s.isdigit() else s


def _get_emp_options(codigos: list[str]) -> list[dict]:
    """Retorna opções de EMP com label amigável (ex: 101 - Veipecas)."""
    codigos = [str(c).strip() for c in (codigos or []) if str(c).strip()]
    if not codigos:
        return []
    # mantém ordem original
    uniq=[]
    seen=set()
    for c in codigos:
        if c not in seen:
            seen.add(c); uniq.append(c)
    rows = {}
    try:
        with SessionLocal() as db:
            for r in db.query(Emp).filter(Emp.codigo.in_(uniq)).all():
                rows[str(r.codigo).strip()] = r
    except Exception:
        rows = {}
    out=[]
    for c in uniq:
        r = rows.get(c)
        if r and (r.nome or '').strip():
            label = f"{c} - {(r.nome or '').strip()}"
        else:
            label = c
        out.append({"value": c, "label": label})
    return out


def _filter_emps_cadastradas(codigos: list[str], apenas_ativas: bool = True) -> list[str]:
    """Remove EMPs que não estão cadastradas na tabela `emps` (ou inativas, se `apenas_ativas`).
    Mantém ordem e faz strip.
    """
    codigos = [str(c).strip() for c in (codigos or []) if str(c).strip()]
    if not codigos:
        return []
    # mantém ordem
    uniq = []
    seen = set()
    for c in codigos:
        if c not in seen:
            seen.add(c)
            uniq.append(c)

    try:
        with SessionLocal() as db:
            q = db.query(Emp.codigo)
            q = q.filter(Emp.codigo.in_(uniq))
            if apenas_ativas:
                q = q.filter(Emp.ativo.is_(True))
            rows = q.all()
            ok = {str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip()}
    except Exception:
        ok = set()

    if not ok:
        # Sem cadastro disponível/consultável → não filtra (compatibilidade)
        return uniq

    return [c for c in uniq if c in ok]


def _get_vendedores_cadastrados_por_emp(emp: str) -> set[str]:
    """Retorna conjunto de vendedores cadastrados e vinculados à EMP (via usuario_emps).
    Se não houver vínculo, retorna conjunto global de vendedores cadastrados.
    """
    emp = (emp or "").strip()
    if not emp:
        return set()

    try:
        with SessionLocal() as db:
            # 1) Vendedores vinculados à EMP
            rows = (
                db.query(Usuario.username)
                .join(UsuarioEmp, UsuarioEmp.usuario_id == Usuario.id)
                .filter(func.lower(Usuario.role) == "vendedor")
                .filter(UsuarioEmp.ativo.is_(True))
                .filter(UsuarioEmp.emp == emp)
                .all()
            )
            vinc = {(r[0] or "").strip().upper() for r in rows if r and (r[0] or "").strip()}
            if vinc:
                return vinc

            # 2) fallback: vendedores cadastrados (global)
            rows2 = db.query(Usuario.username).filter(func.lower(Usuario.role) == "vendedor").all()
            glob = {(r[0] or "").strip().upper() for r in rows2 if r and (r[0] or "").strip()}
            return glob
    except Exception:
        return set()


# Compat: services recebem `args` explicitamente (evita dependência direta do `request` no service).
def _parse_multi_args_from(args, name: str) -> list[str]:
    try:
        if hasattr(args, "getlist"):
            vals = args.getlist(name)
        else:
            vals = args.get(name)
            vals = vals if isinstance(vals, list) else ([vals] if vals else [])
        return [str(v).strip() for v in vals if str(v).strip()]
    except Exception:
        return []



def _get_all_emp_codigos(apenas_ativas: bool = True) -> list[str]:
    """Lista todas as EMPs cadastradas (tabela emps).
    Usado para Admin quando estiver em modo __ALL__ (todos vendedores) e não houver filtro de EMP.
    """
    try:
        with SessionLocal() as db:
            q = db.query(Emp.codigo)
            if apenas_ativas:
                q = q.filter(Emp.ativo.is_(True))
            rows = q.order_by(Emp.codigo.asc()).all()
            cods = [str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip()]
            if cods:
                return cods
    except Exception:
        pass
    # fallback: tenta inferir via vendas
    try:
        with SessionLocal() as db:
            rows = db.query(Venda.emp).distinct().order_by(Venda.emp.asc()).all()
            cods = [str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip()]
            return cods
    except Exception:
        return []


def _mes_fechado(emp: str | None, ano: int, mes: int) -> bool:
    """Retorna True se o mês estiver marcado como fechado para a EMP."""
    emp_n = _emp_norm(emp)
    with SessionLocal() as db:
        row = (
            db.query(FechamentoMensal)
            .filter(FechamentoMensal.emp == emp_n, FechamentoMensal.ano == ano, FechamentoMensal.mes == mes)
            .first()
        )
        return bool(row and row.fechado)

def _vendedores_from_db(role: str, emp_usuario: str | None):
    """Lista de vendedores disponível para dropdown (sem carregar dataframe inteiro)."""
    role = (role or '').strip().lower()
    usuario_logado = (session.get('usuario') or '').strip().upper()
    if role == 'vendedor':
        return [usuario_logado] if usuario_logado else []

    with SessionLocal() as db:
        q = db.query(Venda.vendedor).distinct()
        if role == 'supervisor':
            if not emp_usuario:
                return []
            q = q.filter(Venda.emp == str(emp_usuario))
        vendedores = [ (v[0] or '').strip().upper() for v in q.all() ]
    vendedores = sorted([v for v in vendedores if v])
    return vendedores


def _cache_is_fresh(row: DashboardCache) -> bool:
    """Retorna True se a linha do cache ainda está dentro do TTL."""
    try:
        ts = getattr(row, "atualizado_em", None) or getattr(row, "updated_at", None)
        if not ts:
            return False
        # ts pode vir timezone-aware ou naive; normaliza pra naive UTC
        if getattr(ts, "tzinfo", None) is not None:
            ts = ts.replace(tzinfo=None)
        limite = datetime.utcnow() - timedelta(hours=float(CACHE_TTL_HOURS or 0))
        return ts >= limite
    except Exception:
        return False

def _get_cache_row(vendedor: str, ano: int, mes: int, emp_scope: str | None):
    vendedor = (vendedor or '').strip().upper()
    if not vendedor:
        return None
    with SessionLocal() as db:
        if emp_scope:
            row = db.query(DashboardCache).filter(
                DashboardCache.emp == str(emp_scope),
                DashboardCache.vendedor == vendedor,
                DashboardCache.ano == int(ano),
                DashboardCache.mes == int(mes),
            ).first()
            if not row or not _cache_is_fresh(row):
                return None
            return row

        # ADMIN/VENDEDOR sem EMP: soma múltiplas EMPs
        rows = db.query(DashboardCache).filter(
            DashboardCache.vendedor == vendedor,
            DashboardCache.ano == int(ano),
            DashboardCache.mes == int(mes),
        ).all()
        if not rows:
            return None

        # cria um objeto "fake" com os totais somados
        agg = DashboardCache(emp='*', vendedor=vendedor, ano=int(ano), mes=int(mes))
        agg.valor_bruto = sum(r.valor_bruto or 0 for r in rows)
        agg.valor_liquido = sum(r.valor_liquido or 0 for r in rows)
        agg.devolucoes = sum(r.devolucoes or 0 for r in rows)
        agg.cancelamentos = sum(r.cancelamentos or 0 for r in rows)
        agg.pct_devolucao = (agg.devolucoes / agg.valor_bruto * 100.0) if agg.valor_bruto else 0.0
        agg.mix_produtos = sum(r.mix_produtos or 0 for r in rows)
        agg.mix_marcas = sum(r.mix_marcas or 0 for r in rows)

        # agrega ranking por marca somando valores
        marca_map = {}
        total = 0.0
        for r in rows:
            try:
                lst = json.loads(r.ranking_json or '[]')
            except Exception:
                lst = []
            for it in lst:
                m = (it.get('marca') or '').strip()
                v = float(it.get('valor') or 0.0)
                marca_map[m] = marca_map.get(m, 0.0) + v
                total += v
        ranking = sorted([
            {'marca': m, 'valor': val, 'pct': (val/total*100.0) if total else 0.0}
            for m, val in marca_map.items()
        ], key=lambda x: x['valor'], reverse=True)
        agg.ranking_json = json.dumps(ranking, ensure_ascii=False)
        agg.ranking_top15_json = json.dumps(ranking[:15], ensure_ascii=False)
        agg.total_liquido_periodo = total
        return agg



def _ano_passado_valor_mix(vendedor: str, ano: int, mes: int, emp_scope: str | None) -> tuple[float, int]:
    """Retorna (valor_liquido, mix_produtos) para o mesmo mês do ano anterior.

    Regra:
    1) Se existir venda detalhada em `vendas` para o período (ano-1, mes), usa vendas (fonte real).
    2) Se não existir, faz fallback para `vendas_resumo_periodo` (cadastro manual/importação consolidada).

    Observação:
    - Quando emp_scope for None (admin/vendedor), agrega todas as EMPs.
    - Quando emp_scope existir (supervisor), filtra pela EMP do supervisor.
    """
    vendedor = (vendedor or '').strip().upper()
    if not vendedor:
        return 0.0, 0

    ano_passado = int(ano) - 1
    start, end = _periodo_bounds(ano_passado, int(mes))

    try:
        with SessionLocal() as db:
            q_cnt = db.query(func.count()).select_from(Venda).filter(
                Venda.vendedor == vendedor,
                Venda.movimento >= start,
                Venda.movimento < end,
            )
            if emp_scope:
                q_cnt = q_cnt.filter(Venda.emp == str(emp_scope))
            cnt = int(q_cnt.scalar() or 0)

            if cnt > 0:
                signed = case(
                    (Venda.mov_tipo_movto.in_(['DS', 'CA']), -Venda.valor_total),
                    else_=Venda.valor_total,
                )
                liquido = func.coalesce(func.sum(signed), 0.0)
                mix = func.count(func.distinct(case((~Venda.mov_tipo_movto.in_(['DS', 'CA']), Venda.mestre), else_=None)))

                row = (
                    db.query(liquido, mix)
                    .select_from(Venda)
                    .filter(
                        Venda.vendedor == vendedor,
                        Venda.movimento >= start,
                        Venda.movimento < end,
                    )
                )
                if emp_scope:
                    row = row.filter(Venda.emp == str(emp_scope))
                r = row.first()
                return float(r[0] or 0.0), int(r[1] or 0)

            # Fallback: resumo manual (vendas_resumo_periodo)
            base_sql = """
                select
                  coalesce(sum(valor_venda), 0) as valor,
                  coalesce(sum(mix_produtos), 0) as mix
                from public.vendas_resumo_periodo
                where vendedor = :vendedor
                  and ano = :ano
                  and mes = :mes
            """
            params = {"vendedor": vendedor, "ano": int(ano_passado), "mes": int(mes)}

            if emp_scope:
                base_sql += " and coalesce(emp,'') = :emp"
                params["emp"] = str(emp_scope).strip()

            row_sum = db.execute(text(base_sql), params).mappings().first()
            if row_sum:
                return float(row_sum.get('valor', 0) or 0.0), int(row_sum.get('mix', 0) or 0)

    except Exception:
        try:
            app.logger.exception("Erro ao buscar dados do ano passado")
        except Exception:
            pass

    return 0.0, 0

def _dados_from_cache(vendedor_alvo, mes, ano, emp_scope):
    """Carrega os dados do dashboard a partir do cache (dashboard_cache).

    Regra para *Ano passado*:
    - Se existir venda detalhada em `vendas` no (ano-1, mesmo mês), usa esse valor (mais fiel).
    - Se não existir, faz fallback para `vendas_resumo_periodo` (cadastro manual/consolidado).
    """

    row = _get_cache_row(vendedor_alvo, ano, mes, emp_scope)
    if not row:
        return None

    # ---- valores atuais (do cache) ----
    valor_atual = float(getattr(row, "valor_liquido", 0) or 0)
    valor_bruto = float(getattr(row, "valor_bruto", 0) or 0)

    devolucoes = float(getattr(row, "devolucoes", 0) or 0)
    cancelamentos = float(getattr(row, "cancelamentos", 0) or 0)
    valor_devolvido = devolucoes + cancelamentos

    pct_devolucao = float(getattr(row, "pct_devolucao", 0) or 0)
    mix_atual = int(getattr(row, "mix_produtos", 0) or 0)

    total_liquido_periodo = float(getattr(row, "total_liquido_periodo", None) or valor_atual)

    # ---- mês anterior ----
    if mes == 1:
        prev_mes, prev_ano = 12, ano - 1
    else:
        prev_mes, prev_ano = mes - 1, ano

    prev_row = _get_cache_row(vendedor_alvo, prev_ano, prev_mes, emp_scope)
    if prev_row:
        valor_mes_anterior = float(getattr(prev_row, "valor_liquido", 0) or 0)
    else:
        # Fallback: quando o cache do mês anterior ainda não existe (muito comum),
        # calcula o líquido do mês anterior ao vivo para não mostrar "R$ 0,00" indevidamente.
        try:
            s_ant = date(prev_ano, prev_mes, 1)
            e_ant = date(prev_ano + 1, 1, 1) if prev_mes == 12 else date(prev_ano, prev_mes + 1, 1)

            with SessionLocal() as db:
                q = db.query(Venda).filter(Venda.vendedor == vendedor_alvo)

                if emp_scope:
                    if isinstance(emp_scope, (list, tuple, set)):
                        emps = [str(e).strip() for e in emp_scope if e is not None and str(e).strip()]
                        if emps:
                            q = q.filter(Venda.emp.in_(emps))
                    else:
                        q = q.filter(Venda.emp == str(emp_scope))

                signed = case((Venda.mov_tipo_movto.in_(['DS','CA']), -Venda.valor_total), else_=Venda.valor_total)
                valor_mes_anterior = float(q.filter(Venda.movimento >= s_ant, Venda.movimento < e_ant)
                                          .with_entities(func.coalesce(func.sum(signed), 0.0))
                                          .scalar() or 0.0)
        except Exception:
            app.logger.exception("Erro ao calcular mês anterior ao vivo")
            valor_mes_anterior = 0.0

    crescimento_mes_anterior = None
    if prev_row and valor_mes_anterior != 0:
        crescimento_mes_anterior = ((valor_atual - valor_mes_anterior) / valor_mes_anterior) * 100.0

    # ---- ano passado (vendas real -> fallback resumo_periodo) ----
    valor_ano_passado, mix_ano_passado = _ano_passado_valor_mix(
        vendedor_alvo,
        ano=ano,
        mes=mes,
        emp_scope=emp_scope,
    )

    # ---- ranking ----
    ranking_list = []
    ranking_top15_list = []
    try:
        if getattr(row, "ranking_json", None):
            ranking_list = json.loads(row.ranking_json) or []
    except Exception:
        ranking_list = []
    try:
        if getattr(row, "ranking_top15_json", None):
            ranking_top15_list = json.loads(row.ranking_top15_json) or []
    except Exception:
        ranking_top15_list = []

    return {
        "valor_atual": valor_atual,
        "valor_bruto": valor_bruto,
        "valor_devolvido": valor_devolvido,
        "pct_devolucao": pct_devolucao,
        "mix_atual": mix_atual,
        "valor_mes_anterior": valor_mes_anterior,
        "crescimento_mes_anterior": crescimento_mes_anterior,
        "crescimento": crescimento_mes_anterior,
        "valor_ano_passado": valor_ano_passado,
        "mix_ano_passado": mix_ano_passado,
        "ranking_list": ranking_list,
        "ranking_top15_list": ranking_top15_list,
        "total_liquido_periodo": total_liquido_periodo,
    }

def _dados_ao_vivo(vendedor: str, mes: int, ano: int, emp_scope: str | list[str] | None):
    """Calcula o dashboard direto do banco (sem pandas).

    Usado apenas quando o cache ainda não existe para aquele período.
    """
    vendedor = (vendedor or '').strip().upper()
    if not vendedor:
        return None

    # intervalos
    start = date(ano, mes, 1)
    end = date(ano + 1, 1, 1) if mes == 12 else date(ano, mes + 1, 1)

    def _range(ay, mm):
        s = date(ay, mm, 1)
        e = date(ay + 1, 1, 1) if mm == 12 else date(ay, mm + 1, 1)
        return s, e

    if mes == 1:
        mes_ant, ano_ant = 12, ano - 1
    else:
        mes_ant, ano_ant = mes - 1, ano

    s_ant, e_ant = _range(ano_ant, mes_ant)
    s_ano_passado, e_ano_passado = _range(ano - 1, mes)

    with SessionLocal() as db:
        base = db.query(Venda).filter(Venda.vendedor == vendedor)
        if emp_scope:
            if isinstance(emp_scope, (list, tuple, set)):
                emps = [str(e).strip() for e in emp_scope if e is not None and str(e).strip()]
                if emps:
                    base = base.filter(Venda.emp.in_(emps))
            else:
                base = base.filter(Venda.emp == str(emp_scope))
        def sums(s, e):
            q = base.filter(Venda.movimento >= s, Venda.movimento < e)
            signed = case((Venda.mov_tipo_movto.in_(['DS','CA']), -Venda.valor_total), else_=Venda.valor_total)
            bruto = func.coalesce(func.sum(case((~Venda.mov_tipo_movto.in_(['DS','CA']), Venda.valor_total), else_=0.0)), 0.0)
            devol = func.coalesce(func.sum(case((Venda.mov_tipo_movto.in_(['DS','CA']), Venda.valor_total), else_=0.0)), 0.0)
            liquido = func.coalesce(func.sum(signed), 0.0)
            mix = func.count(func.distinct(case((~Venda.mov_tipo_movto.in_(['DS','CA']), Venda.mestre), else_=None)))

            row = q.with_entities(bruto, devol, liquido, mix).first()
            return float(row[0] or 0.0), float(row[1] or 0.0), float(row[2] or 0.0), int(row[3] or 0)

        bruto, devol, liquido, mix = sums(start, end)
        bruto_ant, devol_ant, liquido_ant, mix_ant = sums(s_ant, e_ant)
        bruto_ano_pass, devol_ano_pass, liquido_ano_pass, mix_ano_pass = sums(s_ano_passado, e_ano_passado)

        pct_devolucao = (devol / bruto * 100.0) if bruto else None
        crescimento = ((liquido - liquido_ant) / abs(liquido_ant) * 100.0) if liquido_ant else None

        # Ano passado: vendas real (se existir) -> fallback resumo_periodo
        liquido_ano_pass, mix_ano_pass = _ano_passado_valor_mix(
            vendedor,
            ano=ano,
            mes=mes,
            emp_scope=emp_scope,
        )
        # ranking por marca (líquido)
        signed = case((Venda.mov_tipo_movto.in_(['DS','CA']), -Venda.valor_total), else_=Venda.valor_total)
        q_rank = base.filter(Venda.movimento >= start, Venda.movimento < end)\
            .with_entities(Venda.marca, func.coalesce(func.sum(signed), 0.0))\
            .group_by(Venda.marca)
        rows = q_rank.all()
        ranking = sorted([(str(m or ''), float(v or 0.0)) for m,v in rows], key=lambda x: x[1], reverse=True)
        total = sum(v for _,v in ranking)
        ranking_list = [
            {'marca': m, 'valor': v, 'pct': (v/total*100.0) if total else 0.0}
            for m,v in ranking
        ]
        return {
            'valor_atual': liquido,
            'valor_ano_passado': liquido_ano_pass,
            'valor_mes_anterior': liquido_ant,
            'mix_atual': mix,
            'mix_ano_passado': mix_ano_pass,
            'valor_bruto': bruto,
            'valor_devolvido': devol,
            'pct_devolucao': pct_devolucao,
            'crescimento': crescimento,
            'ranking_list': ranking_list,
            'ranking_top15_list': ranking_list[:15],
            'total_liquido_periodo': total,
        }
def _resolver_vendedor_e_lista(df: pd.DataFrame | None) -> tuple[str | None, list[str], str | None, str | None]:
    """Resolve qual vendedor o usuário pode ver.

    Retorna: (vendedor_alvo, lista_vendedores, emp_usuario, aviso)
    - vendedor_alvo pode ser None quando ADMIN/SUPERVISOR ainda não selecionou.
    - lista_vendedores é usada no dropdown para ADMIN/SUPERVISOR.
    - emp_usuario é a EMP do supervisor (quando existir).
    - aviso é uma mensagem opcional para exibir na tela.
    """
    role = (session.get("role") or "").strip().lower()
    # No login o app grava session["usuario"].
    usuario_logado = (session.get("usuario") or "").strip().upper()
    df = _normalize_cols(df)

    # Lista base de vendedores (da tabela de vendas, pois a tabela usuarios pode não ter EMP preenchida)
    if df is None or df.empty or "VENDEDOR" not in df.columns:
        # fallback leve: busca direto do banco
        vendedores = _get_vendedores_db(role, _emp())
        if (role == 'vendedor'):
            return usuario_logado, [], _emp(), None
        if not vendedores:
            return None, [], _emp(), 'Sem dados de vendas para montar a lista de vendedores.'
        vendedor_req = (request.args.get('vendedor') or '').strip().upper() or None
        vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores) else None
        return vendedor_alvo, vendedores, _emp(), None

    emp_usuario = _emp()
    if role == "supervisor":
        if not emp_usuario:
            return None, [], None, "Supervisor sem EMP cadastrada. Cadastre a EMP do supervisor na tabela usuarios."
        df_scope = df[df["EMP"] == str(emp_usuario)] if "EMP" in df.columns else df.iloc[0:0]
    elif role == "admin":
        df_scope = df
    else:
        # vendedor
        return usuario_logado, [], emp_usuario, None

    vendedores = (
        df_scope["VENDEDOR"].dropna().astype(str).str.strip().str.upper().unique().tolist()
        if not df_scope.empty
        else []
    )
    vendedores = sorted([v for v in vendedores if v])

    vendedor_req = (request.args.get("vendedor") or "").strip().upper() or None
    vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores) else None

    if not vendedores:
        # Ajuda a diagnosticar: existe EMP no df?
        if role == "supervisor" and emp_usuario:
            return None, [], emp_usuario, f"Nenhum vendedor encontrado para EMP {emp_usuario}. Verifique se a coluna EMP na tabela vendas está preenchida com {emp_usuario}."
        return None, [], emp_usuario, "Nenhum vendedor encontrado."

    return vendedor_alvo, vendedores, emp_usuario, None

# ------------- Rotas -------------
@app.route("/healthz", methods=["GET", "HEAD"])
def healthz():
    # Health check must be ultra-light and never require auth/DB
    return ("OK", 200)

@app.route("/", methods=["GET", "HEAD"])
def home():
    # Render/health-check friendly: return 200 for HEAD (and for Go-http-client probes)
    ua = (request.headers.get("User-Agent") or "").lower()
    if request.method == "HEAD" or "go-http-client" in ua:
        return ("OK", 200)

    # Browser/users: redirect to the right place
    if session.get("vendedor") and session.get("role"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("auth.login"))

@app.get("/favicon.ico")
def favicon():
    # Avoid noisy 404s in logs
    return ("", 204)


def _dados_admin_geral(mes: int, ano: int, emp_scope: list[str] | None = None):
    """Visão geral do ADMIN quando nenhum vendedor é selecionado.

    Mantém as mesmas regras de sinal (DS/CA negativos) usadas no dashboard por vendedor,
    mas agrega por EMP (e também gera ranking de vendedores do período).
    """
    start = date(ano, mes, 1)
    end = date(ano + 1, 1, 1) if mes == 12 else date(ano, mes + 1, 1)

    signed = case((Venda.mov_tipo_movto.in_(['DS','CA']), -Venda.valor_total), else_=Venda.valor_total)

    with SessionLocal() as db:
        base = db.query(Venda).filter(Venda.movimento >= start, Venda.movimento < end)
        if emp_scope:
            emps = [str(e).strip() for e in emp_scope if e is not None and str(e).strip()]
            if emps:
                base = base.filter(Venda.emp.in_(emps))

        bruto_expr = func.coalesce(func.sum(case((~Venda.mov_tipo_movto.in_(['DS','CA']), Venda.valor_total), else_=0.0)), 0.0)
        devol_expr = func.coalesce(func.sum(case((Venda.mov_tipo_movto.in_(['DS','CA']), Venda.valor_total), else_=0.0)), 0.0)
        liquido_expr = func.coalesce(func.sum(signed), 0.0)

        total_row = base.with_entities(bruto_expr, devol_expr, liquido_expr).first()
        total_bruto = float(total_row[0] or 0.0)
        total_devol = float(total_row[1] or 0.0)
        total_liquido = float(total_row[2] or 0.0)
        pct_devolucao = (total_devol / total_bruto * 100.0) if total_bruto else None

        # Por EMP
        q_emp = (
            base.with_entities(Venda.emp, bruto_expr.label("bruto"), devol_expr.label("devol"), liquido_expr.label("liquido"))
            .group_by(Venda.emp)
        )
        emp_rows = []
        for emp, bruto, devol, liquido in q_emp:
            emp_rows.append({
                "emp": (emp or "").strip(),
                "valor_bruto": float(bruto or 0.0),
                "valor_devolvido": float(devol or 0.0),
                "valor_atual": float(liquido or 0.0),
            })
        emp_rows.sort(key=lambda r: r.get("valor_atual", 0.0), reverse=True)

        # Top vendedores (líquido) – útil para drill-down rápido
        q_vend = (
            base.with_entities(Venda.vendedor, func.coalesce(func.sum(signed), 0.0))
            .group_by(Venda.vendedor)
        )
        vend_rows = [{"vendedor": (v or "").strip().upper(), "valor": float(val or 0.0)} for v, val in q_vend]
        vend_rows.sort(key=lambda r: r["valor"], reverse=True)

    return {
        "valor_bruto": total_bruto,
        "valor_devolvido": total_devol,
        "valor_atual": total_liquido,
        "pct_devolucao": pct_devolucao,
        "ranking_emp_list": emp_rows[:30],
        "ranking_vendedores_list": vend_rows[:30],
    }



def _periodo_prev(ano: int, mes: int) -> tuple[int, int]:
    if int(mes) == 1:
        return int(ano) - 1, 12
    return int(ano), int(mes) - 1

def _signed_expr():
    return case((Venda.mov_tipo_movto.in_(["DS", "CA"]), -Venda.valor_total), else_=Venda.valor_total)

def _clientes_destaque(vendedor: str, ano: int, mes: int, emp_scope: str | None, topn: int = 5) -> dict:
    """Top clientes por crescimento/queda vs mês anterior (ΔR$ e Δ%)."""
    vendedor = (vendedor or "").strip().upper()
    if not vendedor:
        return {"crescimento": [], "queda": []}

    ano_prev, mes_prev = _periodo_prev(ano, mes)
    start, end = _periodo_bounds(int(ano), int(mes))
    start_prev, end_prev = _periodo_bounds(int(ano_prev), int(mes_prev))
    signed = _signed_expr()

    with SessionLocal() as db:
        base_cur = db.query(Venda).filter(
            func.upper(Venda.vendedor) == vendedor,
            Venda.movimento >= start,
            Venda.movimento < end,
            Venda.cliente_id_norm.isnot(None),
        )
        base_prev = db.query(Venda).filter(
            func.upper(Venda.vendedor) == vendedor,
            Venda.movimento >= start_prev,
            Venda.movimento < end_prev,
            Venda.cliente_id_norm.isnot(None),
        )
        if emp_scope:
            base_cur = base_cur.filter(Venda.emp == str(emp_scope))
            base_prev = base_prev.filter(Venda.emp == str(emp_scope))

        cur_rows = (
            base_cur.with_entities(
                Venda.cliente_id_norm.label("cid"),
                func.coalesce(func.max(Venda.razao), "").label("label"),
                func.coalesce(func.sum(signed), 0.0).label("total"),
            )
            .group_by(Venda.cliente_id_norm)
            .all()
        )
        prev_rows = (
            base_prev.with_entities(
                Venda.cliente_id_norm.label("cid"),
                func.coalesce(func.max(Venda.razao), "").label("label"),
                func.coalesce(func.sum(signed), 0.0).label("total"),
            )
            .group_by(Venda.cliente_id_norm)
            .all()
        )

    cur = {str(r.cid): {"label": (r.label or "").strip(), "total": float(r.total or 0.0)} for r in cur_rows}
    prev = {str(r.cid): {"label": (r.label or "").strip(), "total": float(r.total or 0.0)} for r in prev_rows}

    all_ids = set(cur.keys()) | set(prev.keys())
    items = []
    for cid in all_ids:
        c = cur.get(cid, {"label": "", "total": 0.0})
        p = prev.get(cid, {"label": "", "total": 0.0})
        atual = float(c["total"] or 0.0)
        ant = float(p["total"] or 0.0)
        delta = atual - ant
        # label: prefere atual, senão anterior, senão cid
        label = c["label"] or p["label"] or cid
        pct = None
        if ant != 0:
            pct = (delta / ant) * 100.0
        elif atual != 0:
            pct = 100.0
        items.append({
            "cliente_id": cid,
            "cliente": label,
            "atual": atual,
            "anterior": ant,
            "delta": delta,
            "pct": pct,
        })

    crescimento = sorted([x for x in items if x["delta"] > 0], key=lambda x: x["delta"], reverse=True)[:topn]
    queda = sorted([x for x in items if x["delta"] < 0], key=lambda x: x["delta"])[:topn]

    return {"crescimento": crescimento, "queda": queda}

def _dashboard_insights(vendedor: str, ano: int, mes: int, emp_scope: str | list[str] | None) -> dict | None:
    """Insights leves para cards do dashboard (cidade/cliente destaque e novos/recorrentes)."""
    vendedor = (vendedor or "").strip().upper()
    if not vendedor:
        return None

    signed = _signed_expr()
    start, end = _periodo_bounds(int(ano), int(mes))
    ano_prev, mes_prev = _periodo_prev(ano, mes)
    start_prev, end_prev = _periodo_bounds(int(ano_prev), int(mes_prev))

    with SessionLocal() as db:
        base = db.query(Venda).filter(
            func.upper(Venda.vendedor) == vendedor,
            Venda.movimento >= start,
            Venda.movimento < end,
        )
        base_prev = db.query(Venda).filter(
            func.upper(Venda.vendedor) == vendedor,
            Venda.movimento >= start_prev,
            Venda.movimento < end_prev,
        )
        base_hist = db.query(Venda).filter(func.upper(Venda.vendedor) == vendedor, Venda.movimento.isnot(None))

        if emp_scope:
            if isinstance(emp_scope, (list, tuple, set)):
                emps = [str(e).strip() for e in emp_scope if e is not None and str(e).strip()]
                if emps:
                    base = base.filter(Venda.emp.in_(emps))
                    base_prev = base_prev.filter(Venda.emp.in_(emps))
                    base_hist = base_hist.filter(Venda.emp.in_(emps))
            else:
                base = base.filter(Venda.emp == str(emp_scope))
                base_prev = base_prev.filter(Venda.emp == str(emp_scope))
                base_hist = base_hist.filter(Venda.emp == str(emp_scope))

        # Cidade destaque (por valor líquido)
        city_cur = (
            base.with_entities(
                func.coalesce(Venda.cidade_norm, "sem_cidade").label("cidade_norm"),
                func.coalesce(func.sum(signed), 0.0).label("total"),
            )
            .group_by(func.coalesce(Venda.cidade_norm, "sem_cidade"))
            .order_by(func.coalesce(func.sum(signed), 0.0).desc())
            .first()
        )
        cidade_destaque = None
        if city_cur:
            cidade_destaque = {"cidade_norm": (city_cur.cidade_norm or "SEM CIDADE").upper(), "total_vendido": float(city_cur.total or 0.0)}

        # Cidade em queda (variação vs mês anterior)
        prev_map_rows = (
            base_prev.with_entities(
                func.coalesce(Venda.cidade_norm, "sem_cidade").label("cidade_norm"),
                func.coalesce(func.sum(signed), 0.0).label("total"),
            )
            .group_by(func.coalesce(Venda.cidade_norm, "sem_cidade"))
            .all()
        )
        prev_map = {str(r.cidade_norm): float(r.total or 0.0) for r in prev_map_rows}
        queda_item = None
        if city_cur:
            # computa variações para cidades com base anterior
            cur_rows = (
                base.with_entities(
                    func.coalesce(Venda.cidade_norm, "sem_cidade").label("cidade_norm"),
                    func.coalesce(func.sum(signed), 0.0).label("total"),
                )
                .group_by(func.coalesce(Venda.cidade_norm, "sem_cidade"))
                .all()
            )
            variacoes = []
            for r in cur_rows:
                k = str(r.cidade_norm)
                ant = prev_map.get(k, 0.0)
                if ant == 0:
                    continue
                curv = float(r.total or 0.0)
                variacoes.append({"cidade_norm": (k or "sem_cidade").upper(), "variacao": curv - ant})
            variacoes = sorted(variacoes, key=lambda x: x["variacao"])
            if variacoes and variacoes[0]["variacao"] < 0:
                queda_item = variacoes[0]

        # Clientes novos vs recorrentes (pelo 1º movimento do cliente)
        clientes_periodo = (
            base.with_entities(Venda.cliente_id_norm.label("cid"))
            .filter(Venda.cliente_id_norm.isnot(None))
            .distinct()
            .subquery()
        )
        min_datas = (
            base_hist.with_entities(
                Venda.cliente_id_norm.label("cid"),
                func.min(Venda.movimento).label("min_data"),
            )
            .filter(Venda.cliente_id_norm.isnot(None))
            .group_by(Venda.cliente_id_norm)
            .subquery()
        )

        novos = (
            db.query(func.count())
            .select_from(clientes_periodo.join(min_datas, clientes_periodo.c.cid == min_datas.c.cid))
            .filter(min_datas.c.min_data >= start)
            .scalar()
        ) or 0
        recorr = (
            db.query(func.count())
            .select_from(clientes_periodo.join(min_datas, clientes_periodo.c.cid == min_datas.c.cid))
            .filter(min_datas.c.min_data < start)
            .scalar()
        ) or 0

    clientes_destaque = _clientes_destaque(vendedor, ano, mes, emp_scope, topn=3)

    return {
        "cidade_destaque": cidade_destaque or {"cidade_norm": "—", "total_vendido": 0.0},
        "cidade_queda": queda_item,
        "clientes_novos": int(novos),
        "clientes_recorrentes": int(recorr),
        "clientes_destaque": clientes_destaque,
    }



@app.get("/dashboard")
def dashboard():
    red = _login_required()
    if red:
        return red

    mes, ano = _mes_ano_from_request()

    role = _role() or ""
    emp_usuario = _emp()
    allowed_emps = _allowed_emps()

    # Resolve vendedor alvo + lista para dropdown sem carregar toda a tabela em memória
    if role == "vendedor":
        vendedor_alvo = (_usuario_logado() or "").strip().upper()
        vendedores_lista = []
        msg = None
    else:
        vendedores_lista = _get_vendedores_db(role, emp_usuario)
        vendedor_req = (request.args.get("vendedor") or "").strip().upper() or None
        vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores_lista) else None
        msg = None
        if role == "supervisor" and not allowed_emps:
            msg = "Supervisor sem EMP vinculada. Cadastre EMPs do supervisor em usuario_emps."

    dados = None
    if vendedor_alvo:
        try:
            emp_scope = (allowed_emps if (role or '').lower() in ['supervisor','vendedor'] else None)
            dados = _dados_from_cache(vendedor_alvo, mes, ano, emp_scope)
        except Exception:
            app.logger.exception("Erro ao carregar dashboard do cache")
            dados = None

        # Fallback: calcula ao vivo (sem pandas) se cache ainda não existe
        if dados is None:
            try:
                emp_scope = (allowed_emps if (role or '').lower() in ['supervisor','vendedor'] else None)
                dados = _dados_ao_vivo(vendedor_alvo, mes, ano, emp_scope)
            except Exception:
                app.logger.exception("Erro ao calcular dashboard ao vivo")
                dados = None

    insights = None
    if vendedor_alvo:
        try:
            emp_scope = (allowed_emps if (role or '').lower() in ['supervisor','vendedor'] else None)
            insights = _dashboard_insights(vendedor_alvo, ano=ano, mes=mes, emp_scope=emp_scope)
        except Exception:
            app.logger.exception("Erro ao calcular insights do dashboard")
            insights = None

    
    dados_admin = None
    if (role or '').lower() == "admin" and not vendedor_alvo:
        try:
            dados_admin = _dados_admin_geral(mes=mes, ano=ano)
        except Exception:
            app.logger.exception("Erro ao carregar dashboard geral do admin")
            dados_admin = None

    return render_template(
        "dashboard.html",
        insights=insights,
        vendedor=vendedor_alvo or "",
        usuario=_usuario_logado(),
        role=_role(),
        emp=(" / ".join(allowed_emps) if (role or '').lower()=="supervisor" and allowed_emps else emp_usuario),
        vendedores=vendedores_lista,
        vendedor_selecionado=vendedor_alvo or "",
        mensagem_role=msg,
        mes=mes,
        ano=ano,
        dados=dados,
        dados_admin=dados_admin,
        admin_geral=(bool(dados_admin) and not (vendedor_alvo or '').strip()),
    )


@app.get("/percentuais")
def percentuais():
    red = _login_required()
    if red:
        return red

    mes, ano = _mes_ano_from_request()
    role = (_role() or '').lower()
    emp_scope = _emp() if role == 'supervisor' else None

    # resolve vendedor
    if role in {'admin', 'supervisor'}:
        vendedores = _get_vendedores_db(role, emp_scope)
        vendedor_req = (request.args.get('vendedor') or '').strip().upper() or None
        vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores) else None
    else:
        vendedor_alvo = (_usuario_logado() or '').strip().upper()

    dados = None
    if vendedor_alvo:
        dados = _dados_from_cache(vendedor_alvo, mes, ano, emp_scope)
        if dados is None:
            dados = _dados_ao_vivo(vendedor_alvo, mes, ano, emp_scope)
    dados = dados or {}

    ranking_list = dados.get('ranking_list', [])
    total = float(dados.get('total_liquido_periodo', 0.0))

    return render_template(
        'percentuais.html',
        vendedor=vendedor_alvo or '',
        role=_role(),
        emp=emp_scope,
        mes=mes,
        ano=ano,
        total=total,
        ranking_list=ranking_list,
    )


@app.get("/marcas")
def marcas():
    red = _login_required()
    if red:
        return red

    mes, ano = _mes_ano_from_request()
    role = (_role() or '').lower()
    emp_scope = _emp() if role == 'supervisor' else None

    if role in {'admin','supervisor'}:
        vendedores = _get_vendedores_db(role, emp_scope)
        vendedor_req = (request.args.get('vendedor') or '').strip().upper() or None
        vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores) else None
    else:
        vendedor_alvo = (_usuario_logado() or '').strip().upper()

    dados = None
    if vendedor_alvo:
        dados = _dados_from_cache(vendedor_alvo, mes, ano, emp_scope)
        if dados is None:
            dados = _dados_ao_vivo(vendedor_alvo, mes, ano, emp_scope)
    dados = dados or {}

    marcas_map = {row.get('marca'): row.get('valor') for row in (dados.get('ranking_list') or [])}

    return render_template(
        'marcas.html',
        vendedor=vendedor_alvo or '',
        role=_role(),
        emp=emp_scope,
        mes=mes,
        ano=ano,
        marcas=marcas_map,
    )


@app.get("/devolucoes")
def devolucoes():
    red = _login_required()
    if red:
        return red

    mes, ano = _mes_ano_from_request()
    role = (_role() or '').lower()
    emp_scope = _emp() if role == 'supervisor' else None

    # resolve vendedor
    if role in {'admin','supervisor'}:
        vendedores = _get_vendedores_db(role, emp_scope)
        vendedor_req = (request.args.get('vendedor') or '').strip().upper() or None
        vendedor_alvo = vendedor_req if (vendedor_req and vendedor_req in vendedores) else None
    else:
        vendedor_alvo = (_usuario_logado() or '').strip().upper()

    if not vendedor_alvo:
        devol = {}
    else:
        # Usa o helper padrão do sistema (intervalo [start, end))
        start, end = _periodo_bounds(ano, mes)
        with SessionLocal() as db:
            q = (
                db.query(Venda.marca, func.coalesce(func.sum(Venda.valor_total), 0.0))
                .filter(Venda.vendedor == vendedor_alvo)
                .filter(Venda.movimento >= start)
                .filter(Venda.movimento < end)
                .filter(Venda.mov_tipo_movto.in_(['DS','CA']))
            )
            if emp_scope:
                q = q.filter(Venda.emp == str(emp_scope))
            q = q.group_by(Venda.marca).order_by(func.sum(Venda.valor_total).desc())
            devol = {str(m or ''): float(v or 0.0) for m, v in q.all() if m}

    return render_template(
        'devolucoes.html',
        vendedor=vendedor_alvo or '',
        role=_role(),
        emp=emp_scope,
        mes=mes,
        ano=ano,
        devolucoes=devol,
    )


@app.get("/itens_parados")
def itens_parados():
    """Relatório de itens parados (liquidação) por EMP.

    Cadastro é feito pelo ADMIN por EMP.
    - ADMIN: pode visualizar todas as EMPs (e opcionalmente filtrar por EMP e/ou vendedor)
    - SUPERVISOR: visualiza somente a EMP cadastrada no usuário
    - VENDEDOR: a(s) EMP(s) é(são) derivada(s) de vendas.emp (pode ser multi-EMP)

    O campo "Valor" só aparece quando houver venda do código no período selecionado.
    """
    red = _login_required()
    if red:
        return red

    mes, ano = _mes_ano_from_request()
    role = (_role() or '').lower()

    # --- vendedor alvo (para cálculo do VALOR) ---
    vendedor_alvo = None
    vendedores_lista = []

    if role in {'admin', 'supervisor'}:
        emp_supervisor = _emp() if role == 'supervisor' else None
        if role == 'supervisor' and not emp_supervisor:
            flash('Seu usuário supervisor não possui EMP cadastrada. Solicite ao ADMIN para cadastrar.', 'warning')
            return redirect(url_for('dashboard'))

        vendedores_lista = _get_vendedores_db(role, emp_supervisor)
        vendedor_req = (request.args.get('vendedor') or '').strip().upper() or None
        if vendedor_req and vendedor_req in vendedores_lista:
            vendedor_alvo = vendedor_req
        else:
            vendedor_alvo = None  # admin/supervisor sem seleção = só lista

    else:
        vendedor_alvo = (_usuario_logado() or '').strip().upper()

    # --- EMP(s) visíveis para o usuário ---
    emp_param = (request.args.get('emp') or '').strip()
    emp_scopes = []

    if role == 'admin':
        if emp_param:
            emp_scopes = [str(emp_param)]
        else:
            # admin sem filtro: mostrar todas as EMPs que possuem itens cadastrados
            with SessionLocal() as db:
                # `itens_parados.ativo` is boolean in the database (TRUE/FALSE)
                emp_scopes = [str(x[0]) for x in db.query(ItemParado.emp).filter(ItemParado.ativo.is_(True)).distinct().all()]

    elif role == 'supervisor':
        emps = _allowed_emps()
        emp_scopes = emps if emps else ([str(_emp())] if _emp() else [])

    else:
        # vendedor: EMP(s) via usuario_emps (recomendado); fallback = derivadas das vendas
        emps = _allowed_emps()
        if emps:
            emp_scopes = emps
        else:
            with SessionLocal() as db:
                emp_scopes = [str(x[0]) for x in db.query(Venda.emp).filter(Venda.vendedor == vendedor_alvo).distinct().all()]

    emp_scopes = sorted({e.strip() for e in emp_scopes if e and str(e).strip()})
    if not emp_scopes:
        flash('Não foi possível identificar a EMP para este usuário (sem vendas registradas).', 'warning')
        return redirect(url_for('dashboard'))

    # --- Buscar itens por EMP e agrupar ---
    with SessionLocal() as db:
        itens_all = (
            db.query(ItemParado)
            .filter(ItemParado.emp.in_(emp_scopes))
            .filter(ItemParado.ativo.is_(True))
            .order_by(ItemParado.emp.asc(), ItemParado.codigo.asc())
            .all()
        )

    itens_por_emp = {}
    for it in itens_all:
        e = str(it.emp).strip() if it.emp is not None else ''
        itens_por_emp.setdefault(e, []).append(it)

    # --- Calcular vendido_total por (emp, codigo) e recompensa ---
    vendido_total_map = {}
    recomp_map = {}

    if vendedor_alvo and itens_all:
        # lista de códigos (mestre) cadastrados nos itens
        codigos = [ (i.codigo or '').strip() for i in itens_all if (i.codigo or '').strip() ]
        codigos = sorted(set(codigos))
        if codigos:
            start, end = _periodo_bounds(ano, mes)
            with SessionLocal() as db:
                q = (
                    db.query(Venda.emp, Venda.mestre, func.coalesce(func.sum(Venda.valor_total), 0.0))
                    .filter(Venda.emp.in_(emp_scopes))
                    .filter(Venda.vendedor == vendedor_alvo)
                    .filter(Venda.movimento >= start)
                    .filter(Venda.movimento < end)
                    .filter(Venda.mov_tipo_movto == 'OA')
                    .filter(Venda.mestre.in_(codigos))
                    .group_by(Venda.emp, Venda.mestre)
                )
                for emp_v, mestre, total in q.all():
                    k_emp = str(emp_v).strip() if emp_v is not None else ''
                    k_cod = (mestre or '').strip()
                    vendido_total_map[(k_emp, k_cod)] = float(total or 0.0)

            for it in itens_all:
                emp_it = str(it.emp).strip() if it.emp is not None else ''
                cod = (it.codigo or '').strip()
                total = vendido_total_map.get((emp_it, cod), 0.0)
                pct = float(it.recompensa_pct or 0.0)
                valor = (total * (pct / 100.0)) if total > 0 and pct > 0 else 0.0
                recomp_map[(emp_it, cod)] = valor

    return render_template(
        "itens_parados.html",
        role=role,
        mes=mes,
        ano=ano,
        emp_param=emp_param,
        emp_scopes=emp_scopes,
        itens_por_emp=itens_por_emp,
        vendedor=vendedor_alvo,
        vendedores_lista=vendedores_lista,
        vendido_total_map=vendido_total_map,
        recomp_map=recomp_map,
    )

@app.get("/itens_parados/pdf")
def itens_parados_pdf():
    """Exporta o relatório de itens parados em PDF (mes/ano e escopo do usuário)."""
    red = _login_required()
    if red:
        return red

    mes, ano = _mes_ano_from_request()
    role = (_role() or '').lower()

    # Reaproveita a lógica da tela para determinar vendedor/emp_scopes/itens e valores
    vendedor_alvo = None
    vendedores_lista = []

    if role in {'admin', 'supervisor'}:
        emp_supervisor = _emp() if role == 'supervisor' else None
        if role == 'supervisor' and not emp_supervisor:
            flash('Seu usuário supervisor não possui EMP cadastrada. Solicite ao ADMIN para cadastrar.', 'warning')
            return redirect(url_for('dashboard'))

        vendedores_lista = _get_vendedores_db(role, emp_supervisor)
        vendedor_req = (request.args.get('vendedor') or '').strip().upper() or None
        if vendedor_req and vendedor_req in vendedores_lista:
            vendedor_alvo = vendedor_req
        else:
            vendedor_alvo = None
    else:
        vendedor_alvo = (_usuario_logado() or '').strip().upper()

    emp_param = (request.args.get('emp') or '').strip()
    emp_scopes = []

    if role == 'admin':
        if emp_param:
            emp_scopes = [str(emp_param)]
        else:
            with SessionLocal() as db:
                # `itens_parados.ativo` is boolean in the database (TRUE/FALSE)
                emp_scopes = [str(x[0]) for x in db.query(ItemParado.emp).filter(ItemParado.ativo.is_(True)).distinct().all()]
    elif role == 'supervisor':
        emps = _allowed_emps()
        emp_scopes = emps if emps else ([str(_emp())] if _emp() else [])
    else:
        with SessionLocal() as db:
                emp_scopes = [str(x[0]) for x in db.query(Venda.emp).filter(Venda.vendedor == vendedor_alvo).distinct().all()]

    emp_scopes = sorted({e.strip() for e in emp_scopes if e and str(e).strip()})
    if not emp_scopes:
        flash('Não foi possível identificar a EMP para este usuário (sem vendas registradas).', 'warning')
        return redirect(url_for('dashboard'))

    with SessionLocal() as db:
        itens_all = (
            db.query(ItemParado)
            .filter(ItemParado.emp.in_(emp_scopes))
            .filter(ItemParado.ativo.is_(True))
            .order_by(ItemParado.emp.asc(), ItemParado.codigo.asc())
            .all()
        )

    itens_por_emp = {}
    for it in itens_all:
        e = str(it.emp).strip() if it.emp is not None else ''
        itens_por_emp.setdefault(e, []).append(it)

    vendido_total_map = {}
    recomp_map = {}

    if vendedor_alvo and itens_all:
        codigos = [ (i.codigo or '').strip() for i in itens_all if (i.codigo or '').strip() ]
        codigos = sorted(set(codigos))
        if codigos:
            start, end = _periodo_bounds(ano, mes)
            with SessionLocal() as db:
                q = (
                    db.query(Venda.emp, Venda.mestre, func.coalesce(func.sum(Venda.valor_total), 0.0))
                    .filter(Venda.emp.in_(emp_scopes))
                    .filter(Venda.vendedor == vendedor_alvo)
                    .filter(Venda.movimento >= start)
                    .filter(Venda.movimento < end)
                    .filter(Venda.mov_tipo_movto == 'OA')
                    .filter(Venda.mestre.in_(codigos))
                    .group_by(Venda.emp, Venda.mestre)
                )
                for emp_v, mestre, total in q.all():
                    k_emp = str(emp_v).strip() if emp_v is not None else ''
                    k_cod = (mestre or '').strip()
                    vendido_total_map[(k_emp, k_cod)] = float(total or 0.0)

            for it in itens_all:
                emp_it = str(it.emp).strip() if it.emp is not None else ''
                cod = (it.codigo or '').strip()
                total = vendido_total_map.get((emp_it, cod), 0.0)
                pct = float(it.recompensa_pct or 0.0)
                valor = (total * (pct / 100.0)) if total > 0 and pct > 0 else 0.0
                recomp_map[(emp_it, cod)] = valor

    # --- Gerar PDF (ReportLab) ---
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4

    titulo = "Relatório - Itens Parados"
    periodo = f"Período: {mes:02d}/{ano}"
    vendedor_txt = f"Vendedor: {vendedor_alvo}" if vendedor_alvo else "Vendedor: (não selecionado)"
    agora = datetime.now().strftime("%d/%m/%Y %H:%M")

    def draw_header():
        y = height - 18*mm
        c.setFont("Helvetica-Bold", 14)
        c.drawString(18*mm, y, titulo)
        c.setFont("Helvetica", 10)
        c.drawString(18*mm, y-6*mm, periodo)
        c.drawString(18*mm, y-11*mm, vendedor_txt)
        c.drawRightString(width-18*mm, y-6*mm, f"Gerado em: {agora}")
        return y-18*mm

    y = draw_header()

    # tabela simples por EMP
    c.setFont("Helvetica", 9)

    for emp in emp_scopes:
        itens_emp = itens_por_emp.get(emp, [])
        if not itens_emp:
            continue

        # quebra página se necessário
        if y < 35*mm:
            c.showPage()
            y = draw_header()
            c.setFont("Helvetica", 9)

        c.setFont("Helvetica-Bold", 11)
        c.drawString(18*mm, y, f"EMP {emp}")
        y -= 6*mm
        c.setFont("Helvetica-Bold", 9)
        c.drawString(18*mm, y, "CÓDIGO")
        c.drawString(40*mm, y, "DESCRIÇÃO")
        c.drawRightString(width-55*mm, y, "QTD")
        c.drawRightString(width-35*mm, y, "%")
        c.drawRightString(width-18*mm, y, "VALOR")
        y -= 4*mm
        c.setLineWidth(0.5)
        c.line(18*mm, y, width-18*mm, y)
        y -= 5*mm
        c.setFont("Helvetica", 9)

        for it in itens_emp:
            cod = (it.codigo or '').strip()
            desc = (it.descricao or '').strip()
            qtd = it.quantidade or 0
            pct = float(it.recompensa_pct or 0.0)

            valor = recomp_map.get((emp, cod), 0.0)
            valor_txt = "" if valor <= 0 else f"R$ {valor:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")

            # quebra página
            if y < 20*mm:
                c.showPage()
                y = draw_header()
                c.setFont("Helvetica", 9)

            c.drawString(18*mm, y, cod[:20])
            c.drawString(40*mm, y, desc[:55])
            c.drawRightString(width-55*mm, y, str(qtd))
            c.drawRightString(width-35*mm, y, f"{pct:.0f}%")
            c.drawRightString(width-18*mm, y, valor_txt)
            y -= 5*mm

        y -= 4*mm

    c.showPage()
    c.save()
    buf.seek(0)

    filename = f"itens_parados_{mes:02d}_{ano}.pdf"
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)

# ---------------------------------------------------------------------
# Campanhas de recompensa por quantidade (prefixo + marca)
# ---------------------------------------------------------------------
def _campanhas_mes_overlap(ano: int, mes: int, emp: str | None) -> list[CampanhaQtd]:
    """Retorna campanhas que intersectam o mês (e opcionalmente a EMP)."""
    inicio_mes, fim_mes = _periodo_bounds(int(ano), int(mes))
    with SessionLocal() as db:
        q = db.query(CampanhaQtd).filter(CampanhaQtd.ativo == 1)
        if emp:
            emp_str = str(emp)
            # suporta campanhas globais (emp = 'ALL'/'*'/'') e campanhas específicas da EMP
            q = q.filter(or_(CampanhaQtd.emp == emp_str, CampanhaQtd.emp.in_(['ALL', '*', ''])))
        # overlap: inicio <= fim_mes AND fim >= inicio_mes
        q = q.filter(and_(CampanhaQtd.data_inicio <= fim_mes, CampanhaQtd.data_fim >= inicio_mes))
        return q.order_by(CampanhaQtd.emp.asc(), CampanhaQtd.data_inicio.asc()).all()

def _upsert_resultado(
    db,
    campanha: CampanhaQtd,
    vendedor: str,
    emp: str,
    competencia_ano: int,
    competencia_mes: int,
    periodo_ini: date,
    periodo_fim: date,
) -> CampanhaQtdResultado:
    """Calcula e grava (upsert) o snapshot do resultado da campanha."""
    vendedor = (vendedor or "").strip().upper()
    emp = str(emp)

    # Campo usado para match do item:
    # - campo_match='codigo'   -> prefixo em Venda.mestre (compatibilidade com base antiga)
    # - campo_match='descricao'-> prefixo em Venda.descricao_norm (novo)
    campo_match = (getattr(campanha, "campo_match", None) or "codigo").strip().lower()

    def _norm_prefix(s: str) -> str:
        import unicodedata, re
        s = (s or "").strip()
        s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
        s = re.sub(r"\s+", " ", s).strip().lower()
        return s

    if campo_match == "descricao":
        prefix_raw = (getattr(campanha, "descricao_prefixo", "") or "").strip()
        # fallback: se não preencher descricao_prefixo, usa produto_prefixo como prefixo de descrição
        if not prefix_raw:
            prefix_raw = (campanha.produto_prefixo or "").strip()
        prefix = _norm_prefix(prefix_raw)
        # descricao_norm já é esperado estar normalizado; garantimos lower/trim para evitar mismatch
        campo_item = func.lower(func.trim(func.coalesce(Venda.descricao_norm, "")))
        cond_prefix = campo_item.like(prefix + "%")
    else:
        prefix_raw = (campanha.produto_prefixo or "").strip()
        prefix = prefix_raw
        prefix_up = prefix.upper()
        campo_item = func.upper(func.trim(cast(Venda.mestre, String)))
        cond_prefix = campo_item.like(prefix_up + "%")
    cond_marca = func.upper(func.trim(cast(Venda.marca, String))) == (campanha.marca or "").strip().upper()

    base = (
        db.query(
            func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd"),
            func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor"),
        )
        .filter(
            Venda.emp == emp,
            Venda.vendedor == vendedor,
            Venda.movimento >= periodo_ini,
            Venda.movimento <= periodo_fim,
            ~Venda.mov_tipo_movto.in_(["DS", "CA"]),
            cond_prefix,
            cond_marca,
        )
        .first()
    )
    qtd_vendida = float(base.qtd or 0.0)
    valor_vendido = float(base.valor or 0.0)

    min_qtd = getattr(campanha, "qtd_minima", None)
    min_val = getattr(campanha, "valor_minimo", None)

    atingiu = 1
    if min_qtd is not None and float(min_qtd) > 0:
        atingiu = 1 if qtd_vendida >= float(min_qtd) else 0
    if atingiu and min_val is not None and float(min_val) > 0:
        atingiu = 1 if valor_vendido >= float(min_val) else 0

    try:
        recompensa_unit_dec = Decimal(str(campanha.recompensa_unit or 0))
    except Exception:
        recompensa_unit_dec = Decimal("0")

    if atingiu:
        valor_recomp_dec = (Decimal(str(qtd_vendida)) * recompensa_unit_dec)
        # arredondamento monetário
        valor_recomp = float(valor_recomp_dec.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    else:
        valor_recomp = 0.0

    # Upsert por chave única
    res = (
        db.query(CampanhaQtdResultado)
        .filter(
            CampanhaQtdResultado.campanha_id == campanha.id,
            CampanhaQtdResultado.emp == emp,
            CampanhaQtdResultado.vendedor == vendedor,
            CampanhaQtdResultado.competencia_ano == int(competencia_ano),
            CampanhaQtdResultado.competencia_mes == int(competencia_mes),
        )
        .first()
    )
    if not res:
        res = CampanhaQtdResultado(
            campanha_id=campanha.id,
            emp=emp,
            vendedor=vendedor,
            competencia_ano=int(competencia_ano),
            competencia_mes=int(competencia_mes),
            status_pagamento="PENDENTE",
        )
        db.add(res)

    # snapshot
    res.titulo = campanha.titulo
    res.produto_prefixo = (locals().get('prefix_raw') or prefix)
    res.marca = (campanha.marca or "").strip()
    res.recompensa_unit = float(campanha.recompensa_unit or 0.0)
    res.qtd_minima = float(min_qtd) if (min_qtd is not None and float(min_qtd) > 0) else None
    res.data_inicio = campanha.data_inicio
    res.data_fim = campanha.data_fim

    res.qtd_vendida = qtd_vendida
    res.valor_vendido = valor_vendido
    res.atingiu_minimo = int(atingiu)
    res.valor_recompensa = float(valor_recomp)
    res.atualizado_em = datetime.utcnow()
    return res



def _calc_resultado_all_vendedores(
    db,
    campanha: CampanhaQtd,
    emp: str,
    competencia_ano: int,
    competencia_mes: int,
    periodo_ini: date,
    periodo_fim: date,
):
    """Calcula (sem persistir) o agregado da campanha para TODOS os vendedores da EMP no período.

    Otimização: evita multiplicar o custo por N vendedores quando o filtro está em 'TODOS'.
    Mantém as mesmas regras de cálculo (qtd_vendida/valor_total, exclusões DS/CA, match por prefixo+marca),
    apenas removendo o filtro por vendedor.
    """
    emp = str(emp)

    campo_match = (getattr(campanha, "campo_match", None) or "codigo").strip().lower()

    def _norm_prefix(s: str) -> str:
        import unicodedata, re
        s = (s or "").strip()
        s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
        s = re.sub(r"\s+", " ", s).strip().lower()
        return s

    if campo_match == "descricao":
        prefix_raw = (getattr(campanha, "descricao_prefixo", "") or "").strip()
        if not prefix_raw:
            prefix_raw = (campanha.produto_prefixo or "").strip()
        prefix = _norm_prefix(prefix_raw)
        campo_item = func.lower(func.trim(func.coalesce(Venda.descricao_norm, "")))
        cond_prefix = campo_item.like(prefix + "%")
    else:
        prefix_raw = (campanha.produto_prefixo or "").strip()
        prefix = prefix_raw
        prefix_up = prefix.upper()
        campo_item = func.upper(func.trim(cast(Venda.mestre, String)))
        cond_prefix = campo_item.like(prefix_up + "%")

    cond_marca = func.upper(func.trim(cast(Venda.marca, String))) == (campanha.marca or "").strip().upper()

    base = (
        db.query(
            func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd"),
            func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor"),
        )
        .filter(
            Venda.emp == emp,
            Venda.movimento >= periodo_ini,
            Venda.movimento <= periodo_fim,
            ~Venda.mov_tipo_movto.in_(["DS", "CA"]),
            cond_prefix,
            cond_marca,
        )
        .first()
    )

    qtd_vendida = float(getattr(base, "qtd", 0.0) or 0.0)
    valor_vendido = float(getattr(base, "valor", 0.0) or 0.0)

    min_qtd = getattr(campanha, "qtd_minima", None)
    min_val = getattr(campanha, "valor_minimo", None)

    atingiu = 1
    if min_qtd is not None and float(min_qtd) > 0:
        atingiu = 1 if qtd_vendida >= float(min_qtd) else 0
    if atingiu and min_val is not None and float(min_val) > 0:
        atingiu = 1 if valor_vendido >= float(min_val) else 0

    try:
        recompensa_unit_dec = Decimal(str(campanha.recompensa_unit or 0))
    except Exception:
        recompensa_unit_dec = Decimal("0")

    if atingiu:
        valor_recomp_dec = (Decimal(str(qtd_vendida)) * recompensa_unit_dec)
        valor_recomp = float(valor_recomp_dec.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    else:
        valor_recomp = 0.0

    # Objeto leve com os mesmos campos que o template usa
    from types import SimpleNamespace
    return SimpleNamespace(
        campanha_id=campanha.id,
        emp=emp,
        vendedor="__ALL__",
        competencia_ano=int(competencia_ano),
        competencia_mes=int(competencia_mes),
        status_pagamento="PENDENTE",
        titulo=campanha.titulo,
        produto_prefixo=prefix_raw,
        marca=(campanha.marca or "").strip(),
        recompensa_unit=float(campanha.recompensa_unit or 0.0),
        qtd_minima=float(min_qtd) if (min_qtd is not None and float(min_qtd) > 0) else None,
        data_inicio=campanha.data_inicio,
        data_fim=campanha.data_fim,
        qtd_vendida=qtd_vendida,
        valor_vendido=valor_vendido,
        atingiu_minimo=int(atingiu),
        valor_recompensa=float(valor_recomp),
        atualizado_em=datetime.utcnow(),
    )


def _resolver_emp_scope_para_usuario(vendedor: str, role: str, emp_usuario: str | None) -> list[str]:
    """Retorna lista de EMPs que o usuário pode visualizar (para campanhas e relatórios).

    Regra nova (recomendada):
    - Supervisor/Vendedor: usa usuario_emps (session['allowed_emps']) quando disponível.
    - Fallback: supervisor usa emp_usuario; vendedor infere pelas vendas.
    """
    role = (role or "").strip().lower()
    if role == "admin":
        return []

    if role in ("supervisor", "vendedor"):
        emps = _allowed_emps()
        if emps:
            return emps

    if role == "supervisor":
        return [str(emp_usuario)] if emp_usuario else []

    return _get_emps_vendedor(vendedor)


# --------------------------
# Services (injeção de deps)
# --------------------------
_campanhas_deps = CampanhasDeps(
    SessionLocal=SessionLocal,
    parse_multi_args=_parse_multi_args_from,
    get_emp_options=_get_emp_options,
    get_vendedores_db=_get_vendedores_db,
    get_emps_vendedor=_get_emps_vendedor,
    get_all_emp_codigos=_get_all_emp_codigos,
    periodo_bounds=_periodo_bounds,
    resolver_emp_scope_para_usuario=_resolver_emp_scope_para_usuario,
    campanhas_mes_overlap=_campanhas_mes_overlap,
    upsert_resultado=_upsert_resultado,
    calc_resultado_all_vendedores=_calc_resultado_all_vendedores,
    get_emps_com_vendas_no_periodo=lambda ano, mes: _get_emps_com_vendas_no_periodo(ano, mes),
    get_vendedores_emp_no_periodo=lambda emp, ano, mes: _get_vendedores_emp_no_periodo(emp, ano, mes),
    recalcular_resultados_campanhas_para_scope=lambda **kwargs: _recalcular_resultados_campanhas_para_scope(**kwargs),
    recalcular_resultados_combos_para_scope=lambda **kwargs: _recalcular_resultados_combos_para_scope(**kwargs),
)

@app.get("/campanhas")
def campanhas_qtd():
    """Relatório de campanhas de recompensa por quantidade.

    - Vendedor: vê por EMPs inferidas de vendas (multi-EMP)
    - Supervisor: vê apenas EMP dele
    - Admin: pode escolher vendedor/EMP
    """
    red = _login_required()
    if red:
        return red

    role = _role() or ""
    emp_usuario = _emp()
    vendedor_logado = (_usuario_logado() or "").strip().upper()

    # Flags de permissão para a UI (templates)
    ctx_role = role
    ctx_is_admin = (ctx_role == "admin")
    ctx_is_supervisor = (ctx_role == "supervisor")
    ctx_is_vendedor = (ctx_role == "vendedor")
    ctx_is_financeiro = (ctx_role == "financeiro")


    ctx = build_campanhas_page_context(
        _campanhas_deps,
        role=role,
        emp_usuario=emp_usuario,
        vendedor_logado=vendedor_logado,
        args=request.args,
    )
    return render_template("campanhas_qtd.html", **ctx)


@app.get("/campanhas/pdf")
def campanhas_qtd_pdf():
    red = _login_required()
    if red:
        return red

    role = _role() or ""
    emp_usuario = _emp()
    hoje = date.today()
    mes = int(request.args.get("mes") or hoje.month)
    ano = int(request.args.get("ano") or hoje.year)

    vendedor_logado = (_usuario_logado() or "").strip().upper()
    if (role or "").lower() == "supervisor":
        vendedor_sel = (request.args.get("vendedor") or "__ALL__").strip().upper()
        if vendedor_sel == "__ALL__":
            try:
                vs = _get_vendedores_db(role, emp_usuario)
                vendedor_sel = (vs[0] if vs else vendedor_logado).strip().upper()
            except Exception:
                vendedor_sel = vendedor_logado
    else:
        vendedor_sel = (request.args.get("vendedor") or vendedor_logado).strip().upper()
        if (role or "").lower() != "admin" and vendedor_sel != vendedor_logado:
            vendedor_sel = vendedor_logado

    emp_param = (request.args.get("emp") or "").strip()
    if (role or "").lower() == "admin":
        emps_scope = [emp_param] if emp_param else _get_emps_vendedor(vendedor_sel)
    else:
        emps_scope = _resolver_emp_scope_para_usuario(vendedor_sel, role, emp_usuario)

    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4

    def _money(v: float) -> str:
        return f"R$ {v:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")

    y = height - 18 * mm
    c.setFont("Helvetica-Bold", 14)
    c.drawString(18 * mm, y, "Campanhas - Recompensa por Quantidade")
    y -= 7 * mm
    c.setFont("Helvetica", 10)
    c.drawString(18 * mm, y, f"Vendedor: {vendedor_sel}   Período: {mes:02d}/{ano}")
    y -= 10 * mm

    with SessionLocal() as db:
        for emp in emps_scope:
            emp = str(emp)
            resultados = (
                db.query(CampanhaQtdResultado)
                .filter(
                    CampanhaQtdResultado.emp == emp,
                    CampanhaQtdResultado.vendedor == vendedor_sel,
                    CampanhaQtdResultado.competencia_ano == int(ano),
                    CampanhaQtdResultado.competencia_mes == int(mes),
                )
                .order_by(CampanhaQtdResultado.valor_recompensa.desc())
                .all()
            )

            if y < 40 * mm:
                c.showPage()
                y = height - 18 * mm

            c.setFont("Helvetica-Bold", 12)
            c.drawString(18 * mm, y, f"EMP {emp}")
            y -= 6 * mm
            c.setFont("Helvetica-Bold", 9)
            c.drawString(18 * mm, y, "PRODUTO")
            c.drawString(65 * mm, y, "MARCA")
            c.drawRightString(width - 70 * mm, y, "QTD")
            c.drawRightString(width - 50 * mm, y, "MÍN")
            c.drawRightString(width - 18 * mm, y, "VALOR")
            y -= 4 * mm
            c.setLineWidth(0.5)
            c.line(18 * mm, y, width - 18 * mm, y)
            y -= 5 * mm
            c.setFont("Helvetica", 9)

            total_emp = 0.0
            for r in resultados:
                if y < 25 * mm:
                    c.showPage()
                    y = height - 18 * mm
                    c.setFont("Helvetica", 9)
                minimo_txt = "" if r.qtd_minima is None else f"{float(r.qtd_minima):.0f}"
                valor_txt = _money(float(r.valor_recompensa or 0.0)) if float(r.valor_recompensa or 0.0) > 0 else "-"
                c.drawString(18 * mm, y, (r.produto_prefixo or "")[:22])
                c.drawString(65 * mm, y, (r.marca or "")[:14])
                c.drawRightString(width - 70 * mm, y, f"{float(r.qtd_vendida or 0):.0f}")
                c.drawRightString(width - 50 * mm, y, minimo_txt)
                c.drawRightString(width - 18 * mm, y, valor_txt)
                y -= 5 * mm
                total_emp += float(r.valor_recompensa or 0.0)

            y -= 2 * mm
            c.setFont("Helvetica-Bold", 10)
            c.drawRightString(width - 18 * mm, y, f"Total EMP {emp}: {_money(total_emp)}")
            y -= 10 * mm

    c.showPage()
    c.save()
    buf.seek(0)
    filename = f"campanhas_{mes:02d}_{ano}.pdf"
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)

# ---------------------------------------------------------------------
# Relatórios (Campanhas) - visão por EMP -> vendedores -> campanhas
# ---------------------------------------------------------------------
def _get_emps_com_vendas_no_periodo(ano: int, mes: int) -> list[str]:
    inicio_mes, fim_mes = _periodo_bounds(int(ano), int(mes))
    with SessionLocal() as db:
        rows = (
            db.query(func.distinct(Venda.emp))
            .filter(Venda.movimento >= inicio_mes, Venda.movimento <= fim_mes)
            .all()
        )
    emps = sorted({str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip() != ""})
    return _filter_emps_cadastradas(emps, apenas_ativas=True)

def _get_vendedores_emp_no_periodo(emp: str, ano: int, mes: int) -> list[str]:
    inicio_mes, fim_mes = _periodo_bounds(int(ano), int(mes))
    emp = str(emp)
    with SessionLocal() as db:
        rows = (
            db.query(func.distinct(Venda.vendedor))
            .filter(Venda.emp == emp, Venda.movimento >= inicio_mes, Venda.movimento <= fim_mes)
            .all()
        )
    vendedores = sorted({(r[0] or '').strip().upper() for r in rows if r and (r[0] or '').strip()})
    # Remove vendedores não cadastrados (usuários inexistentes)
    cad = _get_vendedores_cadastrados_por_emp(emp)
    if cad:
        vendedores = [v for v in vendedores if v in cad]
    return vendedores

def _calc_vendas_por_vendedor_para_campanha(db, emp: str, campanha: CampanhaQtd, periodo_ini: date, periodo_fim: date) -> dict[str, tuple[float, float]]:
    """Retorna dict vendedor -> (qtd_vendida, valor_vendido) para uma campanha no período.

    IMPORTANTE: usa a MESMA regra de match de itens do _upsert_resultado:
      - campo_match='codigo'    -> prefixo em Venda.mestre
      - campo_match='descricao' -> prefixo em Venda.descricao_norm (normalizada)
    """
    emp = str(emp)

    # Campo usado para match do item
    campo_match = (getattr(campanha, "campo_match", None) or "codigo").strip().lower()

    def _norm_prefix(s: str) -> str:
        import unicodedata, re as _re
        s = (s or "").strip()
        s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
        s = _re.sub(r"\s+", " ", s).strip().lower()
        return s

    if campo_match == "descricao":
        prefix_raw = (getattr(campanha, "descricao_prefixo", "") or "").strip()
        if not prefix_raw:
            prefix_raw = (campanha.produto_prefixo or "").strip()
        prefix = _norm_prefix(prefix_raw)
        campo_item = func.lower(func.trim(func.coalesce(Venda.descricao_norm, "")))
        cond_prefix = campo_item.like(prefix + "%")
    else:
        prefix = (campanha.produto_prefixo or "").strip()
        prefix_up = prefix.upper()
        campo_item = func.upper(func.trim(cast(Venda.mestre, String)))
        cond_prefix = campo_item.like(prefix_up + "%")

    cond_marca = func.upper(func.trim(cast(Venda.marca, String))) == (campanha.marca or "").strip().upper()

    q = (
        db.query(
            func.upper(func.trim(cast(Venda.vendedor, String))).label("vendedor"),
            func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd"),
            func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor"),
        )
        .filter(
            Venda.emp == emp,
            Venda.movimento >= periodo_ini,
            Venda.movimento <= periodo_fim,
            ~Venda.mov_tipo_movto.in_(["DS", "CA"]),
            cond_prefix,
            cond_marca,
        )
        .group_by(func.upper(func.trim(cast(Venda.vendedor, String))))
    )
    rows = q.all()
    out: dict[str, tuple[float, float]] = {}
    for r in rows:
        v = (r.vendedor or '').strip().upper()
        if not v:
            continue
        out[v] = (float(r.qtd or 0.0), float(r.valor or 0.0))
    return out


def _combos_mes_overlap(ano: int, mes: int, emp: str) -> list[CampanhaCombo]:
    """Combos ativos cuja vigência intersecta a competência (mês/ano).
    Considera combos globais (emp null/''), e combos específicos da EMP.
    """
    inicio_mes, fim_mes = _periodo_bounds(int(ano), int(mes))
    emp = str(emp)
    with SessionLocal() as db:
        q = (
            db.query(CampanhaCombo)
            .filter(
                CampanhaCombo.ativo.is_(True),
                # Emp específico OU global
                or_(CampanhaCombo.emp.is_(None), CampanhaCombo.emp == "", CampanhaCombo.emp == emp),
                # Interseção de datas
                CampanhaCombo.data_inicio <= fim_mes,
                CampanhaCombo.data_fim >= inicio_mes,
            )
            .order_by(CampanhaCombo.data_inicio.asc(), CampanhaCombo.id.asc())
        )
        return q.all()


def _norm_text(s: str) -> str:
    import unicodedata, re as _re
    s = (s or "").strip()
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    s = _re.sub(r"\s+", " ", s).strip().lower()
    return s


def _calc_qtd_por_vendedor_para_combo_item(db, emp: str, item: CampanhaComboItem, marca: str, periodo_ini: date, periodo_fim: date) -> dict[str, float]:
    """Retorna dict vendedor -> qtd para um item do combo no período.

    Regras de match (compatível com banco antigo):
      - Se item.mestre_prefixo existir: prefix match em Venda.mestre
      - Se item.descricao_contains existir: contains case-insensitive em descricao_norm/descricao
      - Se ambos vazios: usa item.match_mestre como fallback (prefixo se parecer código; senão contains)
    """
    emp = str(emp)
    marca_up = (marca or "").strip().upper()

    conds = [
        Venda.emp == emp,
        Venda.movimento >= periodo_ini,
        Venda.movimento <= periodo_fim,
        ~Venda.mov_tipo_movto.in_(["DS", "CA"]),
        ]

    mp = (item.mestre_prefixo or "").strip()
    dc = (item.descricao_contains or "").strip()

    # Fallback para bases antigas: match_mestre é obrigatório e pode ser a única regra persistida
    if not mp and not dc:
        mm = (getattr(item, "match_mestre", None) or "").strip()
        if mm:
            # Se não tem espaços e é alfanumérico/símbolos comuns, tratamos como código (prefixo).
            # Caso contrário, tratamos como trecho de descrição (contains).
            import re as _re
            if _re.fullmatch(r"[A-Za-z0-9._\-/]+", mm):
                mp = mm
            else:
                dc = mm

    if mp:
        conds.append(func.upper(func.trim(cast(Venda.mestre, String))) == mp.strip().upper())
    if dc:
        needle = _norm_text(dc)
        campo = func.lower(func.trim(func.coalesce(Venda.descricao_norm, Venda.descricao, "")))
        conds.append(campo.like("%" + needle + "%"))

    # Se nenhum match foi definido, não retorna nada (evita pagar "tudo")
    if not mp and not dc:
        return {}

    q = (
        db.query(
            func.upper(func.trim(cast(Venda.vendedor, String))).label("vendedor"),
            func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd"),
        )
        .filter(*conds)
        .group_by(func.upper(func.trim(cast(Venda.vendedor, String))))
    )
    rows = q.all()
    out: dict[str, float] = {}
    for r in rows:
        v = (r.vendedor or "").strip().upper()
        if not v:
            continue
        out[v] = float(r.qtd or 0.0)
    return out


def _recalcular_resultados_combos_para_scope(ano: int, mes: int, emps: list[str], vendedores_por_emp: dict[str, list[str]]) -> None:
    """Recalcula (upsert) snapshots em campanhas_combo_resultados para o escopo informado."""
    inicio_mes, fim_mes = _periodo_bounds(int(ano), int(mes))
    with SessionLocal() as db:
        for emp in emps:
            emp = str(emp)
            vendedores_emp = [v.strip().upper() for v in (vendedores_por_emp.get(emp) or []) if (v or "").strip()]
            if not vendedores_emp:
                continue

            combos = _combos_mes_overlap(int(ano), int(mes), emp)
            if not combos:
                # limpa resultados do período para evitar lixo antigo
                db.query(CampanhaComboResultado).filter(
                    CampanhaComboResultado.emp == emp,
                    CampanhaComboResultado.competencia_ano == int(ano),
                    CampanhaComboResultado.competencia_mes == int(mes),
                ).delete(synchronize_session=False)
                db.commit()
                continue

            # apaga resultados antigos do escopo (EMP+competência)
            db.query(CampanhaComboResultado).filter(
                CampanhaComboResultado.emp == emp,
                CampanhaComboResultado.competencia_ano == int(ano),
                CampanhaComboResultado.competencia_mes == int(mes),
            ).delete(synchronize_session=False)

            novos = []
            for combo in combos:
                periodo_ini = max(combo.data_inicio, inicio_mes)
                periodo_fim = min(combo.data_fim, fim_mes)

                itens = (
                    db.query(CampanhaComboItem)
                    .filter(CampanhaComboItem.combo_id == combo.id)
                    .order_by(CampanhaComboItem.ordem.asc(), CampanhaComboItem.id.asc())
                    .all()
                )
                if not itens:
                    continue

                # qtd por vendedor por item
                qtd_por_item: list[dict[str, float]] = []
                for it in itens:
                    qtd_por_item.append(_calc_qtd_por_vendedor_para_combo_item(db, emp, it, combo.marca, periodo_ini, periodo_fim))

                for vend in vendedores_emp:
                    # Gate: precisa bater mínimo em todos os itens
                    atingiu = 1
                    total = 0.0
                    for it, qtd_map in zip(itens, qtd_por_item):
                        qtd = float(qtd_map.get(vend, 0.0))
                        minimo = float(it.minimo_qtd or 0.0)
                        if minimo <= 0:
                            atingiu = 0
                            break
                        if qtd < minimo:
                            atingiu = 0
                            break
                        total += float(it.valor_unitario or 0.0)
                    if not atingiu:
                        total = 0.0

                    novos.append(CampanhaComboResultado(
                        combo_id=combo.id,
                        competencia_ano=int(ano),
                        competencia_mes=int(mes),
                        emp=emp,
                        vendedor=vend,
                        titulo=combo.titulo,
                        marca=combo.marca,
                        data_inicio=combo.data_inicio,
                        data_fim=combo.data_fim,
                        atingiu_gate=int(atingiu),
                        valor_recompensa=float(total),
                        status_pagamento="PENDENTE",
                        atualizado_em=datetime.utcnow(),
                    ))

            if novos:
                db.bulk_save_objects(novos)
            db.commit()


def _build_campanhas_escolhidas_por_vendedor(campanhas: list[CampanhaQtd], vendedores: list[str]) -> dict[str, list[CampanhaQtd]]:
    """Aplica a regra de prioridade por chave (prefixo+marca): campanha do vendedor substitui campanha geral."""
    # geral: vendedor NULL
    geral_by_key: dict[tuple[str, str, str], CampanhaQtd] = {}
    especificas: dict[str, dict[tuple[str, str], CampanhaQtd]] = {}
    for c in campanhas:
        campo_match = (getattr(c, "campo_match", None) or "codigo").strip().lower()
        if campo_match == "descricao":
            pref = (getattr(c, "descricao_prefixo", "") or "").strip() or (c.produto_prefixo or "").strip()
            key = ("descricao", pref.lower().strip(), (c.marca or "").strip().upper())
        else:
            key = ("codigo", (c.produto_prefixo or "").strip().upper(), (c.marca or "").strip().upper())

        if c.vendedor and c.vendedor.strip():
            vend = c.vendedor.strip().upper()
            especificas.setdefault(vend, {})[key] = c
        else:
            geral_by_key.setdefault(key, c)

    escolhidas: dict[str, list[CampanhaQtd]] = {}
    for v in vendedores:
        base = dict(geral_by_key)
        if v in especificas:
            base.update(especificas[v])
        escolhidas[v] = list(base.values())
    return escolhidas

def _recalcular_resultados_campanhas_para_scope(ano: int, mes: int, emps: list[str], vendedores_por_emp: dict[str, list[str]]) -> None:
    """Recalcula (upsert) snapshots em campanhas_qtd_resultados para o escopo informado.
    Focado em desempenho: faz agregação por campanha com group_by vendedor e só grava para vendedores no escopo.
    """
    inicio_mes, fim_mes = _periodo_bounds(int(ano), int(mes))
    with SessionLocal() as db:
        for emp in emps:
            emp = str(emp)

            vendedores_emp = [v.strip().upper() for v in (vendedores_por_emp.get(emp) or []) if (v or '').strip()]
            if not vendedores_emp:
                continue

            # campanhas que intersectam o mês (inclui globais se houver)
            campanhas = _campanhas_mes_overlap(int(ano), int(mes), emp)

            # campanhas escolhidas por vendedor (aplica override)
            escolhidas_por_vendedor = _build_campanhas_escolhidas_por_vendedor(campanhas, vendedores_emp)

            # União de campanhas realmente usadas
            campanhas_usadas: dict[int, CampanhaQtd] = {}
            for v, lst in escolhidas_por_vendedor.items():
                for c in lst:
                    campanhas_usadas[c.id] = c

            # Pré-calcula vendas por vendedor para cada campanha
            vendas_por_campanha: dict[int, dict[str, tuple[float, float]]] = {}
            for cid, c in campanhas_usadas.items():
                periodo_ini = max(c.data_inicio, inicio_mes)
                periodo_fim = min(c.data_fim, fim_mes)
                vendas_por_campanha[cid] = _calc_vendas_por_vendedor_para_campanha(db, emp, c, periodo_ini, periodo_fim)

            # Apaga resultados existentes do escopo (para evitar conflito e garantir consistência)
            # (apenas para a EMP e competência; é rápido pois tem índice)
            db.query(CampanhaQtdResultado).filter(
                CampanhaQtdResultado.emp == emp,
                CampanhaQtdResultado.competencia_ano == int(ano),
                CampanhaQtdResultado.competencia_mes == int(mes),
            ).delete(synchronize_session=False)

            # Insere novos snapshots
            novos = []
            for v in vendedores_emp:
                for c in escolhidas_por_vendedor.get(v, []):
                    qtd, valor = vendas_por_campanha.get(c.id, {}).get(v, (0.0, 0.0))
                    minimo = c.qtd_minima
                    atingiu = 1
                    if minimo is not None and float(minimo) > 0:
                        atingiu = 1 if float(qtd) >= float(minimo) else 0
                    valor_recomp = (float(qtd) * float(c.recompensa_unit or 0.0)) if atingiu else 0.0

                    novos.append(CampanhaQtdResultado(
                        campanha_id=c.id,
                        competencia_ano=int(ano),
                        competencia_mes=int(mes),
                        emp=emp,
                        vendedor=v,
                        titulo=c.titulo,
                        produto_prefixo=(c.produto_prefixo or "").strip(),
                        marca=(c.marca or "").strip(),
                        recompensa_unit=float(c.recompensa_unit or 0.0),
                        qtd_minima=float(minimo) if minimo is not None else None,
                        data_inicio=c.data_inicio,
                        data_fim=c.data_fim,
                        qtd_vendida=float(qtd),
                        valor_vendido=float(valor),
                        atingiu_minimo=int(atingiu),
                        valor_recompensa=float(valor_recomp),
                        status_pagamento="PENDENTE",
                        atualizado_em=datetime.utcnow(),
                    ))
            if novos:
                db.bulk_save_objects(novos)
            db.commit()

@app.get("/relatorios/campanhas")
def relatorio_campanhas():
    """Relatório gerencial de campanhas por EMP -> vendedores -> campanhas (mês/ano).

    - ADMIN: todas as EMPs (ou filtra por emp)
    - SUPERVISOR: apenas EMP vinculada ao supervisor
    - VENDEDOR: apenas ele (suas EMPs)
    """
    red = _login_required()
    if red:
        return red

    role = (_role() or "").strip().lower()

    # Flags de permissão para a UI (templates)
    ctx_is_admin = (role == "admin")
    ctx_is_supervisor = (role == "supervisor")
    ctx_is_vendedor = (role == "vendedor")
    ctx_is_financeiro = (role == "financeiro")

    emp_usuario = _emp()

    vendedor_logado = (_usuario_logado() or "").strip().upper()
    scope = build_relatorio_campanhas_scope(
        _campanhas_deps,
        role=role,
        emp_usuario=emp_usuario,
        vendedor_logado=vendedor_logado,
        args=request.args,
        flash=flash,
    )
    ano = int(scope["ano"])
    mes = int(scope["mes"])
    emps_sel = scope["emps_sel"]
    vendedores_sel = scope["vendedores_sel"]
    emps_scope = scope["emps_scope"]
    vendedores_por_emp = scope["vendedores_por_emp"]


    ctx = build_relatorio_campanhas_unificado_context(
        _campanhas_deps,
        role=role,
        vendedor_logado=vendedor_logado,
        ano=ano,
        mes=mes,
        emps_scope=emps_scope,
        emps_sel=emps_sel,
        vendedores_sel=vendedores_sel,
        vendedores_por_emp=vendedores_por_emp,
        recalc=str(request.args.get("recalc") or "").strip() in ("1", "true", "True", "sim", "SIM"),
        flash=flash,
    )
    # Permissões para template
    ctx["role"] = role
    ctx["is_admin"] = ctx_is_admin
    ctx["is_supervisor"] = ctx_is_supervisor
    ctx["is_vendedor"] = ctx_is_vendedor
    ctx["is_financeiro"] = ctx_is_financeiro



    # Paginação simples (client-side seria ok, mas server-side evita payloads enormes)
    try:
        page = int(request.args.get("page") or 1)
        per_page = int(request.args.get("per_page") or 200)
        page = max(page, 1)
        per_page = max(50, min(per_page, 1000))
    except Exception:
        page, per_page = 1, 200

    rows = ctx.get("rows") or []
    total_rows = len(rows)
    start = (page - 1) * per_page
    end = start + per_page
    ctx["rows_page"] = rows[start:end]
    ctx["page"] = page
    ctx["per_page"] = per_page
    ctx["total_rows"] = total_rows
    ctx["total_pages"] = (total_rows + per_page - 1) // per_page if per_page else 1

    # Resumo financeiro (topo do relatório) — total geral + por status + por EMP/Vendedor
    def _to_float(x):
        try:
            return float(x or 0)
        except Exception:
            return 0.0

    def _norm_status(s: str) -> str:
        s = (s or "PENDENTE").strip().upper()
        if s in ("A PAGAR", "A_PAGAR", "APAGAR"):
            return "A_PAGAR"
        if s in ("PAGO",):
            return "PAGO"
        if s in ("PENDENTE",):
            return "PENDENTE"
        return s

    def _calc_resumo_financeiro(_rows):
        resumo = {
            "linhas": 0,
            "total_valor": 0.0,
            "status": {"PENDENTE": 0.0, "A_PAGAR": 0.0, "PAGO": 0.0, "OUTROS": 0.0},
            "por_emp": {},
        }
        def _pick(obj, *keys):
            """Lê valor de dict/objeto (ex.: UnifiedRow) de forma compatível."""
            for k in keys:
                try:
                    if isinstance(obj, dict):
                        v = obj.get(k)
                    else:
                        v = getattr(obj, k, None)
                    if v is None:
                        continue
                    # trata strings vazias como None
                    if isinstance(v, str) and not v.strip():
                        continue
                    return v
                except Exception:
                    continue
            return None

        for r in (_rows or []):
            emp = str(_pick(r, "emp", "EMP") or "").strip() or "—"
            vendedor = str(_pick(r, "vendedor", "VENDEDOR") or "").strip() or "—"
            valor = _to_float(_pick(r, "valor_recompensa", "valor", "VALOR_RECOMPENSA") or 0)
            st = _norm_status(_pick(r, "status_pagamento", "status", "STATUS_PAGAMENTO") or "PENDENTE")
            if st not in ("PENDENTE", "A_PAGAR", "PAGO"):
                st_key = "OUTROS"
            else:
                st_key = st

            resumo["linhas"] += 1
            resumo["total_valor"] += valor
            resumo["status"][st_key] = resumo["status"].get(st_key, 0.0) + valor

            empd = resumo["por_emp"].setdefault(emp, {
                "total": 0.0,
                "status": {"PENDENTE": 0.0, "A_PAGAR": 0.0, "PAGO": 0.0, "OUTROS": 0.0},
                "vendedores": {}
            })
            empd["total"] += valor
            empd["status"][st_key] = empd["status"].get(st_key, 0.0) + valor

            vd = empd["vendedores"].setdefault(vendedor, {
                "total": 0.0,
                "status": {"PENDENTE": 0.0, "A_PAGAR": 0.0, "PAGO": 0.0, "OUTROS": 0.0},
                "linhas": 0
            })
            vd["linhas"] += 1
            vd["total"] += valor
            vd["status"][st_key] = vd["status"].get(st_key, 0.0) + valor

        # ordenar EMPs por total desc (para UI ficar útil)
        resumo["por_emp_ordenado"] = sorted(
            resumo["por_emp"].items(),
            key=lambda kv: kv[1].get("total", 0.0),
            reverse=True
        )
        return resumo

    ctx["resumo"] = _calc_resumo_financeiro(rows)

    # Agrupamento para UI: exibir campanhas dentro do vendedor (mais legível)
    def _group_rows_por_vendedor(_rows):
        grouped = {}
        for r in (_rows or []):
            # suporta UnifiedRow (objeto) e dict
            emp = (getattr(r, "emp", None) if not isinstance(r, dict) else (r.get("emp") or r.get("EMP"))) or "—"
            vendedor = (getattr(r, "vendedor", None) if not isinstance(r, dict) else (r.get("vendedor") or r.get("VENDEDOR"))) or "—"
            titulo = (
                (getattr(r, "titulo", None) if not isinstance(r, dict) else (r.get("titulo") or r.get("TITULO")))
                or (getattr(r, "campanha", None) if not isinstance(r, dict) else (r.get("campanha") or r.get("CAMPANHA")))
                or "—"
            )
            valor = (
                (getattr(r, "valor_recompensa", None) if not isinstance(r, dict) else (r.get("valor_recompensa") or r.get("VALOR_RECOMPENSA")))
                or (getattr(r, "valor", None) if not isinstance(r, dict) else r.get("valor"))
                or 0
            )
            status = (
                (getattr(r, "status_pagamento", None) if not isinstance(r, dict) else (r.get("status_pagamento") or r.get("STATUS_PAGAMENTO")))
                or "PENDENTE"
            )
            try:
                v = float(valor or 0)
            except Exception:
                v = 0.0
            emp_s = str(emp).strip() or "—"
            vend_s = str(vendedor).strip().upper() or "—"
            key = (emp_s, vend_s)
            if key not in grouped:
                grouped[key] = {
                    "emp": emp_s,
                    "vendedor": vend_s,
                    "total": 0.0,
                    "status_totais": {"PENDENTE": 0.0, "A_PAGAR": 0.0, "PAGO": 0.0},
                    "campanhas": [],
                }
            g = grouped[key]
            g["total"] += v
            st_key = str(status).strip().upper()
            if st_key not in g["status_totais"]:
                g["status_totais"][st_key] = 0.0
            g["status_totais"][st_key] += v
            g["campanhas"].append({"titulo": str(titulo).strip() or "—", "valor": v, "status": st_key})
        # ordenar: vendedores por total, campanhas por valor
        out = list(grouped.values())
        for g in out:
            g["campanhas"].sort(key=lambda x: x.get("valor", 0.0), reverse=True)
        out.sort(key=lambda x: x.get("total", 0.0), reverse=True)
        return out

    ctx["rows_grouped"] = _group_rows_por_vendedor(rows)

    # URLs auxiliares (Jinja não suporta **kwargs dinâmico com dict em algumas versões)
    from urllib.parse import urlencode

    base_args = request.args.to_dict(flat=False) if request.args else {}

    def _make_url(endpoint: str, **updates):
        d = dict(base_args)
        for k, v in updates.items():
            if v is None:
                d.pop(k, None)
            else:
                d[k] = str(v)
        qs = urlencode(d, doseq=True)
        return url_for(endpoint) + (("?" + qs) if qs else "")

    ctx["recalc_url"] = _make_url("relatorio_campanhas", recalc=1, page=1)
    ctx["export_url"] = _make_url("relatorio_campanhas_export_csv", page=None, per_page=None)

    per_page_opts = [200, 500, 1000]
    ctx["per_page_opts"] = per_page_opts
    ctx["per_page_urls"] = {opt: _make_url("relatorio_campanhas", per_page=opt, page=1) for opt in per_page_opts}

    ctx["prev_url"] = _make_url("relatorio_campanhas", page=max(1, page - 1))
    ctx["next_url"] = _make_url("relatorio_campanhas", page=min(ctx["total_pages"], page + 1))

    return render_template("relatorio_campanhas.html", ctx=ctx, **ctx)


@app.get("/relatorios/campanhas/export.csv")
def relatorio_campanhas_export_csv():
    """Exporta o relatório unificado (mes/ano/filtros) em CSV."""
    red = _login_required()
    if red:
        return red

    role = (_role() or "").strip().lower()
    emp_usuario = _emp()
    vendedor_logado = (_usuario_logado() or "").strip().upper()

    scope = build_relatorio_campanhas_scope(
        _campanhas_deps,
        role=role,
        emp_usuario=emp_usuario,
        vendedor_logado=vendedor_logado,
        args=request.args,
        flash=flash,
    )
    ano = int(scope["ano"])
    mes = int(scope["mes"])
    emps_sel = scope["emps_sel"]
    vendedores_sel = scope["vendedores_sel"]
    emps_scope = scope["emps_scope"]
    vendedores_por_emp = scope["vendedores_por_emp"]

    ctx = build_relatorio_campanhas_unificado_context(
        _campanhas_deps,
        role=role,
        vendedor_logado=vendedor_logado,
        ano=ano,
        mes=mes,
        emps_scope=emps_scope,
        emps_sel=emps_sel,
        vendedores_sel=vendedores_sel,
        vendedores_por_emp=vendedores_por_emp,
        recalc=False,
        flash=flash,
    )

    import csv
    from io import StringIO
    sio = StringIO()
    w = csv.writer(sio, delimiter=";")
    w.writerow(["tipo","competencia","emp","vendedor","titulo","atingiu_gate","qtd_base","qtd_premiada","valor_recompensa","status_pagamento","pago_em"])
    for r in (ctx.get("rows") or []):
        comp = f"{getattr(r,'competencia_mes',mes):02d}/{getattr(r,'competencia_ano',ano)}"
        w.writerow([
            getattr(r,"tipo",""),
            comp,
            getattr(r,"emp",""),
            getattr(r,"vendedor",""),
            getattr(r,"titulo",""),
            "SIM" if getattr(r,"atingiu_gate",None) else "NÃO" if getattr(r,"atingiu_gate",None) is not None else "",
            getattr(r,"qtd_base", "") if getattr(r,"qtd_base",None) is not None else "",
            getattr(r,"qtd_premiada","") if getattr(r,"qtd_premiada",None) is not None else "",
            getattr(r,"valor_recompensa",0.0),
            getattr(r,"status_pagamento","PENDENTE"),
            getattr(r,"pago_em","") or "",
        ])

    out = sio.getvalue().encode("utf-8")
    filename = f"relatorio_campanhas_{ano}_{mes:02d}.csv"
    return send_file(
        BytesIO(out),
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename,
    )


@app.get("/relatorios/cidades-clientes")
def relatorio_cidades_clientes():
    """Relatórios por EMP (Cidades e Clientes) — mês/ano.

    Permissões:
    - ADMIN: todas as EMPs (pode filtrar por EMP e vendedor)
    - SUPERVISOR: apenas EMP vinculada (pode filtrar por vendedor)
    - VENDEDOR: apenas o próprio vendedor (agrupado por EMP)
    """
    red = _login_required()
    if red:
        return red

    role = (_role() or "").strip().lower()
    emp_usuario = _emp()
    vendedor_logado = (_usuario_logado() or "").strip().upper()

    hoje = date.today()
    mes = int(request.args.get("mes") or hoje.month)
    ano = int(request.args.get("ano") or hoje.year)

    emp_filtro = (request.args.get("emp") or "").strip()
    vendedor_filtro = (request.args.get("vendedor") or "").strip().upper()

    # janela do período
    inicio = date(ano, mes, 1)
    fim = date(ano + 1, 1, 1) if mes == 12 else date(ano, mes + 1, 1)

    db = SessionLocal()
    try:
        base = db.query(Venda).filter(Venda.movimento >= inicio, Venda.movimento < fim)
        base_hist = db.query(Venda).filter(Venda.movimento.isnot(None))

        escopo_label = None
        pode_filtrar_emp = False
        pode_filtrar_vendedor = False

        if role == "admin":
            pode_filtrar_emp = True
            pode_filtrar_vendedor = True
            if emp_filtro:
                base = base.filter(Venda.emp == emp_filtro)
                base_hist = base_hist.filter(Venda.emp == emp_filtro)
                escopo_label = f"EMP {emp_filtro}"
            if vendedor_filtro:
                base = base.filter(func.upper(Venda.vendedor) == vendedor_filtro)
                base_hist = base_hist.filter(func.upper(Venda.vendedor) == vendedor_filtro)
                escopo_label = (escopo_label + " • " if escopo_label else "") + f"Vendedor {vendedor_filtro}"

        elif role == "supervisor":
            # Supervisor: acesso às Empresas vinculadas via usuario_emps (pode ser 1 ou várias)
            allowed_emps = _allowed_emps()
            if allowed_emps:
                base = base.filter(Venda.emp.in_(allowed_emps))
                base_hist = base_hist.filter(Venda.emp.in_(allowed_emps))
                # permite filtrar por uma Empresa específica dentro do escopo
                if emp_filtro and emp_filtro in allowed_emps:
                    base = base.filter(Venda.emp == emp_filtro)
                    base_hist = base_hist.filter(Venda.emp == emp_filtro)
                    escopo_label = f"Empresa {emp_filtro}"
                else:
                    escopo_label = "Empresas vinculadas"
            else:
                # sem Empresas vinculadas -> sem dados
                base = base.filter(text("1=0"))
                base_hist = base_hist.filter(text("1=0"))
                escopo_label = "Sem empresas vinculadas"
            pode_filtrar_vendedor = True
            if vendedor_filtro:
                base = base.filter(func.upper(Venda.vendedor) == vendedor_filtro)
                base_hist = base_hist.filter(func.upper(Venda.vendedor) == vendedor_filtro)
                escopo_label += f" • Vendedor {vendedor_filtro}"

        else:
            base = base.filter(func.upper(Venda.vendedor) == vendedor_logado)
            base_hist = base_hist.filter(func.upper(Venda.vendedor) == vendedor_logado)
            escopo_label = f"Vendedor {vendedor_logado}"

        # EMPs no período
        emps = [str(e[0]) for e in base.with_entities(Venda.emp).distinct().order_by(Venda.emp).all() if e[0] is not None]

        # Totais por EMP
        totais_rows = (
            base.with_entities(
                Venda.emp.label("emp"),
                func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor_total"),
                func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd_total"),
                func.coalesce(func.count(func.distinct(Venda.mestre)), 0).label("mix_itens"),
                func.count(func.distinct(func.upper(Venda.vendedor))).label("vendedores"),
                func.count(func.distinct(Venda.cliente_id_norm)).label("clientes_unicos"),
                func.count(func.distinct(Venda.cidade_norm)).label("cidades"),
            )
            .group_by(Venda.emp)
            .all()
        )
        totais_map = {str(r.emp): {
            "valor_total": float(r.valor_total or 0.0),
            "qtd_total": float(r.qtd_total or 0.0),
                "mix_itens": int(getattr(r, "mix_itens", 0) or 0),
            "vendedores": int(r.vendedores or 0),
            "clientes_unicos": int(r.clientes_unicos or 0),
            "cidades": int(r.cidades or 0),
        } for r in totais_rows}

        # Ranking de cidades por EMP
        city_rows = (
            base.with_entities(
                Venda.emp.label("emp"),
                func.coalesce(Venda.cidade_norm, "sem_cidade").label("cidade_norm"),
                func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor_total"),
                func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd_total"),
                func.coalesce(func.count(func.distinct(Venda.mestre)), 0).label("mix_itens"),
                func.count(func.distinct(Venda.cliente_id_norm)).label("clientes_unicos"),
            )
            .group_by(Venda.emp, func.coalesce(Venda.cidade_norm, "sem_cidade"))
            .order_by(Venda.emp, func.sum(Venda.valor_total).desc())
            .all()
        )

        cidades_por_emp = {}
        for r in city_rows:
            emp = str(r.emp)
            total_emp = (totais_map.get(emp, {}) or {}).get("valor_total", 0.0) or 0.0
            cidade_norm = r.cidade_norm
            label = "SEM CIDADE" if (cidade_norm in (None, "", "sem_cidade")) else str(cidade_norm).upper()
            valor = float(r.valor_total or 0.0)
            pct = (valor / total_emp * 100.0) if total_emp > 0 else 0.0
            cidades_por_emp.setdefault(emp, []).append({
                "cidade_norm": cidade_norm,
                "cidade_label": label,
                "valor_total": valor,
                "pct": pct,
                "qtd_total": float(r.qtd_total or 0.0),
                "mix_itens": int(getattr(r, "mix_itens", 0) or 0),
                "clientes_unicos": int(r.clientes_unicos or 0),
            })

        # Top clientes por EMP (por valor no período)
        signed_val = case(
            (Venda.mov_tipo_movto.in_(["DS", "CA"]), -Venda.valor_total),
            else_=Venda.valor_total,
        )

        cliente_rows = (
            base.with_entities(
                Venda.emp.label("emp"),
                Venda.cliente_id_norm.label("cliente_id"),
                func.coalesce(func.max(Venda.razao), "").label("cliente_label"),
                func.coalesce(func.max(Venda.razao_norm), "").label("razao_norm"),
                func.coalesce(func.sum(signed_val), 0.0).label("valor_total"),
                func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd_total"),
                func.coalesce(func.count(func.distinct(Venda.mestre)), 0).label("mix_itens"),
            )
            .filter(Venda.cliente_id_norm.isnot(None))
            .group_by(Venda.emp, Venda.cliente_id_norm)
            .order_by(Venda.emp, func.coalesce(func.sum(signed_val), 0.0).desc())
            .all()
        )

        clientes_por_emp = {}
        for r in cliente_rows:
            emp = str(r.emp)
            cliente_id = str(getattr(r, "cliente_id", "") or "").strip()
            label = (getattr(r, "cliente_label", "") or "").strip() or cliente_id or "SEM CLIENTE"
            clientes_por_emp.setdefault(emp, []).append({
                "cliente_id": cliente_id,
                "cliente_label": label,
                "razao_norm": (getattr(r, "razao_norm", "") or "").strip(),
                "valor_total": float(r.valor_total or 0.0),
                "qtd_total": float(r.qtd_total or 0.0),
                "mix_itens": int(getattr(r, "mix_itens", 0) or 0),
            })

        # Clientes novos vs recorrentes por EMP
        clientes_periodo = (
            base.with_entities(
                Venda.emp.label("emp"),
                Venda.cliente_id_norm.label("cid"),
            )
            .filter(Venda.cliente_id_norm.isnot(None))
            .distinct()
            .subquery()
        )

        min_datas = (
            base_hist.with_entities(
                Venda.emp.label("emp"),
                Venda.cliente_id_norm.label("cid"),
                func.min(Venda.movimento).label("min_data"),
            )
            .filter(Venda.cliente_id_norm.isnot(None))
            .group_by(Venda.emp, Venda.cliente_id_norm)
            .subquery()
        )

        novos_rows = (
            db.query(clientes_periodo.c.emp.label("emp"), func.count().label("qtd"))
            .select_from(clientes_periodo.join(min_datas, (clientes_periodo.c.emp == min_datas.c.emp) & (clientes_periodo.c.cid == min_datas.c.cid)))
            .filter(min_datas.c.min_data >= inicio)
            .group_by(clientes_periodo.c.emp)
            .all()
        )
        recorr_rows = (
            db.query(clientes_periodo.c.emp.label("emp"), func.count().label("qtd"))
            .select_from(clientes_periodo.join(min_datas, (clientes_periodo.c.emp == min_datas.c.emp) & (clientes_periodo.c.cid == min_datas.c.cid)))
            .filter(min_datas.c.min_data < inicio)
            .group_by(clientes_periodo.c.emp)
            .all()
        )
        novos_map = {str(r.emp): int(r.qtd or 0) for r in novos_rows}
        recorr_map = {str(r.emp): int(r.qtd or 0) for r in recorr_rows}

        # Cards por EMP (preview + detalhe)
        emp_cards = []
        for emp in emps:
            t = totais_map.get(emp) or {"valor_total": 0.0, "qtd_total": 0.0, "vendedores": 0, "clientes_unicos": 0, "cidades": 0}
            cities_full = cidades_por_emp.get(emp, [])
            clients_full = clientes_por_emp.get(emp, [])

            emp_cards.append({
                "emp": emp,
                "image_url": None,  # preparado para imagem da loja futuramente
                "totais": {
                    **t,
                    "clientes_novos": novos_map.get(emp, 0),
                    "clientes_recorrentes": recorr_map.get(emp, 0),
                },
                "cidades_preview": cities_full[:5],
                "cidades_full": cities_full,
                "clientes_preview": clients_full[:5],
                "clientes_full": clients_full,
            })

        return render_template(
            "relatorio_cidades_clientes.html",
            mes=mes,
            ano=ano,
            escopo_label=escopo_label,
            pode_filtrar_emp=pode_filtrar_emp,
            pode_filtrar_vendedor=pode_filtrar_vendedor,
            emp_filtro=emp_filtro,
            vendedor_filtro=vendedor_filtro,
            emp_cards=emp_cards,
        )
    finally:
        db.close()





## Relatório (AJAX): cidade -> clientes (modal)
@app.get("/relatorios/cidade-clientes")
def relatorio_cidade_clientes_api():
    """Retorna JSON com ranking de clientes dentro de uma cidade no período.

    Parâmetros:
      - emp (obrigatório)
      - cidade_norm (obrigatório; use 'sem_cidade' para vazio)
      - mes, ano (obrigatórios)
      - vendedor (opcional, ADMIN/SUPERVISOR)
    """
    red = _login_required()
    if red:
        return red

    role = (_role() or "").strip().lower()
    emp_usuario = _emp()
    vendedor_logado = (_usuario_logado() or "").strip().upper()

    emp = (request.args.get("emp") or "").strip()
    cidade_norm = (request.args.get("cidade_norm") or "").strip()
    mes = int(request.args.get("mes") or 0)
    ano = int(request.args.get("ano") or 0)
    vendedor = (request.args.get("vendedor") or "").strip().upper()

    if not emp or not cidade_norm or not mes or not ano:
        return jsonify({"error": "Parâmetros inválidos"}), 400

    # Permissões
    if role == "supervisor":
        allowed_emps = _allowed_emps()
        if allowed_emps and str(emp) not in set(allowed_emps):
            return jsonify({"error": "Acesso negado"}), 403
    elif role == "vendedor":
        vendedor = vendedor_logado

    inicio = date(int(ano), int(mes), 1)
    fim = date(int(ano) + 1, 1, 1) if int(mes) == 12 else date(int(ano), int(mes) + 1, 1)

    signed_val = case(
        (Venda.mov_tipo_movto.in_(["DS", "CA"]), -Venda.valor_total),
        else_=Venda.valor_total,
    )

    with SessionLocal() as db:
        base = db.query(Venda).filter(
            Venda.emp == str(emp),
            Venda.movimento >= inicio,
            Venda.movimento < fim,
        )

        if cidade_norm == "sem_cidade":
            base = base.filter(or_(Venda.cidade_norm.is_(None), Venda.cidade_norm == "", Venda.cidade_norm == "sem_cidade"))
        else:
            base = base.filter(Venda.cidade_norm == cidade_norm)

        if vendedor:
            base = base.filter(func.upper(Venda.vendedor) == vendedor)

        rows = (
            base.with_entities(
                Venda.cliente_id_norm.label("cliente_id"),
                func.coalesce(func.max(Venda.razao), "").label("cliente"),
                func.coalesce(func.sum(signed_val), 0.0).label("valor_total"),
                func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd_total"),
                func.count(func.distinct(Venda.mestre)).label("mix_itens"),
            )
            .filter(Venda.cliente_id_norm.isnot(None))
            .group_by(Venda.cliente_id_norm)
            .order_by(func.coalesce(func.sum(signed_val), 0.0).desc())
            .all()
        )

    out = []
    for r in rows:
        label = (r.cliente or "").strip() or str(r.cliente_id)
        out.append({
            "cliente_id": str(r.cliente_id),
            "cliente": label,
            "valor_total": float(r.valor_total or 0.0),
            "qtd_total": float(r.qtd_total or 0.0),
            "mix_itens": int(r.mix_itens or 0),
        })

    return jsonify({"emp": emp, "cidade_norm": cidade_norm, "ano": ano, "mes": mes, "clientes": out})



## Relatório (AJAX): cliente -> marcas (modal)
@app.get("/relatorios/cliente-marcas")
def relatorio_cliente_marcas_api():
    """Retorna JSON com participação por marca para um cliente (RAZAO_NORM) no período."""
    red = _login_required()
    if red:
        return red

    role = (_role() or "").strip().lower()
    allowed_emps = _allowed_emps()
    vendedor_logado = (_usuario_logado() or "").strip().upper()

    emp = (request.args.get("emp") or "").strip()
    # compat: o front antigo mandava razao_norm; o novo usa cliente_id (cliente_id_norm)
    razao_norm = (request.args.get("razao_norm") or "").strip()
    cliente_id = (request.args.get("cliente_id") or request.args.get("cliente") or "").strip()
    cidade_norm = (request.args.get("cidade_norm") or "").strip()
    mes = int(request.args.get("mes") or 0)
    ano = int(request.args.get("ano") or 0)
    vendedor = (request.args.get("vendedor") or "").strip().upper()

    # Requer emp + (razao_norm ou cliente_id) + período
    if not emp or (not razao_norm and not cliente_id) or not mes or not ano:
        return jsonify({"error": "Parâmetros inválidos"}), 400

    # Permissões
    if role == "supervisor":
        if allowed_emps and str(emp) not in [str(e) for e in allowed_emps]:
            return jsonify({"error": "Acesso negado"}), 403
    elif role == "vendedor":
        vendedor = vendedor_logado  # vendedor não pode consultar outro vendedor

    with SessionLocal() as db:
        base = db.query(Venda).filter(
            Venda.emp == str(emp),
            extract("month", Venda.movimento) == mes,
            extract("year", Venda.movimento) == ano,
        )

        # Identificação do cliente (compat)
        if razao_norm:
            base = base.filter(Venda.razao_norm == razao_norm)
        elif cliente_id:
            base = base.filter(Venda.cliente_id_norm == cliente_id)
        else:
            return jsonify({"error": "Parâmetros inválidos"}), 400

        if cidade_norm:
            if cidade_norm == "sem_cidade":
                base = base.filter(or_(Venda.cidade_norm.is_(None), Venda.cidade_norm == "", Venda.cidade_norm == "sem_cidade"))
            else:
                base = base.filter(Venda.cidade_norm == cidade_norm)
        if vendedor:
            base = base.filter(func.upper(Venda.vendedor) == vendedor)

        signed_val = case(
            (Venda.mov_tipo_movto.in_(["DS", "CA"]), -Venda.valor_total),
            else_=Venda.valor_total,
        )

        total = float(base.with_entities(func.coalesce(func.sum(signed_val), 0)).scalar() or 0.0)

        mix_itens = int(base.with_entities(func.count(func.distinct(Venda.mestre))).scalar() or 0)

        marcas_rows = (
            base.with_entities(
                Venda.marca.label("marca"),
                func.coalesce(func.sum(signed_val), 0).label("valor_total"),
                func.count(func.distinct(Venda.mestre)).label("mix_itens"),
            )
            .group_by(Venda.marca)
            .order_by(func.coalesce(func.sum(signed_val), 0).desc())
            .all()
        )

    marcas = []
    for r in marcas_rows:
        v = float(r.valor_total or 0.0)
        marcas.append(
            {
                "marca": r.marca or "SEM MARCA",
                "valor_total": v,
                "mix_itens": int(r.mix_itens or 0),
                "percent": (v / total * 100.0) if total else 0.0,
            }
        )

    return jsonify(
        {
            "emp": str(emp),
            "razao_norm": razao_norm,
            "ano": ano,
            "mes": mes,
            "total": total,
            "mix_itens": mix_itens,
            "marcas": marcas,
        }
    )



## Relatório (AJAX): cliente -> itens (modal)
@app.get("/relatorios/cliente-itens")
def relatorio_cliente_itens_api():
    """Retorna JSON com itens únicos comprados por um cliente (RAZAO_NORM) no período.

    Retorna:
    - total: soma (com sinal) do valor_total no período
    - itens_unicos: quantidade de itens únicos (distinct mestre)
    - itens: lista de {mestre, descricao, valor_total}
    """
    red = _login_required()
    if red:
        return red

    role = (_role() or "").strip().lower()
    emp_usuario = _emp()
    vendedor_logado = (_usuario_logado() or "").strip().upper()

    emp = (request.args.get("emp") or "").strip()
    # compat: front antigo mandava razao_norm; novo prefere cliente_id (cliente_id_norm)
    razao_norm = (request.args.get("razao_norm") or "").strip()
    cliente_id = (request.args.get("cliente_id") or request.args.get("cliente") or "").strip()
    mes = int(request.args.get("mes") or 0)
    ano = int(request.args.get("ano") or 0)
    vendedor = (request.args.get("vendedor") or "").strip().upper()
    cliente_label = (request.args.get("cliente_label") or request.args.get("label") or "").strip()

    if not emp or (not razao_norm and not cliente_id and not cliente_label) or not mes or not ano:
        return jsonify({"error": "Parâmetros inválidos"}), 400

    # Permissões por perfil
    if role == "supervisor":
        allowed_emps = _allowed_emps()
        if allowed_emps and str(emp) not in set(allowed_emps):
            return jsonify({"error": "Acesso negado"}), 403
    elif role == "vendedor":
        # vendedor só pode ver os próprios dados (e não pode trocar vendedor via query)
        vendedor = vendedor_logado

    # Query base
    with SessionLocal() as db:
        base = db.query(Venda).filter(
            Venda.emp == str(emp),
            extract("month", Venda.movimento) == mes,
            extract("year", Venda.movimento) == ano,
        )

        # Identificação do cliente (compat / robusto)
        # Alguns bancos podem ter cliente_id_norm ou razao_norm inconsistentes; se vierem ambos, usamos OR.
        if cliente_id and razao_norm:
            base = base.filter(or_(Venda.cliente_id_norm == cliente_id, Venda.razao_norm == razao_norm))
        elif cliente_id:
            base = base.filter(Venda.cliente_id_norm == cliente_id)
        elif razao_norm:
            base = base.filter(Venda.razao_norm == razao_norm)
        elif cliente_label:
            # fallback: tenta pelo nome do cliente (normalizado)
            lbl_norm = _norm_txt(cliente_label)
            base = base.filter(or_(func.upper(Venda.cliente) == cliente_label.upper(), Venda.razao_norm == lbl_norm))
        else:
            return jsonify({"error": "Parâmetros inválidos"}), 400

        if vendedor:
            base = base.filter(func.upper(Venda.vendedor) == vendedor)

        signed_val = case(
            (Venda.mov_tipo_movto.in_(["DS", "CA"]), -Venda.valor_total),
            else_=Venda.valor_total,
        )

        total = base.with_entities(func.coalesce(func.sum(signed_val), 0)).scalar() or 0
        total = float(total)

        itens_unicos = base.with_entities(func.count(func.distinct(Venda.mestre))).scalar() or 0
        itens_unicos = int(itens_unicos)

        itens_rows = (
            base.with_entities(
                Venda.mestre.label("mestre"),
                Venda.descricao.label("descricao"),
                func.coalesce(func.sum(signed_val), 0).label("valor_total"),
            )
            .group_by(Venda.mestre, Venda.descricao)
            .order_by(func.coalesce(func.sum(signed_val), 0).desc())
            .all()
        )

    itens = []
    for r in itens_rows:
        itens.append({
            "mestre": (r.mestre or "").strip(),
            "descricao": (r.descricao or "").strip(),
            "valor_total": float(r.valor_total or 0.0),
        })

    return jsonify({
        "emp": emp,
        "cliente_id": cliente_id,
        "razao_norm": razao_norm,
        "cliente_label": cliente_label,

        "ano": ano,
        "mes": mes,
        "total": total,
        "itens_unicos": itens_unicos,
        "itens": itens,
    })

@app.route("/senha", methods=["GET", "POST"])
def senha():
    red = _login_required()
    if red:
        return red

    vendedor = _usuario_logado()
    if request.method == "GET":
        return render_template("senha.html", vendedor=vendedor, erro=None, ok=None)

    senha_atual = request.form.get("senha_atual") or ""
    nova_senha = request.form.get("nova_senha") or ""
    confirmar = request.form.get("confirmar") or ""

    if len(nova_senha) < 4:
        return render_template("senha.html", vendedor=vendedor, erro="Nova senha muito curta.", ok=None)
    if nova_senha != confirmar:
        return render_template("senha.html", vendedor=vendedor, erro="As senhas não conferem.", ok=None)

    with SessionLocal() as db:
        u = db.query(Usuario).filter(Usuario.username == vendedor).first()
        if not u or not check_password_hash(u.senha_hash, senha_atual):
            return render_template("senha.html", vendedor=vendedor, erro="Senha atual incorreta.", ok=None)

        u.senha_hash = generate_password_hash(nova_senha)
        db.commit()

    return render_template("senha.html", vendedor=vendedor, erro=None, ok="Senha atualizada com sucesso!")

@app.route("/admin/usuarios", methods=["GET", "POST"])
def admin_usuarios():
    red = _login_required()
    if red:
        return red
    red = _admin_required()
    if red:
        return red

    usuario = _usuario_logado()
    erro = None
    ok = None

    with SessionLocal() as db:
        if request.method == "POST":
            acao = request.form.get("acao")
            try:
                if acao == "criar":
                    novo_usuario = (request.form.get("novo_usuario") or "").strip().upper()
                    nova_senha = request.form.get("nova_senha") or ""
                    role = (request.form.get("role") or "vendedor").strip().lower()

                    # EMPs vinculadas (preferencialmente via multi-select). Aceita também texto (compatibilidade).
                    emps_sel = [str(x).strip() for x in (request.form.getlist("emps_multi") or []) if str(x).strip()]
                    emps_raw = (request.form.get("emps_text") or request.form.get("emps") or "").strip()
                    if emps_raw:
                        for part in re.split(r"[\s,;]+", emps_raw):
                            if part:
                                emps_sel.append(str(part).strip())
                    # normaliza e remove duplicadas
                    desired_emps = sorted({e for e in emps_sel if e})
                    if len(nova_senha) < 4:
                        raise ValueError("Senha muito curta (mín. 4).")
                    if role not in {"admin", "supervisor", "vendedor", "financeiro"}:
                        role = "vendedor"
                    # Regras:
                    # - Vendedor/Supervisor: precisam ter ao menos 1 EMP ativa
                    # - Admin/Financeiro: EMP é opcional (Financeiro enxerga todas as EMPs)
                    if role in {"vendedor", "supervisor"} and not desired_emps:
                        raise ValueError("Selecione ao menos 1 EMP para vendedor/supervisor.")

                    # EMP legado (usuarios.emp) não é mais usado na UI/regra de permissão.
                    # A fonte oficial agora é usuario_emps.
                    emp_val = None
                    u = db.query(Usuario).filter(Usuario.username == novo_usuario).first()
                    if u:
                        u.senha_hash = generate_password_hash(nova_senha)
                        u.role = role
                        # Não mantém EMP legado para evitar duplicidade/confusão visual
                        setattr(u, "emp", None)

                        # Atualiza vínculos multi-EMP (usuario_emps)
                        if desired_emps:
                            links = db.query(UsuarioEmp).filter(UsuarioEmp.usuario_id == u.id).all()
                            current = {lk.emp: lk for lk in links}
                            for emp, lk in current.items():
                                lk.ativo = (emp in desired_emps)
                            for emp in desired_emps:
                                if emp not in current:
                                    db.add(UsuarioEmp(usuario_id=u.id, emp=emp, ativo=True))
                        else:
                            # Admin: desativa qualquer vínculo existente (opcional)
                            links = db.query(UsuarioEmp).filter(UsuarioEmp.usuario_id == u.id).all()
                            for lk in links:
                                lk.ativo = False

                        db.commit()
                        ok = f"Usuário {novo_usuario} atualizado."
                    else:
                        u_new = Usuario(
                            username=novo_usuario,
                            senha_hash=generate_password_hash(nova_senha),
                            role=role,
                            emp=None,
                        )
                        db.add(u_new)
                        db.commit()  # precisa do id

                        if desired_emps:
                            for emp in desired_emps:
                                db.add(UsuarioEmp(usuario_id=u_new.id, emp=emp, ativo=True))
                            db.commit()

                        ok = f"Usuário {novo_usuario} criado."

                elif acao == "reset":
                    alvo = (request.form.get("alvo") or "").strip().upper()
                    nova_senha = request.form.get("nova_senha") or ""
                    if alvo == "ADMIN":
                        raise ValueError("Para o ADMIN, use 'Trocar minha senha'.")
                    u = db.query(Usuario).filter(Usuario.username == alvo).first()
                    if not u:
                        raise ValueError("Usuário não encontrado.")
                    if len(nova_senha) < 4:
                        raise ValueError("Senha muito curta (mín. 4).")
                    u.senha_hash = generate_password_hash(nova_senha)
                    db.commit()
                    ok = f"Senha de {alvo} atualizada."

                elif acao == "remover":
                    alvo = (request.form.get("alvo") or "").strip().upper()
                    if alvo == "ADMIN":
                        raise ValueError("O usuário ADMIN não pode ser removido.")
                    u = db.query(Usuario).filter(Usuario.username == alvo).first()
                    if not u:
                        raise ValueError("Usuário não encontrado.")
                    db.delete(u)
                    db.commit()
                    ok = f"Usuário {alvo} removido."
                elif acao == "set_emps":
                    alvo = (request.form.get("alvo") or "").strip().upper()
                    # Aceita lista via checkbox/multi (emps_multi) ou texto (compatibilidade)
                    emps_sel = [str(x).strip() for x in (request.form.getlist("emps_multi") or []) if str(x).strip()]
                    emps_raw = (request.form.get("emps") or "")
                    if emps_raw.strip():
                        for part in re.split(r"[\s,;]+", emps_raw.strip()):
                            if part:
                                emps_sel.append(str(part).strip())
                    emps = sorted({e for e in emps_sel if e})
                    if not alvo:
                        raise ValueError("Informe o usuário.")
                    u = db.query(Usuario).filter(Usuario.username == alvo).first()
                    if not u:
                        raise ValueError("Usuário não encontrado.")
                    # Admin pode ter 0+ vínculos (opcional). Vendedor/Supervisor precisam de 1+.
                    if u.role in ("vendedor", "supervisor") and not emps:
                        raise ValueError("Vendedor/Supervisor precisam ter ao menos 1 EMP.")
                    desired = set(emps)
                    links = db.query(UsuarioEmp).filter(UsuarioEmp.usuario_id == u.id).all()
                    current = {lk.emp: lk for lk in links}
                    # desativa o que não está no desired
                    for emp, lk in current.items():
                        should_active = (emp in desired)
                        if lk.ativo != should_active:
                            lk.ativo = should_active
                    # cria/ativa os que faltam
                    for emp in desired:
                        lk = current.get(emp)
                        if lk is None:
                            db.add(UsuarioEmp(usuario_id=u.id, emp=emp))
                        elif not lk.ativo:
                            lk.ativo = True
                    db.commit()
                    ok = "EMPs do usuário %s atualizadas: %s" % (alvo, (", ".join(sorted(desired)) if desired else "nenhuma"))

                elif acao == "set_emp_e_emps":
                    """Atualiza EMP legado (Usuario.emp) e vínculos multi-EMP (UsuarioEmp).

                    Regras:
                    - Aceita EMP legado vazia (remove), mas para SUPERVISOR exige ao menos 1 EMP válida (legado ou vinculada).
                    - Se EMP legado vier vazia e houver EMPs vinculadas, define legado como a primeira (mantém compatibilidade).
                    """
                    alvo = (request.form.get("alvo") or "").strip().upper()
                    emp_legado_raw = (request.form.get("emp_legado") or "").strip()
                    emps_raw = (request.form.get("emps") or "")

                    if not alvo:
                        raise ValueError("Informe o usuário.")
                    u = db.query(Usuario).filter(Usuario.username == alvo).first()
                    if not u:
                        raise ValueError("Usuário não encontrado.")
                    if u.role not in ("vendedor", "supervisor"):
                        raise ValueError("Apenas VENDEDOR ou SUPERVISOR podem ser vinculados a EMPs.")

                    # Normaliza lista de EMPs vinculadas
                    emps = []
                    for part in re.split(r"[\s,;]+", emps_raw.strip()):
                        if part:
                            emps.append(str(part).strip())
                    desired = set([e for e in emps if e])

                    # Atualiza vínculos (substitui lista)
                    links = db.query(UsuarioEmp).filter(UsuarioEmp.usuario_id == u.id).all()
                    current = {lk.emp: lk for lk in links}
                    for emp, lk in current.items():
                        should_active = (emp in desired)
                        if lk.ativo != should_active:
                            lk.ativo = should_active
                    for emp in desired:
                        lk = current.get(emp)
                        if lk is None:
                            db.add(UsuarioEmp(usuario_id=u.id, emp=emp))
                        elif not lk.ativo:
                            lk.ativo = True

                    # Atualiza EMP legado
                    emp_legado = str(emp_legado_raw).strip() if emp_legado_raw else None
                    if not emp_legado and desired:
                        # Mantém compatibilidade: define a primeira EMP vinculada como padrão
                        emp_legado = sorted(desired)[0]

                    if u.role == "supervisor" and not emp_legado and not desired:
                        raise ValueError("Supervisor precisa ter ao menos 1 EMP (legado ou vinculada).")

                    setattr(u, "emp", emp_legado)
                    db.commit()
                    ok = f"Atualizado: {alvo} | EMP legado: {emp_legado or '-'} | EMPs vinculadas: {( ', '.join(sorted(desired)) if desired else '-') }"

                elif acao == "vincular_emps":
                    alvo = (request.form.get("alvo") or "").strip().upper()
                    emps_raw = (request.form.get("emps") or "")
                    emps = []
                    for part in re.split(r"[\s,;]+", emps_raw.strip()):
                        if part:
                            emps.append(str(part).strip())
                    if not alvo or not emps:
                        raise ValueError("Informe o usuário e uma ou mais EMPs (ex.: 101,102).")
                    u = db.query(Usuario).filter(Usuario.username == alvo).first()
                    if not u:
                        raise ValueError("Usuário não encontrado.")
                    if u.role not in {"vendedor", "supervisor"}:
                        raise ValueError("Apenas VENDEDOR ou SUPERVISOR podem ter múltiplas EMPs vinculadas.")
                    added = 0
                    for emp in sorted(set(emps)):
                        # upsert simples: tenta buscar, senão cria
                        link = db.query(UsuarioEmp).filter(UsuarioEmp.usuario_id == u.id, UsuarioEmp.emp == emp).first()
                        if link:
                            if not link.ativo:
                                link.ativo = True
                                added += 1
                        else:
                            db.add(UsuarioEmp(usuario_id=u.id, emp=emp))
                            added += 1
                    db.commit()
                    ok = f"Vínculo atualizado: {alvo} agora está em {added} EMP(s) adicionada(s)/reativada(s)."

                elif acao == "remover_emp":
                    alvo = (request.form.get("alvo") or "").strip().upper()
                    emp = (request.form.get("emp") or "").strip()
                    if not alvo or not emp:
                        raise ValueError("Informe o usuário e a EMP para remover.")
                    u = db.query(Usuario).filter(Usuario.username == alvo).first()
                    if not u:
                        raise ValueError("Usuário não encontrado.")
                    link = db.query(UsuarioEmp).filter(UsuarioEmp.usuario_id == u.id, UsuarioEmp.emp == emp).first()
                    if not link:
                        raise ValueError("Vínculo usuário×EMP não encontrado.")
                    link.ativo = False
                    db.commit()
                    ok = f"EMP {emp} removida do usuário {alvo}."

                else:
                    raise ValueError("Ação inválida.")

            except Exception as e:
                db.rollback()
                erro = str(e)
                app.logger.exception("Erro na admin/usuarios")

        usuarios = db.query(Usuario).order_by(Usuario.role.desc(), Usuario.username.asc()).all()
        usuarios_out = [
            {"usuario": u.username, "role": u.role}
            for u in usuarios
        ]

        # Vínculos multi-EMP (usuario_emps)
        vinculos = {}
        try:
            links = db.query(UsuarioEmp).filter(UsuarioEmp.ativo == True).order_by(UsuarioEmp.emp.asc()).all()
            # map usuario_id -> username
            id_to_user = {u.id: u.username for u in usuarios}
            for lk in links:
                uname = id_to_user.get(lk.usuario_id)
                if not uname:
                    continue
                vinculos.setdefault(uname, []).append(lk.emp)
        except Exception:
            vinculos = {}

        # EMPs cadastradas (profissional). Se ainda não tiver, cai para EMPs vistas em vendas.
        emps_cadastradas = []
        try:
            emps_cadastradas = (
                db.query(Emp)
                .order_by(Emp.codigo.asc())
                .all()
            )
        except Exception:
            emps_cadastradas = []

        # Labels para exibir EMP de forma amigável (código — nome (cidade/UF))
        emp_labels: dict[str, str] = {}
        for e in emps_cadastradas or []:
            try:
                code = str(e.codigo).strip()
                if not code:
                    continue
                extra = ""
                if getattr(e, "cidade", None) or getattr(e, "uf", None):
                    c = (getattr(e, "cidade", None) or "").strip()
                    uf = (getattr(e, "uf", None) or "").strip()
                    if c and uf:
                        extra = f" ({c}/{uf})"
                    elif c:
                        extra = f" ({c})"
                    elif uf:
                        extra = f" ({uf})"
                emp_labels[code] = f"{code} — {(getattr(e, 'nome', '') or '').strip()}{extra}".strip()
            except Exception:
                continue

        try:
            emps_disponiveis = [str(r[0]) for r in db.query(Venda.emp).distinct().order_by(Venda.emp.asc()).all() if r[0] is not None]
        except Exception:
            emps_disponiveis = []


    return render_template(
        "admin_usuarios.html",
        usuario=usuario,
        usuarios=usuarios_out,
        erro=erro,
        ok=ok,
        vinculos=vinculos,
        emps_cadastradas=emps_cadastradas,
        emp_labels=emp_labels,
        emps_disponiveis=emps_disponiveis,
    )


@app.route("/admin/emps", methods=["GET", "POST"])
def admin_emps():
    """Cadastro de EMPs (ADMIN).

    Permite cadastrar nome/cidade/UF para cada código EMP (loja/filial).
    """
    red = _login_required()
    if red:
        return red
    red = _admin_required()
    if red:
        return red

    usuario = _usuario_logado()
    erro = None
    ok = None

    with SessionLocal() as db:
        if request.method == "POST":
            acao = (request.form.get("acao") or "").strip()
            try:
                codigo = (request.form.get("codigo") or "").strip()
                nome = (request.form.get("nome") or "").strip()
                cidade = (request.form.get("cidade") or "").strip()
                uf = (request.form.get("uf") or "").strip().upper()
                ativo_raw = (request.form.get("ativo") or "1").strip()
                ativo = ativo_raw in {"1", "true", "True", "on", "SIM", "sim"}

                if acao in {"criar", "atualizar"}:
                    if not codigo:
                        raise ValueError("Informe o código EMP (ex.: 101).")
                    if not nome:
                        raise ValueError("Informe o nome da EMP.")
                    if uf and len(uf) != 2:
                        raise ValueError("UF inválida (use 2 letras, ex.: SP).")

                    emp = db.query(Emp).filter(Emp.codigo == codigo).first()
                    if emp:
                        emp.nome = nome
                        emp.cidade = cidade or None
                        emp.uf = uf or None
                        emp.ativo = ativo
                        emp.updated_at = datetime.utcnow()
                        ok = f"EMP {codigo} atualizada."
                    else:
                        db.add(
                            Emp(
                                codigo=codigo,
                                nome=nome,
                                cidade=cidade or None,
                                uf=uf or None,
                                ativo=ativo,
                            )
                        )
                        ok = f"EMP {codigo} criada."
                    db.commit()

                elif acao == "toggle":
                    if not codigo:
                        raise ValueError("Informe o código EMP.")
                    emp = db.query(Emp).filter(Emp.codigo == codigo).first()
                    if not emp:
                        raise ValueError("EMP não encontrada.")
                    emp.ativo = not bool(emp.ativo)
                    emp.updated_at = datetime.utcnow()
                    db.commit()
                    ok = f"EMP {codigo} agora está {'ATIVA' if emp.ativo else 'INATIVA'}."
                else:
                    raise ValueError("Ação inválida.")
            except Exception as e:
                db.rollback()
                erro = str(e)
                app.logger.exception("Erro na admin/emps")

        emps = db.query(Emp).order_by(Emp.ativo.desc(), Emp.codigo.asc()).all()

    return render_template(
        "admin_emps.html",
        usuario=usuario,
        erro=erro,
        ok=ok,
        emps=emps,
    )


@app.get("/admin/cache/refresh")
def admin_cache_refresh():
    """Recalcula o cache do dashboard para um EMP/mês/ano (ADMIN).

    Exemplo:
      /admin/cache/refresh?emp=101&ano=2026&mes=1
    """
    red = _login_required()
    if red:
        return red
    red2 = _admin_required()
    if red2:
        return red2

    emp = (request.args.get("emp") or "").strip()
    ano = int(request.args.get("ano") or datetime.now().year)
    mes = int(request.args.get("mes") or datetime.now().month)

    if not emp:
        return jsonify({"ok": False, "error": "Parâmetro 'emp' é obrigatório."}), 400

    try:
        from dashboard_cache import refresh_dashboard_cache
        info = refresh_dashboard_cache(emp, ano, mes)
        return jsonify({"ok": True, "emp": emp, "ano": ano, "mes": mes, **info})
    except Exception as e:
        app.logger.exception("Falha ao atualizar cache")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/admin/importar", methods=["GET", "POST"])
def admin_importar():
    red = _login_required()
    if red:
        return red
    red = _admin_required()
    if red:
        return red

    if request.method == "GET":
        return render_template("admin_importar.html")

    arquivo = request.files.get("arquivo")
    if not arquivo or not arquivo.filename:
        flash("Selecione um arquivo .xlsx para importar.", "warning")
        return redirect(url_for("admin_importar"))

    if not arquivo.filename.lower().endswith(".xlsx"):
        flash("Formato inválido. Envie um arquivo .xlsx.", "danger")
        return redirect(url_for("admin_importar"))

    modo = request.form.get("modo", "ignorar_duplicados")
    # IMPORTANTISSIMO:
    # A chave de deduplicidade precisa bater com o indice/constraint UNIQUE do banco.
    # Seu banco foi padronizado com:
    #   (mestre, marca, vendedor, movimento, mov_tipo_movto, nota, emp)
    # Se a chave nao incluir MOVIMENTO e MOV_TIPO_MOVTO (DS/CA/OA), o Postgres
    # pode retornar erro de ON CONFLICT e/ou DS/CA pode ser ignorado.
    chave = request.form.get("chave", "mestre_movimento_vendedor_nota_tipo_emp")

    # Salva temporariamente
    import tempfile

    with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
        arquivo.save(tmp.name)
        tmp_path = tmp.name

    try:
        resumo = importar_planilha(tmp_path, modo=modo, chave=chave)
        if not resumo.get("ok"):
            faltando = resumo.get("faltando")
            if faltando:
                flash("Colunas faltando: " + ", ".join(faltando), "danger")
            else:
                flash(resumo.get("msg", "Falha ao importar."), "danger")
            return redirect(url_for("admin_importar"))

        flash(
            (
                f"Importação concluída. Válidas: {resumo['validas']} | "
                f"Inseridas: {resumo['inseridas']} | "
                f"Ignoradas: {resumo['ignoradas']} | "
                f"Erros: {resumo['erros_linha']}"
            ),
            "success",
        )
        # Limpa cache do DataFrame para refletir novos dados imediatamente
        try:
            limpar_cache_df()
        except Exception:
            pass
        return redirect(url_for("admin_importar"))

    except Exception:
        app.logger.exception("Erro ao importar planilha")
        flash("Erro ao importar. Veja os logs no Render.", "danger")
        return redirect(url_for("admin_importar"))
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass



@app.route("/admin/itens_parados", methods=["GET", "POST"])
def admin_itens_parados():
    """Cadastro de itens parados (liquidação) por EMP.

    Campos: EMP, Código, Descrição, Quantidade, Recompensa(%).
    """
    red = _login_required()
    if red:
        return red
    red = _admin_required()
    if red:
        return red

    erro = None
    ok = None

    with SessionLocal() as db:
        if request.method == 'POST':
            acao = (request.form.get('acao') or '').strip().lower()
            try:
                if acao == 'criar':
                    emp = (request.form.get('emp') or '').strip()
                    codigo = (request.form.get('codigo') or '').strip()
                    descricao = (request.form.get('descricao') or '').strip()
                    quantidade_raw = (request.form.get('quantidade') or '').strip()
                    recompensa_raw = (request.form.get('recompensa_pct') or '').strip().replace(',', '.')

                    if not emp:
                        raise ValueError('Informe a EMP.')
                    if not codigo:
                        raise ValueError('Informe o CÓDIGO.')

                    quantidade = int(quantidade_raw) if quantidade_raw else None
                    recompensa_pct = float(recompensa_raw) if recompensa_raw else 0.0

                    db.add(ItemParado(
                        emp=str(emp),
                        codigo=str(codigo),
                        descricao=descricao or None,
                        quantidade=quantidade,
                        recompensa_pct=recompensa_pct,
                        ativo=1,
                    ))
                    db.commit()
                    ok = 'Item cadastrado com sucesso.'

                elif acao == 'toggle':
                    item_id = int(request.form.get('item_id') or 0)
                    it = db.query(ItemParado).filter(ItemParado.id == item_id).first()
                    if not it:
                        raise ValueError('Item não encontrado.')
                    it.ativo = 0 if int(it.ativo or 0) == 1 else 1
                    it.atualizado_em = datetime.utcnow()
                    db.commit()
                    ok = 'Status do item atualizado.'

                elif acao == 'remover':
                    item_id = int(request.form.get('item_id') or 0)
                    it = db.query(ItemParado).filter(ItemParado.id == item_id).first()
                    if not it:
                        raise ValueError('Item não encontrado.')
                    db.delete(it)
                    db.commit()
                    ok = 'Item removido.'

                else:
                    raise ValueError('Ação inválida.')

            except Exception as e:
                db.rollback()
                erro = str(e)
                app.logger.exception('Erro no cadastro de itens parados')

        itens = db.query(ItemParado).order_by(ItemParado.emp.asc(), ItemParado.codigo.asc()).all()

    return render_template(
        'admin_itens_parados.html',
        usuario=_usuario_logado(),
        itens=itens,
        erro=erro,
        ok=ok,
    )

@app.route('/admin/resumos_periodo', methods=['GET', 'POST'])
def admin_resumos_periodo():
    red = _admin_required()
    if red:
        return red

    # filtros
    emp = _emp_norm(request.values.get('emp', ''))
    vendedor = (request.values.get('vendedor') or '').strip().upper()
    ano = int(request.values.get('ano') or datetime.now().year)
    mes = int(request.values.get('mes') or datetime.now().month)

    msgs: list[str] = []

    acao = (request.form.get('acao') or '').strip().lower()
    if request.method == 'POST' and acao:
        # alvo do POST (permite editar/cadastrar resumos em um período diferente do filtro)
        emp_alvo = _emp_norm(request.form.get('emp_edit') or emp)

        # Se a EMP não vier no POST (alguns modais não enviam), tenta inferir pelo escopo do usuário.
        # Importante para que Dashboard/Metas encontrem a base do ano passado corretamente.
        if not emp_alvo:
            try:
                allowed_tmp = session.get('allowed_emps') or _allowed_emps()
            except Exception:
                allowed_tmp = []
            if isinstance(allowed_tmp, (list, tuple)) and len(allowed_tmp) == 1:
                emp_alvo = _emp_norm(allowed_tmp[0])

        try:
            ano_alvo = int(request.form.get('ano_edit') or ano)
        except Exception:
            ano_alvo = ano
        try:
            mes_alvo = int(request.form.get('mes_edit') or mes)
        except Exception:
            mes_alvo = mes

        ano_passado = ano - 1
        # Regra: permitir edição/importação manual apenas para anos anteriores ao ano filtrado.
        if acao in {'salvar', 'excluir', 'salvar_lote', 'importar_xlsx'} and ano_alvo >= ano:
            msgs.append('⚠️ Edição/importação manual permitida apenas para anos anteriores ao ano filtrado.')
            acao = ''

        if acao in {'salvar', 'excluir'} and _mes_fechado(emp_alvo, ano_alvo, mes_alvo):
            msgs.append('⚠️ Mês fechado. Reabra o mês para editar os resumos.')
        else:
            with SessionLocal() as db:
                if acao == 'fechar':
                    rec = (
                        db.query(FechamentoMensal)
                        .filter(
                            FechamentoMensal.emp == emp,
                            FechamentoMensal.ano == ano,
                            FechamentoMensal.mes == mes,
                        )
                        .one_or_none()
                    )
                    if rec is None:
                        rec = FechamentoMensal(emp=emp, ano=ano, mes=mes, fechado=True, fechado_em=datetime.utcnow())
                        db.add(rec)
                    else:
                        rec.fechado = True
                        rec.fechado_em = datetime.utcnow()
                    db.commit()
                    msgs.append('✅ Mês fechado. Edição travada.')

                elif acao == 'reabrir':
                    rec = (
                        db.query(FechamentoMensal)
                        .filter(
                            FechamentoMensal.emp == emp,
                            FechamentoMensal.ano == ano,
                            FechamentoMensal.mes == mes,
                        )
                        .one_or_none()
                    )
                    if rec is None:
                        rec = FechamentoMensal(emp=emp, ano=ano, mes=mes, fechado=False)
                        db.add(rec)
                    else:
                        rec.fechado = False
                    db.commit()
                    msgs.append('✅ Mês reaberto. Edição liberada.')

                elif acao == 'salvar':
                    vend = (request.form.get('vendedor_edit') or '').strip().upper()
                    if not vend:
                        msgs.append('⚠️ Informe o vendedor.')
                    else:
                        try:
                            valor_venda = _parse_num_ptbr(request.form.get('valor_venda'))
                        except Exception:
                            valor_venda = 0.0
                        try:
                            mix_produtos = int(request.form.get('mix_produtos') or 0)
                        except Exception:
                            mix_produtos = 0

                        rec = (
                            db.query(VendasResumoPeriodo)
                            .filter(
                                VendasResumoPeriodo.emp == emp_alvo,
                                VendasResumoPeriodo.vendedor == vend,
                                VendasResumoPeriodo.ano == ano_alvo,
                                VendasResumoPeriodo.mes == mes_alvo,
                            )
                            .one_or_none()
                        )
                        if rec is None:
                            rec = VendasResumoPeriodo(
                                emp=emp_alvo,
                                vendedor=vend,
                                ano=ano_alvo,
                                mes=mes_alvo,
                                valor_venda=valor_venda,
                                mix_produtos=mix_produtos,
                                created_at=datetime.utcnow(),
                                updated_at=datetime.utcnow(),
                            )
                            db.add(rec)
                        else:
                            rec.valor_venda = valor_venda
                            rec.mix_produtos = mix_produtos
                            rec.updated_at = datetime.utcnow()
                        db.commit()
                        msgs.append('✅ Resumo salvo.')


                elif acao == 'salvar_lote':
                    # Cadastro em lote destinado ao ano passado (ano-1), permitindo informar MÊS por linha.
                    # Campos esperados: vendedor_lote, mes_ref, valor_venda_lote, mix_produtos_lote (listas)
                    emp_lote = _emp_norm(request.form.get('emp_edit') or emp)
                    ano_lote = ano_alvo

                    vendedores_l = [ (v or '').strip().upper() for v in request.form.getlist('vendedor_lote') ]
                    meses_l = request.form.getlist('mes_ref')
                    valores_l = request.form.getlist('valor_venda_lote')
                    mix_l = request.form.getlist('mix_produtos_lote')

                    total_linhas = max(len(vendedores_l), len(meses_l), len(valores_l), len(mix_l))
                    # Normaliza tamanhos
                    def _get(lst, i, default=''):
                        try:
                            return lst[i]
                        except Exception:
                            return default

                    salvos = 0
                    pulados = 0
                    fechados = 0

                    for i in range(total_linhas):
                        vend = _get(vendedores_l, i, '').strip().upper()
                        if not vend:
                            pulados += 1
                            continue
                        try:
                            mes_ref = int(str(_get(meses_l, i, mes)).strip() or mes)
                        except Exception:
                            mes_ref = mes
                        if mes_ref < 1 or mes_ref > 12:
                            msgs.append(f'⚠️ Linha {i+1}: mês inválido ({_get(meses_l, i, "")}).')
                            pulados += 1
                            continue

                        # Mês fechado? trava edição para aquele mês
                        if _mes_fechado(emp_lote, ano_lote, mes_ref):
                            fechados += 1
                            continue

                        try:
                            valor_venda = _parse_num_ptbr(str(_get(valores_l, i, '0')))
                        except Exception:
                            valor_venda = 0.0
                        try:
                            mix_produtos = int(str(_get(mix_l, i, '0')).strip() or 0)
                        except Exception:
                            mix_produtos = 0

                        rec = (
                            db.query(VendasResumoPeriodo)
                            .filter(
                                VendasResumoPeriodo.emp == emp_lote,
                                VendasResumoPeriodo.vendedor == vend,
                                VendasResumoPeriodo.ano == ano_lote,
                                VendasResumoPeriodo.mes == mes_ref,
                            )
                            .one_or_none()
                        )
                        if rec is None:
                            rec = VendasResumoPeriodo(
                                emp=emp_lote,
                                vendedor=vend,
                                ano=ano_lote,
                                mes=mes_ref,
                                valor_venda=valor_venda,
                                mix_produtos=mix_produtos,
                                created_at=datetime.utcnow(),
                                updated_at=datetime.utcnow(),
                            )
                            db.add(rec)
                        else:
                            rec.valor_venda = valor_venda
                            rec.mix_produtos = mix_produtos
                            rec.updated_at = datetime.utcnow()
                        salvos += 1

                    db.commit()
                    if fechados:
                        msgs.append(f'⚠️ {fechados} linha(s) não foram salvas porque o mês está fechado.')
                    msgs.append(f'✅ Lote concluído: {salvos} salvo(s), {pulados} linha(s) em branco/ inválida(s).')
                
                elif acao == 'importar_xlsx':
                    # Importação de resumos por Excel (.xlsx) / CSV
                    # Colunas aceitas (case-insensitive):
                    # ANO, MES, EMP(opcional), VENDEDOR, VALOR_VENDA/VALOR, MIX
                    file = request.files.get('arquivo')
                    if not file or not getattr(file, 'filename', ''):
                        msgs.append('⚠️ Selecione um arquivo .xlsx ou .csv para importar.')
                    else:
                        filename = (file.filename or '').lower()
                        try:
                            if filename.endswith('.csv'):
                                df = pd.read_csv(file, dtype=str)
                            else:
                                df = pd.read_excel(file, dtype=str)
                        except Exception as e:
                            msgs.append('❌ Não consegui ler o arquivo. Verifique se é um .xlsx válido.')
                            df = None

                        if df is not None:
                            # normaliza colunas
                            cols = {c.strip().upper(): c for c in df.columns}
                            def _col(*names):
                                for n in names:
                                    if n in cols:
                                        return cols[n]
                                return None

                            c_ano = _col('ANO')
                            c_mes = _col('MES', 'MÊS')
                            c_emp = _col('EMP')
                            c_vend = _col('VENDEDOR', 'VEND', 'VENDEDOR_NOME')
                            c_val = _col('VALOR_VENDA', 'VALOR', 'VALORVENDA')
                            c_mix = _col('MIX')

                            if not c_ano or not c_mes or not c_vend or not c_val:
                                msgs.append('❌ Colunas obrigatórias: ANO, MES, VENDEDOR, VALOR_VENDA (ou VALOR).')
                            else:
                                total = 0
                                salvos = 0
                                pulados = 0
                                fechados = 0
                                erros = 0

                                for _, row in df.iterrows():
                                    total += 1
                                    try:
                                        ano_ref = int(str(row.get(c_ano, '')).strip())
                                        mes_ref = int(str(row.get(c_mes, '')).strip())
                                    except Exception:
                                        pulados += 1
                                        continue
                                    if mes_ref < 1 or mes_ref > 12:
                                        pulados += 1
                                        continue

                                    vend = str(row.get(c_vend, '')).strip().upper()
                                    if not vend:
                                        pulados += 1
                                        continue

                                    emp_ref = emp  # padrão do filtro, se vier em branco
                                    if c_emp:
                                        raw_emp = str(row.get(c_emp, '')).strip()
                                        if raw_emp.lower() in {'nan', 'none', 'null'}:
                                            raw_emp = ''
                                        emp_ref = _emp_norm(raw_emp) or emp

                                    # regra: não permite importar para ano atual/futuro
                                    if ano_ref >= ano:
                                        pulados += 1
                                        continue

                                    if _mes_fechado(emp_ref, ano_ref, mes_ref):
                                        fechados += 1
                                        continue

                                    valor_venda = _parse_num_ptbr(str(row.get(c_val, '0')))
                                    try:
                                        if c_mix:
                                            raw_mix = str(row.get(c_mix, '')).strip()
                                            if raw_mix.lower() in {'', 'nan', 'none', 'null'}:
                                                mix_produtos = 0
                                            else:
                                                try:
                                                    mix_produtos = int(float(raw_mix.replace(',', '.')))
                                                except Exception:
                                                    mix_produtos = 0
                                        else:
                                            mix_produtos = 0

                                    except Exception:
                                        mix_produtos = 0

                                    rec = (
                                        db.query(VendasResumoPeriodo)
                                        .filter(
                                            VendasResumoPeriodo.emp == emp_ref,
                                            VendasResumoPeriodo.vendedor == vend,
                                            VendasResumoPeriodo.ano == ano_ref,
                                            VendasResumoPeriodo.mes == mes_ref,
                                        )
                                        .one_or_none()
                                    )
                                    if rec is None:
                                        rec = VendasResumoPeriodo(
                                            emp=emp_ref,
                                            vendedor=vend,
                                            ano=ano_ref,
                                            mes=mes_ref,
                                            valor_venda=valor_venda,
                                            mix_produtos=mix_produtos,
                                            created_at=datetime.utcnow(),
                                            updated_at=datetime.utcnow(),
                                        )
                                        db.add(rec)
                                    else:
                                        rec.valor_venda = valor_venda
                                        rec.mix_produtos = mix_produtos
                                        rec.updated_at = datetime.utcnow()
                                    salvos += 1

                                db.commit()
                                if fechados:
                                    msgs.append(f'⚠️ {fechados} linha(s) não importadas: mês fechado.')
                                msgs.append(f'✅ Importação concluída: {salvos} salvo(s) de {total} linha(s). {pulados} pulada(s).')

                elif acao == 'excluir':
                    vend = (request.form.get('vendedor_edit') or '').strip().upper()
                    if not vend:
                        msgs.append('⚠️ Informe o vendedor para excluir.')
                    else:
                        rec = (
                            db.query(VendasResumoPeriodo)
                            .filter(
                                VendasResumoPeriodo.emp == emp_alvo,
                                VendasResumoPeriodo.vendedor == vend,
                                VendasResumoPeriodo.ano == ano_alvo,
                                VendasResumoPeriodo.mes == mes_alvo,
                            )
                            .one_or_none()
                        )
                        if rec is None:
                            msgs.append('⚠️ Não encontrei esse resumo para excluir.')
                        else:
                            db.delete(rec)
                            db.commit()
                            msgs.append('✅ Resumo excluído.')

    # carregar lista e status de fechamento
    fechado = _mes_fechado(emp, ano, mes)
    with SessionLocal() as db:
        # EMP e vendedor são opcionais: quando vierem em branco, listamos TODOS.
        q = db.query(VendasResumoPeriodo).filter(
            VendasResumoPeriodo.ano == ano,
            VendasResumoPeriodo.mes == mes,
        )
        if emp:
            q = q.filter(or_(VendasResumoPeriodo.emp == emp, VendasResumoPeriodo.emp.in_(['', 'EMPTY'])))
        if vendedor:
            q = q.filter(VendasResumoPeriodo.vendedor == vendedor)
        registros = q.order_by(VendasResumoPeriodo.vendedor.asc()).all()

        # Resumos do mesmo período no ano passado (ano-1) para conferência/edição rápida
        ano_passado = ano - 1
        q2 = db.query(VendasResumoPeriodo).filter(
            VendasResumoPeriodo.ano == ano_passado,
        )
        if emp:
            q2 = q2.filter(or_(VendasResumoPeriodo.emp == emp, VendasResumoPeriodo.emp.in_(['', 'EMPTY'])))
        if vendedor:
            q2 = q2.filter(VendasResumoPeriodo.vendedor == vendedor)

        # Carrega TODOS os meses do ano passado (ano-1) para permitir cadastro/edição independente do mês atual.
        _res_all = q2.order_by(VendasResumoPeriodo.mes.asc(), VendasResumoPeriodo.vendedor.asc()).all()

        resumos_ano_passado_por_mes = {m: [] for m in range(1, 13)}
        for r in _res_all:
            try:
                resumos_ano_passado_por_mes[int(r.mes)].append(r)
            except Exception:
                pass

        # contagem por mês (para renderizar os "chips")
        counts_ano_passado = {m: len(resumos_ano_passado_por_mes.get(m, [])) for m in range(1, 13)}

        # Sugestão rápida de vendedores (com base em vendas do período)
        # Ajuda o admin a não digitar errado
        start, end = _periodo_bounds(ano, mes)
        vs_q = db.query(Venda.vendedor).filter(Venda.movimento >= start, Venda.movimento < end)
        if emp:
            vs_q = vs_q.filter(Venda.emp == emp)
        vendedores_sugeridos = (
            vs_q.distinct().order_by(Venda.vendedor.asc()).all()
        )
        vendedores_sugeridos = [v[0] for v in vendedores_sugeridos if v and v[0]]

    return render_template(
        'admin_resumos_periodo.html',
        emp=emp,
        ano=ano,
        mes=mes,
        vendedor_filtro=vendedor,
        registros=registros,
        rows=registros,
        vendedor=vendedor,
        ano_passado=ano_passado,
        resumos_ano_passado_por_mes=resumos_ano_passado_por_mes,
        counts_ano_passado=counts_ano_passado,
        
        fechado=fechado,
        vendedores_sugeridos=vendedores_sugeridos,
        msgs=msgs,
    )

# Compatibilidade: algumas telas/atalhos antigos apontavam para /admin/fechamento.
# O fechamento mensal hoje é feito dentro da tela de resumos por período.
@app.route("/admin/combos", methods=["GET", "POST"])
def admin_combos():
    """Cadastro de Campanhas Combo (SIMPLES).
    Regra (venda casada):
      - Cada requisito define um MESTRE (match em vendas.mestre), uma quantidade mínima e um Valor R$ (recompensa).
      - O vendedor só ganha se bater o mínimo em TODOS os requisitos do combo (gate).
      - Ao bater o gate, a recompensa do combo é a SOMA dos valores R$ cadastrados nos requisitos (recompensa fixa por requisito atingido).
    Observação: mantemos campos extras do modelo (marca/modelo/etc) com defaults para compatibilidade do banco.
    """
    red = _login_required()
    if red:
        return red
    red = _admin_required()
    if red:
        return red

    erro = None
    ok = None

    hoje = date.today()
    mes = int(request.values.get("mes") or hoje.month)
    ano = int(request.values.get("ano") or hoje.year)

    inicio_mes, fim_mes = _periodo_bounds(ano, mes)
    default_data_inicio = request.values.get("data_inicio") or inicio_mes.isoformat()
    default_data_fim = request.values.get("data_fim") or fim_mes.isoformat()

    with SessionLocal() as db:
        # Carrega EMPs (tabela emps)
        try:
            emps = db.query(Emp).order_by(Emp.codigo.asc()).all()
        except Exception:
            emps = []

        if request.method == "POST":
            acao = (request.form.get("acao") or "").strip().lower()

            # Remover combo (e seus itens/resultados)
            if acao == "remover":
                try:
                    combo_id = int(request.form.get("combo_id") or 0)
                    if not combo_id:
                        raise ValueError("combo_id inválido.")
                    # remove itens + resultados + combo
                    db.execute(text("DELETE FROM campanhas_combo_itens WHERE combo_id = :cid"), {"cid": combo_id})
                    db.execute(text("DELETE FROM campanhas_combo_resultados WHERE combo_id = :cid"), {"cid": combo_id})
                    db.execute(text("DELETE FROM campanhas_combo WHERE id = :cid"), {"cid": combo_id})
                    db.commit()
                    ok = "Combo removido."
                except Exception as e:
                    db.rollback()
                    erro = str(e)

            # Criar combo simples
            elif acao == "criar":
                try:
                    titulo = (request.form.get("titulo") or "").strip()
                    emp = (request.form.get("emp") or "").strip()
                    vig_ini = request.form.get("data_inicio") or inicio_mes.isoformat()
                    vig_fim = request.form.get("data_fim") or fim_mes.isoformat()

                    if not titulo:
                        raise ValueError("Título é obrigatório.")

                    # Parse datas
                    try:
                        d_ini = datetime.fromisoformat(vig_ini).date()
                        d_fim = datetime.fromisoformat(vig_fim).date()
                    except Exception:
                        raise ValueError("Datas inválidas. Use o seletor de datas.")

                    if d_fim < d_ini:
                        raise ValueError("Data fim não pode ser menor que data início.")

                    # Campos obrigatórios no banco/modelo (mantemos defaults)
                    combo = CampanhaCombo(
                        titulo=titulo,
                        nome=titulo,
                        emp=emp if emp else None,
                        marca="COMBO",  # NOT NULL no banco
                        data_inicio=d_ini,
                        data_fim=d_fim,
                        ano=int(d_ini.year),
                        mes=int(d_ini.month),
                        valor_unitario_global=None,
                        modelo_pagamento="TODOS_ITENS",  # mantém compat
                        filtro_marca=None,
                        filtro_descricao_prefixo=None,
                        valor_unitario_modelo2=None,
                        ativo=True,
                        created_at=datetime.utcnow(),
                        updated_at=datetime.utcnow(),
                    )
                    db.add(combo)
                    db.flush()  # obtém combo.id

                    mestres = request.form.getlist("mestre_prefixo[]")
                    minimos = request.form.getlist("minimo_qtd[]")
                    vals = request.form.getlist("valor_unitario[]")

                    itens = []
                    n = max(len(mestres), len(minimos), len(vals))
                    for i in range(n):
                        mp = (mestres[i] if i < len(mestres) else "") or ""
                        mi = (minimos[i] if i < len(minimos) else "") or ""
                        vu = (vals[i] if i < len(vals) else "") or ""

                        mp = str(mp).strip()
                        if not mp:
                            continue

                        # mínimo (int)
                        try:
                            minimo_qtd = int(float(str(mi).replace(",", ".") or 0))
                        except Exception:
                            minimo_qtd = 0

                        vu_raw = str(vu).strip().replace(",", ".")
                        if not vu_raw:
                            raise ValueError("Valor R$ é obrigatório em cada requisito do combo simples.")
                        try:
                            valor_unit = float(vu_raw)
                        except Exception:
                            raise ValueError("Valor R$ inválido.")

                        itens.append({
                            "combo_id": combo.id,
                            "mestre_prefixo": mp,
                            "descricao_contains": None,
                            "match_mestre": mp,
                            "minimo_qtd": int(minimo_qtd or 0),
                            "valor_unitario": float(valor_unit),
                            "ordem": i + 1,
                            "criado_em": datetime.utcnow(),
                        })

                    if not itens:
                        raise ValueError("Adicione pelo menos 1 requisito (MESTRE, mínimo e Valor R$).")

                    sql = text(
                        "INSERT INTO campanhas_combo_itens (combo_id, mestre_prefixo, descricao_contains, match_mestre, minimo_qtd, valor_unitario, ordem, criado_em) "
                        "VALUES (:combo_id, :mestre_prefixo, :descricao_contains, :match_mestre, :minimo_qtd, :valor_unitario, :ordem, :criado_em)"
                    )
                    db.execute(sql, itens)
                    db.commit()
                    ok = "Combo criado com sucesso."
                except Exception as e:
                    db.rollback()
                    erro = str(e)

        # lista combos que intersectam o mês/ano (inclui globais)
        combos = (
            db.query(CampanhaCombo)
            .filter(
                CampanhaCombo.ativo.is_(True),
                or_(CampanhaCombo.emp.is_(None), CampanhaCombo.emp == ""),
            )
            .all()
        )

        # Também inclui combos da EMP específica quando filtrada na criação (para admin ver tudo)
        # (Na tela simples, o admin quer ver todos no período filtrado)
        combos = (
            db.query(CampanhaCombo)
            .filter(
                CampanhaCombo.ativo.is_(True),
                or_(
                    and_(CampanhaCombo.data_inicio <= fim_mes, CampanhaCombo.data_fim >= inicio_mes),
                    and_(CampanhaCombo.ano == ano, CampanhaCombo.mes == mes),
                ),
            )
            .order_by(CampanhaCombo.data_inicio.desc(), CampanhaCombo.id.desc())
            .all()
        )

        combo_ids = [c.id for c in combos]
        combos_itens_map = {}
        if combo_ids:
            itens_rows = (
                db.query(CampanhaComboItem)
                .filter(CampanhaComboItem.combo_id.in_(combo_ids))
                .order_by(CampanhaComboItem.combo_id.asc(), CampanhaComboItem.ordem.asc(), CampanhaComboItem.id.asc())
                .all()
            )
            for it in itens_rows:
                combos_itens_map.setdefault(it.combo_id, []).append(it)

    return render_template(
        "admin_combos.html",
        mes=mes,
        ano=ano,
        emps=emps,
        combos=combos,
        combos_itens_map=combos_itens_map,
        default_data_inicio=default_data_inicio,
        default_data_fim=default_data_fim,
        erro=erro,
        ok=ok,
    )



@app.route("/admin/fechamento", methods=["GET", "POST"])
def admin_fechamento():
    """Página dedicada de fechamento mensal (ADMIN).

    Responsável por travar/reativar a competência (EMP + mês/ano), servindo de base
    para relatórios consolidados e impedindo alterações em campanhas/resumos quando fechado.
    """
    red = _admin_required()
    if red:
        return red

    hoje = datetime.now()
    ano = int(request.values.get("ano") or hoje.year)
    mes = int(request.values.get("mes") or hoje.month)

    # multi-EMP: fecha em lote quando selecionar mais de uma EMP
    # multi-EMP: lê tanto querystring (?emp=101&emp=102) quanto POST (inputs hidden name=emp)
    emps_sel = []
    try:
        emps_sel = [str(e).strip() for e in request.values.getlist("emp") if str(e).strip()]
    except Exception:
        emps_sel = []
    if not emps_sel:
        emps_sel = [str(e).strip() for e in _parse_multi_args("emp") if str(e).strip()]
    if not emps_sel:
        # fallback: tenta usar emp único (mantém compatibilidade com versões antigas)
        emp_single = _emp_norm(request.values.get("emp", ""))
        emps_sel = [emp_single] if emp_single else []

    msgs: list[str] = []
    status_por_emp: dict[str, dict] = {}

    # Normaliza a ação vinda do formulário (alguns navegadores/JS podem enviar
    # variações, ex.: sem underscore, com hífen ou com espaços).
    acao_raw = (request.values.get("acao") or request.values.get("action") or request.form.get("acao") or "").strip().lower()
    acao = {
        "fechar_a_pagar": "fechar_a_pagar",
        "fechar_apagar": "fechar_a_pagar",
        "fechar-a-pagar": "fechar_a_pagar",
        "a_pagar": "fechar_a_pagar",
        "fechar_pago": "fechar_pago",
        "fechar-pago": "fechar_pago",
        "pago": "fechar_pago",
        "reabrir": "reabrir",
        "abrir": "reabrir",
    }.get(acao_raw, acao_raw)

    with SessionLocal() as db:
        # Carrega opções de EMP para o filtro (admin: todas cadastradas, fallback: EMPs com vendas no período)
        try:
            emps_all = [str(r.codigo).strip() for r in db.query(Emp).order_by(Emp.codigo.asc()).all()]
        except Exception:
            emps_all = []
        if not emps_all:
            try:
                emps_all = _get_emps_com_vendas_no_periodo(ano, mes)
            except Exception:
                emps_all = []

        if request.method == "POST" and acao in {"fechar_a_pagar", "fechar_pago", "reabrir"}:
            app.logger.info("FECHAMENTO POST: form=%s values=%s", dict(request.form), {k: request.values.getlist(k) for k in request.values.keys()})
            if not emps_sel:
                msgs.append("⚠️ Selecione ao menos 1 EMP para fechar/reabrir.")
            else:
                alvo_status = None
                updated_count = 0
                if acao == "fechar_a_pagar":
                    alvo_status = "a_pagar"
                elif acao == "fechar_pago":
                    alvo_status = "pago"
                for emp in emps_sel:
                    emp = _emp_norm(emp)
                    if not emp:
                        continue
                    try:
                        rec = (
                            db.query(FechamentoMensal)
                            .filter(
                                FechamentoMensal.emp == emp,
                                FechamentoMensal.ano == int(ano),
                                FechamentoMensal.mes == int(mes),
                            )
                            .first()
                        )
                        if not rec:
                            rec = FechamentoMensal(emp=emp, ano=int(ano), mes=int(mes), fechado=False)
                            db.add(rec)

                        if acao in {"fechar_a_pagar", "fechar_pago"}:
                            rec.fechado = True
                            rec.fechado_em = datetime.utcnow()
                            # status financeiro (controle)
                            if hasattr(rec, "status") and alvo_status:
                                rec.status = alvo_status
                        else:
                            rec.fechado = False
                            rec.fechado_em = None  # reabrir zera timestamp
                            if hasattr(rec, "status"):
                                rec.status = "aberto"
                        updated_count += 1
                        # commit no final do lote (mais rápido e consistente)
                    except Exception:
                        app.logger.exception("Erro ao preparar fechamento mensal")
                        msgs.append(f"❌ Falha ao atualizar fechamento da EMP {emp}.")
                if updated_count > 0:
                    try:
                        db.commit()
                        msgs.append(f"✅ Operação concluída ({updated_count} EMPs).")
                        # PRG: evita reenvio e garante recarregar status
                        return redirect(url_for('admin_fechamento', emp=emps_sel, mes=mes, ano=ano))
                    except Exception:
                        db.rollback()
                        app.logger.exception("Erro ao commitar fechamento mensal")
                        msgs.append("❌ Falha ao salvar alterações no fechamento.")
                else:
                    if not msgs:
                        msgs.append("⚠️ Nenhuma EMP válida para atualizar.")
        # Status para tela
        for emp in (emps_sel or []):
            emp = _emp_norm(emp)
            if not emp:
                continue
            fechado = False
            fechado_em = None
            status_fin = "aberto"
            try:
                rec = (
                    db.query(FechamentoMensal)
                    .filter(
                        FechamentoMensal.emp == emp,
                        FechamentoMensal.ano == int(ano),
                        FechamentoMensal.mes == int(mes),
                    )
                    .first()
                )
                if rec:
                    if getattr(rec, "status", None):
                        status_fin = rec.status
                    if rec.fechado:
                        fechado = True
                        fechado_em = rec.fechado_em
            except Exception:
                fechado = False
            status_por_emp[emp] = {"fechado": fechado, "fechado_em": fechado_em, "status": status_fin}

    emps_options = _get_emp_options(emps_all)

    return render_template(
        "admin_fechamento.html",
        role=_role() or "",
        ano=ano,
        mes=mes,
        emps_sel=emps_sel,
        emps_options=emps_options,
        status_por_emp=status_por_emp,
        msgs=msgs,
    )


@app.route("/admin/campanhas", methods=["GET", "POST"])
def admin_campanhas_qtd():
    """Cadastro de campanhas de recompensa por quantidade.

    Campos:
    - EMP (obrigatório)
    - Vendedor (opcional; vazio = todos da EMP)
    - Produto prefixo (obrigatório)
    - Marca (obrigatório)
    - Recompensa (R$/un)
    - Quantidade mínima (opcional)
    - Período (data início/fim)
    """
    red = _login_required()
    if red:
        return red
    red = _admin_required()
    if red:
        return red

    erro = None
    ok = None

    hoje = date.today()
    mes = int(request.values.get("mes") or hoje.month)
    ano = int(request.values.get("ano") or hoje.year)

    with SessionLocal() as db:
        if request.method == "POST":
            acao = (request.form.get("acao") or "").strip().lower()

            # Se a competência estiver FECHADA, bloqueia alterações de campanhas (mantém integridade do fechamento)
            try:
                emp_post = (request.form.get("emp") or "").strip()
                if not emp_post and request.form.get("id"):
                    try:
                        cid = int(request.form.get("id") or 0)
                        obj = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                        if obj:
                            emp_post = (obj.emp or "").strip()
                    except Exception:
                        emp_post = ""
                if emp_post and _competencia_fechada(db, emp_post, ano, mes):
                    erro = f"Competência {mes:02d}/{ano} da EMP {emp_post} está FECHADA. Reabra em /admin/fechamento para editar campanhas."
                    # impede execução do POST
                    return redirect('/admin/fechamento' + f'?emp={emp_post}&mes={mes}&ano={ano}')
            except Exception:
                pass


            try:
                if acao == "criar":
                    emp = (request.form.get("emp") or "").strip()
                    vendedor = (request.form.get("vendedor") or "").strip().upper() or None
                    titulo = (request.form.get("titulo") or "").strip() or None

                    campo_match = (request.form.get("campo_match") or "codigo").strip().lower()
                    if campo_match not in {"codigo", "descricao"}:
                        campo_match = "codigo"

                    produto_prefixo = (request.form.get("produto_prefixo") or "").strip()
                    descricao_prefixo = (request.form.get("descricao_prefixo") or "").strip()
                    marca = (request.form.get("marca") or "").strip()

                    recompensa_raw = (request.form.get("recompensa_unit") or "").strip().replace(",", ".")
                    qtd_min_raw = (request.form.get("qtd_minima") or "").strip().replace(",", ".")
                    valor_min_raw = (request.form.get("valor_minimo") or "").strip().replace(",", ".")

                    data_ini_raw = (request.form.get("data_inicio") or "").strip()
                    data_fim_raw = (request.form.get("data_fim") or "").strip()

                    if not emp:
                        raise ValueError("Informe a EMP.")
                    if campo_match == "descricao":
                        if not descricao_prefixo and not produto_prefixo:
                            raise ValueError("Informe a descrição (início).")
                    else:
                        if not produto_prefixo:
                            raise ValueError("Informe o código/prefixo do produto.")
                    if not marca:
                        raise ValueError("Informe a marca.")
                    if not recompensa_raw:
                        raise ValueError("Informe a recompensa (R$/un).")
                    if not data_ini_raw or not data_fim_raw:
                        raise ValueError("Informe data início e fim.")

                    def _to_dec(s: str) -> Decimal:
                        try:
                            return Decimal(s)
                        except Exception:
                            raise ValueError("Número inválido.")

                    recompensa_unit = _to_dec(recompensa_raw)
                    if recompensa_unit < 0:
                        raise ValueError("Recompensa não pode ser negativa.")

                    qtd_minima = _to_dec(qtd_min_raw) if qtd_min_raw else None
                    if qtd_minima is not None and qtd_minima < 0:
                        raise ValueError("Quantidade mínima não pode ser negativa.")

                    valor_minimo = _to_dec(valor_min_raw) if valor_min_raw else None
                    if valor_minimo is not None and valor_minimo < 0:
                        raise ValueError("Valor mínimo não pode ser negativo.")

                    # Persistimos como float (compatibilidade), mas com precisão controlada
                    recompensa_unit = float(recompensa_unit.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP))
                    if qtd_minima is not None:
                        qtd_minima = float(qtd_minima)
                    if valor_minimo is not None:
                        valor_minimo = float(valor_minimo)
                    data_inicio = datetime.strptime(data_ini_raw, "%Y-%m-%d").date()
                    data_fim = datetime.strptime(data_fim_raw, "%Y-%m-%d").date()
                    if data_fim < data_inicio:
                        raise ValueError("Data fim não pode ser menor que data início.")

                    db.add(
                        CampanhaQtd(
                            emp=str(emp),
                            vendedor=vendedor,
                            titulo=titulo,
                            produto_prefixo=(produto_prefixo or '').upper(),
                            descricao_prefixo=(descricao_prefixo or '').strip(),
                            campo_match=campo_match,
                            marca=marca.upper(),
                            recompensa_unit=float(recompensa_unit),
                            qtd_minima=float(qtd_minima) if qtd_minima is not None else None,
                            valor_minimo=float(valor_minimo) if valor_minimo is not None else None,
                            data_inicio=data_inicio,
                            data_fim=data_fim,
                            ativo=1,
                        )
                    )
                    db.commit()
                    ok = "Campanha cadastrada com sucesso."

                elif acao == "toggle":
                    cid = int(request.form.get("campanha_id") or 0)
                    c = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                    if not c:
                        raise ValueError("Campanha não encontrada.")
                    c.ativo = 0 if int(c.ativo or 0) == 1 else 1
                    c.atualizado_em = datetime.utcnow()
                    db.commit()
                    ok = "Status da campanha atualizado."

                elif acao == "remover":
                    cid = int(request.form.get("campanha_id") or 0)
                    c = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                    if not c:
                        raise ValueError("Campanha não encontrada.")

                    # Remove também o histórico/snapshot mensal dessa campanha
                    db.query(CampanhaQtdResultado).filter(CampanhaQtdResultado.campanha_id == cid).delete(synchronize_session=False)

                    db.delete(c)
                    db.commit()
                    ok = "Campanha removida."

                elif acao == "pagar":
                    rid = int(request.form.get("resultado_id") or 0)
                    r = db.query(CampanhaQtdResultado).filter(CampanhaQtdResultado.id == rid).first()
                    if not r:
                        raise ValueError("Resultado não encontrado.")
                    if (r.status_pagamento or "PENDENTE") == "PAGO":
                        r.status_pagamento = "PENDENTE"
                        r.pago_em = None
                    else:
                        r.status_pagamento = "PAGO"
                        r.pago_em = datetime.utcnow()
                    r.atualizado_em = datetime.utcnow()
                    db.commit()
                    ok = "Status de pagamento atualizado."

                else:
                    raise ValueError("Ação inválida.")

            except Exception as e:
                db.rollback()
                erro = str(e)
                app.logger.exception("Erro ao gerenciar campanhas")

        campanhas = db.query(CampanhaQtd).order_by(CampanhaQtd.emp.asc(), CampanhaQtd.data_inicio.desc()).all()
        resultados = (
            db.query(CampanhaQtdResultado)
            .filter(
                CampanhaQtdResultado.competencia_ano == int(ano),
                CampanhaQtdResultado.competencia_mes == int(mes),
            )
            .order_by(CampanhaQtdResultado.valor_recompensa.desc())
            .all()
        )

    
    # UX: agrupa por competência (mês/ano) na lista
    try:
        for c in (campanhas or []):
            di = getattr(c, "data_inicio", None)
            if di:
                setattr(c, "competencia_label", f"{int(di.month):02d}/{int(di.year)}")
            else:
                setattr(c, "competencia_label", "")
    except Exception:
        pass

    return render_template(
            "admin_campanhas_qtd.html",
            usuario=_usuario_logado(),
            campanhas=campanhas,
            resultados=resultados,
            ano=ano,
            mes=mes,
            erro=erro,
            ok=ok,
        )

@app.route("/admin/apagar_vendas", methods=["POST"])
def admin_apagar_vendas():
    """Apaga vendas por dia ou por mes.

    Usado pela tela /admin/importar (admin_importar.html).
    """
    red = _login_required()
    if red:
        return red
    red = _admin_required()
    if red:
        return red

    tipo = (request.form.get("tipo") or "").strip().lower()
    valor = (request.form.get("valor") or "").strip()
    if tipo not in {"dia", "mes"}:
        flash("Tipo invalido para apagar vendas.", "danger")
        return redirect(url_for("admin_importar"))
    if not valor:
        flash("Informe uma data/mes para apagar.", "warning")
        return redirect(url_for("admin_importar"))

    db = SessionLocal()
    try:
        if tipo == "dia":
            # valor: YYYY-MM-DD
            try:
                dt = datetime.strptime(valor, "%Y-%m-%d").date()
            except Exception:
                flash("Data invalida. Use o seletor de data.", "danger")
                return redirect(url_for("admin_importar"))

            q = db.query(Venda).filter(Venda.movimento == dt)
            apagadas = q.delete(synchronize_session=False)
            db.commit()
            try:
                limpar_cache_df()
            except Exception:
                pass
            flash(f"Apagadas {apagadas} vendas do dia {dt.strftime('%d/%m/%Y')}.", "success")
            return redirect(url_for("admin_importar"))

        # tipo == "mes"  valor: YYYY-MM
        try:
            ano = int(valor[:4])
            mes = int(valor[5:7])
            if mes < 1 or mes > 12:
                raise ValueError
        except Exception:
            flash("Mes invalido. Use o seletor de mes.", "danger")
            return redirect(url_for("admin_importar"))

        last_day = calendar.monthrange(ano, mes)[1]
        d_ini = date(ano, mes, 1)
        d_fim = date(ano, mes, last_day)

        q = db.query(Venda).filter(and_(Venda.movimento >= d_ini, Venda.movimento <= d_fim))
        apagadas = q.delete(synchronize_session=False)
        db.commit()
        try:
            limpar_cache_df()
        except Exception:
            pass
        flash(f"Apagadas {apagadas} vendas de {mes:02d}/{ano}.", "success")
        return redirect(url_for("admin_importar"))

    except Exception:
        db.rollback()
        app.logger.exception("Erro ao apagar vendas")
        flash("Erro ao apagar vendas. Veja os logs.", "danger")
        return redirect(url_for("admin_importar"))
    finally:
        try:
            db.close()
        except Exception:
            pass


# =====================
# Mensagens (Central + Bloqueio diário)
# =====================

@app.route("/mensagens", methods=["GET"])
def mensagens_central():
    red = _login_required()
    if red:
        return red

    usuario = _usuario_logado()
    role = (_role() or "").lower()
    user_id = session.get("user_id")
    allowed_emps = _allowed_emps()  # [] => todas (admin_all_emps)
    today = date.today()

    with SessionLocal() as db:
        # Mensagens ativas e no período
        msgs = (
            db.query(Mensagem)
            .filter(Mensagem.ativo.is_(True))
            .order_by(Mensagem.bloqueante.desc(), Mensagem.id.desc())
            .all()
        )

        out = []
        for msg in msgs:
            if not _is_date_in_range(today, msg.inicio_em, msg.fim_em):
                continue

            targeted_user = (
                db.query(MensagemUsuario)
                .filter(MensagemUsuario.mensagem_id == msg.id)
                .filter(MensagemUsuario.usuario_id == int(user_id))
                .first()
                is not None
            )

            targeted_emp = False
            if role == "admin" and session.get("admin_all_emps"):
                targeted_emp = (
                    db.query(MensagemEmpresa)
                    .filter(MensagemEmpresa.mensagem_id == msg.id)
                    .first()
                    is not None
                )
            else:
                if allowed_emps:
                    targeted_emp = (
                        db.query(MensagemEmpresa)
                        .filter(MensagemEmpresa.mensagem_id == msg.id)
                        .filter(MensagemEmpresa.emp.in_(allowed_emps))
                        .first()
                        is not None
                    )

            if not (targeted_user or targeted_emp):
                continue

            lida_hoje = (
                db.query(MensagemLidaDiaria)
                .filter(MensagemLidaDiaria.mensagem_id == msg.id)
                .filter(MensagemLidaDiaria.usuario_id == int(user_id))
                .filter(MensagemLidaDiaria.data == today)
                .first()
                is not None
            )

            out.append({
                "msg": msg,
                "lida_hoje": lida_hoje,
            })

        return render_template("mensagens.html", mensagens=out, usuario=usuario, role=role)


@app.route("/mensagens/bloqueio/<int:mensagem_id>", methods=["GET"])
def mensagens_bloqueio(mensagem_id: int):
    red = _login_required()
    if red:
        return red

    usuario = _usuario_logado()
    role = (_role() or "").lower()
    user_id = session.get("user_id")
    allowed_emps = _allowed_emps()
    today = date.today()

    with SessionLocal() as db:
        msg = db.query(Mensagem).filter(Mensagem.id == mensagem_id).first()
        if not msg or not msg.ativo or not msg.bloqueante or not _is_date_in_range(today, msg.inicio_em, msg.fim_em):
            return redirect(url_for("dashboard"))

        # Confere destino (segurança)
        targeted_user = (
            db.query(MensagemUsuario)
            .filter(MensagemUsuario.mensagem_id == msg.id)
            .filter(MensagemUsuario.usuario_id == int(user_id))
            .first()
            is not None
        )

        targeted_emp = False
        if role == "admin" and session.get("admin_all_emps"):
            targeted_emp = (
                db.query(MensagemEmpresa)
                .filter(MensagemEmpresa.mensagem_id == msg.id)
                .first()
                is not None
            )
        else:
            if allowed_emps:
                targeted_emp = (
                    db.query(MensagemEmpresa)
                    .filter(MensagemEmpresa.mensagem_id == msg.id)
                    .filter(MensagemEmpresa.emp.in_(allowed_emps))
                    .first()
                    is not None
                )

        if not (targeted_user or targeted_emp):
            return redirect(url_for("dashboard"))

        return render_template("mensagem_bloqueio.html", msg=msg, usuario=usuario, role=role)


@app.route("/mensagens/lida/<int:mensagem_id>", methods=["POST"])
def mensagens_marcar_lida(mensagem_id: int):
    red = _login_required()
    if red:
        return red

    user_id = session.get("user_id")
    today = date.today()

    with SessionLocal() as db:
        msg = db.query(Mensagem).filter(Mensagem.id == mensagem_id).first()
        if msg and msg.ativo and msg.bloqueante:
            # upsert simples (tenta inserir; se já existir, ignora)
            existe = (
                db.query(MensagemLidaDiaria)
                .filter(MensagemLidaDiaria.mensagem_id == mensagem_id)
                .filter(MensagemLidaDiaria.usuario_id == int(user_id))
                .filter(MensagemLidaDiaria.data == today)
                .first()
            )
            if not existe:
                db.add(MensagemLidaDiaria(
                    mensagem_id=mensagem_id,
                    usuario_id=int(user_id),
                    data=today,
                ))
                db.commit()

    next_url = session.pop("after_block_redirect", None)
    if next_url:
        return redirect(next_url)
    return redirect(url_for("dashboard"))


@app.route("/admin/mensagens", methods=["GET", "POST"])
def admin_mensagens():
    red = _login_required()
    if red:
        return red
    red = _admin_or_supervisor_required()
    if red:
        return red

    usuario = _usuario_logado()
    role = (_role() or "").lower()
    user_id = session.get("user_id")
    allowed_emps = _allowed_emps()
    today = date.today()

    with SessionLocal() as db:
        emps_q = db.query(Emp).filter(Emp.ativo.is_(True)).order_by(Emp.codigo.asc()).all()
        # Supervisor só pode ver/usar as empresas dele
        if role == "supervisor":
            emps_q = [e for e in emps_q if str(e.codigo) in set(allowed_emps or [])]

        users_q = []
        allowed_user_ids = set()
        if role == "admin":
            users_q = db.query(Usuario).order_by(Usuario.username.asc()).all()
            allowed_user_ids = {u.id for u in users_q}
        elif role == "supervisor":
            # Supervisor pode enviar para usuários individuais, mas apenas dentro das empresas dele
            allowed_set = set(allowed_emps or [])
            if allowed_set:
                users_q = (
                    db.query(Usuario)
                    .join(UsuarioEmp, UsuarioEmp.usuario_id == Usuario.id)
                    .filter(UsuarioEmp.emp.in_(list(allowed_set)))
                    .filter(UsuarioEmp.ativo.is_(True))
                    .distinct()
                    .order_by(Usuario.username.asc())
                    .all()
                )
                allowed_user_ids = {u.id for u in users_q}

        if request.method == "POST":
            titulo = (request.form.get("titulo") or "").strip()
            conteudo = (request.form.get("conteudo") or "").strip()
            bloqueante = (request.form.get("bloqueante") == "on")
            ativo = True if (request.form.get("ativo") != "off") else False
            inicio_em = (request.form.get("inicio_em") or "").strip()
            fim_em = (request.form.get("fim_em") or "").strip()
            empresas_sel = request.form.getlist("empresas")
            usuario_dest = (request.form.get("usuario_id") or "").strip()  # opcional (admin e supervisor)

            # validações
            erros = []
            if not titulo:
                erros.append("Informe um título.")
            if not conteudo:
                erros.append("Informe a mensagem.")
            if role == "supervisor" and (not empresas_sel and not usuario_dest):
                erros.append("Selecione ao menos 1 empresa ou 1 usuário.")
            if role == "admin" and (not empresas_sel and not usuario_dest):
                erros.append("Selecione ao menos 1 empresa ou 1 usuário.")

            # restringe empresas do supervisor
            if role == "supervisor":
                allowed_set = set(allowed_emps or [])
                empresas_sel = [e for e in empresas_sel if str(e) in allowed_set]


            # restringe usuário destino (admin: qualquer; supervisor: apenas usuários das empresas dele)
            if usuario_dest:
                try:
                    uid = int(usuario_dest)
                    if uid not in allowed_user_ids:
                        erros.append("Usuário inválido para envio.")
                        usuario_dest = ""
                except Exception:
                    erros.append("Usuário inválido para envio.")
                    usuario_dest = ""

            if not erros:
                def _parse_date(s: str):
                    try:
                        return datetime.strptime(s, "%Y-%m-%d").date()
                    except Exception:
                        return None

                msg = Mensagem(
                    titulo=titulo,
                    conteudo=conteudo,
                    bloqueante=bloqueante,
                    ativo=ativo,
                    inicio_em=_parse_date(inicio_em),
                    fim_em=_parse_date(fim_em),
                    created_by_user_id=int(user_id) if user_id else None,
                )
                db.add(msg)
                db.flush()

                for emp_code in empresas_sel:
                    db.add(MensagemEmpresa(mensagem_id=msg.id, emp=str(emp_code).strip()))
                if usuario_dest:
                    try:
                        uid = int(usuario_dest)
                        db.add(MensagemUsuario(mensagem_id=msg.id, usuario_id=uid))
                    except Exception:
                        pass

                db.commit()
                flash("Mensagem criada com sucesso.", "success")
                return redirect(url_for("admin_mensagens"))
            else:
                for e in erros:
                    flash(e, "danger")

        # listagem
        mensagens = (
            db.query(Mensagem)
            .order_by(Mensagem.ativo.desc(), Mensagem.id.desc())
            .limit(300)
            .all()
        )
        # supervisor vê apenas as mensagens que ele criou
        if role == "supervisor":
            mensagens = [m for m in mensagens if m.created_by_user_id == int(user_id)]

        # Enriquecer destinos para exibição
        destinos = {}
        for m_ in mensagens:
            emp_codes = [x.emp for x in db.query(MensagemEmpresa).filter(MensagemEmpresa.mensagem_id == m_.id).all()]
            usr_ids = [x.usuario_id for x in db.query(MensagemUsuario).filter(MensagemUsuario.mensagem_id == m_.id).all()]
            destinos[m_.id] = {"emps": emp_codes, "users": usr_ids}

        return render_template(
            "admin_mensagens.html",
            usuario=usuario,
            role=role,
            emps=emps_q,
            users=users_q,
            mensagens=mensagens,
            destinos=destinos,
            today=today,
        )


@app.route("/admin/mensagens/<int:mensagem_id>/toggle", methods=["POST"])
def admin_mensagens_toggle(mensagem_id: int):
    red = _login_required()
    if red:
        return red
    red = _admin_or_supervisor_required()
    if red:
        return red

    role = (_role() or "").lower()
    allowed_emps = _allowed_emps()

    with SessionLocal() as db:
        msg = db.query(Mensagem).filter(Mensagem.id == mensagem_id).first()
        if not msg:
            flash("Mensagem não encontrada.", "warning")
            return redirect(url_for("admin_mensagens"))

        if role == "supervisor":
            # supervisor só pode alterar mensagens que ele mesmo criou
            if msg.created_by_user_id != int(session.get("user_id") or 0):
                flash("Acesso restrito.", "danger")
                return redirect(url_for("admin_mensagens"))
                return redirect(url_for("admin_mensagens"))

        msg.ativo = not bool(msg.ativo)
        db.commit()
        flash("Status atualizado.", "success")
        return redirect(url_for("admin_mensagens"))

# =====================
# Metas (Crescimento / MIX / Share de Marcas)
# =====================

def _periodo_bounds_ym(ano: int, mes: int) -> tuple[date, date]:
    inicio = date(int(ano), int(mes), 1)
    fim = date(int(ano), int(mes), calendar.monthrange(int(ano), int(mes))[1])
    return inicio, fim


def _as_decimal(v) -> Decimal:
    try:
        if v is None:
            return Decimal("0")
        return Decimal(str(v))
    except Exception:
        return Decimal("0")


def _money2(v: Decimal) -> Decimal:
    return v.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# NOTE: _allowed_emps() is defined once earlier in this file (loads from DB when needed).
# Do not duplicate it below — duplicated defs silently override the correct version.

def _meta_pick_bonus(escalas: list[MetaEscala], valor_metric: float) -> float:
    """Retorna o bonus_percentual da maior faixa cujo limite_min <= valor_metric."""
    try:
        v = float(valor_metric or 0.0)
    except Exception:
        v = 0.0
    best = 0.0
    for esc in sorted(escalas, key=lambda x: (x.limite_min, x.ordem)):
        try:
            lim = float(esc.limite_min or 0.0)
        except Exception:
            lim = 0.0
        if v >= lim:
            best = float(esc.bonus_percentual or 0.0)
    return float(best or 0.0)


def _sql_valor_mes_signed():
    # CA e DS deduzem do valor. Outros somam.
    return """
        SUM(
          CASE
            WHEN mov_tipo_movto IN ('CA','DS') THEN -COALESCE(valor_total,0)
            ELSE COALESCE(valor_total,0)
          END
        )::double precision
    """


def _sql_valor_marcas_signed(marcas: list[str]):
    # marcas: lista já normalizada para UPPER
    # Faz match exato em vendas.marca (que no seu banco costuma estar em maiúsculo)
    if not marcas:
        return "0::double precision"
    # usa ANY(:marcas) para evitar string concat insegura
    return f"""
        SUM(
          CASE
            WHEN UPPER(COALESCE(marca,'')) = ANY(:marcas)
              THEN CASE WHEN mov_tipo_movto IN ('CA','DS') THEN -COALESCE(valor_total,0) ELSE COALESCE(valor_total,0) END
            ELSE 0
          END
        )::double precision
    """


def _query_valor_mes(db, ano: int, mes: int, emp: str, vendedor: str) -> float:
    """Retorna o valor líquido do mês para (EMP, vendedor).
    Prioridade:
      1) Base manual/importada em vendas_resumo_periodo (ano/mes do registro)
      2) Fallback: cálculo direto na tabela vendas (signed OA/DS/CA)
    Observação: versões antigas gravaram emp como ''/EMPTY; fazemos fallback seguro.
    """
    vend = (vendedor or '').strip().upper()
    emp_n = _emp_norm(emp)

    # 1) tenta base manual (resumo)
    try:
        q = (
            db.query(VendasResumoPeriodo.valor_venda)
            .filter(
                VendasResumoPeriodo.vendedor == vend,
                VendasResumoPeriodo.ano == ano,
                VendasResumoPeriodo.mes == mes,
            )
        )
        if emp_n:
            q_emp = q.filter(VendasResumoPeriodo.emp == emp_n).one_or_none()
            if q_emp is not None:
                return float(q_emp[0] or 0.0)
            # fallback compat: registros antigos sem emp
            q_fallback = q.filter(VendasResumoPeriodo.emp.in_(['', 'EMPTY'])).one_or_none()
            if q_fallback is not None:
                return float(q_fallback[0] or 0.0)
        else:
            # se emp vier vazio, tenta pegar qualquer um (mas preferimos ''/EMPTY)
            q_fallback = q.filter(VendasResumoPeriodo.emp.in_(['', 'EMPTY'])).one_or_none()
            if q_fallback is not None:
                return float(q_fallback[0] or 0.0)
    except Exception:
        pass

    # 2) fallback: cálculo na tabela vendas
    inicio, fim = _periodo_bounds_ym(ano, mes)
    sql = f"""
      SELECT {_sql_valor_mes_signed()} AS valor_mes
      FROM vendas
      WHERE emp = :emp
        AND vendedor = :vendedor
        AND movimento BETWEEN :ini AND :fim
    """
    row = db.execute(text(sql), {"emp": emp_n, "vendedor": vend, "ini": inicio, "fim": fim}).fetchone()
    return float(row[0] or 0.0) if row else 0.0


def _query_mix_itens(db, ano: int, mes: int, emp: str, vendedor: str) -> float:
    """Retorna MIX (qtd de itens/produtos) do mês para (EMP, vendedor).
    Prioridade:
      1) Base manual/importada em vendas_resumo_periodo.mix_produtos
      2) Fallback: cálculo na tabela vendas (qtd_liquida > 0 por mestre)
    Compat: emp antigo ''/EMPTY.
    """
    vend = (vendedor or '').strip().upper()
    emp_n = _emp_norm(emp)

    # 1) tenta base manual (resumo)
    try:
        q = (
            db.query(VendasResumoPeriodo.mix_produtos)
            .filter(
                VendasResumoPeriodo.vendedor == vend,
                VendasResumoPeriodo.ano == ano,
                VendasResumoPeriodo.mes == mes,
            )
        )
        if emp_n:
            q_emp = q.filter(VendasResumoPeriodo.emp == emp_n).one_or_none()
            if q_emp is not None:
                return float(q_emp[0] or 0.0)
            q_fallback = q.filter(VendasResumoPeriodo.emp.in_(['', 'EMPTY'])).one_or_none()
            if q_fallback is not None:
                return float(q_fallback[0] or 0.0)
        else:
            q_fallback = q.filter(VendasResumoPeriodo.emp.in_(['', 'EMPTY'])).one_or_none()
            if q_fallback is not None:
                return float(q_fallback[0] or 0.0)
    except Exception:
        pass

    # 2) fallback: calcula no detalhe em vendas
    inicio, fim = _periodo_bounds_ym(ano, mes)
    sql = """
      WITH por_produto AS (
        SELECT
          mestre,
          SUM(
            CASE
              WHEN mov_tipo_movto = 'CA' THEN -COALESCE(qtdade_vendida,0)
              WHEN mov_tipo_movto = 'DS' THEN 0
              ELSE COALESCE(qtdade_vendida,0)
            END
          ) AS qtd_liquida
        FROM vendas
        WHERE emp = :emp
          AND vendedor = :vendedor
          AND movimento BETWEEN :ini AND :fim
          AND mestre IS NOT NULL AND mestre <> ''
        GROUP BY mestre
      )
      SELECT COUNT(*)::double precision
      FROM por_produto
      WHERE qtd_liquida > 0
    """
    row = db.execute(text(sql), {"emp": emp_n, "vendedor": vend, "ini": inicio, "fim": fim}).fetchone()
    return float(row[0] or 0.0) if row else 0.0


def _query_share_marca(db, ano: int, mes: int, emp: str, vendedor: str, marcas: list[str]) -> tuple[float, float, float]:
    """Retorna (share_pct, valor_marcas, valor_total_mes)."""
    inicio, fim = _periodo_bounds_ym(ano, mes)
    marcas_norm = [str(m).strip().upper() for m in (marcas or []) if str(m).strip()]
    sql = f"""
      SELECT
        ({_sql_valor_marcas_signed(marcas_norm)}) AS valor_marcas,
        ({_sql_valor_mes_signed()}) AS valor_mes
      FROM vendas
      WHERE emp = :emp
        AND vendedor = :vendedor
        AND movimento BETWEEN :ini AND :fim
    """
    params = {"emp": emp, "vendedor": vendedor, "ini": inicio, "fim": fim, "marcas": marcas_norm}
    row = db.execute(text(sql), params).fetchone()
    valor_marcas = float((row[0] or 0.0)) if row else 0.0
    valor_mes = float((row[1] or 0.0)) if row else 0.0
    share = (valor_marcas / valor_mes * 100.0) if valor_mes else 0.0
    return float(share), float(valor_marcas), float(valor_mes)


def _get_vendedores_no_periodo(db, ano: int, mes: int, emps: list[str]) -> list[str]:
    inicio, fim = _periodo_bounds_ym(ano, mes)
    if emps:
        rows = db.execute(
            text("""
                SELECT DISTINCT vendedor
                FROM vendas
                WHERE emp = ANY(:emps)
                  AND movimento BETWEEN :ini AND :fim
                ORDER BY vendedor
            """),
            {"emps": emps, "ini": inicio, "fim": fim},
        ).fetchall()
    else:
        rows = db.execute(
            text("""
                SELECT DISTINCT vendedor
                FROM vendas
                WHERE movimento BETWEEN :ini AND :fim
                ORDER BY vendedor
            """),
            {"ini": inicio, "fim": fim},
        ).fetchall()
    return [str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip()]


def _get_emps_no_periodo(db, ano: int, mes: int, emps_allowed: list[str]) -> list[str]:
    inicio, fim = _periodo_bounds_ym(ano, mes)
    if emps_allowed:
        rows = db.execute(
            text("""
                SELECT DISTINCT emp
                FROM vendas
                WHERE emp = ANY(:emps)
                  AND movimento BETWEEN :ini AND :fim
                ORDER BY emp
            """),
            {"emps": emps_allowed, "ini": inicio, "fim": fim},
        ).fetchall()
    else:
        rows = db.execute(
            text("""
                SELECT DISTINCT emp
                FROM vendas
                WHERE movimento BETWEEN :ini AND :fim
                ORDER BY emp
            """),
            {"ini": inicio, "fim": fim},
        ).fetchall()
    return [str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip()]


def _calc_and_upsert_meta_result(db, meta: MetaPrograma, emp: str, vendedor: str) -> MetaResultado:
    # Carrega escalas e configurações
    escalas = db.query(MetaEscala).filter(MetaEscala.meta_id == meta.id).order_by(MetaEscala.ordem.asc()).all()
    if not escalas:
        escalas = []

    # Resultado existente
    res = (
        db.query(MetaResultado)
        .filter(
            MetaResultado.meta_id == meta.id,
            MetaResultado.emp == emp,
            MetaResultado.vendedor == vendedor,
            MetaResultado.ano == meta.ano,
            MetaResultado.mes == meta.mes,
        )
        .first()
    )
    if not res:
        res = MetaResultado(meta_id=meta.id, emp=emp, vendedor=vendedor, ano=meta.ano, mes=meta.mes)

    # calcula conforme tipo
    bonus = 0.0
    premio = Decimal("0.00")

    if meta.tipo == "MIX":
        valor_mes = _as_decimal(_query_valor_mes(db, meta.ano, meta.mes, emp, vendedor))
        mix = float(_query_mix_itens(db, meta.ano, meta.mes, emp, vendedor))
        bonus = _meta_pick_bonus(escalas, mix)
        premio = _money2(valor_mes * (Decimal(str(bonus)) / Decimal("100")))
        res.valor_mes = float(valor_mes)
        res.mix_itens_unicos = float(mix)
        res.bonus_percentual = float(bonus)
        res.premio = float(premio)

    elif meta.tipo == "SHARE_MARCA":
        marcas = [m.marca for m in db.query(MetaMarca).filter(MetaMarca.meta_id == meta.id).all()]
        share_pct, valor_marcas, valor_mes = _query_share_marca(db, meta.ano, meta.mes, emp, vendedor, marcas)
        bonus = _meta_pick_bonus(escalas, share_pct)
        premio = _money2(_as_decimal(valor_mes) * (Decimal(str(bonus)) / Decimal("100")))
        res.valor_mes = float(valor_mes)
        res.valor_marcas = float(valor_marcas)
        res.share_pct = float(share_pct)
        res.bonus_percentual = float(bonus)
        res.premio = float(premio)

    else:  # CRESCIMENTO
        valor_mes = _as_decimal(_query_valor_mes(db, meta.ano, meta.mes, emp, vendedor))
        # base manual?
        bm = (
            db.query(MetaBaseManual)
            .filter(MetaBaseManual.meta_id == meta.id, MetaBaseManual.emp == emp, MetaBaseManual.vendedor == vendedor)
            .first()
        )
        if bm and bm.base_valor is not None:
            base_val = _as_decimal(bm.base_valor)
        else:
            # base automática: mesmo mês do ano passado
            base_val = _as_decimal(_query_valor_mes(db, meta.ano - 1, meta.mes, emp, vendedor))

        base_f = float(base_val)
        if base_val != 0:
            crescimento_pct = float((valor_mes - base_val) / base_val * Decimal("100"))
        else:
            crescimento_pct = 0.0

        bonus = _meta_pick_bonus(escalas, crescimento_pct)
        premio = _money2(valor_mes * (Decimal(str(bonus)) / Decimal("100")))

        res.valor_mes = float(valor_mes)
        res.base_valor = float(base_val)
        res.crescimento_pct = float(crescimento_pct)
        res.bonus_percentual = float(bonus)
        res.premio = float(premio)

    res.calculado_em = datetime.utcnow()
    db.add(res)
    db.commit()
    return res


@app.get("/metas")
def metas():
    red = _login_required()
    if red:
        return red

    role = _role() or ""
    hoje = date.today()
    ano = int(request.args.get("ano") or hoje.year)
    mes = int(request.args.get("mes") or hoje.month)

    # filtros
    emp_filtro = (request.args.get("emp") or "").strip()
    vendedor_filtro = (request.args.get("vendedor") or "").strip().upper()

    with SessionLocal() as db:
        emps_allowed = _allowed_emps()
        # Admin pode ver tudo; supervisor/vendedor restringe
        emps_no_periodo = _get_emps_no_periodo(db, ano, mes, emps_allowed)
        if emp_filtro:
            # valida contra allowed
            if emps_allowed and emp_filtro not in emps_allowed:
                flash("EMP não permitida para seu usuário.", "danger")
                emp_filtro = ""
        emps_scope = [emp_filtro] if emp_filtro else emps_no_periodo

        # metas ativas do período
        metas_list = (
            db.query(MetaPrograma)
            .filter(MetaPrograma.ano == ano, MetaPrograma.mes == mes, MetaPrograma.ativo.is_(True))
            .order_by(MetaPrograma.tipo.asc(), MetaPrograma.nome.asc())
            .all()
        )

        # aplica meta -> emps
        meta_emps_map = {}
        for m in metas_list:
            rows = db.query(MetaProgramaEmp.emp).filter(MetaProgramaEmp.meta_id == m.id).all()
            meta_emps_map[m.id] = sorted({str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip()})

        # vendedores
        if role == "vendedor":
            vendedores = [str(session.get("usuario") or "").strip().upper()]
        else:
            vendedores = _get_vendedores_no_periodo(db, ano, mes, emps_scope)
            if vendedor_filtro:
                vendedores = [v for v in vendedores if v == vendedor_filtro]

        # calcula resultados
        resultados = []  # cada item: {vendedor, emp, metas: {meta_id: premio}, detalhes...}
        for emp in emps_scope:
            for vend in vendedores:
                # checa se vend tem vendas no período nessa emp (evita linha vazia)
                valor_mes = _query_valor_mes(db, ano, mes, emp, vend)
                if (not valor_mes) and role != "vendedor":
                    continue

                row = {"emp": emp, "vendedor": vend, "valor_mes": float(valor_mes), "metas": {}, "detalhes": {}}
                total_premios = Decimal("0.00")

                for meta in metas_list:
                    # meta vale para esta emp?
                    emps_meta = meta_emps_map.get(meta.id) or []
                    if emps_meta and emp not in emps_meta:
                        continue

                    res = _calc_and_upsert_meta_result(db, meta, emp, vend)
                    row["metas"][meta.id] = float(res.premio or 0.0)
                    # detalhes principais (pra tooltip/modal futuro)
                    row["detalhes"][meta.id] = {
                        "tipo": meta.tipo,
                        "bonus": float(res.bonus_percentual or 0.0),
                        "crescimento_pct": float(res.crescimento_pct or 0.0) if res.crescimento_pct is not None else None,
                        "base_valor": float(res.base_valor or 0.0) if res.base_valor is not None else None,
                        "mix": float(res.mix_itens_unicos or 0.0) if res.mix_itens_unicos is not None else None,
                        "share_pct": float(res.share_pct or 0.0) if res.share_pct is not None else None,
                        "valor_marcas": float(res.valor_marcas or 0.0) if res.valor_marcas is not None else None,
                    }
                    total_premios += _as_decimal(res.premio or 0.0)

                row["total_premios"] = float(_money2(total_premios))
                resultados.append(row)

        # listas para filtros
        emps_choices = emps_no_periodo
        vendedores_choices = _get_vendedores_no_periodo(db, ano, mes, emps_scope) if role != "vendedor" else vendedores

        # nomes amigáveis dos tipos
        tipo_label = {"CRESCIMENTO": "📈 Crescimento", "MIX": "🧩 MIX", "SHARE_MARCA": "🏷️ Share de Marcas"}

        return render_template(
            "metas.html",
            role=role,
            emp=_emp(),
            ano=ano,
            mes=mes,
            metas_list=metas_list,
            tipo_label=tipo_label,
            resultados=resultados,
            emps_choices=emps_choices,
            vendedores_choices=vendedores_choices,
            emp_filtro=emp_filtro,
            vendedor_filtro=vendedor_filtro,
        )


@app.get("/admin/metas")
def admin_metas():
    red = _login_required()
    if red:
        return red

    role = _role() or ""
    if role not in ("admin", "supervisor"):
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    hoje = date.today()
    ano = int(request.args.get("ano") or hoje.year)
    mes = int(request.args.get("mes") or hoje.month)

    with SessionLocal() as db:
        emps_allowed = _allowed_emps()
        # lista de EMPs cadastradas (melhor do que inferir por vendas)
        emps_rows = db.query(Emp).filter(Emp.ativo.is_(True)).order_by(Emp.codigo.asc()).all()
        # supervisor só pode suas emps
        if role == "supervisor" and emps_allowed:
            emps_rows = [e for e in emps_rows if str(e.codigo) in set(emps_allowed)]

        metas_list = (
            db.query(MetaPrograma)
            .filter(MetaPrograma.ano == ano, MetaPrograma.mes == mes)
            .order_by(MetaPrograma.ativo.desc(), MetaPrograma.tipo.asc(), MetaPrograma.nome.asc())
            .all()
        )

        # mapa de emps e escalas/marcas
        meta_emps = {}
        meta_escalas = {}
        meta_marcas = {}
        for m in metas_list:
            meta_emps[m.id] = [r[0] for r in db.query(MetaProgramaEmp.emp).filter(MetaProgramaEmp.meta_id == m.id).all()]
            meta_escalas[m.id] = db.query(MetaEscala).filter(MetaEscala.meta_id == m.id).order_by(MetaEscala.ordem.asc()).all()
            meta_marcas[m.id] = [r[0] for r in db.query(MetaMarca.marca).filter(MetaMarca.meta_id == m.id).all()]

        return render_template(
            "admin_metas.html",
            role=role,
            emp=_emp(),
            ano=ano,
            mes=mes,
            emps_rows=emps_rows,
            metas_list=metas_list,
            meta_emps=meta_emps,
            meta_escalas=meta_escalas,
            meta_marcas=meta_marcas,
        )


@app.post("/admin/metas/criar")
def admin_metas_criar():
    red = _login_required()
    if red:
        return red

    role = _role() or ""
    if role not in ("admin", "supervisor"):
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    nome = (request.form.get("nome") or "").strip()
    tipo = (request.form.get("tipo") or "").strip().upper()
    ano = int(request.form.get("ano") or date.today().year)
    mes = int(request.form.get("mes") or date.today().month)
    bloqueio = request.form.get("ativo")  # checkbox

    emps = request.form.getlist("emps") or []

    escalas_raw = (request.form.get("escalas") or "").strip()
    marcas_raw = (request.form.get("marcas") or "").strip()

    if not nome or tipo not in ("CRESCIMENTO", "MIX", "SHARE_MARCA"):
        flash("Preencha Nome e Tipo da meta.", "danger")
        return redirect(url_for("admin_metas", ano=ano, mes=mes))

    if not emps:
        flash("Selecione ao menos 1 Empresa.", "danger")
        return redirect(url_for("admin_metas", ano=ano, mes=mes))

    # parse escalas: linhas "limite=bonus" ou "limite:bonus"
    escalas = []
    for ln in escalas_raw.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        ln = ln.replace(",", ".")
        if ":" in ln:
            a, b = ln.split(":", 1)
        elif "=" in ln:
            a, b = ln.split("=", 1)
        else:
            continue
        try:
            lim = float(a.strip())
            bon = float(b.strip())
            escalas.append((lim, bon))
        except Exception:
            continue

    if not escalas:
        flash("Informe as faixas (escadas) no formato 'limite:bonus'.", "danger")
        return redirect(url_for("admin_metas", ano=ano, mes=mes))

    marcas = []
    if tipo == "SHARE_MARCA":
        # aceita separador por vírgula, ponto-e-vírgula e quebra de linha
        parts = re.split(r"[,\n;]+", marcas_raw)
        marcas = [p.strip().upper() for p in parts if p.strip()]
        if not marcas:
            flash("Informe pelo menos 1 marca para Share de Marcas.", "danger")
            return redirect(url_for("admin_metas", ano=ano, mes=mes))

    with SessionLocal() as db:
        # supervisor só pode emps dele
        if role == "supervisor":
            allowed = set(_allowed_emps())
            emps = [e for e in emps if e in allowed]
            if not emps:
                flash("Você não tem permissão para as Empresas selecionadas.", "danger")
                return redirect(url_for("admin_metas", ano=ano, mes=mes))

        meta = MetaPrograma(
            nome=nome,
            tipo=tipo,
            ano=ano,
            mes=mes,
            ativo=True if (bloqueio is None or str(bloqueio).lower() in ("1", "on", "true", "yes", "")) else False,
            created_by_user_id=session.get("user_id"),
        )
        db.add(meta)
        db.commit()

        # vincula emps
        for e in emps:
            db.add(MetaProgramaEmp(meta_id=meta.id, emp=str(e).strip()))
        # escalas
        for idx, (lim, bon) in enumerate(sorted(escalas, key=lambda x: x[0])):
            db.add(MetaEscala(meta_id=meta.id, ordem=idx + 1, limite_min=lim, bonus_percentual=bon))
        # marcas
        for m in marcas:
            db.add(MetaMarca(meta_id=meta.id, marca=m))

        db.commit()

    flash("Meta criada com sucesso.", "success")
    return redirect(url_for("admin_metas", ano=ano, mes=mes))


@app.post("/admin/metas/toggle/<int:meta_id>")
def admin_metas_toggle(meta_id: int):
    red = _login_required()
    if red:
        return red

    role = _role() or ""
    if role not in ("admin", "supervisor"):
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    ano = int(request.form.get("ano") or date.today().year)
    mes = int(request.form.get("mes") or date.today().month)

    with SessionLocal() as db:
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == meta_id).first()
        if not meta:
            flash("Meta não encontrada.", "danger")
            return redirect(url_for("admin_metas", ano=ano, mes=mes))

        # supervisor só pode mexer em metas que atinjam emps dele (e opcionalmente as que ele criou)
        if role == "supervisor":
            allowed = set(_allowed_emps())
            meta_emps = [r[0] for r in db.query(MetaProgramaEmp.emp).filter(MetaProgramaEmp.meta_id == meta.id).all()]
            if not any(e in allowed for e in meta_emps):
                flash("Você não tem permissão para esta meta.", "danger")
                return redirect(url_for("admin_metas", ano=ano, mes=mes))

        meta.ativo = not bool(meta.ativo)
        db.commit()

    flash("Status atualizado.", "success")
    return redirect(url_for("admin_metas", ano=ano, mes=mes))


@app.get("/admin/metas/bases/<int:meta_id>")
def admin_meta_bases(meta_id: int):
    red = _login_required()
    if red:
        return red

    role = _role() or ""
    if role not in ("admin", "supervisor"):
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    with SessionLocal() as db:
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == meta_id).first()
        if not meta:
            flash("Meta não encontrada.", "danger")
            return redirect(url_for("admin_metas"))

        if meta.tipo != "CRESCIMENTO":
            flash("Base manual só se aplica a metas de Crescimento.", "warning")
            return redirect(url_for("admin_metas", ano=meta.ano, mes=meta.mes))

        emps_meta = [r[0] for r in db.query(MetaProgramaEmp.emp).filter(MetaProgramaEmp.meta_id == meta.id).all()]

        # supervisor restringe emps
        if role == "supervisor":
            allowed = set(_allowed_emps())
            emps_meta = [e for e in emps_meta if e in allowed]

        # lista vendedores do período e dessas emps
        vendedores = _get_vendedores_no_periodo(db, meta.ano, meta.mes, emps_meta)

        # bases existentes
        bases = db.query(MetaBaseManual).filter(MetaBaseManual.meta_id == meta.id).all()
        bases_map = {(b.emp, b.vendedor): b for b in bases}

        # prepara linhas
        linhas = []
        for emp in emps_meta:
            for vend in vendedores:
                # total atual (para referência)
                total_atual = _query_valor_mes(db, meta.ano, meta.mes, emp, vend)
                base_auto = _query_valor_mes(db, meta.ano - 1, meta.mes, emp, vend)
                b = bases_map.get((emp, vend))
                linhas.append(
                    {
                        "emp": emp,
                        "vendedor": vend,
                        "total_atual": float(total_atual),
                        "base_auto": float(base_auto),
                        "base_manual": float(b.base_valor) if b else None,
                        "observacao": (b.observacao if b else ""),
                    }
                )

        return render_template(
            "admin_meta_bases.html",
            role=role,
            emp=_emp(),
            meta=meta,
            linhas=linhas,
        )


@app.post("/admin/metas/bases/<int:meta_id>/salvar")
def admin_meta_bases_salvar(meta_id: int):
    red = _login_required()
    if red:
        return red

    role = _role() or ""
    if role not in ("admin", "supervisor"):
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    with SessionLocal() as db:
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == meta_id).first()
        if not meta or meta.tipo != "CRESCIMENTO":
            flash("Meta inválida.", "danger")
            return redirect(url_for("admin_metas"))

        # supervisor restringe emps
        emps_meta = [r[0] for r in db.query(MetaProgramaEmp.emp).filter(MetaProgramaEmp.meta_id == meta.id).all()]
        if role == "supervisor":
            allowed = set(_allowed_emps())
            emps_meta = [e for e in emps_meta if e in allowed]

        # recebe pares emp|vendedor
        # campos: base__EMP__VENDEDOR e obs__EMP__VENDEDOR
        updated = 0
        for key, val in request.form.items():
            if not key.startswith("base__"):
                continue
            parts = key.split("__", 2)
            if len(parts) != 3:
                continue
            emp, vend = parts[1], parts[2]
            if emp not in emps_meta:
                continue
            vend = (vend or "").strip().upper()
            base_str = (val or "").strip().replace(".", "").replace(",", ".")
            obs = (request.form.get(f"obs__{emp}__{vend}") or "").strip()

            if base_str == "":
                # remove manual se existir
                b = (
                    db.query(MetaBaseManual)
                    .filter(MetaBaseManual.meta_id == meta.id, MetaBaseManual.emp == emp, MetaBaseManual.vendedor == vend)
                    .first()
                )
                if b:
                    db.delete(b)
                    updated += 1
                continue

            try:
                base_val = float(base_str)
            except Exception:
                continue

            b = (
                db.query(MetaBaseManual)
                .filter(MetaBaseManual.meta_id == meta.id, MetaBaseManual.emp == emp, MetaBaseManual.vendedor == vend)
                .first()
            )
            if not b:
                b = MetaBaseManual(meta_id=meta.id, emp=emp, vendedor=vend)
            b.base_valor = base_val
            b.observacao = obs
            db.add(b)
            updated += 1

        db.commit()

    flash(f"Bases manuais salvas ({updated} alterações).", "success")
    return redirect(url_for("admin_meta_bases", meta_id=meta_id))



# ------------- Erros -------------
@app.errorhandler(500)
def err_500(e):
    app.logger.exception("Erro 500: %s", e)
    return ("Erro interno. Verifique os logs no Render (ou fale com o admin).", 500)

# Campanhas V2 (Enterprise)
# ==========================

@app.route("/admin/campanhas_v2", methods=["GET", "POST"])
@admin_required
def admin_campanhas_v2():
    from datetime import date
    ano = int(request.args.get("ano") or date.today().year)
    mes = int(request.args.get("mes") or date.today().month)
    db = SessionLocal()
    try:
        if request.method == "POST":
            titulo = (request.form.get("titulo") or "").strip()
            tipo = (request.form.get("tipo") or "RANKING_VALOR").strip().upper()
            ativo = (request.form.get("ativo") or "1") == "1"
            regras_json = (request.form.get("regras_json") or "").strip() or "{}"
            c = CampanhaV2Master(titulo=titulo, tipo=tipo, ativo=ativo, regras_json=regras_json)
            db.add(c)
            db.flush()

            emps_raw = (request.form.get("emps") or "").strip()
            if emps_raw:
                for p in emps_raw.split(","):
                    p = p.strip()
                    if not p:
                        continue
                    try:
                        db.add(CampanhaV2ScopeEMP(campanha_id=c.id, emp=int(p)))
                    except Exception:
                        continue

            db.commit()
            flash("Campanha V2 criada.", "success")
            return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes))

        campanhas = db.query(CampanhaV2Master).order_by(CampanhaV2Master.id.desc()).all()
        return render_template("admin_campanhas_v2.html", campanhas=campanhas, ano=ano, mes=mes)
    finally:
        db.close()


@app.route("/admin/campanhas_v2/recalcular", methods=["GET"])
@admin_required
def admin_campanhas_v2_recalcular():
    from datetime import date
    ano = int(request.args.get("ano") or date.today().year)
    mes = int(request.args.get("mes") or date.today().month)
    db = SessionLocal()
    try:
        actor = session.get("username") or "admin"
        recalc_v2_competencia(db, ano=ano, mes=mes, actor=str(actor))
        flash(f"Recalculo V2 concluído para {mes}/{ano}.", "success")
    except Exception as e:
        db.rollback()
        flash(f"Erro ao recalcular: {e}", "danger")
    finally:
        db.close()
    return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes))


@app.route("/financeiro/campanhas_v2", methods=["GET"])
@financeiro_required
def financeiro_campanhas_v2():
    # por enquanto, redireciona para o fechamento (mesma visão)
    return redirect(url_for("financeiro_fechamento_v2"))


@app.route("/financeiro/fechamento_v2", methods=["GET"])
@financeiro_required
def financeiro_fechamento_v2():
    from datetime import date
    ano = int(request.args.get("ano") or date.today().year)
    mes = int(request.args.get("mes") or date.today().month)
    db = SessionLocal()
    try:
        rows = (
            db.query(CampanhaV2Resultado, CampanhaV2Master.titulo)
            .join(CampanhaV2Master, CampanhaV2Master.id==CampanhaV2Resultado.campanha_id)
            .filter(CampanhaV2Resultado.ano==ano, CampanhaV2Resultado.mes==mes)
            .order_by(CampanhaV2Resultado.status_financeiro.asc(), CampanhaV2Resultado.recompensa.desc())
            .all()
        )
        resultados=[]
        for r, titulo in rows:
            resultados.append({
                "id": r.id,
                "campanha_titulo": titulo,
                "emp": r.emp,
                "vendedor": r.vendedor,
                "valor_base": r.valor_base,
                "recompensa": r.recompensa,
                "status_financeiro": r.status_financeiro,
            })
        return render_template("financeiro_fechamento_v2.html", resultados=resultados, ano=ano, mes=mes)
    finally:
        db.close()


@app.route("/financeiro/fechamento_v2/status", methods=["POST"])
@financeiro_required
def financeiro_fechamento_v2_status():
    rid = int(request.form.get("resultado_id") or 0)
    status = (request.form.get("status_financeiro") or "PENDENTE").strip().upper()
    if status not in ("PENDENTE", "A_PAGAR", "PAGO"):
        status = "PENDENTE"
    db = SessionLocal()
    try:
        r = db.query(CampanhaV2Resultado).filter(CampanhaV2Resultado.id==rid).first()
        if not r:
            flash("Resultado não encontrado.", "danger")
            return redirect(url_for("financeiro_fechamento_v2"))
        r.status_financeiro = status
        db.commit()
        flash("Status atualizado.", "success")
    except Exception as e:
        db.rollback()
        flash(f"Erro ao atualizar status: {e}", "danger")
    finally:
        db.close()
    return redirect(url_for("financeiro_fechamento_v2"))






# =========================================
# Campanhas — Ranking por Marca (V2 NEW)
# =========================================

@app.route("/admin/campanhas/ranking-marca", methods=["GET", "POST"])
@admin_required
def admin_campanhas_ranking_marca():
    from services.ranking_marca_v2_new import (
        list_campaigns_for_admin,
        get_scope_emps,
        create_or_update_campaign,
        delete_campaign,
        recalc_ranking_marca,
        _to_float,
        _parse_date,
        _to_int,
    )
    from db import Emp, SessionLocal

    db = SessionLocal()
    erro = None
    ok = None

    try:
        # competência para recalcular (default mês atual)
        hoje = date.today()
        ano = _to_int(request.args.get("ano"), hoje.year)
        mes = _to_int(request.args.get("mes"), hoje.month)

        anos = list(range(hoje.year - 2, hoje.year + 2 + 1))

        # options de EMPs (cadastro)
        emps_rows = db.query(Emp).order_by(Emp.codigo.asc()).all()
        emps_opts = [{"value": int(e.codigo), "label": f"{int(e.codigo)} — {e.nome}"} for e in emps_rows]

        if request.method == "POST":
            acao = (request.form.get("acao") or "").strip().lower()

            # helper para ler emps do multiselect (pode vir como vários inputs "emps")
            emps_vals = request.form.getlist("emps")
            if not emps_vals:
                # fallback: "101,1001"
                raw = (request.form.get("emps") or "").strip()
                if raw:
                    emps_vals = [x.strip() for x in raw.split(",") if x.strip()]

            emps = []
            for v in emps_vals:
                try:
                    emps.append(int(v))
                except Exception:
                    pass

            if acao in ("criar", "editar"):
                campanha_id = request.form.get("id") if acao == "editar" else None

                nome = (request.form.get("nome") or "").strip()
                marca_alvo = (request.form.get("marca_alvo") or "").strip()

                vig_ini = _parse_date(request.form.get("vigencia_inicio"))
                vig_fim = _parse_date(request.form.get("vigencia_fim"))

                scope_mode = (request.form.get("scope_mode") or "GLOBAL").strip()

                minimo = _to_float(request.form.get("base_minima_valor"), 0.0)

                p1 = _to_float(request.form.get("premio_top1"), 0.0)
                p2 = _to_float(request.form.get("premio_top2"), 0.0)
                p3 = _to_float(request.form.get("premio_top3"), 0.0)

                ativo = (request.form.get("ativo") or "1") == "1"

                create_or_update_campaign(
                    db,
                    campanha_id=int(campanha_id) if campanha_id else None,
                    nome=nome,
                    marca_alvo=marca_alvo,
                    vigencia_inicio=vig_ini,
                    vigencia_fim=vig_fim,
                    scope_mode=scope_mode,
                    emps=emps,
                    base_minima_valor=minimo,
                    premio_top1=p1,
                    premio_top2=p2,
                    premio_top3=p3,
                    ativo=ativo,
                )
                db.commit()
                ok = "Campanha salva com sucesso."

            elif acao == "remover":
                cid = int(request.form.get("id") or 0)
                delete_campaign(db, cid)
                db.commit()
                ok = f"Campanha #{cid} removida."

            elif acao == "recalcular":
                cid = int(request.form.get("id") or 0)
                ano_p = _to_int(request.form.get("ano"), ano)
                mes_p = _to_int(request.form.get("mes"), mes)
                actor = (session.get("username") or session.get("nome") or session.get("user") or "admin")

                try:
                    # Compatibilidade: algumas versões do service não aceitam periodo_ini/periodo_fim
                    import inspect as _inspect
                    _kwargs = dict(campanha_id=cid, ano=ano_p, mes=mes_p, actor=str(actor))
                    periodo_ini = (request.form.get("periodo_ini") or "").strip()
                    periodo_fim = (request.form.get("periodo_fim") or "").strip()
                    try:
                        _sig = _inspect.signature(recalc_ranking_marca)
                        if "periodo_ini" in _sig.parameters and periodo_ini:
                            _kwargs["periodo_ini"] = periodo_ini
                        if "periodo_fim" in _sig.parameters and periodo_fim:
                            _kwargs["periodo_fim"] = periodo_fim
                    except Exception:
                        pass
                    res = recalc_ranking_marca(db, **_kwargs)
                    db.commit()

                    if res.get("rows", 0) > 0:
                        ok = f"✅ Snapshot recalculado: {res.get('rows', 0)} vendedores qualificados ({mes_p:02d}/{ano_p})."
                    else:
                        motivo = res.get("motivo") or "Nenhum vendedor atingiu o mínimo"
                        ok = f"⚠️ Recálculo concluído: {motivo} ({mes_p:02d}/{ano_p})."

                except Exception as e:
                    db.rollback()
                    erro = f"Erro no recálculo: {str(e)}"
                    try:
                        app.logger.exception("Erro no recálculo ranking-marca")
                    except Exception:
                        pass

            else:
                erro = "Ação inválida."

        campanhas = list_campaigns_for_admin(db)

        emps_map = {int(c.id): get_scope_emps(db, int(c.id)) for c in campanhas}

        return render_template(
            "admin_campanhas_ranking_marca.html",
            role=_role(),
            emp=session.get("emp"),
            campanhas=campanhas,
            emps_map=emps_map,
            emps_opts=emps_opts,
            erro=erro,
            ok=ok,
            ano=ano,
            mes=mes,
            anos=anos,
        )

    except Exception as e:
        db.rollback()
        erro = str(e)
        # fallback render
        campanhas = []
        emps_map = {}
        return render_template(
            "admin_campanhas_ranking_marca.html",
            role=_role(),
            emp=session.get("emp"),
            campanhas=campanhas,
            emps_map=emps_map,
            emps_opts=[],
            erro=erro,
            ok=None,
            ano=date.today().year,
            mes=date.today().month,
            anos=list(range(date.today().year - 2, date.today().year + 3)),
        )

    finally:
        try:
            db.close()
        except Exception:
            pass


@app.route("/campanhas/ranking-marca", methods=["GET"])
@login_required
def campanhas_ranking_marca():
    from services.ranking_marca_v2_new import list_campaigns_for_user, get_scope_emps, _to_int
    from db import SessionLocal, CampanhaV2MasterNewSchema as CampanhaV2MasterNew, CampanhaV2ResultadoNewSchema as CampanhaV2ResultadoNew

    db = SessionLocal()
    erro = None
    info = None

    try:
        hoje = date.today()
        ano = _to_int(request.args.get("ano"), hoje.year)
        mes = _to_int(request.args.get("mes"), hoje.month)

        anos = list(range(hoje.year - 2, hoje.year + 2 + 1))

        role = (_role() or "").lower()
        allowed_emps = _allowed_emps()  # [] = todas (admin_all_emps)
        campanhas = list_campaigns_for_user(db, role=role, allowed_emps=allowed_emps)

        campanha_id = request.args.get("campanha_id")
        campanha = None
        resultados = []
        scope_emps = []

        if campanha_id:
            try:
                cid = int(campanha_id)
            except Exception:
                cid = 0

            campanha = db.query(CampanhaV2MasterNew).filter(CampanhaV2MasterNew.id == cid).first()
            if not campanha:
                info = "Campanha não encontrada."
                campanha = None
            else:
                # regra de visibilidade para POR_EMP
                if (campanha.scope_mode or "GLOBAL").upper() == "POR_EMP" and role != "admin":
                    scope_emps = get_scope_emps(db, cid)
                    if allowed_emps:
                        allowed_set = {int(e) for e in allowed_emps if str(e).isdigit()}
                        scope_set = {int(e) for e in scope_emps}
                        if not scope_set.intersection(allowed_set):
                            campanha = None
                            info = "Você não tem acesso a esta campanha."
                    else:
                        # allowed_emps vazio => treat as all
                        pass
                else:
                    scope_emps = get_scope_emps(db, cid)

                if campanha:
                    resultados = (
                        db.query(CampanhaV2ResultadoNew)
                        .filter(CampanhaV2ResultadoNew.campanha_id == cid)
                        .filter(CampanhaV2ResultadoNew.ano == int(ano))
                        .filter(CampanhaV2ResultadoNew.mes == int(mes))
                        .order_by(CampanhaV2ResultadoNew.posicao.asc().nullslast())
                        .all()
                    )

        me = (session.get("nome") or session.get("username") or session.get("vendedor") or "").strip().upper()

        return render_template(
            "campanhas_ranking_marca.html",
            role=_role(),
            emp=session.get("emp"),
            campanhas=campanhas,
            campanha_id=int(campanha_id) if campanha_id and str(campanha_id).isdigit() else None,
            campanha=campanha,
            resultados=resultados,
            scope_emps=scope_emps,
            ano=ano,
            mes=mes,
            anos=anos,
            me=me,
            erro=erro,
            info=info,
        )

    except Exception as e:
        erro = str(e)
        return render_template(
            "campanhas_ranking_marca.html",
            role=_role(),
            emp=session.get("emp"),
            campanhas=[],
            campanha_id=None,
            campanha=None,
            resultados=[],
            scope_emps=[],
            ano=date.today().year,
            mes=date.today().month,
            anos=list(range(date.today().year - 2, date.today().year + 3)),
            me="",
            erro=erro,
            info=None,
        )
    finally:
        try:
            db.close()
        except Exception:
            pass