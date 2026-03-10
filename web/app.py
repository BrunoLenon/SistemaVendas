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
# Filtros Jinja (formatação BR)
# --------------------------
from jinja_filters import register_template_filters
register_template_filters(app)

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


# Campanhas V2 (admin / enterprise)
try:
    from blueprints.campanhas_v2_admin import bp as campanhas_v2_admin_bp
    app.register_blueprint(campanhas_v2_admin_bp)
except Exception:
    app.logger.exception("Falha ao registrar blueprint de campanhas_v2_admin")



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


@app.context_processor
def inject_globals():
    """Variáveis globais disponíveis em todos os templates Jinja (evita UndefinedError)."""
    try:
        return {"today": date.today(), "now": datetime.now()}
    except Exception:
        # fallback ultra-defensivo
        return {"today": date.today()}
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



# --- Dashboard (rotas extraídas) ------------------------------------------------

from dashboard_routes import register_dashboard_routes

register_dashboard_routes(
    app,
    login_required_fn=_login_required,
    mes_ano_from_request_fn=_mes_ano_from_request,
    role_fn=_role,
    emp_fn=_emp,
    allowed_emps_fn=_allowed_emps,
    usuario_logado_fn=_usuario_logado,
    get_vendedores_db_fn=_get_vendedores_db,
    dados_from_cache_fn=_dados_from_cache,
    dados_ao_vivo_fn=_dados_ao_vivo,
    dashboard_insights_fn=_dashboard_insights,
    dados_admin_geral_fn=_dados_admin_geral,
)



# --- Itens Parados (rotas extraídas) ------------------------------------------------

from itens_parados_routes import register_itens_parados_routes

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




# ---------------------------------------------------------------------
# -----------------------------------------------------------------------------
# Rotas extraídas (ativação consolidada)
#
# Objetivo: manter o app.py como bootstrap + registros, preservando endpoints e
# comportamento externo. Todos os módulos abaixo registram endpoints explícitos
# (endpoint="...") para manter compatibilidade com url_for(...) existente.
# -----------------------------------------------------------------------------

from admin_config_routes import register_admin_config_routes
from relatorio_campanhas_routes import register_relatorio_campanhas_routes
from relatorio_cidades_clientes_routes import register_relatorio_cidades_clientes_routes
from admin_usuarios_routes import register_admin_usuarios_routes
from admin_emps_routes import register_admin_emps_routes
from admin_importar_routes import register_admin_importar_routes
from admin_combos_routes import register_admin_combos_routes
from admin_campanhas_routes import register_admin_campanhas_routes
from admin_apagar_vendas_routes import register_admin_apagar_vendas_routes
from mensagens_routes import register_mensagens_routes
from metas_routes import register_metas_routes
from ranking_marca_routes import register_ranking_marca_routes
from admin_cache_routes import register_admin_cache_routes
from core_routes import register_core_routes
from errors import register_error_handlers
from operacoes_vendas_produtos_routes import register_operacoes_vendas_produtos_routes

# Admin / Configurações
register_admin_config_routes(app)

# Relatórios
register_relatorio_campanhas_routes(
    app,
    deps=_campanhas_deps,
    login_required_fn=_login_required,
    role_fn=_role,
    emp_fn=_emp,
    usuario_logado_fn=_usuario_logado,
)
register_relatorio_cidades_clientes_routes(
    app,
    login_required_fn=_login_required,
    role_fn=_role,
    emp_fn=_emp,
    allowed_emps_fn=_allowed_emps,
    usuario_logado_fn=_usuario_logado,
)

# Admin / Cadastros
register_admin_usuarios_routes(
    app,
    login_required_fn=_login_required,
    admin_required_fn=_admin_required,
    usuario_logado_fn=_usuario_logado,
)
register_admin_emps_routes(
    app,
    SessionLocal=SessionLocal,
    Emp=Emp,
    login_required_fn=_login_required,
    admin_required_fn=_admin_required,
    usuario_logado_fn=_usuario_logado,
)
register_admin_importar_routes(
    app,
    importar_planilha=importar_planilha,
    limpar_cache_df=limpar_cache_df,
    login_required_fn=_login_required,
    admin_required_fn=_admin_required,
)
register_admin_combos_routes(
    app,
    SessionLocal=SessionLocal,
    Emp=Emp,
    CampanhaCombo=CampanhaCombo,
    CampanhaComboItem=CampanhaComboItem,
    login_required_fn=_login_required,
    admin_required_fn=_admin_required,
    periodo_bounds_fn=_periodo_bounds,
)
register_admin_campanhas_routes(
    app,
    SessionLocal=SessionLocal,
    CampanhaQtd=CampanhaQtd,
    CampanhaQtdResultado=CampanhaQtdResultado,
    login_required_fn=_login_required,
    admin_required_fn=_admin_required,
    competencia_fechada_fn=_competencia_fechada,
    usuario_logado_fn=_usuario_logado,
)
register_admin_apagar_vendas_routes(
    app,
    SessionLocal=SessionLocal,
    Venda=Venda,
    limpar_cache_df=limpar_cache_df,
    login_required_fn=_login_required,
    admin_required_fn=_admin_required,
)

# Mensagens + Metas
register_mensagens_routes(app)
register_metas_routes(app)

# Ranking por Marca
register_ranking_marca_routes(
    app,
    admin_required_fn=admin_required,
    login_required_fn=login_required,
    role_fn=_role,
    allowed_emps_fn=_allowed_emps,
)

# Admin / Cache
register_admin_cache_routes(
    app,
    login_required_fn=_login_required,
    admin_required_fn=_admin_required,
)

# Core / Handlers
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
register_error_handlers(app)

# Operações
register_operacoes_vendas_produtos_routes(
    app,
    login_required_fn=login_required,
    allowed_emps_fn=_allowed_emps,
    role_fn=_role,
    emp_fn=_emp,
)

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









## Relatório (AJAX): cidade -> clientes (modal)



## Relatório (AJAX): cliente -> marcas (modal)





## Relatório (AJAX): cliente + marca -> itens (modal)



## Relatório (AJAX): cliente -> itens (modal)

from admin_itens_parados_routes import register_admin_itens_parados_routes

register_admin_itens_parados_routes(
    app,
    SessionLocal=SessionLocal,
    ItemParado=ItemParado,
    login_required_fn=_login_required,
    admin_required_fn=_admin_required,
    usuario_logado_fn=_usuario_logado,
)


from admin_resumos_periodo_routes import register_admin_resumos_periodo_routes

register_admin_resumos_periodo_routes(
    app,
    SessionLocal=SessionLocal,
    Venda=Venda,
    VendasResumoPeriodo=VendasResumoPeriodo,
    FechamentoMensal=FechamentoMensal,
    admin_required_fn=_admin_required,
    allowed_emps_fn=_allowed_emps,
    emp_norm_fn=_emp_norm,
    parse_num_ptbr_fn=_parse_num_ptbr,
    periodo_bounds_fn=_periodo_bounds,
    mes_fechado_fn=_mes_fechado,
)




from admin_fechamento_routes import register_admin_fechamento_routes

register_admin_fechamento_routes(
    app,
    SessionLocal=SessionLocal,
    Emp=Emp,
    FechamentoMensal=FechamentoMensal,
    admin_required_fn=_admin_required,
    parse_multi_args_fn=_parse_multi_args,
    emp_norm_fn=_emp_norm,
    get_emps_com_vendas_no_periodo_fn=_get_emps_com_vendas_no_periodo,
    get_emp_options_fn=_get_emp_options,
    role_fn=_role,
)





# =====================
# Mensagens (Central + Bloqueio diário)
# =====================










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















# ------------- Erros -------------
# Campanhas V2 (Enterprise)
# ==========================
# (rotas admin migradas para o blueprint blueprints/campanhas_v2_admin.py)












# =========================================

# Ranking por Marca (rotas movidas para ranking_marca_routes.py)


