import os
import re
import mimetypes
import logging
import json
from datetime import date, datetime, timedelta
import calendar
from io import BytesIO

import pandas as pd
import requests
from sqlalchemy import and_, or_, func, case, cast, String, text, extract
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

from dados_db import carregar_df
from db import (
    SessionLocal,
    Usuario,
    UsuarioEmp,
    Venda,
    DashboardCache,
    ItemParado,
    CampanhaQtd,
    CampanhaQtdResultado,
    VendasResumoPeriodo,
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

# Rate limit simples (memória) para reduzir brute-force/abuso
from collections import defaultdict
_rl_store: dict[str, list[float]] = defaultdict(list)

def _client_ip() -> str:
    # ProxyFix + X-Forwarded-For
    xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return xff or (request.remote_addr or "unknown")

def _rate_limit(bucket: str, limit: int, window_sec: int) -> bool:
    """Retorna True se pode seguir, False se estourou."""
    now = datetime.utcnow().timestamp()
    key = f"{bucket}:{_client_ip()}"
    arr = _rl_store[key]
    # remove entradas fora da janela
    cutoff = now - window_sec
    i = 0
    while i < len(arr) and arr[i] < cutoff:
        i += 1
    if i:
        del arr[:i]
    if len(arr) >= limit:
        return False
    arr.append(now)
    return True

def audit(event: str, **data):
    """Log estruturado (vai para os logs do Render)."""
    payload = {
        "event": event,
        "ts": datetime.utcnow().isoformat() + "Z",
        "ip": _client_ip(),
        "user": session.get("usuario"),
        "role": session.get("role"),
        **data,
    }
    try:
        app.logger.info(json.dumps(payload, ensure_ascii=False))
    except Exception:
        app.logger.info(str(payload))

@app.before_request
def _security_rate_limits():
    # limita tentativas de login (POST)
    if request.path == "/login" and request.method == "POST":
        if not _rate_limit("login", limit=8, window_sec=60):
            audit("login_rate_limited")
            return render_template("login.html", erro="Muitas tentativas. Aguarde 1 minuto e tente novamente."), 429

    # limita endpoints de relatórios (evita abuso e picos)
    if request.path.startswith("/relatorios/"):
        if not _rate_limit("reports", limit=120, window_sec=60):
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
                return redirect(url_for("login"))
        except Exception:
            # Se estiver inválido, reseta
            pass
    session["last_activity"] = now.isoformat()
    return None


# Garante tabelas
try:
    criar_tabelas()
except Exception:
    app.logger.exception("Falha ao criar/verificar tabelas")

# ------------- Helpers -------------
def _normalize_role(r: str | None) -> str:
    r = (r or '').strip().lower()
    if r in {'admin', 'administrador'}:
        return 'admin'
    if r in {'sup', 'super', 'supervisor'}:
        return 'supervisor'
    return 'vendedor'


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

@app.route('/admin/configuracoes', methods=['GET', 'POST'])
def admin_configuracoes():
    red = _admin_required()
    if red:
        return red

    msgs: list[str] = []
    today = date.today()

    with SessionLocal() as db:
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

def _login_required():
    if not _usuario_logado():
        return redirect(url_for("login"))
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

def _get_vendedores_db(role: str, emp_usuario: str | None) -> list[str]:
    """Lista de vendedores para dropdown sem carregar todas as vendas em memória."""
    role = (role or "").strip().lower()
    with SessionLocal() as db:
        q = db.query(func.distinct(Venda.vendedor))
        if role == "supervisor":
            if emp_usuario:
                q = q.filter(Venda.emp == str(emp_usuario))
            else:
                return []
        # admin vê tudo
        vendedores = [ (r[0] or "").strip().upper() for r in q.all() ]
    vendedores = sorted([v for v in vendedores if v])
    return vendedores

def _get_emps_vendedor(username: str) -> list[str]:
    """Lista de EMPs em que o vendedor possui vendas (para vendedor multi-EMP).

    Regra do sistema: para vendedores, a EMP é inferida da tabela de vendas.
    """
    username = (username or "").strip().upper()
    if not username:
        return []
    with SessionLocal() as db:
        rows = (
            db.query(func.distinct(Venda.emp))
            .filter(Venda.vendedor == username)
            .all()
        )
    emps = sorted({str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip() != ""})
    return emps

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

    # ---- mês anterior (cache) ----
    if mes == 1:
        prev_mes, prev_ano = 12, ano - 1
    else:
        prev_mes, prev_ano = mes - 1, ano

    prev_row = _get_cache_row(vendedor_alvo, prev_ano, prev_mes, emp_scope)
    valor_mes_anterior = float(getattr(prev_row, "valor_liquido", 0) or 0) if prev_row else 0.0

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

def _dados_ao_vivo(vendedor: str, mes: int, ano: int, emp_scope: str | None):
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
            base = base.filter(Venda.emp == str(emp_scope))

        def sums(s, e):
            q = base.filter(Venda.movimento >= s, Venda.movimento < e)
            signed = case((Venda.mov_tipo_movto.in_(['DS','CA']), -Venda.valor_total), else_=Venda.valor_total)
            bruto = func.coalesce(func.sum(case((~Venda.mov_tipo_movto.in_(['DS','CA']), Venda.valor_total), else_=0.0)), 0.0)
            devol = func.coalesce(func.sum(case((Venda.mov_tipo_movto.in_(['DS','CA']), Venda.valor_total), else_=0.0)), 0.0)
            liquido = func.coalesce(func.sum(signed), 0.0)
            mix = func.count(func.distinct(case((~Venda.mov_tipo_movto.in_(['DS','CA']), Venda.mestre), else_=None)))
            row = db.query(bruto, devol, liquido, mix).select_from(Venda).filter(Venda.vendedor == vendedor)
            if emp_scope:
                row = row.filter(Venda.emp == str(emp_scope))
            row = row.filter(Venda.movimento >= s, Venda.movimento < e).first()
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


        # ranking por marca (liquido)
        signed = case((Venda.mov_tipo_movto.in_(['DS','CA']), -Venda.valor_total), else_=Venda.valor_total)
        q_rank = db.query(Venda.marca, func.coalesce(func.sum(signed), 0.0)).filter(Venda.vendedor == vendedor)
        if emp_scope:
            q_rank = q_rank.filter(Venda.emp == str(emp_scope))
        q_rank = q_rank.filter(Venda.movimento >= start, Venda.movimento < end).group_by(Venda.marca)
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
@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.route("/", methods=["GET", "HEAD"])
def home():
    # Render/health-check friendly: return 200 for HEAD (and for Go-http-client probes)
    ua = (request.headers.get("User-Agent") or "").lower()
    if request.method == "HEAD" or "go-http-client" in ua:
        return ("OK", 200)

    # Browser/users: redirect to the right place
    if session.get("vendedor") and session.get("role"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.get("/favicon.ico")
def favicon():
    # Avoid noisy 404s in logs
    return ("", 204)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", erro=None)

    vendedor = (request.form.get("vendedor") or "").strip().upper()
    senha = request.form.get("senha") or ""

    if not vendedor or not senha:
        audit("login_failed", reason="missing_fields", username=vendedor)
        return render_template("login.html", erro="Informe usuário e senha.")

    with SessionLocal() as db:
        u = db.query(Usuario).filter(Usuario.username == vendedor).first()
        if not u or not check_password_hash(u.senha_hash, senha):
            audit("login_failed", reason="invalid_credentials", username=vendedor)
            return render_template("login.html", erro="Usuário ou senha inválidos.")

        session["user_id"] = u.id
        session["usuario"] = u.username
        session["role"] = _normalize_role(getattr(u, "role", None))
        # EMP pode não existir em versões antigas do schema
        session["emp"] = str(getattr(u, "emp", "")) if getattr(u, "emp", None) is not None else ""
        session.permanent = True
        session["last_activity"] = datetime.utcnow().isoformat()

    return redirect(url_for("dashboard"))

@app.get("/logout")
def logout():
    audit("logout")
    session.clear()
    return redirect(url_for("login"))


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

def _dashboard_insights(vendedor: str, ano: int, mes: int, emp_scope: str | None) -> dict | None:
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
        if role == "supervisor" and not emp_usuario:
            msg = "Supervisor sem EMP cadastrada. Cadastre a EMP do supervisor na tabela usuarios."

    dados = None
    if vendedor_alvo:
        try:
            emp_scope = emp_usuario if role == "supervisor" else None
            dados = _dados_from_cache(vendedor_alvo, mes, ano, emp_scope)
        except Exception:
            app.logger.exception("Erro ao carregar dashboard do cache")
            dados = None

        # Fallback: calcula ao vivo (sem pandas) se cache ainda não existe
        if dados is None:
            try:
                emp_scope = emp_usuario if role == "supervisor" else None
                dados = _dados_ao_vivo(vendedor_alvo, mes, ano, emp_scope)
            except Exception:
                app.logger.exception("Erro ao calcular dashboard ao vivo")
                dados = None

    insights = None
    if vendedor_alvo:
        try:
            emp_scope = emp_usuario if role == "supervisor" else None
            insights = _dashboard_insights(vendedor_alvo, ano=ano, mes=mes, emp_scope=emp_scope)
        except Exception:
            app.logger.exception("Erro ao calcular insights do dashboard")
            insights = None

    return render_template(
        "dashboard.html",
        insights=insights,
        vendedor=vendedor_alvo or "",
        usuario=_usuario_logado(),
        role=_role(),
        emp=emp_usuario,
        vendedores=vendedores_lista,
        vendedor_selecionado=vendedor_alvo or "",
        mensagem_role=msg,
        mes=mes,
        ano=ano,
        dados=dados,
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
                emp_scopes = [str(x[0]) for x in db.query(ItemParado.emp).filter(ItemParado.ativo == 1).distinct().all()]

    elif role == 'supervisor':
        emp_scopes = [str(_emp())]

    else:
        # vendedor: EMP(s) derivadas das vendas
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
            .filter(ItemParado.ativo == 1)
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
                emp_scopes = [str(x[0]) for x in db.query(ItemParado.emp).filter(ItemParado.ativo == 1).distinct().all()]
    elif role == 'supervisor':
        emp_scopes = [str(_emp())]
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
            .filter(ItemParado.ativo == 1)
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
        prefix = _norm_prefix(getattr(campanha, "descricao_prefixo", "") or "")
        # fallback: se não preencher descricao_prefixo, usa produto_prefixo como prefixo de descrição
        if not prefix:
            prefix = _norm_prefix((campanha.produto_prefixo or ""))
        campo_item = func.coalesce(Venda.descricao_norm, "")
        cond_prefix = campo_item.like(prefix + "%")
    else:
        prefix = (campanha.produto_prefixo or "").strip()
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

    valor_recomp = (qtd_vendida * float(campanha.recompensa_unit or 0.0)) if atingiu else 0.0

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
    res.produto_prefixo = prefix
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

def _resolver_emp_scope_para_usuario(vendedor: str, role: str, emp_usuario: str | None) -> list[str]:
    """Retorna lista de EMPs que o usuário pode visualizar (para campanhas e relatórios)."""
    role = (role or "").strip().lower()
    if role == "admin":
        # Admin: se emp estiver definido via query param, filtra. Caso contrário, pode ver as EMPs do vendedor selecionado
        return []
    if role == "supervisor":
        return [str(emp_usuario)] if emp_usuario else []
    # vendedor
    return _get_emps_vendedor(vendedor)

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

    # período
    hoje = date.today()
    mes = int(request.args.get("mes") or hoje.month)
    ano = int(request.args.get("ano") or hoje.year)

    # vendedor alvo
    vendedor_logado = (_usuario_logado() or "").strip().upper()
    vendedor_sel = (request.args.get("vendedor") or vendedor_logado).strip().upper()
    if role != "admin" and vendedor_sel != vendedor_logado and role != "supervisor":
        vendedor_sel = vendedor_logado

    # EMP scope
    emp_param = (request.args.get("emp") or "").strip()
    emps_scope: list[str] = []
    if (role or "").lower() == "admin":
        if emp_param:
            emps_scope = [emp_param]
        else:
            emps_scope = _get_emps_vendedor(vendedor_sel)
    else:
        emps_scope = _resolver_emp_scope_para_usuario(vendedor_sel, role, emp_usuario)

    # Se não temos EMP, não dá pra montar relatório
    if not emps_scope and (role or "").lower() != "admin":
        flash("Não foi possível identificar a EMP do vendedor pelas vendas. Verifique se já existem vendas importadas.", "warning")

    inicio_mes, fim_mes = _periodo_bounds(ano, mes)

    # Busca vendedores dropdown
    vendedores_dropdown = []
    try:
        vendedores_dropdown = _get_vendedores_db(role, emp_usuario)
    except Exception:
        vendedores_dropdown = []

    # Calcula resultados e agrupa por EMP
    blocos: list[dict] = []
    with SessionLocal() as db:
        for emp in emps_scope or ([emp_param] if emp_param else []):
            emp = str(emp)

            # campanhas relevantes (overlap do mês)
            campanhas = _campanhas_mes_overlap(ano, mes, emp)

            # aplica prioridade: regras do vendedor substituem regras gerais
            # chave: (produto_prefixo, marca)
            by_key: dict[tuple[str, str], CampanhaQtd] = {}
            for c in campanhas:
                key = ((c.produto_prefixo or "").strip().upper(), (c.marca or "").strip().upper())
                if c.vendedor and c.vendedor.strip().upper() == vendedor_sel:
                    by_key[key] = c
                else:
                    by_key.setdefault(key, c)
            campanhas_final = list(by_key.values())

            linhas = []
            total_recomp = 0.0

            for c in campanhas_final:
                # interseção do período
                periodo_ini = max(c.data_inicio, inicio_mes)
                periodo_fim = min(c.data_fim, fim_mes)
                res = _upsert_resultado(db, c, vendedor_sel, emp, ano, mes, periodo_ini, periodo_fim)
                linhas.append(res)
                total_recomp += float(res.valor_recompensa or 0.0)

            db.commit()

            # Recarrega resultados (já persistidos)
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

            blocos.append({
                "emp": emp,
                "resultados": resultados,
                "total": total_recomp,
            })

    return render_template(
        "campanhas_qtd.html",
        role=role,
        ano=ano,
        mes=mes,
        vendedor=vendedor_sel,
        vendedor_logado=vendedor_logado,
        vendedores=vendedores_dropdown,
        blocos=blocos,
        emp_param=emp_param,
    )

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
    vendedor_sel = (request.args.get("vendedor") or vendedor_logado).strip().upper()
    if role != "admin" and vendedor_sel != vendedor_logado and role != "supervisor":
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
    return emps

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
    return vendedores

def _calc_vendas_por_vendedor_para_campanha(db, emp: str, campanha: CampanhaQtd, periodo_ini: date, periodo_fim: date) -> dict[str, tuple[float, float]]:
    """Retorna dict vendedor -> (qtd_vendida, valor_vendido) para uma campanha no período (já considerando EMP e filtros da campanha)."""
    emp = str(emp)
    prefix = (campanha.produto_prefixo or '').strip()
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

def _build_campanhas_escolhidas_por_vendedor(campanhas: list[CampanhaQtd], vendedores: list[str]) -> dict[str, list[CampanhaQtd]]:
    """Aplica a regra de prioridade por chave (prefixo+marca): campanha do vendedor substitui campanha geral."""
    # geral: vendedor NULL
    geral_by_key: dict[tuple[str, str], CampanhaQtd] = {}
    especificas: dict[str, dict[tuple[str, str], CampanhaQtd]] = {}
    for c in campanhas:
        key = ((c.produto_prefixo or "").strip().upper(), (c.marca or "").strip().upper())
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
    emp_usuario = _emp()

    hoje = date.today()
    mes = int(request.args.get("mes") or hoje.month)
    ano = int(request.args.get("ano") or hoje.year)

    emp_param = (request.args.get("emp") or "").strip()

    vendedor_logado = (_usuario_logado() or "").strip().upper()
    vendedor_param = (request.args.get("vendedor") or "").strip().upper()

    # Define escopo de EMPs e vendedores
    emps_scope: list[str] = []
    vendedores_por_emp: dict[str, list[str]] = {}

    if role == "admin":
        if emp_param:
            emps_scope = [emp_param]
        else:
            emps_scope = _get_emps_com_vendas_no_periodo(ano, mes)
    elif role == "supervisor":
        if not emp_usuario:
            flash("Supervisor sem EMP cadastrada. Ajuste o usuário do supervisor.", "warning")
            emps_scope = []
        else:
            emps_scope = [str(emp_usuario)]
    else:
        # vendedor
        emps_scope = _get_emps_vendedor(vendedor_logado)
        if not emps_scope:
            flash("Não foi possível identificar a EMP do vendedor pelas vendas.", "warning")

    # Vendedores por EMP (limitado por role)
    for emp in emps_scope:
        emp = str(emp)
        if role == "admin":
            # admin: todos os vendedores que venderam no período na EMP
            vendedores = _get_vendedores_emp_no_periodo(emp, ano, mes)
            # se admin passar vendedor, filtra (útil para testar)
            if vendedor_param:
                vendedores = [vendedor_param] if vendedor_param in vendedores else [vendedor_param]
        elif role == "supervisor":
            vendedores = _get_vendedores_emp_no_periodo(emp, ano, mes)
        else:
            vendedores = [vendedor_logado]
        vendedores_por_emp[emp] = vendedores

    # Recalcula snapshots do escopo para garantir relatório correto
    try:
        _recalcular_resultados_campanhas_para_scope(ano, mes, emps_scope, vendedores_por_emp)
    except Exception as e:
        print(f"[RELATORIO_CAMPANHAS] erro ao recalcular snapshots: {e}")
        flash("Não foi possível recalcular os resultados das campanhas agora. Exibindo dados já salvos.", "warning")

    # Carrega resultados e organiza para o template
    emps_data = []
    with SessionLocal() as db:
        for emp in emps_scope:
            emp = str(emp)
            vendedores = vendedores_por_emp.get(emp) or []
            if not vendedores:
                continue

            resultados = (
                db.query(CampanhaQtdResultado)
                .filter(
                    CampanhaQtdResultado.emp == emp,
                    CampanhaQtdResultado.competencia_ano == int(ano),
                    CampanhaQtdResultado.competencia_mes == int(mes),
                    CampanhaQtdResultado.vendedor.in_([v.strip().upper() for v in vendedores]),
                )
                .order_by(CampanhaQtdResultado.vendedor.asc(), CampanhaQtdResultado.valor_recompensa.desc())
                .all()
            )

            # agrupa por vendedor
            by_vend: dict[str, list[CampanhaQtdResultado]] = {}
            for r in resultados:
                by_vend.setdefault((r.vendedor or "").strip().upper(), []).append(r)

            vendedores_data = []
            for v in vendedores:
                lst = by_vend.get(v.strip().upper(), [])
                total = sum(float(x.valor_recompensa or 0.0) for x in lst)
                vendedores_data.append({
                    "vendedor": v.strip().upper(),
                    "total_recompensa": float(total),
                    "campanhas": lst,
                })

            total_emp = sum(float(vd["total_recompensa"] or 0.0) for vd in vendedores_data)
            emps_data.append({
                "emp": emp,
                "total_emp": float(total_emp),
                "vendedores": vendedores_data,
            })

    return render_template(
        "relatorio_campanhas.html",
        role=role,
        ano=ano,
        mes=mes,
        emp_param=emp_param,
        emps_data=emps_data,
        vendedor=vendedor_logado,
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
            base = base.filter(Venda.emp == emp_usuario)
            base_hist = base_hist.filter(Venda.emp == emp_usuario)
            escopo_label = f"EMP {emp_usuario}"
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
        cliente_rows = (
            base.with_entities(
                Venda.emp.label("emp"),
                func.coalesce(Venda.razao_norm, "sem_cliente").label("razao_norm"),
                func.coalesce(func.max(Venda.razao), "").label("razao_label"),
                func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor_total"),
                func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd_total"),
                func.coalesce(func.count(func.distinct(Venda.mestre)), 0).label("mix_itens"),
            )
            .filter(Venda.cliente_id_norm.isnot(None))
            .group_by(Venda.emp, func.coalesce(Venda.razao_norm, "sem_cliente"))
            .order_by(Venda.emp, func.sum(Venda.valor_total).desc())
            .all()
        )

        clientes_por_emp = {}
        for r in cliente_rows:
            emp = str(r.emp)
            label = (r.razao_label or "").strip()
            if not label:
                label = "SEM CLIENTE" if (r.razao_norm in (None, "", "sem_cliente")) else str(r.razao_norm).upper()
            clientes_por_emp.setdefault(emp, []).append({
                "razao_norm": r.razao_norm,
                "razao_label": label,
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
                "cidades_full": cities_full[:50],
                "clientes_preview": clients_full[:5],
                "clientes_full": clients_full[:50],
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
        if str(emp_usuario or "").strip() and str(emp) != str(emp_usuario):
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
            .limit(50)
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
    emp_usuario = _emp()
    vendedor_logado = (_usuario_logado() or "").strip().upper()

    emp = (request.args.get("emp") or "").strip()
    razao_norm = (request.args.get("razao_norm") or "").strip()
    cidade_norm = (request.args.get("cidade_norm") or "").strip()
    mes = int(request.args.get("mes") or 0)
    ano = int(request.args.get("ano") or 0)
    vendedor = (request.args.get("vendedor") or "").strip().upper()

    if not emp or not razao_norm or not mes or not ano:
        return jsonify({"error": "Parâmetros inválidos"}), 400

    # Permissões
    if role == "supervisor":
        if str(emp_usuario or "").strip() and str(emp) != str(emp_usuario):
            return jsonify({"error": "Acesso negado"}), 403
    elif role == "vendedor":
        vendedor = vendedor_logado  # vendedor não pode consultar outro vendedor

    with SessionLocal() as db:
        base = db.query(Venda).filter(
            Venda.emp == str(emp),
            Venda.razao_norm == razao_norm,
            extract("month", Venda.movimento) == mes,
            extract("year", Venda.movimento) == ano,
        )
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
    razao_norm = (request.args.get("razao_norm") or "").strip()
    mes = int(request.args.get("mes") or 0)
    ano = int(request.args.get("ano") or 0)
    vendedor = (request.args.get("vendedor") or "").strip().upper()

    if not emp or not razao_norm or not mes or not ano:
        return jsonify({"error": "Parâmetros inválidos"}), 400

    # Permissões por perfil
    if role == "supervisor":
        if str(emp_usuario or "").strip() and str(emp) != str(emp_usuario):
            return jsonify({"error": "Acesso negado"}), 403
    elif role == "vendedor":
        # vendedor só pode ver os próprios dados (e não pode trocar vendedor via query)
        vendedor = vendedor_logado

    # Query base
    with SessionLocal() as db:
        base = db.query(Venda).filter(
            Venda.emp == str(emp),
            Venda.razao_norm == razao_norm,
            extract("month", Venda.movimento) == mes,
            extract("year", Venda.movimento) == ano,
        )
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
            .limit(200)
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
        "razao_norm": razao_norm,
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
                    emp_sup = (request.form.get("emp_supervisor") or "").strip()
                    if len(nova_senha) < 4:
                        raise ValueError("Senha muito curta (mín. 4).")
                    if role not in {"admin", "supervisor", "vendedor"}:
                        role = "vendedor"
                    # Supervisor precisa de EMP
                    emp_val = None
                    if role == "supervisor":
                        if not emp_sup:
                            raise ValueError("Informe a EMP para o supervisor.")
                        # Normaliza EMP como texto (ex.: "101")
                        emp_val = str(emp_sup).strip()
                        if not emp_val:
                            raise ValueError("Informe a EMP para o supervisor.")
                    u = db.query(Usuario).filter(Usuario.username == novo_usuario).first()
                    if u:
                        u.senha_hash = generate_password_hash(nova_senha)
                        u.role = role
                        # Atualiza EMP quando aplicável
                        if role == "supervisor":
                            setattr(u, "emp", emp_val)
                        else:
                            setattr(u, "emp", None)
                        # BUGFIX: sem commit, alterações não eram persistidas.
                        db.commit()
                        ok = f"Usuário {novo_usuario} atualizado."
                    else:
                        db.add(
                            Usuario(
                                username=novo_usuario,
                                senha_hash=generate_password_hash(nova_senha),
                                role=role,
                                emp=emp_val,
                            )
                        )
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
                    emps_raw = (request.form.get("emps") or "")
                    emps = []
                    for part in re.split(r"[\s,;]+", emps_raw.strip()):
                        if part:
                            emps.append(str(part).strip())
                    if not alvo:
                        raise ValueError("Informe o usuário.")
                    u = db.query(Usuario).filter(Usuario.username == alvo).first()
                    if not u:
                        raise ValueError("Usuário não encontrado.")
                    if u.role not in ('vendedor', 'supervisor'):
                        raise ValueError("Apenas VENDEDOR ou SUPERVISOR podem ter múltiplas EMPs vinculadas.")
                    desired = set([e for e in emps if e])
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
                            db.add(UsuarioEmp(usuario_id=u.id, emp=emp, ativo=True))
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
                            db.add(UsuarioEmp(usuario_id=u.id, emp=emp, ativo=True))
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
                            db.add(UsuarioEmp(usuario_id=u.id, emp=emp, ativo=True))
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
            {"usuario": u.username, "role": u.role, "emp": getattr(u, "emp", None)}
            for u in usuarios
        ]

        # Vínculos multi-EMP (usuario_emp)
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

        # EMPs conhecidas (para ajudar no cadastro) - vindas de vendas
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
        emps_disponiveis=emps_disponiveis,
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
            q = q.filter(VendasResumoPeriodo.emp == emp)
        if vendedor:
            q = q.filter(VendasResumoPeriodo.vendedor == vendedor)
        registros = q.order_by(VendasResumoPeriodo.vendedor.asc()).all()

        # Resumos do mesmo período no ano passado (ano-1) para conferência/edição rápida
        ano_passado = ano - 1
        q2 = db.query(VendasResumoPeriodo).filter(
            VendasResumoPeriodo.ano == ano_passado,
        )
        if emp:
            q2 = q2.filter(VendasResumoPeriodo.emp == emp)
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
@app.get('/admin/fechamento')
def admin_fechamento_redirect():
    red = _admin_required()
    if red:
        return red
    return redirect(url_for('admin_resumos_periodo'))


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

                    recompensa_unit = float(recompensa_raw)
                    qtd_minima = float(qtd_min_raw) if qtd_min_raw else None
                    valor_minimo = float(valor_min_raw) if valor_min_raw else None
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
                            recompensa_unit=recompensa_unit,
                            qtd_minima=qtd_minima,
                            valor_minimo=valor_minimo,
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

# ------------- Erros -------------
@app.errorhandler(500)
def err_500(e):
    app.logger.exception("Erro 500: %s", e)
    return (
        "Erro interno. Verifique os logs no Render (ou fale com o admin).",
        500,
    )