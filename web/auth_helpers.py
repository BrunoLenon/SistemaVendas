from __future__ import annotations

from functools import wraps

from flask import flash, redirect, request, session, url_for

from db import Emp, SessionLocal, Usuario
from security_utils import audit, normalize_role
from services.scope import get_session_emps, refresh_session_emps


# ------------- Helpers -------------
def _normalize_role(r: str | None) -> str:
    # Compatibilidade: o sistema historicamente usa `_normalize_role`.
    # A lógica agora vive em `security_utils.normalize_role`.
    return normalize_role(r)


def _usuario_logado() -> str | None:
    return session.get("usuario")


def _role():
    """Retorna o papel/perfil normalizado do usuário logado (admin/supervisor/vendedor/financeiro)."""
    try:
        return normalize_role(session.get("role"))
    except Exception:
        # fallback defensivo
        val = session.get("role") or session.get("perfil") or ""
        return str(val).strip().lower()


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


# =========================
# Auth helpers / decorators
# =========================
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
