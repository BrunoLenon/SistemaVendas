"""Autorização (authz) e escopo do usuário.

Objetivo: centralizar checagens de login/role/EMP para evitar divergências entre rotas.
Este módulo NÃO importa `app` para evitar import circular.

Uso:
  from authz import login_required, admin_required, get_user_scope
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Iterable

from flask import flash, redirect, session, url_for

from security_utils import audit, normalize_role


@dataclass(frozen=True)
class UserScope:
    usuario: str | None
    role: str
    emps: list[int]
    emp_default: int | None
    vendedor: str | None

    def is_admin(self) -> bool:
        return self.role == "admin"

    def is_supervisor(self) -> bool:
        return self.role == "supervisor"

    def is_vendedor(self) -> bool:
        return self.role == "vendedor"


def _to_int_list(value: Any) -> list[int]:
    """Normaliza lista de EMPs a partir do que estiver na sessão.

    Aceita:
      - list/tuple/set de int/str
      - str "101,102"
      - None
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        out = []
        for v in value:
            try:
                out.append(int(str(v).strip()))
            except Exception:
                continue
        return sorted(set(out))
    if isinstance(value, str):
        parts = [p.strip() for p in value.replace(";", ",").split(",") if p.strip()]
        out = []
        for p in parts:
            try:
                out.append(int(p))
            except Exception:
                continue
        return sorted(set(out))
    try:
        return [int(value)]
    except Exception:
        return []


def get_user_scope() -> UserScope:
    """Retorna escopo do usuário logado (baseado na sessão)."""
    usuario = session.get("usuario")
    role = normalize_role(session.get("role"))
    emps = _to_int_list(session.get("emps") or session.get("allowed_emps"))
    emp_default = session.get("emp")
    try:
        emp_default = int(emp_default) if emp_default is not None and str(emp_default).strip() != "" else None
    except Exception:
        emp_default = None
    vendedor = session.get("vendedor")
    return UserScope(usuario=usuario, role=role, emps=emps, emp_default=emp_default, vendedor=vendedor)


def is_logged_in() -> bool:
    sc = get_user_scope()
    return bool(sc.usuario)


def role() -> str:
    return get_user_scope().role


def require_login_redirect():
    if not is_logged_in():
        return redirect(url_for("auth.login"))
    return None


def require_role(allowed: Iterable[str], *, redirect_endpoint: str = "dashboard"):
    r = role()
    allowed_norm = {normalize_role(x) for x in allowed}
    if r not in allowed_norm:
        flash("Acesso não autorizado.", "warning")
        audit("forbidden", role=r, allowed=list(allowed_norm))
        return redirect(url_for(redirect_endpoint))
    return None


def login_required(fn: Callable):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        red = require_login_redirect()
        if red:
            return red
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn: Callable):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        red = require_login_redirect()
        if red:
            return red
        red = require_role(["admin"])
        if red:
            # mensagem mais específica para admin
            flash("Acesso restrito ao administrador.", "warning")
            audit("admin_forbidden")
            return red
        return fn(*args, **kwargs)
    return wrapper


def admin_or_supervisor_required(fn: Callable):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        red = require_login_redirect()
        if red:
            return red
        red = require_role(["admin", "supervisor"])
        if red:
            flash("Acesso restrito ao administrador/supervisor.", "warning")
            audit("admin_or_supervisor_forbidden")
            return red
        return fn(*args, **kwargs)
    return wrapper
