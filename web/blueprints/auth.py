from __future__ import annotations

from datetime import datetime

from flask import Blueprint, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash
from sqlalchemy import text

from db import SessionLocal, Usuario, UsuarioEmp
from security_utils import audit, normalize_role


bp = Blueprint("auth", __name__)


def _load_allowed_emps(db, usuario_id: int) -> list[str]:
    rows = (db.query(UsuarioEmp.emp)
            .filter(UsuarioEmp.usuario_id == usuario_id)
            .filter(UsuarioEmp.ativo.is_(True))
            .all())
    emps = sorted({str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip()})
    return emps


@bp.route("/login", methods=["GET", "POST"], endpoint="login")
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

        role = normalize_role(getattr(u, "role", None))

        session.clear()
        session["user_id"] = u.id
        session["usuario"] = u.username
        session["role"] = role
        # EMP pode não existir em versões antigas do schema
        session["emp"] = str(getattr(u, "emp", "")) if getattr(u, "emp", None) is not None else ""
        session.permanent = True
        session["last_activity"] = datetime.utcnow().isoformat()

        # Admin recomendado: acesso total, independente de cadastros em usuario_emps
        if role == "admin":
            session["admin_all_emps"] = True
            session["allowed_emps"] = []
        else:
            emps = _load_allowed_emps(db, u.id)
            # fallback: se não houver vínculos ainda, usa EMP do usuário (se existir)
            if (not emps) and session.get("emp"):
                emps = [str(session.get("emp")).strip()]
            session["allowed_emps"] = emps

    # Redireciona para a melhor primeira tela por perfil
    if role in ("vendedor", "supervisor"):
        return redirect(url_for("itens_parados"))
    return redirect(url_for("dashboard"))


@bp.get("/logout", endpoint="logout")
def logout():
    audit("logout")
    session.clear()
    return redirect(url_for("auth.login"))
