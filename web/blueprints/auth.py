from __future__ import annotations

from datetime import datetime

from flask import Blueprint, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from db import SessionLocal, Usuario
from security_utils import audit, normalize_role


bp = Blueprint("auth", __name__)


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

        session["user_id"] = u.id
        session["usuario"] = u.username
        session["role"] = normalize_role(getattr(u, "role", None))
        # EMP pode não existir em versões antigas do schema
        session["emp"] = str(getattr(u, "emp", "")) if getattr(u, "emp", None) is not None else ""
        session.permanent = True
        session["last_activity"] = datetime.utcnow().isoformat()

    return redirect(url_for("dashboard"))


@bp.get("/logout", endpoint="logout")
def logout():
    audit("logout")
    session.clear()
    return redirect(url_for("login"))
