from __future__ import annotations

from typing import Any, Callable

from flask import redirect, request, session, url_for


def register_core_routes(
    app,
    *,
    login_required_fn: Callable[[], Any],
    usuario_logado_fn: Callable[[], str | None],
    session_local_factory: Callable[[], Any],
    usuario_model: Any,
    render_template_fn: Callable[..., Any],
    check_password_hash_fn: Callable[[str, str], bool],
    generate_password_hash_fn: Callable[[str], str],
) -> None:
    """Registra rotas core do sistema sem alterar a API pública."""

    def healthz():
        return ("OK", 200)

    def home():
        ua = (request.headers.get("User-Agent") or "").lower()
        if request.method == "HEAD" or "go-http-client" in ua:
            return ("OK", 200)

        if session.get("vendedor") and session.get("role"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("auth.login"))

    def favicon():
        return ("", 204)

    def senha():
        red = login_required_fn()
        if red:
            return red

        vendedor = usuario_logado_fn()
        if request.method == "GET":
            return render_template_fn("senha.html", vendedor=vendedor, erro=None, ok=None)

        senha_atual = request.form.get("senha_atual") or ""
        nova_senha = request.form.get("nova_senha") or ""
        confirmar = request.form.get("confirmar") or ""

        if len(nova_senha) < 4:
            return render_template_fn("senha.html", vendedor=vendedor, erro="Nova senha muito curta.", ok=None)
        if nova_senha != confirmar:
            return render_template_fn("senha.html", vendedor=vendedor, erro="As senhas não conferem.", ok=None)

        with session_local_factory() as db:
            u = db.query(usuario_model).filter(usuario_model.username == vendedor).first()
            if not u or not check_password_hash_fn(u.senha_hash, senha_atual):
                return render_template_fn("senha.html", vendedor=vendedor, erro="Senha atual incorreta.", ok=None)

            u.senha_hash = generate_password_hash_fn(nova_senha)
            db.commit()

        return render_template_fn("senha.html", vendedor=vendedor, erro=None, ok="Senha atualizada com sucesso!")

    app.add_url_rule("/healthz", endpoint="healthz", view_func=healthz, methods=["GET", "HEAD"])
    app.add_url_rule("/", endpoint="home", view_func=home, methods=["GET", "HEAD"])
    app.add_url_rule("/favicon.ico", endpoint="favicon", view_func=favicon, methods=["GET"])
    app.add_url_rule("/senha", endpoint="senha", view_func=senha, methods=["GET", "POST"])
