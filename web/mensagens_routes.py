# -*- coding: utf-8 -*-
"""Rotas de Mensagens (central + bloqueio + admin).

Extraído do app.py como refatoração pura (sem alterar comportamento externo).
- Mantém os mesmos paths e os mesmos nomes de endpoint usados em url_for(...)
"""

from __future__ import annotations

from datetime import date, datetime

from flask import flash, redirect, render_template, request, session, url_for

from auth_helpers import (
    _admin_or_supervisor_required,
    _allowed_emps,
    _login_required,
    _role,
    _usuario_logado,
)
from db import (
    Emp,
    Mensagem,
    MensagemEmpresa,
    MensagemLidaDiaria,
    MensagemUsuario,
    SessionLocal,
    Usuario,
    UsuarioEmp,
)
from mensagens_guard import is_date_in_range as _is_date_in_range


def register_mensagens_routes(app) -> None:
    """Registra rotas de Mensagens no app Flask.

    Importante: definimos explicitamente o 'endpoint' para manter 100% backward compatibility
    (ex.: url_for('admin_mensagens')).
    """
    app.add_url_rule(
        "/mensagens",
        endpoint="mensagens_central",
        view_func=mensagens_central,
        methods=["GET"],
    )
    app.add_url_rule(
        "/mensagens/bloqueio/<int:mensagem_id>",
        endpoint="mensagens_bloqueio",
        view_func=mensagens_bloqueio,
        methods=["GET"],
    )
    app.add_url_rule(
        "/mensagens/lida/<int:mensagem_id>",
        endpoint="mensagens_marcar_lida",
        view_func=mensagens_marcar_lida,
        methods=["POST"],
    )
    app.add_url_rule(
        "/admin/mensagens",
        endpoint="admin_mensagens",
        view_func=admin_mensagens,
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/admin/mensagens/<int:mensagem_id>/toggle",
        endpoint="admin_mensagens_toggle",
        view_func=admin_mensagens_toggle,
        methods=["POST"],
    )


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
