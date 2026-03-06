from __future__ import annotations

"""Rotas de Admin: Usuários.

Extraído do app.py como refatoração pura (sem alterar comportamento externo).
- Mantém o mesmo path /admin/usuarios
- Mantém o mesmo endpoint 'admin_usuarios' usado em url_for(...)
"""

import re
from typing import Callable, Any

from flask import render_template, request
from werkzeug.security import generate_password_hash

from db import SessionLocal, Usuario, UsuarioEmp, Emp, Venda


# Dependências injetadas (refatoração pura)
_app = None
_login_required: Callable[[], Any] | None = None
_admin_required: Callable[[], Any] | None = None
_usuario_logado: Callable[[], str | None] | None = None


def register_admin_usuarios_routes(
    app,
    *,
    login_required_fn: Callable[[], Any],
    admin_required_fn: Callable[[], Any],
    usuario_logado_fn: Callable[[], str | None],
) -> None:
    """Registra a rota /admin/usuarios sem alterar contratos/endpoints."""
    global _app, _login_required, _admin_required, _usuario_logado
    _app = app
    _login_required = login_required_fn
    _admin_required = admin_required_fn
    _usuario_logado = usuario_logado_fn

    app.add_url_rule(
        "/admin/usuarios",
        endpoint="admin_usuarios",
        view_func=admin_usuarios,
        methods=["GET", "POST"],
    )


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
                _app.logger.exception("Erro na admin/usuarios")

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


