"""Guard e utilitários de mensagens bloqueantes.

Refatoração pura: código extraído do app.py sem alterar comportamento externo.

Observação:
- Este módulo NÃO conhece regras de escopo/EMPs; elas continuam sendo fornecidas
  pelo app via callables (role_fn, allowed_emps_fn) para evitar import circular.
"""

from __future__ import annotations

from datetime import date

from flask import session

from db import (
    Mensagem,
    MensagemEmpresa,
    MensagemUsuario,
    MensagemLidaDiaria,
)


def is_date_in_range(today: date, inicio: date | None, fim: date | None) -> bool:
    """Retorna True se a data 'today' está dentro do intervalo [inicio, fim]."""
    if inicio and today < inicio:
        return False
    if fim and today > fim:
        return False
    return True


def find_pending_blocking_message(
    db,
    *,
    role_fn,
    allowed_emps_fn,
) -> Mensagem | None:
    """Retorna a primeira mensagem bloqueante pendente para o usuário (hoje).

    Dependências (injeção para evitar circular imports):
      - role_fn(): retorna o papel/perfil normalizado do usuário.
      - allowed_emps_fn(): retorna a lista de EMPs permitidas (ou [] para "todas").
    """

    role = (role_fn() or "").lower()
    user_id = session.get("user_id")
    if not user_id:
        return None

    today = date.today()
    allowed_emps = allowed_emps_fn()  # [] significa "todas" para admin_all_emps

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
        if not is_date_in_range(today, msg.inicio_em, msg.fim_em):
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
