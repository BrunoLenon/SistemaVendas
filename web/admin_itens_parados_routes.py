"""Rotas: Admin Itens Parados (cadastro) — extraído do app.py (refatoração pura).

Objetivo: melhorar manutenibilidade/legibilidade sem alterar comportamento externo.
"""

from __future__ import annotations

from datetime import datetime
from typing import Callable, Type

from flask import current_app, render_template, request


def register_admin_itens_parados_routes(
    app,
    *,
    SessionLocal,
    ItemParado: Type,
    login_required_fn: Callable[[], object | None],
    admin_required_fn: Callable[[], object | None],
    usuario_logado_fn: Callable[[], object],
):
    """Registra rotas de cadastro de itens parados (Admin).

    Mantém paths e endpoints (backward compatibility).
    """

    def admin_itens_parados():
        """Cadastro de itens parados (liquidação) por EMP.

        Campos: EMP, Código, Descrição, Quantidade, Recompensa(%).
        """
        red = login_required_fn()
        if red:
            return red
        red = admin_required_fn()
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

                        db.add(
                            ItemParado(
                                emp=str(emp),
                                codigo=str(codigo),
                                descricao=descricao or None,
                                quantidade=quantidade,
                                recompensa_pct=recompensa_pct,
                                ativo=1,
                            )
                        )
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
                    current_app.logger.exception('Erro no cadastro de itens parados')

            itens = db.query(ItemParado).order_by(ItemParado.emp.asc(), ItemParado.codigo.asc()).all()

        return render_template(
            'admin_itens_parados.html',
            usuario=usuario_logado_fn(),
            itens=itens,
            erro=erro,
            ok=ok,
        )

    app.add_url_rule(
        '/admin/itens_parados',
        endpoint='admin_itens_parados',
        view_func=admin_itens_parados,
        methods=['GET', 'POST'],
    )
