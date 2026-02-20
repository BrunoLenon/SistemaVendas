from __future__ import annotations
from flask import Blueprint

bp = Blueprint('mensagens', __name__)

# Wrappers: mantêm o endpoint original (url_for("...") continua funcionando)
# e chamam a lógica existente em web.app (handlers).

import web.app as handlers

@bp.route("/mensagens", methods=["GET"], endpoint='mensagens_central')
def mensagens_central():
    return handlers.mensagens_central()

@bp.route("/mensagens/bloqueio/<int:mensagem_id>", methods=["GET"], endpoint='mensagens_bloqueio')
def mensagens_bloqueio(mensagem_id):
    return handlers.mensagens_bloqueio(mensagem_id=mensagem_id)

@bp.route("/mensagens/lida/<int:mensagem_id>", methods=["POST"], endpoint='mensagens_marcar_lida')
def mensagens_marcar_lida(mensagem_id):
    return handlers.mensagens_marcar_lida(mensagem_id=mensagem_id)

