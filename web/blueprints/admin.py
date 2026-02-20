from __future__ import annotations
from flask import Blueprint

bp = Blueprint('admin', __name__)

# Wrappers: mantêm o endpoint original (url_for("...") continua funcionando)
# e chamam a lógica existente em web.app (handlers).

import web.app as handlers

@bp.route('/admin/configuracoes', methods=['GET', 'POST'], endpoint='admin_configuracoes')
def admin_configuracoes():
    return handlers.admin_configuracoes()

@bp.route("/admin/usuarios", methods=["GET", "POST"], endpoint='admin_usuarios')
def admin_usuarios():
    return handlers.admin_usuarios()

@bp.route("/admin/emps", methods=["GET", "POST"], endpoint='admin_emps')
def admin_emps():
    return handlers.admin_emps()

@bp.route("/admin/cache/refresh", methods=['GET'], endpoint='admin_cache_refresh')
def admin_cache_refresh():
    return handlers.admin_cache_refresh()

@bp.route("/admin/importar", methods=["GET", "POST"], endpoint='admin_importar')
def admin_importar():
    return handlers.admin_importar()

@bp.route("/admin/itens_parados", methods=["GET", "POST"], endpoint='admin_itens_parados')
def admin_itens_parados():
    return handlers.admin_itens_parados()

@bp.route('/admin/resumos_periodo', methods=['GET', 'POST'], endpoint='admin_resumos_periodo')
def admin_resumos_periodo():
    return handlers.admin_resumos_periodo()

@bp.route("/admin/combos", methods=["GET", "POST"], endpoint='admin_combos')
def admin_combos():
    return handlers.admin_combos()

@bp.route("/admin/fechamento", methods=["GET", "POST"], endpoint='admin_fechamento')
def admin_fechamento():
    return handlers.admin_fechamento()

@bp.route("/admin/campanhas", methods=["GET", "POST"], endpoint='admin_campanhas_qtd')
def admin_campanhas_qtd():
    return handlers.admin_campanhas_qtd()

@bp.route("/admin/apagar_vendas", methods=["POST"], endpoint='admin_apagar_vendas')
def admin_apagar_vendas():
    return handlers.admin_apagar_vendas()

@bp.route("/admin/mensagens", methods=["GET", "POST"], endpoint='admin_mensagens')
def admin_mensagens():
    return handlers.admin_mensagens()

@bp.route("/admin/mensagens/<int:mensagem_id>/toggle", methods=["POST"], endpoint='admin_mensagens_toggle')
def admin_mensagens_toggle(mensagem_id):
    return handlers.admin_mensagens_toggle(mensagem_id=mensagem_id)

@bp.route("/admin/metas", methods=['GET'], endpoint='admin_metas')
def admin_metas():
    return handlers.admin_metas()

@bp.route("/admin/metas/criar", methods=['POST'], endpoint='admin_metas_criar')
def admin_metas_criar():
    return handlers.admin_metas_criar()

@bp.route("/admin/metas/toggle/<int:meta_id>", methods=['POST'], endpoint='admin_metas_toggle')
def admin_metas_toggle(meta_id):
    return handlers.admin_metas_toggle(meta_id=meta_id)

@bp.route("/admin/metas/bases/<int:meta_id>", methods=['GET'], endpoint='admin_meta_bases')
def admin_meta_bases(meta_id):
    return handlers.admin_meta_bases(meta_id=meta_id)

@bp.route("/admin/metas/bases/<int:meta_id>/salvar", methods=['POST'], endpoint='admin_meta_bases_salvar')
def admin_meta_bases_salvar(meta_id):
    return handlers.admin_meta_bases_salvar(meta_id=meta_id)

@bp.route("/admin/campanhas_v2", methods=["GET", "POST"], endpoint='admin_campanhas_v2')
def admin_campanhas_v2():
    return handlers.admin_campanhas_v2()

@bp.route("/admin/campanhas_v2/recalcular", methods=["GET"], endpoint='admin_campanhas_v2_recalcular')
def admin_campanhas_v2_recalcular():
    return handlers.admin_campanhas_v2_recalcular()

@bp.route("/admin/campanhas/ranking-marca", methods=["GET", "POST"], endpoint='admin_campanhas_ranking_marca')
def admin_campanhas_ranking_marca():
    return handlers.admin_campanhas_ranking_marca()

