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

@bp.route("/admin/campanhas_v2", methods=["GET", "POST"], endpoint="admin_campanhas_v2")
def admin_campanhas_v2():
    """Cadastro de campanhas V2 (fonte da verdade).

    Mantém o template existente (admin_campanhas_v2.html) e garante que as variáveis
    esperadas (today/edit_obj) existam.
    """
    from datetime import date

    # Imports locais para evitar circular import com web.app
    from flask import request, render_template, redirect, url_for, flash
    from db import SessionLocal, CampanhaV2Master, CampanhaV2Resultado
    from services.campanhas_v2_engine import recalc_v2_competencia, recalc_v2_campanha

    ano = int(request.args.get("ano") or date.today().year)
    mes = int(request.args.get("mes") or date.today().month)

    edit_id = request.args.get("edit")
    today = date.today()

    db = SessionLocal()
    try:
        # Carrega objeto em edição, se houver
        edit_obj = None
        if edit_id:
            try:
                edit_obj = db.query(CampanhaV2Master).filter(CampanhaV2Master.id == int(edit_id)).first()
            except Exception:
                edit_obj = None

        if request.method == "POST":
            cid = (request.form.get("id") or "").strip()
            titulo = (request.form.get("titulo") or "").strip()
            tipo = (request.form.get("tipo") or "RANKING_VALOR").strip().upper()

            # checkbox pode vir como "on" ou pode nem vir
            ativo = bool(request.form.get("ativo"))

            escopo = (request.form.get("escopo") or "EMP").strip().upper()
            if escopo not in ("EMP", "GLOBAL"):
                escopo = "EMP"

            emps_raw = (request.form.get("emps") or "").strip()
            # Guardamos emps_json como string; o template já trabalha com isso
            emps_json = emps_raw or None

            vig_ini_raw = (request.form.get("vigencia_ini") or "").strip()
            vig_fim_raw = (request.form.get("vigencia_fim") or "").strip()
            regras_json = (request.form.get("regras_json") or "").strip() or "{}"

            if not titulo:
                flash("Informe o título da campanha.", "danger")
                return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes, edit=edit_id) if edit_id else url_for("admin_campanhas_v2", ano=ano, mes=mes))

            try:
                vigencia_ini = date.fromisoformat(vig_ini_raw) if vig_ini_raw else None
                vigencia_fim = date.fromisoformat(vig_fim_raw) if vig_fim_raw else None
            except Exception:
                vigencia_ini = None
                vigencia_fim = None

            if not vigencia_ini or not vigencia_fim:
                flash("Informe vigência inicial e final em formato válido.", "danger")
                return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes, edit=edit_id) if edit_id else url_for("admin_campanhas_v2", ano=ano, mes=mes))

            if vigencia_fim < vigencia_ini:
                flash("Vigência final não pode ser menor que a inicial.", "danger")
                return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes, edit=edit_id) if edit_id else url_for("admin_campanhas_v2", ano=ano, mes=mes))

            # Create or update
            if cid:
                c = db.query(CampanhaV2Master).filter(CampanhaV2Master.id == int(cid)).first()
                if not c:
                    flash("Campanha não encontrada para edição.", "danger")
                    return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes))
            else:
                c = CampanhaV2Master()

            c.titulo = titulo
            c.tipo = tipo
            c.escopo = escopo
            c.emps_json = emps_json
            c.vigencia_ini = vigencia_ini
            c.vigencia_fim = vigencia_fim
            c.ativo = ativo
            c.regras_json = regras_json

            db.add(c)
            db.commit()

            flash("Campanha V2 salva com sucesso.", "success")
            return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes))

        # Lista campanhas: exibimos todas (ordenadas), a filtragem por competência fica na apuração
        campanhas = (
            db.query(CampanhaV2Master)
            .order_by(CampanhaV2Master.id.desc())
            .all()
        )

        return render_template(
            "admin_campanhas_v2.html",
            campanhas=campanhas,
            ano=ano,
            mes=mes,
            today=today,
            edit_obj=edit_obj,
        )
    finally:
        db.close()


@bp.route("/admin/campanhas_v2/recalcular", methods=["GET"], endpoint="admin_campanhas_v2_recalcular")
def admin_campanhas_v2_recalcular():
    """Recalcula a competência (ano/mes) para V2."""
    from datetime import date
    from flask import request, redirect, url_for, flash
    from db import SessionLocal
    from services.campanhas_v2_engine import recalc_v2_competencia

    ano = int(request.args.get("ano") or date.today().year)
    mes = int(request.args.get("mes") or date.today().month)

    db = SessionLocal()
    try:
        recalc_v2_competencia(db, ano=ano, mes=mes)
        db.commit()
        flash("Competência V2 recalculada.", "success")
    except Exception as e:
        db.rollback()
        flash(f"Falha ao recalcular competência V2: {e}", "danger")
    finally:
        db.close()

    return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes))


@bp.route("/admin/campanhas_v2/<int:cid>/recalcular", methods=["POST"], endpoint="admin_campanhas_v2_recalcular_uma")
def admin_campanhas_v2_recalcular_uma(cid: int):
    from datetime import date
    from flask import request, redirect, url_for, flash
    from db import SessionLocal
    from services.campanhas_v2_engine import recalc_v2_campanha

    ano = int(request.args.get("ano") or request.form.get("ano") or date.today().year)
    mes = int(request.args.get("mes") or request.form.get("mes") or date.today().month)

    db = SessionLocal()
    try:
        recalc_v2_campanha(db, campanha_id=cid, ano=ano, mes=mes)
        db.commit()
        flash("Campanha V2 recalculada.", "success")
    except Exception as e:
        db.rollback()
        flash(f"Falha ao recalcular campanha: {e}", "danger")
    finally:
        db.close()

    return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes))


@bp.route("/admin/campanhas_v2/<int:cid>/toggle", methods=["POST"], endpoint="admin_campanhas_v2_toggle")
def admin_campanhas_v2_toggle(cid: int):
    from flask import request, redirect, url_for, flash
    from db import SessionLocal, CampanhaV2Master

    ano = request.form.get("ano")
    mes = request.form.get("mes")

    db = SessionLocal()
    try:
        c = db.query(CampanhaV2Master).filter(CampanhaV2Master.id == cid).first()
        if not c:
            flash("Campanha não encontrada.", "danger")
            return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes))
        c.ativo = not bool(c.ativo)
        db.add(c)
        db.commit()
        flash("Status atualizado.", "success")
    except Exception as e:
        db.rollback()
        flash(f"Falha ao atualizar status: {e}", "danger")
    finally:
        db.close()

    return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes))


@bp.route("/admin/campanhas_v2/<int:cid>/duplicar", methods=["POST"], endpoint="admin_campanhas_v2_duplicar")
def admin_campanhas_v2_duplicar(cid: int):
    from flask import request, redirect, url_for, flash
    from db import SessionLocal, CampanhaV2Master

    ano = request.form.get("ano")
    mes = request.form.get("mes")

    db = SessionLocal()
    try:
        c = db.query(CampanhaV2Master).filter(CampanhaV2Master.id == cid).first()
        if not c:
            flash("Campanha não encontrada.", "danger")
            return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes))

        nova = CampanhaV2Master(
            titulo=(c.titulo or "Campanha") + " (Cópia)",
            tipo=c.tipo,
            escopo=c.escopo,
            emps_json=c.emps_json,
            vigencia_ini=c.vigencia_ini,
            vigencia_fim=c.vigencia_fim,
            ativo=False,
            regras_json=c.regras_json,
        )
        db.add(nova)
        db.commit()
        flash("Campanha duplicada (criada desativada).", "success")
    except Exception as e:
        db.rollback()
        flash(f"Falha ao duplicar: {e}", "danger")
    finally:
        db.close()

    return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes))


@bp.route("/admin/campanhas_v2/<int:cid>/delete", methods=["POST"], endpoint="admin_campanhas_v2_delete")
def admin_campanhas_v2_delete(cid: int):
    from flask import request, redirect, url_for, flash
    from db import SessionLocal, CampanhaV2Master, CampanhaV2Resultado

    ano = request.form.get("ano")
    mes = request.form.get("mes")

    db = SessionLocal()
    try:
        # remove resultados primeiro (não depende de FK)
        db.query(CampanhaV2Resultado).filter(CampanhaV2Resultado.campanha_id == cid).delete()
        db.query(CampanhaV2Master).filter(CampanhaV2Master.id == cid).delete()
        db.commit()
        flash("Campanha excluída.", "success")
    except Exception as e:
        db.rollback()
        flash(f"Falha ao excluir: {e}", "danger")
    finally:
        db.close()

    return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes))


@bp.route("/admin/campanhas_v2/seed_defaults", methods=["POST"], endpoint="admin_campanhas_v2_seed_defaults")
def admin_campanhas_v2_seed_defaults():
    """Cria alguns modelos padrão (idempotente)."""
    from datetime import date
    from flask import request, redirect, url_for, flash
    from db import SessionLocal, CampanhaV2Master

    ano = int(request.form.get("ano") or date.today().year)
    mes = int(request.form.get("mes") or date.today().month)

    db = SessionLocal()
    try:
        # Cria somente se não existir nada
        existe = db.query(CampanhaV2Master).count()
        if existe > 0:
            flash("Já existem campanhas V2 cadastradas. Nenhuma ação executada.", "info")
            return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes))

        hoje = date.today()
        ini = hoje.replace(day=1)
        fim = hoje.replace(month=12, day=31)

        defaults = [
            CampanhaV2Master(
                titulo="Ranking por Valor (Top 3)",
                tipo="RANKING_VALOR",
                escopo="EMP",
                emps_json=None,
                vigencia_ini=ini,
                vigencia_fim=fim,
                ativo=True,
                regras_json='{"premios":{"top1":300,"top2":200,"top3":100}}',
            ),
            CampanhaV2Master(
                titulo="Meta Percentual (MOM)",
                tipo="META_PERCENTUAL",
                escopo="EMP",
                emps_json=None,
                vigencia_ini=ini,
                vigencia_fim=fim,
                ativo=False,
                regras_json='{"ref_tipo":"MOM","meta_percentual":10}',
            ),
        ]
        for c in defaults:
            db.add(c)
        db.commit()
        flash("Modelos padrão criados.", "success")
    except Exception as e:
        db.rollback()
        flash(f"Falha ao criar modelos: {e}", "danger")
    finally:
        db.close()

    return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes))

@bp.route("/admin/campanhas/ranking-marca"@bp.route("/admin/campanhas/ranking-marca", methods=["GET", "POST"], endpoint='admin_campanhas_ranking_marca')
def admin_campanhas_ranking_marca():
    return handlers.admin_campanhas_ranking_marca()

