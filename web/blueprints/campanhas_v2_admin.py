import json
from datetime import date, datetime

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from authz import admin_required
from db import SessionLocal, CampanhaV2Master
from services.campanhas_v2_engine import recalc_v2_competencia, recalc_v2_campanha
from services.campanhas_v2_service import (
    delete_campanha_v2,
    list_campanhas_v2,
    seed_defaults_if_empty,
    upsert_campanha_v2,
)

bp = Blueprint("campanhas_v2_admin", __name__)


def _parse_int_list(raw: str) -> list[int]:
    raw = (raw or "").strip()
    if not raw:
        return []
    out: list[int] = []
    for p in raw.split(","):
        p = p.strip()
        if not p:
            continue
        try:
            out.append(int(p))
        except Exception:
            continue
    # unique preserving order
    seen = set()
    uniq = []
    for x in out:
        if x in seen:
            continue
        seen.add(x)
        uniq.append(x)
    return uniq


def _parse_date(raw: str, fallback: date) -> date:
    raw = (raw or "").strip()
    if not raw:
        return fallback
    # accepts YYYY-MM-DD
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date()
    except Exception:
        return fallback


def _safe_json(raw: str) -> dict:
    raw = (raw or "").strip() or "{}"
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            return obj
        return {}
    except Exception:
        return {}


@bp.route("/admin/campanhas_v2", methods=["GET", "POST"], endpoint="admin_campanhas_v2")
@admin_required
def admin_campanhas_v2():
    """Cadastro SaaS/enterprise das campanhas V2.

    Importante: este handler é a *fonte da verdade* do cadastro.
    Resultados são gerados por recalc (snapshot) e consumidos pelo Financeiro/relatórios.
    """
    today = date.today()
    ano = int(request.args.get("ano") or today.year)
    mes = int(request.args.get("mes") or today.month)
    edit_id = request.args.get("edit")
    db = SessionLocal()
    try:
        # Ações POST (seed / upsert)
        if request.method == "POST":
            action = (request.form.get("action") or "").strip().lower()

            if action == "seed_defaults":
                created = seed_defaults_if_empty(db)
                db.commit()
                flash(
                    "Modelos padrão criados." if created else "Cadastro já possui campanhas (nenhuma criada).",
                    "success",
                )
                return redirect(url_for("admin_campanhas_v2"))

            # Upsert (criar/editar)
            cid = request.form.get("id")
            campanha_id = int(cid) if (cid and str(cid).isdigit()) else None

            titulo = (request.form.get("titulo") or "").strip()
            tipo = (request.form.get("tipo") or "RANKING_VALOR").strip().upper()
            escopo = (request.form.get("escopo") or "EMP").strip().upper()
            # Checkbox HTML geralmente envia "on" quando marcado; em alguns casos pode vir "1".
            ativo_raw = (request.form.get("ativo") or "").strip().lower()
            ativo = ativo_raw in {"1", "on", "true", "yes", "y"}

            # Se não informar vigência, usamos o ano inteiro (padrão seguro)
            default_ini = date(int(ano), 1, 1)
            default_fim = date(int(ano), 12, 31)
            vig_ini = _parse_date(request.form.get("vigencia_ini"), default_ini)
            vig_fim = _parse_date(request.form.get("vigencia_fim"), default_fim)

            emps = _parse_int_list(request.form.get("emps") or "")
            # Compatibilidade: alguns templates antigos usam name="regras".
            regras_txt = request.form.get("regras_json") or request.form.get("regras") or "{}"
            regras = _safe_json(regras_txt)

            if not titulo:
                flash("Informe o título da campanha.", "warning")
            else:
                upsert_campanha_v2(
                    db,
                    campanha_id=campanha_id,
                    titulo=titulo,
                    tipo=tipo,
                    escopo=escopo,
                    emps=emps,
                    vigencia_ini=vig_ini,
                    vigencia_fim=vig_fim,
                    ativo=ativo,
                    regras=regras,
                )
                db.commit()
                flash("Campanha V2 salva.", "success")
                return redirect(url_for("admin_campanhas_v2"))

        # GET / listagem + edição
        campanhas = list_campanhas_v2(db)
        edit_obj = None
        if edit_id and str(edit_id).isdigit():
            edit_obj = db.query(CampanhaV2Master).filter(CampanhaV2Master.id == int(edit_id)).first()

        return render_template(
            "admin_campanhas_v2.html",
            campanhas=campanhas,
            edit_obj=edit_obj,
            today=today,
            ano=ano,
            mes=mes,
        )
    finally:
        db.close()


@bp.route("/admin/campanhas_v2/recalcular", methods=["GET"], endpoint="admin_campanhas_v2_recalcular")
@admin_required
def admin_campanhas_v2_recalcular():
    """Recalcula a competência inteira (snapshot)."""
    today = date.today()
    ano = int(request.args.get("ano") or today.year)
    mes = int(request.args.get("mes") or today.month)
    actor = session.get("username") or "admin"
    db = SessionLocal()
    try:
        recalc_v2_competencia(db, ano=ano, mes=mes, actor=str(actor))
        flash(f"Recalculo V2 concluído para {mes:02d}/{ano}.", "success")
    except Exception as e:
        db.rollback()
        flash(f"Erro ao recalcular: {e}", "danger")
    finally:
        db.close()
    return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes))


@bp.route("/admin/campanhas_v2/<int:cid>/recalcular", methods=["POST"], endpoint="admin_campanhas_v2_recalcular_uma")
@admin_required
def admin_campanhas_v2_recalcular_uma(cid: int):
    today = date.today()
    ano = int(request.form.get("ano") or today.year)
    mes = int(request.form.get("mes") or today.month)
    actor = session.get("username") or "admin"
    db = SessionLocal()
    try:
        recalc_v2_campanha(db, campanha_id=int(cid), ano=ano, mes=mes, actor=str(actor))
        flash("Recalculo concluído para a campanha selecionada.", "success")
    except Exception as e:
        db.rollback()
        flash(f"Erro ao recalcular campanha: {e}", "danger")
    finally:
        db.close()
    return redirect(url_for("admin_campanhas_v2", ano=ano, mes=mes))


@bp.route("/admin/campanhas_v2/<int:cid>/toggle", methods=["POST"], endpoint="admin_campanhas_v2_toggle")
@admin_required
def admin_campanhas_v2_toggle(cid: int):
    db = SessionLocal()
    try:
        c = db.query(CampanhaV2Master).filter(CampanhaV2Master.id == int(cid)).first()
        if not c:
            flash("Campanha não encontrada.", "warning")
        else:
            c.ativo = not bool(c.ativo)
            db.commit()
            flash("Status atualizado.", "success")
    except Exception as e:
        db.rollback()
        flash(f"Erro ao alternar status: {e}", "danger")
    finally:
        db.close()
    return redirect(url_for("admin_campanhas_v2"))


@bp.route("/admin/campanhas_v2/<int:cid>/duplicar", methods=["POST"], endpoint="admin_campanhas_v2_duplicar")
@admin_required
def admin_campanhas_v2_duplicar(cid: int):
    db = SessionLocal()
    try:
        c = db.query(CampanhaV2Master).filter(CampanhaV2Master.id == int(cid)).first()
        if not c:
            flash("Campanha não encontrada.", "warning")
            return redirect(url_for("admin_campanhas_v2"))

        # duplica (inativa)
        regras = _safe_json(getattr(c, "regras_json", None))
        emps = _parse_int_list(",".join([str(x) for x in _safe_json(getattr(c, "emps_json", None))]) ) if False else []
        # melhor: ler emps_json diretamente
        try:
            emps_list = json.loads(c.emps_json or "[]")
            if not isinstance(emps_list, list):
                emps_list = []
            emps = [int(x) for x in emps_list if str(x).isdigit()]
        except Exception:
            emps = []

        novo = upsert_campanha_v2(
            db,
            campanha_id=None,
            titulo=f"{c.titulo} (cópia)",
            tipo=(c.tipo or "RANKING_VALOR"),
            escopo=(c.escopo or "EMP"),
            emps=emps,
            vigencia_ini=c.vigencia_ini,
            vigencia_fim=c.vigencia_fim,
            ativo=False,
            regras=regras,
        )
        db.commit()
        flash("Cópia criada (inativa).", "success")
        return redirect(url_for("admin_campanhas_v2", edit=novo.id))
    except Exception as e:
        db.rollback()
        flash(f"Erro ao duplicar: {e}", "danger")
    finally:
        db.close()
    return redirect(url_for("admin_campanhas_v2"))


@bp.route("/admin/campanhas_v2/<int:cid>/delete", methods=["POST"], endpoint="admin_campanhas_v2_delete")
@admin_required
def admin_campanhas_v2_delete(cid: int):
    db = SessionLocal()
    try:
        delete_campanha_v2(db, campanha_id=int(cid))
        db.commit()
        flash("Campanha removida.", "success")
    except Exception as e:
        db.rollback()
        flash(f"Erro ao remover: {e}", "danger")
    finally:
        db.close()
    return redirect(url_for("admin_campanhas_v2"))
