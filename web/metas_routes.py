# -*- coding: utf-8 -*-
"""Rotas oficiais do novo modulo de Metas.

Substitui a estrutura antiga mantendo os endpoints publicos:
- /admin/metas
- /metas
"""

from __future__ import annotations

import re
from datetime import date, datetime

from flask import flash, redirect, render_template, request, session, url_for
from sqlalchemy import func, text

from auth_helpers import _allowed_emps, _emp, _login_required, _role
from db import (
    Emp,
    MetaBaseManual,
    MetaEscala,
    MetaMarca,
    MetaPrograma,
    MetaProgramaEmp,
    SessionLocal,
    ensure_metas_lojas_schema,
)
from services.visao_operacional import (
    filter_emps_by_status,
    get_fechamento_status_map,
    is_emp_period_open,
    normalize_status_filter,
    status_filter_label,
)
from metas_helpers import (
    calcular_meta,
    get_active_emps,
    get_meta_emps,
    get_meta_escalas,
    get_meta_marcas,
    get_vendedores_para_metas,
    metas_ativas_periodo,
    montar_resultados_periodo,
    normalize_emp,
    normalize_text,
    query_valor_mes,
    upsert_base_manual,
)

TIPOS_META = ("CRESCIMENTO", "MIX", "SHARE_MARCA")


def register_metas_routes(app) -> None:
    app.add_url_rule("/metas", endpoint="metas", view_func=metas, methods=["GET"])
    app.add_url_rule("/admin/metas", endpoint="admin_metas", view_func=admin_metas, methods=["GET"])
    app.add_url_rule("/admin/metas/criar", endpoint="admin_metas_criar", view_func=admin_metas_criar, methods=["POST"])
    app.add_url_rule("/admin/metas/toggle/<int:meta_id>", endpoint="admin_metas_toggle", view_func=admin_metas_toggle, methods=["POST"])
    app.add_url_rule("/admin/metas/excluir/<int:meta_id>", endpoint="admin_metas_excluir", view_func=admin_metas_excluir, methods=["POST"])
    app.add_url_rule("/admin/metas/emps/<int:meta_id>", endpoint="admin_metas_emps_salvar", view_func=admin_metas_emps_salvar, methods=["POST"])
    app.add_url_rule("/admin/metas/regra/<int:meta_id>", endpoint="admin_metas_regra_salvar", view_func=admin_metas_regra_salvar, methods=["POST"])
    app.add_url_rule("/admin/metas/recalcular", endpoint="admin_metas_recalcular", view_func=admin_metas_recalcular, methods=["POST"])
    app.add_url_rule("/admin/metas/bases/<int:meta_id>", endpoint="admin_meta_bases", view_func=admin_meta_bases, methods=["GET"])
    app.add_url_rule("/admin/metas/bases/<int:meta_id>/salvar", endpoint="admin_meta_bases_salvar", view_func=admin_meta_bases_salvar, methods=["POST"])


def _safe_int(v, default):
    try:
        return int(v)
    except Exception:
        return default


def _safe_float(v, default=0.0):
    if v is None:
        return default
    raw = str(v).strip()
    if not raw:
        return default
    try:
        s = raw.replace("R$", "").replace("%", "").replace(" ", "").strip()
        # pt-BR: 100.000,00 -> 100000.00 / 0,10 -> 0.10
        if "," in s:
            s = s.replace(".", "").replace(",", ".")
        # US decimal simples: 0.10 -> 0.10; milhar puro: 100.000 -> 100000
        elif s.count(".") == 1:
            left, right = s.split(".", 1)
            if len(right) == 3 and len(left) >= 2:
                s = left + right
        elif s.count(".") > 1:
            s = s.replace(".", "")
        return float(s)
    except Exception:
        return default


def _tipo_label(tipo: str) -> str:
    tipo = normalize_text(tipo)
    if tipo == "CRESCIMENTO":
        return "Crescimento"
    if tipo == "MIX":
        return "Mix de Itens Únicos"
    if tipo == "SHARE_MARCA":
        return "Meta Marcas"
    return tipo or "-"


def _tipo_badge(tipo: str) -> str:
    tipo = normalize_text(tipo)
    if tipo == "CRESCIMENTO":
        return "📈 Crescimento"
    if tipo == "MIX":
        return "🧩 Mix"
    if tipo == "SHARE_MARCA":
        return "🏷️ Marcas"
    return tipo or "-"


def _parse_escalas(raw: str, tipo: str) -> list[tuple[float, float]]:
    """Aceita linhas como 5=0,10 ou 750=100."""
    out: list[tuple[float, float]] = []
    for line in str(raw or "").splitlines():
        ln = line.strip()
        if not ln:
            continue
        # remove textos comuns que o usuario possa colar da planilha
        ln = ln.replace("%", "").replace("R$", "")
        if "=" in ln:
            left, right = ln.split("=", 1)
        elif ":" in ln:
            left, right = ln.split(":", 1)
        elif ";" in ln:
            left, right = ln.split(";", 1)
        else:
            parts = re.split(r"\s+", ln)
            if len(parts) < 2:
                continue
            left, right = parts[0], parts[1]
        lim = _safe_float(left, None)
        val = _safe_float(right, None)
        if lim is None or val is None:
            continue
        out.append((float(lim), float(val)))
    # remove duplicadas por limite, preservando maior valor informado por ultimo
    merged: dict[float, float] = {}
    for lim, val in out:
        merged[lim] = val
    return sorted(merged.items(), key=lambda x: x[0])


def _parse_marcas(raw: str) -> list[str]:
    parts = re.split(r"[,;\n/]+", str(raw or ""))
    marcas = []
    seen = set()
    for p in parts:
        marca = normalize_text(p)
        if marca and marca not in seen:
            seen.add(marca)
            marcas.append(marca)
    return marcas


def _period_from_request():
    hoje = date.today()
    ano = _safe_int(request.values.get("ano"), hoje.year)
    mes = _safe_int(request.values.get("mes"), hoje.month)
    if mes < 1 or mes > 12:
        mes = hoje.month
    return ano, mes


def _allowed_admin_emps(db) -> list[str]:
    role = (_role() or "").lower()
    allowed = _allowed_emps()
    if role == "admin":
        return get_active_emps(db, [])
    return get_active_emps(db, allowed)


def _meta_payload(db, meta: MetaPrograma) -> dict:
    emps = get_meta_emps(db, int(meta.id))
    escalas = get_meta_escalas(db, int(meta.id))
    marcas = get_meta_marcas(db, int(meta.id))
    bases_count = db.query(func.count(MetaBaseManual.id)).filter(MetaBaseManual.meta_id == meta.id).scalar() or 0
    return {
        "meta": meta,
        "emps": emps,
        "escalas": escalas,
        "marcas": marcas,
        "bases_count": int(bases_count or 0),
    }


def _admin_guard():
    red = _login_required()
    if red:
        return red
    if (_role() or "").lower() != "admin":
        flash("Acesso restrito ao administrador.", "warning")
        return redirect(url_for("dashboard"))
    return None


def metas():
    ensure_metas_lojas_schema()
    red = _login_required()
    if red:
        return red

    ano, mes = _period_from_request()
    status_visao = normalize_status_filter(request.args.get("status"), default="abertas")
    role = (_role() or "").lower()
    usuario = normalize_text(session.get("usuario"))

    emp_filtro = normalize_emp(request.args.get("emp"))
    vendedor_filtro = normalize_text(request.args.get("vendedor"))

    with SessionLocal() as db:
        allowed_emps = _allowed_emps()
        emps_choices = _allowed_admin_emps(db)

        if role == "vendedor":
            vendedor_filtro = usuario
            # Se o vendedor tem EMPs vinculadas, usa elas; senao usa EMP da sessao.
            emps_user = [normalize_emp(e) for e in (allowed_emps or []) if normalize_emp(e)]
            if not emps_user and _emp():
                emps_user = [normalize_emp(_emp())]
            if emp_filtro and emp_filtro in set(emps_user):
                emps_calc = [emp_filtro]
            else:
                emps_calc = emps_user
        elif role == "supervisor":
            allowed = set([normalize_emp(e) for e in (allowed_emps or []) if normalize_emp(e)])
            emps_calc = [emp_filtro] if emp_filtro and emp_filtro in allowed else list(allowed)
        else:
            emps_calc = [emp_filtro] if emp_filtro else []

        vendedores_choices = []
        if role != "vendedor":
            vendedores_choices = get_vendedores_para_metas(db, ano, mes, emps_calc or emps_choices)
            if vendedor_filtro and vendedor_filtro not in vendedores_choices:
                vendedor_filtro = ""

        status_map = get_fechamento_status_map(db, ano, mes)
        if status_visao != "todas":
            base_status_emps = emps_calc or emps_choices
            emps_calc = filter_emps_by_status(base_status_emps, status_visao, status_map)

        metas_list, resultados = montar_resultados_periodo(
            db,
            ano,
            mes,
            emps=emps_calc,
            vendedor=vendedor_filtro,
            persist=True,
        )
        db.commit()

        totais = {
            "venda": round(sum(float(r.get("valor_mes") or 0.0) for r in resultados), 2),
            "premio": round(sum(float(r.get("total_premios") or 0.0) for r in resultados), 2),
            "vendedores": len(resultados),
            "metas": len(metas_list),
        }

        return render_template(
            "metas.html",
            role=role,
            emp=_emp(),
            ano=ano,
            mes=mes,
            status_visao=status_visao,
            status_label=status_filter_label(status_visao),
            emp_filtro=emp_filtro,
            vendedor_filtro=vendedor_filtro,
            emps_choices=emps_choices,
            vendedores_choices=vendedores_choices,
            metas_list=metas_list,
            resultados=resultados,
            totais=totais,
            tipo_label={"CRESCIMENTO": "Crescimento", "MIX": "Mix", "SHARE_MARCA": "Marcas"},
            tipo_label_fn=_tipo_label,
        )


def admin_metas():
    ensure_metas_lojas_schema()
    red = _admin_guard()
    if red:
        return red

    ano, mes = _period_from_request()
    status_visao = normalize_status_filter(request.args.get("status"), default="abertas")
    emp_selected = normalize_emp(request.args.get("emp_sel"))
    vendedor_selected = normalize_text(request.args.get("vendedor"))

    with SessionLocal() as db:
        emps_rows = db.query(Emp).filter(Emp.ativo.is_(True)).order_by(Emp.codigo.asc()).all()
        emps_codes = [normalize_emp(e.codigo) for e in emps_rows]
        if emp_selected and emp_selected not in set(emps_codes):
            emp_selected = ""

        status_map = get_fechamento_status_map(db, ano, mes)
        metas_db_all = (
            db.query(MetaPrograma)
            .filter(MetaPrograma.ano == ano, MetaPrograma.mes == mes)
            .order_by(MetaPrograma.tipo.asc(), MetaPrograma.nome.asc(), MetaPrograma.id.asc())
            .all()
        )
        metas_payload_all = [_meta_payload(db, m) for m in metas_db_all]

        def _payload_operacional_aberto(payload):
            meta_obj = payload.get("meta")
            if not bool(getattr(meta_obj, "ativo", False)):
                return False
            return any(is_emp_period_open(status_map, e) for e in (payload.get("emps") or []))

        if status_visao == "abertas":
            metas_payload = [p for p in metas_payload_all if _payload_operacional_aberto(p)]
        elif status_visao == "encerradas":
            metas_payload = [p for p in metas_payload_all if not _payload_operacional_aberto(p)]
        else:
            metas_payload = metas_payload_all
        metas_db = [p["meta"] for p in metas_payload]

        crescimento_meta = next((p["meta"] for p in metas_payload if normalize_text(p["meta"].tipo) == "CRESCIMENTO" and p["meta"].ativo), None)
        base_rows = []
        vendedores_base = []
        if crescimento_meta and emp_selected:
            vendedores_base = get_vendedores_para_metas(db, ano, mes, [emp_selected])
            if vendedor_selected:
                vendedores_base = [v for v in vendedores_base if v == vendedor_selected]
            for vend in vendedores_base:
                base = (
                    db.query(MetaBaseManual)
                    .filter(MetaBaseManual.meta_id == crescimento_meta.id, MetaBaseManual.emp == emp_selected, MetaBaseManual.vendedor == vend)
                    .first()
                )
                venda_mes = query_valor_mes(db, ano, mes, emp_selected, vend)
                base_valor = float(getattr(base, "base_valor", 0.0) or 0.0) if base else 0.0
                crescimento_pct = ((venda_mes - base_valor) / base_valor * 100.0) if base_valor > 0 else 0.0
                base_rows.append({
                    "emp": emp_selected,
                    "vendedor": vend,
                    "venda_mes": venda_mes,
                    "base_valor": base_valor,
                    "crescimento_pct": crescimento_pct,
                    "observacao": getattr(base, "observacao", "") if base else "",
                })

        sim_emps = [emp_selected] if emp_selected else []
        if status_visao != "todas":
            sim_base_emps = sim_emps or emps_codes
            sim_emps = filter_emps_by_status(sim_base_emps, status_visao, status_map)
        sim_vendedor = vendedor_selected if vendedor_selected else None
        metas_sim, resultados_sim = montar_resultados_periodo(db, ano, mes, emps=sim_emps, vendedor=sim_vendedor, persist=False)

        totais = {
            "metas": len(metas_db),
            "ativas": sum(1 for m in metas_db if m.ativo),
            "bases": sum(int(p["bases_count"] or 0) for p in metas_payload),
            "premio_simulado": round(sum(float(r.get("total_premios") or 0.0) for r in resultados_sim), 2),
            "vendedores_simulados": len(resultados_sim),
        }

        return render_template(
            "admin_metas.html",
            role=_role(),
            emp=_emp(),
            ano=ano,
            mes=mes,
            status_visao=status_visao,
            status_label=status_filter_label(status_visao),
            emp_selected=emp_selected,
            vendedor_selected=vendedor_selected,
            emps_rows=emps_rows,
            metas_payload=metas_payload,
            crescimento_meta=crescimento_meta,
            base_rows=base_rows,
            vendedores_choices=get_vendedores_para_metas(db, ano, mes, [emp_selected] if emp_selected else emps_codes),
            metas_sim=metas_sim,
            resultados_sim=resultados_sim,
            totais=totais,
            tipo_label=_tipo_label,
            tipo_badge=_tipo_badge,
        )


def admin_metas_criar():
    ensure_metas_lojas_schema()
    red = _admin_guard()
    if red:
        return red

    ano, mes = _period_from_request()
    tipo = normalize_text(request.form.get("tipo"))
    nome = (request.form.get("nome") or _tipo_label(tipo)).strip()
    emps = [normalize_emp(e) for e in request.form.getlist("emps") if normalize_emp(e)]
    escalas = _parse_escalas(request.form.get("escalas"), tipo)
    marcas = _parse_marcas(request.form.get("marcas"))
    teto_faturamento = _safe_float(request.form.get("teto_faturamento"), 0.0)
    faturamento_minimo = _safe_float(request.form.get("faturamento_minimo"), 70000.0)

    if tipo not in TIPOS_META:
        flash("Tipo de meta inválido.", "danger")
        return redirect(url_for("admin_metas", ano=ano, mes=mes))
    if not emps:
        flash("Selecione pelo menos uma EMP para a meta.", "warning")
        return redirect(url_for("admin_metas", ano=ano, mes=mes))
    if not escalas:
        flash("Cadastre pelo menos uma faixa válida. Exemplo: 5=0,10 ou 750=100.", "warning")
        return redirect(url_for("admin_metas", ano=ano, mes=mes))
    if tipo == "SHARE_MARCA" and not marcas:
        flash("Informe pelo menos uma marca para a Meta Marcas.", "warning")
        return redirect(url_for("admin_metas", ano=ano, mes=mes))

    with SessionLocal() as db:
        meta = MetaPrograma(
            nome=nome,
            tipo=tipo,
            ano=ano,
            mes=mes,
            ativo=True,
            escopo="VENDEDOR",
            faturamento_minimo=faturamento_minimo if faturamento_minimo > 0 else 0.0,
            # No crescimento, este campo representa a trava: venda >= teto aplica maior faixa.
            teto_faturamento=teto_faturamento if tipo == "CRESCIMENTO" and teto_faturamento > 0 else None,
            teto_bonus_percentual=None,
            created_by_user_id=session.get("user_id"),
        )
        db.add(meta)
        db.flush()

        for emp_codigo in sorted(set(emps)):
            db.add(MetaProgramaEmp(meta_id=meta.id, emp=emp_codigo, ativo=True))
        for idx, (lim, valor) in enumerate(escalas, start=1):
            db.add(MetaEscala(meta_id=meta.id, ordem=idx, limite_min=float(lim), bonus_percentual=float(valor)))
        for marca in marcas:
            db.add(MetaMarca(meta_id=meta.id, marca=marca))
        db.commit()

    flash(f"Meta '{nome}' criada com sucesso.", "success")
    return redirect(url_for("admin_metas", ano=ano, mes=mes, emp_sel=emps[0] if emps else ""))


def admin_metas_emps_salvar(meta_id: int):
    ensure_metas_lojas_schema()
    red = _admin_guard()
    if red:
        return red

    ano, mes = _period_from_request()
    emp_selected = normalize_emp(request.form.get("emp_sel"))
    vendedor_selected = normalize_text(request.form.get("vendedor"))
    novas_emps = sorted(set(normalize_emp(e) for e in request.form.getlist("emps") if normalize_emp(e)))

    if not novas_emps:
        flash("Selecione pelo menos uma EMP para a meta.", "warning")
        return redirect(url_for("admin_metas", ano=ano, mes=mes, emp_sel=emp_selected, vendedor=vendedor_selected))

    with SessionLocal() as db:
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == int(meta_id)).first()
        if not meta:
            flash("Meta não encontrada.", "danger")
            return redirect(url_for("admin_metas", ano=ano, mes=mes, emp_sel=emp_selected, vendedor=vendedor_selected))
        if not bool(meta.ativo):
            flash("Ative a meta antes de alterar as EMPs participantes.", "warning")
            return redirect(url_for("admin_metas", ano=meta.ano, mes=meta.mes, emp_sel=emp_selected, vendedor=vendedor_selected))

        existentes = {normalize_emp(r.emp): r for r in db.query(MetaProgramaEmp).filter(MetaProgramaEmp.meta_id == meta.id).all()}
        agora = datetime.utcnow()
        adicionadas = 0
        removidas = 0

        for emp_codigo in novas_emps:
            vinc = existentes.get(emp_codigo)
            if vinc:
                if not bool(getattr(vinc, "ativo", True)):
                    adicionadas += 1
                vinc.ativo = True
                vinc.removido_em = None
                vinc.atualizado_em = agora
                db.add(vinc)
            else:
                db.add(MetaProgramaEmp(meta_id=meta.id, emp=emp_codigo, ativo=True, criado_em=agora, atualizado_em=agora))
                adicionadas += 1

        novas_set = set(novas_emps)
        for emp_codigo, vinc in existentes.items():
            if emp_codigo and emp_codigo not in novas_set and bool(getattr(vinc, "ativo", True)):
                vinc.ativo = False
                vinc.removido_em = agora
                vinc.atualizado_em = agora
                db.add(vinc)
                removidas += 1

        db.commit()

    flash(f"EMPs da meta atualizadas. Adicionadas: {adicionadas}. Removidas: {removidas}.", "success")
    return redirect(url_for("admin_metas", ano=ano, mes=mes, emp_sel=emp_selected or novas_emps[0], vendedor=vendedor_selected))


def admin_metas_regra_salvar(meta_id: int):
    ensure_metas_lojas_schema()
    red = _admin_guard()
    if red:
        return red

    ano, mes = _period_from_request()
    emp_selected = normalize_emp(request.form.get("emp_sel"))
    vendedor_selected = normalize_text(request.form.get("vendedor"))
    faturamento_minimo = _safe_float(request.form.get("faturamento_minimo"), 0.0)
    teto_faturamento = _safe_float(request.form.get("teto_faturamento"), 0.0)

    with SessionLocal() as db:
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == int(meta_id)).first()
        if not meta:
            flash("Meta não encontrada.", "danger")
            return redirect(url_for("admin_metas", ano=ano, mes=mes, emp_sel=emp_selected, vendedor=vendedor_selected))

        meta.faturamento_minimo = faturamento_minimo if faturamento_minimo > 0 else 0.0
        if normalize_text(meta.tipo) == "CRESCIMENTO":
            meta.teto_faturamento = teto_faturamento if teto_faturamento > 0 else None
        db.add(meta)
        db.commit()

    flash("Regras da meta atualizadas.", "success")
    return redirect(url_for("admin_metas", ano=ano, mes=mes, emp_sel=emp_selected, vendedor=vendedor_selected))


def admin_metas_toggle(meta_id: int):
    ensure_metas_lojas_schema()
    red = _admin_guard()
    if red:
        return red
    ano, mes = _period_from_request()
    with SessionLocal() as db:
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == int(meta_id)).first()
        if not meta:
            flash("Meta não encontrada.", "danger")
            return redirect(url_for("admin_metas", ano=ano, mes=mes))
        meta.ativo = not bool(meta.ativo)
        db.commit()
    flash("Status da meta atualizado.", "success")
    return redirect(url_for("admin_metas", ano=ano, mes=mes))


def admin_metas_excluir(meta_id: int):
    ensure_metas_lojas_schema()
    red = _admin_guard()
    if red:
        return red
    ano, mes = _period_from_request()
    with SessionLocal() as db:
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == int(meta_id)).first()
        if not meta:
            flash("Meta não encontrada.", "danger")
            return redirect(url_for("admin_metas", ano=ano, mes=mes))
        db.query(MetaBaseManual).filter(MetaBaseManual.meta_id == meta.id).delete(synchronize_session=False)
        db.query(MetaEscala).filter(MetaEscala.meta_id == meta.id).delete(synchronize_session=False)
        db.query(MetaMarca).filter(MetaMarca.meta_id == meta.id).delete(synchronize_session=False)
        db.query(MetaProgramaEmp).filter(MetaProgramaEmp.meta_id == meta.id).delete(synchronize_session=False)
        # metas_resultados pode nao estar importada aqui; delete via SQL simples para evitar dependencias.
        db.execute(text("DELETE FROM metas_resultados WHERE meta_id = :mid"), {"mid": meta.id})
        db.delete(meta)
        db.commit()
    flash("Meta excluída com sucesso.", "success")
    return redirect(url_for("admin_metas", ano=ano, mes=mes))


def admin_metas_recalcular():
    ensure_metas_lojas_schema()
    red = _admin_guard()
    if red:
        return red
    ano, mes = _period_from_request()
    emp_selected = normalize_emp(request.form.get("emp_sel"))
    vendedor_selected = normalize_text(request.form.get("vendedor"))

    with SessionLocal() as db:
        emps = [emp_selected] if emp_selected else []
        _, resultados = montar_resultados_periodo(db, ano, mes, emps=emps, vendedor=vendedor_selected or None, persist=True)
        db.commit()

    flash(f"Metas recalculadas: {len(resultados)} vendedor(es)/EMP.", "success")
    return redirect(url_for("admin_metas", ano=ano, mes=mes, emp_sel=emp_selected, vendedor=vendedor_selected))


def admin_meta_bases(meta_id: int):
    ensure_metas_lojas_schema()
    red = _admin_guard()
    if red:
        return red

    with SessionLocal() as db:
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == int(meta_id)).first()
        if not meta:
            flash("Meta não encontrada.", "danger")
            return redirect(url_for("admin_metas"))
        if normalize_text(meta.tipo) != "CRESCIMENTO":
            flash("Bases manuais são utilizadas apenas na Meta de Crescimento.", "warning")
            return redirect(url_for("admin_metas", ano=meta.ano, mes=meta.mes))

        emps = get_meta_emps(db, int(meta.id))
        emp_selected = normalize_emp(request.args.get("emp")) or (emps[0] if emps else "")
        if emp_selected and emp_selected not in set(emps):
            emp_selected = emps[0] if emps else ""

        vendedores = get_vendedores_para_metas(db, meta.ano, meta.mes, [emp_selected] if emp_selected else emps)
        linhas = []
        for vend in vendedores:
            base = (
                db.query(MetaBaseManual)
                .filter(MetaBaseManual.meta_id == meta.id, MetaBaseManual.emp == emp_selected, MetaBaseManual.vendedor == vend)
                .first()
            )
            venda_mes = query_valor_mes(db, meta.ano, meta.mes, emp_selected, vend)
            base_valor = float(getattr(base, "base_valor", 0.0) or 0.0) if base else 0.0
            crescimento_pct = ((venda_mes - base_valor) / base_valor * 100.0) if base_valor > 0 else 0.0
            linhas.append({
                "emp": emp_selected,
                "vendedor": vend,
                "venda_mes": venda_mes,
                "base_valor": base_valor,
                "crescimento_pct": crescimento_pct,
                "observacao": getattr(base, "observacao", "") if base else "",
            })

        return render_template(
            "admin_meta_bases.html",
            role=_role(),
            emp=_emp(),
            meta=meta,
            emps=emps,
            emp_selected=emp_selected,
            linhas=linhas,
            tipo_label=_tipo_badge,
        )


def admin_meta_bases_salvar(meta_id: int):
    ensure_metas_lojas_schema()
    red = _admin_guard()
    if red:
        return red

    with SessionLocal() as db:
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == int(meta_id)).first()
        if not meta:
            flash("Meta não encontrada.", "danger")
            return redirect(url_for("admin_metas"))
        emp_selected = normalize_emp(request.form.get("emp_selected"))
        if not emp_selected:
            flash("EMP não informada.", "warning")
            return redirect(url_for("admin_meta_bases", meta_id=meta.id))

        salvos = 0
        for key, value in request.form.items():
            if not key.startswith("base__"):
                continue
            vendedor = normalize_text(key.replace("base__", "", 1))
            base_valor = _safe_float(value, 0.0)
            obs = request.form.get(f"obs__{vendedor}") or ""
            upsert_base_manual(db, meta.id, emp_selected, vendedor, base_valor, obs)
            salvos += 1
        db.commit()

    flash(f"Bases salvas com sucesso: {salvos} vendedor(es).", "success")
    return redirect(url_for("admin_meta_bases", meta_id=meta_id, emp=emp_selected))
