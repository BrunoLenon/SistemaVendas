# -*- coding: utf-8 -*-
"""Rotas de Metas (Crescimento / MIX / Share de Marcas)."""

from __future__ import annotations

import re
from datetime import date

from flask import flash, redirect, render_template, request, session, url_for

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

from metas_helpers import (
    META_GERENTE_ALIAS,
    META_GERENTE_LABEL,
    _calc_and_upsert_meta_result,
    _get_emps_no_periodo,
    _get_vendedores_no_periodo,
    _query_valor_emp_mes,
    _query_valor_mes,
)


def register_metas_routes(app) -> None:
    app.add_url_rule("/metas", endpoint="metas", view_func=metas, methods=["GET"])
    app.add_url_rule("/admin/metas", endpoint="admin_metas", view_func=admin_metas, methods=["GET"])
    app.add_url_rule("/admin/metas/criar", endpoint="admin_metas_criar", view_func=admin_metas_criar, methods=["POST"])
    app.add_url_rule("/admin/metas/toggle/<int:meta_id>", endpoint="admin_metas_toggle", view_func=admin_metas_toggle, methods=["POST"])
    app.add_url_rule("/admin/metas/bases/<int:meta_id>", endpoint="admin_meta_bases", view_func=admin_meta_bases, methods=["GET"])
    app.add_url_rule("/admin/metas/bases/<int:meta_id>/salvar", endpoint="admin_meta_bases_salvar", view_func=admin_meta_bases_salvar, methods=["POST"])


def _safe_int(v, default):
    try:
        return int(v)
    except Exception:
        return default


def _safe_float(v, default=0.0):
    if v in (None, ""):
        return default
    try:
        return float(str(v).strip().replace(".", "").replace(",", "."))
    except Exception:
        return default


def _meta_tipo_label(tipo: str) -> str:
    if tipo == "CRESCIMENTO":
        return "📈 Crescimento"
    if tipo == "MIX":
        return "🧩 MIX"
    if tipo == "SHARE_MARCA":
        return "🏷️ Share"
    return tipo or "-"


def metas():
    ensure_metas_lojas_schema()
    red = _login_required()
    if red:
        return red

    role = (_role() or "").lower()
    hoje = date.today()
    ano = _safe_int(request.args.get("ano"), hoje.year)
    mes = _safe_int(request.args.get("mes"), hoje.month)
    emp_filtro = (request.args.get("emp") or "").strip()
    vendedor_filtro = (request.args.get("vendedor") or "").strip().upper()

    with SessionLocal() as db:
        emps_allowed = _allowed_emps()
        emps_no_periodo = _get_emps_no_periodo(db, ano, mes, emps_allowed)
        if emp_filtro:
            if emps_allowed and emp_filtro not in emps_allowed:
                flash("EMP não permitida para seu usuário.", "danger")
                emp_filtro = ""
        emps_scope = [emp_filtro] if emp_filtro else emps_no_periodo

        metas_list = (
            db.query(MetaPrograma)
            .filter(MetaPrograma.ano == ano, MetaPrograma.mes == mes, MetaPrograma.ativo.is_(True))
            .order_by(MetaPrograma.escopo.asc(), MetaPrograma.tipo.asc(), MetaPrograma.nome.asc())
            .all()
        )

        meta_emps_map = {}
        for m in metas_list:
            rows = db.query(MetaProgramaEmp.emp).filter(MetaProgramaEmp.meta_id == m.id).all()
            meta_emps_map[m.id] = sorted({str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip()})

        if role == "vendedor":
            vendedores_choices = [str(session.get("usuario") or "").strip().upper()]
        else:
            vendedores_choices = _get_vendedores_no_periodo(db, ano, mes, emps_scope)

        resultados = []
        has_manager_meta = any((getattr(m, "escopo", "VENDEDOR") or "VENDEDOR").upper() == "GERENTE" for m in metas_list)

        for emp in emps_scope:
            vendedores_linha = []
            if role == "vendedor":
                vendedor_logado = str(session.get("usuario") or "").strip().upper()
                vendedores_linha = [vendedor_logado] if vendedor_logado else []
            else:
                vendedores_linha = _get_vendedores_no_periodo(db, ano, mes, [emp])
                if vendedor_filtro:
                    vendedores_linha = [v for v in vendedores_linha if v == vendedor_filtro]

            # Linhas por vendedor
            for vend in vendedores_linha:
                valor_mes = float(_query_valor_mes(db, ano, mes, emp, vend) or 0.0)
                if not valor_mes:
                    continue
                row = {"emp": emp, "vendedor": vend, "valor_mes": valor_mes, "metas": {}, "detalhes": {}}
                for meta in metas_list:
                    emps_meta = meta_emps_map.get(meta.id) or []
                    if emps_meta and emp not in emps_meta:
                        continue
                    if (getattr(meta, "escopo", "VENDEDOR") or "VENDEDOR").upper() == "GERENTE":
                        row["metas"][meta.id] = None
                        continue
                    res = _calc_and_upsert_meta_result(db, meta, emp, vend)
                    row["metas"][meta.id] = float(res.premio or 0.0)
                    row["detalhes"][meta.id] = {
                        "bonus_percentual": float(res.bonus_percentual or 0.0),
                        "crescimento_pct": float(res.crescimento_pct) if res.crescimento_pct is not None else None,
                        "share_pct": float(res.share_pct) if res.share_pct is not None else None,
                        "valor_marcas": float(res.valor_marcas) if res.valor_marcas is not None else None,
                        "base_valor": float(res.base_valor) if res.base_valor is not None else None,
                    }
                row["total_premios"] = round(sum(float(v or 0.0) for v in row["metas"].values()), 2)
                resultados.append(row)

            # Linha gerente/loja
            if has_manager_meta and role in {"admin", "supervisor"} and not vendedor_filtro:
                valor_loja = float(_query_valor_emp_mes(db, ano, mes, emp) or 0.0)
                if valor_loja:
                    row = {"emp": emp, "vendedor": META_GERENTE_LABEL, "valor_mes": valor_loja, "metas": {}, "detalhes": {}}
                    for meta in metas_list:
                        emps_meta = meta_emps_map.get(meta.id) or []
                        if emps_meta and emp not in emps_meta:
                            continue
                        if (getattr(meta, "escopo", "VENDEDOR") or "VENDEDOR").upper() != "GERENTE":
                            row["metas"][meta.id] = None
                            continue
                        res = _calc_and_upsert_meta_result(db, meta, emp, META_GERENTE_ALIAS)
                        row["metas"][meta.id] = float(res.premio or 0.0)
                        row["detalhes"][meta.id] = {
                            "bonus_percentual": float(res.bonus_percentual or 0.0),
                            "crescimento_pct": float(res.crescimento_pct) if res.crescimento_pct is not None else None,
                            "share_pct": float(res.share_pct) if res.share_pct is not None else None,
                            "valor_marcas": float(res.valor_marcas) if res.valor_marcas is not None else None,
                            "base_valor": float(res.base_valor) if res.base_valor is not None else None,
                        }
                    row["total_premios"] = round(sum(float(v or 0.0) for v in row["metas"].values()), 2)
                    resultados.append(row)

        resultados.sort(key=lambda r: (r["emp"], 1 if r["vendedor"] == META_GERENTE_LABEL else 0, r["vendedor"]))

        return render_template(
            "metas.html",
            role=role,
            emp=_emp(),
            ano=ano,
            mes=mes,
            emp_filtro=emp_filtro,
            vendedor_filtro=vendedor_filtro,
            metas_list=metas_list,
            resultados=resultados,
            emps_choices=emps_no_periodo,
            vendedores_choices=vendedores_choices,
            tipo_label={
                "CRESCIMENTO": "Crescimento",
                "MIX": "MIX",
                "SHARE_MARCA": "Share de Marcas",
            },
        )


def admin_metas():
    ensure_metas_lojas_schema()
    red = _login_required()
    if red:
        return red

    role = (_role() or "").lower()
    if role not in ("admin", "supervisor"):
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    hoje = date.today()
    ano = _safe_int(request.args.get("ano"), hoje.year)
    mes = _safe_int(request.args.get("mes"), hoje.month)

    with SessionLocal() as db:
        q_emps = db.query(Emp).filter(Emp.ativo.is_(True))
        emps_allowed = _allowed_emps()
        if role == "supervisor" and emps_allowed:
            q_emps = q_emps.filter(Emp.codigo.in_(emps_allowed))
        emps_rows = q_emps.order_by(Emp.codigo.asc()).all()

        metas_list = (
            db.query(MetaPrograma)
            .filter(MetaPrograma.ano == ano, MetaPrograma.mes == mes)
            .order_by(MetaPrograma.escopo.asc(), MetaPrograma.tipo.asc(), MetaPrograma.nome.asc())
            .all()
        )
        meta_emps = {}
        meta_escalas = {}
        meta_marcas = {}
        for m in metas_list:
            meta_emps[m.id] = [r[0] for r in db.query(MetaProgramaEmp.emp).filter(MetaProgramaEmp.meta_id == m.id).all()]
            meta_escalas[m.id] = db.query(MetaEscala).filter(MetaEscala.meta_id == m.id).order_by(MetaEscala.ordem.asc()).all()
            meta_marcas[m.id] = [r[0] for r in db.query(MetaMarca.marca).filter(MetaMarca.meta_id == m.id).all()]

        return render_template(
            "admin_metas.html",
            role=role,
            emp=_emp(),
            ano=ano,
            mes=mes,
            emps_rows=emps_rows,
            metas_list=metas_list,
            meta_emps=meta_emps,
            meta_escalas=meta_escalas,
            meta_marcas=meta_marcas,
            tipo_label=_meta_tipo_label,
        )


def admin_metas_criar():
    ensure_metas_lojas_schema()
    red = _login_required()
    if red:
        return red

    role = (_role() or "").lower()
    if role not in ("admin", "supervisor"):
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    nome = (request.form.get("nome") or "").strip()
    tipo = (request.form.get("tipo") or "").strip().upper()
    escopo = (request.form.get("escopo") or "VENDEDOR").strip().upper()
    ano = _safe_int(request.form.get("ano"), date.today().year)
    mes = _safe_int(request.form.get("mes"), date.today().month)
    emps = request.form.getlist("emps") or []
    escalas_raw = (request.form.get("escalas") or "").strip()
    marcas_raw = (request.form.get("marcas") or "").strip()
    faturamento_minimo = _safe_float(request.form.get("faturamento_minimo"), 0.0)
    margem_minima = _safe_float(request.form.get("margem_minima"), 0.0)
    teto_faturamento = _safe_float(request.form.get("teto_faturamento"), 0.0)
    teto_bonus_percentual = _safe_float(request.form.get("teto_bonus_percentual"), 0.0)

    if not nome or tipo not in ("CRESCIMENTO", "MIX", "SHARE_MARCA"):
        flash("Preencha Nome e Tipo da meta.", "danger")
        return redirect(url_for("admin_metas", ano=ano, mes=mes))

    if escopo not in ("VENDEDOR", "GERENTE"):
        flash("Escopo inválido.", "danger")
        return redirect(url_for("admin_metas", ano=ano, mes=mes))

    if not emps:
        flash("Selecione ao menos 1 Empresa.", "danger")
        return redirect(url_for("admin_metas", ano=ano, mes=mes))

    escalas = []
    for ln in escalas_raw.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        ln = ln.replace(",", ".")
        if ":" in ln:
            a, b = ln.split(":", 1)
        elif "=" in ln:
            a, b = ln.split("=", 1)
        else:
            continue
        try:
            lim = float(a.strip())
            bon = float(b.strip())
            escalas.append((lim, bon))
        except Exception:
            continue

    if not escalas:
        flash("Informe as faixas no formato 'limite:bonus'.", "danger")
        return redirect(url_for("admin_metas", ano=ano, mes=mes))

    marcas = []
    if tipo == "SHARE_MARCA":
        parts = re.split(r"[,\n;]+", marcas_raw)
        marcas = [p.strip().upper() for p in parts if p.strip()]
        if not marcas:
            flash("Informe pelo menos 1 marca para Share de Marcas.", "danger")
            return redirect(url_for("admin_metas", ano=ano, mes=mes))

    with SessionLocal() as db:
        if role == "supervisor":
            allowed = set(_allowed_emps())
            emps = [e for e in emps if e in allowed]
            if not emps:
                flash("Você não tem permissão para as Empresas selecionadas.", "danger")
                return redirect(url_for("admin_metas", ano=ano, mes=mes))

        meta = MetaPrograma(
            nome=nome,
            tipo=tipo,
            escopo=escopo,
            ano=ano,
            mes=mes,
            ativo=True,
            faturamento_minimo=faturamento_minimo or 0.0,
            margem_minima=margem_minima or 0.0,
            teto_faturamento=teto_faturamento or None,
            teto_bonus_percentual=teto_bonus_percentual or None,
            created_by_user_id=session.get("user_id"),
        )
        db.add(meta)
        db.commit()

        for e in emps:
            db.add(MetaProgramaEmp(meta_id=meta.id, emp=str(e).strip()))
        for idx, (lim, bon) in enumerate(sorted(escalas, key=lambda x: x[0])):
            db.add(MetaEscala(meta_id=meta.id, ordem=idx + 1, limite_min=lim, bonus_percentual=bon))
        for m in marcas:
            db.add(MetaMarca(meta_id=meta.id, marca=m))
        db.commit()

    flash("Meta criada com sucesso.", "success")
    return redirect(url_for("admin_metas", ano=ano, mes=mes))


def admin_metas_toggle(meta_id: int):
    ensure_metas_lojas_schema()
    red = _login_required()
    if red:
        return red

    role = (_role() or "").lower()
    if role not in ("admin", "supervisor"):
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    ano = _safe_int(request.form.get("ano"), date.today().year)
    mes = _safe_int(request.form.get("mes"), date.today().month)

    with SessionLocal() as db:
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == meta_id).first()
        if not meta:
            flash("Meta não encontrada.", "danger")
            return redirect(url_for("admin_metas", ano=ano, mes=mes))

        if role == "supervisor":
            allowed = set(_allowed_emps())
            meta_emps = [r[0] for r in db.query(MetaProgramaEmp.emp).filter(MetaProgramaEmp.meta_id == meta.id).all()]
            if not any(e in allowed for e in meta_emps):
                flash("Você não tem permissão para esta meta.", "danger")
                return redirect(url_for("admin_metas", ano=ano, mes=mes))

        meta.ativo = not bool(meta.ativo)
        db.commit()

    flash("Status atualizado.", "success")
    return redirect(url_for("admin_metas", ano=ano, mes=mes))


def admin_meta_bases(meta_id: int):
    ensure_metas_lojas_schema()
    red = _login_required()
    if red:
        return red

    role = (_role() or "").lower()
    if role not in ("admin", "supervisor"):
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    with SessionLocal() as db:
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == meta_id).first()
        if not meta:
            flash("Meta não encontrada.", "danger")
            return redirect(url_for("admin_metas"))

        emps_meta = [r[0] for r in db.query(MetaProgramaEmp.emp).filter(MetaProgramaEmp.meta_id == meta.id).all()]
        if role == "supervisor":
            allowed = set(_allowed_emps())
            emps_meta = [e for e in emps_meta if e in allowed]

        bases = db.query(MetaBaseManual).filter(MetaBaseManual.meta_id == meta.id).all()
        bases_map = {(b.emp, b.vendedor): b for b in bases}
        scope = (meta.escopo or "VENDEDOR").upper()
        linhas = []

        if scope == "GERENTE":
            for emp in emps_meta:
                total_atual = _query_valor_emp_mes(db, meta.ano, meta.mes, emp)
                base_auto = _query_valor_emp_mes(db, meta.ano - 1, meta.mes, emp)
                b = bases_map.get((emp, META_GERENTE_ALIAS))
                linhas.append(
                    {
                        "emp": emp,
                        "vendedor": META_GERENTE_LABEL,
                        "vendedor_key": META_GERENTE_ALIAS,
                        "total_atual": float(total_atual or 0.0),
                        "base_auto": float(base_auto or 0.0),
                        "base_manual": float(b.base_valor) if b and b.base_valor is not None else None,
                        "margem_percentual": float(b.margem_percentual) if b and b.margem_percentual is not None else None,
                        "bonus_extra_percentual": float(b.bonus_extra_percentual) if b and b.bonus_extra_percentual is not None else None,
                        "observacao": (b.observacao if b else ""),
                    }
                )
        else:
            vendedores = _get_vendedores_no_periodo(db, meta.ano, meta.mes, emps_meta)
            for emp in emps_meta:
                for vend in vendedores:
                    total_atual = _query_valor_mes(db, meta.ano, meta.mes, emp, vend)
                    if float(total_atual or 0.0) == 0.0:
                        continue
                    base_auto = _query_valor_mes(db, meta.ano - 1, meta.mes, emp, vend)
                    b = bases_map.get((emp, vend))
                    linhas.append(
                        {
                            "emp": emp,
                            "vendedor": vend,
                            "vendedor_key": vend,
                            "total_atual": float(total_atual or 0.0),
                            "base_auto": float(base_auto or 0.0),
                            "base_manual": float(b.base_valor) if b and b.base_valor is not None else None,
                            "margem_percentual": float(b.margem_percentual) if b and b.margem_percentual is not None else None,
                            "bonus_extra_percentual": float(b.bonus_extra_percentual) if b and b.bonus_extra_percentual is not None else None,
                            "observacao": (b.observacao if b else ""),
                        }
                    )

        return render_template(
            "admin_meta_bases.html",
            role=role,
            emp=_emp(),
            meta=meta,
            linhas=linhas,
            show_base=(meta.tipo == "CRESCIMENTO"),
        )


def admin_meta_bases_salvar(meta_id: int):
    ensure_metas_lojas_schema()
    red = _login_required()
    if red:
        return red

    role = (_role() or "").lower()
    if role not in ("admin", "supervisor"):
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    with SessionLocal() as db:
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == meta_id).first()
        if not meta:
            flash("Meta inválida.", "danger")
            return redirect(url_for("admin_metas"))

        emps_meta = [r[0] for r in db.query(MetaProgramaEmp.emp).filter(MetaProgramaEmp.meta_id == meta.id).all()]
        if role == "supervisor":
            allowed = set(_allowed_emps())
            emps_meta = [e for e in emps_meta if e in allowed]

        updated = 0
        for key, val in request.form.items():
            if not key.startswith("base__"):
                continue
            parts = key.split("__", 2)
            if len(parts) != 3:
                continue
            emp, vend = parts[1], parts[2]
            if emp not in emps_meta:
                continue

            vend = (vend or "").strip().upper()
            base_raw = (val or "").strip()
            margem_raw = (request.form.get(f"margem__{emp}__{vend}") or "").strip()
            bonus_raw = (request.form.get(f"extra__{emp}__{vend}") or "").strip()
            obs = (request.form.get(f"obs__{emp}__{vend}") or "").strip()

            base_val = _safe_float(base_raw, None)
            margem_val = _safe_float(margem_raw, None)
            bonus_val = _safe_float(bonus_raw, None)

            item = (
                db.query(MetaBaseManual)
                .filter(MetaBaseManual.meta_id == meta.id, MetaBaseManual.emp == emp, MetaBaseManual.vendedor == vend)
                .first()
            )

            should_delete = (
                (meta.tipo != "CRESCIMENTO" or base_raw == "") and margem_raw == "" and bonus_raw == "" and not obs
            )
            if should_delete:
                if item:
                    db.delete(item)
                    updated += 1
                continue

            if not item:
                item = MetaBaseManual(meta_id=meta.id, emp=emp, vendedor=vend, base_valor=0.0)

            if meta.tipo == "CRESCIMENTO":
                item.base_valor = float(base_val or 0.0)
            else:
                item.base_valor = float(item.base_valor or 0.0)
            item.margem_percentual = margem_val
            item.bonus_extra_percentual = bonus_val
            item.observacao = obs
            db.add(item)
            updated += 1

        db.commit()

    flash(f"Insumos salvos ({updated} alterações).", "success")
    return redirect(url_for("admin_meta_bases", meta_id=meta_id))
