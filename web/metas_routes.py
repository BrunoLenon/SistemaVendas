# -*- coding: utf-8 -*-
"""Rotas de Metas (Crescimento / MIX / Share de Marcas).

Extraído do app.py como refatoração pura (sem alterar comportamento externo).
- Mantém os mesmos paths e os mesmos nomes de endpoint usados em url_for(...)

Observação:
- Registramos explicitamente o 'endpoint' para garantir backward compatibility.
"""

from __future__ import annotations

import re
from datetime import date
from decimal import Decimal

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
)

from metas_helpers import (
    _as_decimal,
    _calc_and_upsert_meta_result,
    _get_emps_no_periodo,
    _get_vendedores_no_periodo,
    _money2,
    _meta_pick_bonus,
    _query_valor_mes,
)


def register_metas_routes(app) -> None:
    """Registra rotas de Metas no app Flask."""
    app.add_url_rule(
        "/metas",
        endpoint="metas",
        view_func=metas,
        methods=["GET"],
    )
    app.add_url_rule(
        "/admin/metas",
        endpoint="admin_metas",
        view_func=admin_metas,
        methods=["GET"],
    )
    app.add_url_rule(
        "/admin/metas/criar",
        endpoint="admin_metas_criar",
        view_func=admin_metas_criar,
        methods=["POST"],
    )
    app.add_url_rule(
        "/admin/metas/toggle/<int:meta_id>",
        endpoint="admin_metas_toggle",
        view_func=admin_metas_toggle,
        methods=["POST"],
    )
    app.add_url_rule(
        "/admin/metas/bases/<int:meta_id>",
        endpoint="admin_meta_bases",
        view_func=admin_meta_bases,
        methods=["GET"],
    )
    app.add_url_rule(
        "/admin/metas/bases/<int:meta_id>/salvar",
        endpoint="admin_meta_bases_salvar",
        view_func=admin_meta_bases_salvar,
        methods=["POST"],
    )


def metas():
    red = _login_required()
    if red:
        return red

    role = _role() or ""
    hoje = date.today()
    ano = int(request.args.get("ano") or hoje.year)
    mes = int(request.args.get("mes") or hoje.month)

    # filtros
    emp_filtro = (request.args.get("emp") or "").strip()
    vendedor_filtro = (request.args.get("vendedor") or "").strip().upper()

    with SessionLocal() as db:
        emps_allowed = _allowed_emps()
        # Admin pode ver tudo; supervisor/vendedor restringe
        emps_no_periodo = _get_emps_no_periodo(db, ano, mes, emps_allowed)
        if emp_filtro:
            # valida contra allowed
            if emps_allowed and emp_filtro not in emps_allowed:
                flash("EMP não permitida para seu usuário.", "danger")
                emp_filtro = ""
        emps_scope = [emp_filtro] if emp_filtro else emps_no_periodo

        # metas ativas do período
        metas_list = (
            db.query(MetaPrograma)
            .filter(MetaPrograma.ano == ano, MetaPrograma.mes == mes, MetaPrograma.ativo.is_(True))
            .order_by(MetaPrograma.tipo.asc(), MetaPrograma.nome.asc())
            .all()
        )

        # aplica meta -> emps
        meta_emps_map = {}
        for m in metas_list:
            rows = db.query(MetaProgramaEmp.emp).filter(MetaProgramaEmp.meta_id == m.id).all()
            meta_emps_map[m.id] = sorted({str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip()})

        # vendedores
        if role == "vendedor":
            vendedores = [str(session.get("usuario") or "").strip().upper()]
        else:
            vendedores = _get_vendedores_no_periodo(db, ano, mes, emps_scope)
            if vendedor_filtro:
                vendedores = [v for v in vendedores if v == vendedor_filtro]

        # calcula resultados
        resultados = []  # cada item: {vendedor, emp, metas: {meta_id: premio}, detalhes...}
        for emp in emps_scope:
            for vend in vendedores:
                # checa se vend tem vendas no período nessa emp (evita linha vazia)
                valor_mes = _query_valor_mes(db, ano, mes, emp, vend)
                if (not valor_mes) and role != "vendedor":
                    continue

                row = {"emp": emp, "vendedor": vend, "valor_mes": float(valor_mes), "metas": {}, "detalhes": {}}
                total_premios = Decimal("0.00")

                for meta in metas_list:
                    # meta vale para esta emp?
                    emps_meta = meta_emps_map.get(meta.id) or []
                    if emps_meta and emp not in emps_meta:
                        continue

                    res = _calc_and_upsert_meta_result(db, meta, emp, vend)
                    row["metas"][meta.id] = float(res.premio or 0.0)
                    # detalhes principais (pra tooltip/modal futuro)
                    row["detalhes"][meta.id] = {
                        "tipo": meta.tipo,
                        "bonus": float(res.bonus_percentual or 0.0),
                        "crescimento_pct": float(res.crescimento_pct or 0.0) if res.crescimento_pct is not None else None,
                        "base_valor": float(res.base_valor or 0.0) if res.base_valor is not None else None,
                        "mix": float(res.mix_itens_unicos or 0.0) if res.mix_itens_unicos is not None else None,
                        "share_pct": float(res.share_pct or 0.0) if res.share_pct is not None else None,
                        "valor_marcas": float(res.valor_marcas or 0.0) if res.valor_marcas is not None else None,
                    }
                    total_premios += _as_decimal(res.premio or 0.0)

                row["total_premios"] = float(_money2(total_premios))
                resultados.append(row)

        # listas para filtros
        emps_choices = emps_no_periodo
        vendedores_choices = _get_vendedores_no_periodo(db, ano, mes, emps_scope) if role != "vendedor" else vendedores

        # nomes amigáveis dos tipos
        tipo_label = {"CRESCIMENTO": "📈 Crescimento", "MIX": "🧩 MIX", "SHARE_MARCA": "🏷️ Share de Marcas"}

        return render_template(
            "metas.html",
            role=role,
            emp=_emp(),
            ano=ano,
            mes=mes,
            metas_list=metas_list,
            tipo_label=tipo_label,
            resultados=resultados,
            emps_choices=emps_choices,
            vendedores_choices=vendedores_choices,
            emp_filtro=emp_filtro,
            vendedor_filtro=vendedor_filtro,
        )


def admin_metas():
    red = _login_required()
    if red:
        return red

    role = _role() or ""
    if role not in ("admin", "supervisor"):
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    hoje = date.today()
    ano = int(request.args.get("ano") or hoje.year)
    mes = int(request.args.get("mes") or hoje.month)

    with SessionLocal() as db:
        emps_allowed = _allowed_emps()
        # lista de EMPs cadastradas (melhor do que inferir por vendas)
        emps_rows = db.query(Emp).filter(Emp.ativo.is_(True)).order_by(Emp.codigo.asc()).all()
        # supervisor só pode suas emps
        if role == "supervisor" and emps_allowed:
            emps_rows = [e for e in emps_rows if str(e.codigo) in set(emps_allowed)]

        metas_list = (
            db.query(MetaPrograma)
            .filter(MetaPrograma.ano == ano, MetaPrograma.mes == mes)
            .order_by(MetaPrograma.ativo.desc(), MetaPrograma.tipo.asc(), MetaPrograma.nome.asc())
            .all()
        )

        # mapa de emps e escalas/marcas
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
        )


def admin_metas_criar():
    red = _login_required()
    if red:
        return red

    role = _role() or ""
    if role not in ("admin", "supervisor"):
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    nome = (request.form.get("nome") or "").strip()
    tipo = (request.form.get("tipo") or "").strip().upper()
    ano = int(request.form.get("ano") or date.today().year)
    mes = int(request.form.get("mes") or date.today().month)
    bloqueio = request.form.get("ativo")  # checkbox

    emps = request.form.getlist("emps") or []

    escalas_raw = (request.form.get("escalas") or "").strip()
    marcas_raw = (request.form.get("marcas") or "").strip()

    if not nome or tipo not in ("CRESCIMENTO", "MIX", "SHARE_MARCA"):
        flash("Preencha Nome e Tipo da meta.", "danger")
        return redirect(url_for("admin_metas", ano=ano, mes=mes))

    if not emps:
        flash("Selecione ao menos 1 Empresa.", "danger")
        return redirect(url_for("admin_metas", ano=ano, mes=mes))

    # parse escalas: linhas "limite=bonus" ou "limite:bonus"
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
        flash("Informe as faixas (escadas) no formato 'limite:bonus'.", "danger")
        return redirect(url_for("admin_metas", ano=ano, mes=mes))

    marcas = []
    if tipo == "SHARE_MARCA":
        # aceita separador por vírgula, ponto-e-vírgula e quebra de linha
        parts = re.split(r"[,\n;]+", marcas_raw)
        marcas = [p.strip().upper() for p in parts if p.strip()]
        if not marcas:
            flash("Informe pelo menos 1 marca para Share de Marcas.", "danger")
            return redirect(url_for("admin_metas", ano=ano, mes=mes))

    with SessionLocal() as db:
        # supervisor só pode emps dele
        if role == "supervisor":
            allowed = set(_allowed_emps())
            emps = [e for e in emps if e in allowed]
            if not emps:
                flash("Você não tem permissão para as Empresas selecionadas.", "danger")
                return redirect(url_for("admin_metas", ano=ano, mes=mes))

        meta = MetaPrograma(
            nome=nome,
            tipo=tipo,
            ano=ano,
            mes=mes,
            ativo=True if (bloqueio is None or str(bloqueio).lower() in ("1", "on", "true", "yes", "")) else False,
            created_by_user_id=session.get("user_id"),
        )
        db.add(meta)
        db.commit()

        # vincula emps
        for e in emps:
            db.add(MetaProgramaEmp(meta_id=meta.id, emp=str(e).strip()))
        # escalas
        for idx, (lim, bon) in enumerate(sorted(escalas, key=lambda x: x[0])):
            db.add(MetaEscala(meta_id=meta.id, ordem=idx + 1, limite_min=lim, bonus_percentual=bon))
        # marcas
        for m in marcas:
            db.add(MetaMarca(meta_id=meta.id, marca=m))

        db.commit()

    flash("Meta criada com sucesso.", "success")
    return redirect(url_for("admin_metas", ano=ano, mes=mes))


def admin_metas_toggle(meta_id: int):
    red = _login_required()
    if red:
        return red

    role = _role() or ""
    if role not in ("admin", "supervisor"):
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    ano = int(request.form.get("ano") or date.today().year)
    mes = int(request.form.get("mes") or date.today().month)

    with SessionLocal() as db:
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == meta_id).first()
        if not meta:
            flash("Meta não encontrada.", "danger")
            return redirect(url_for("admin_metas", ano=ano, mes=mes))

        # supervisor só pode mexer em metas que atinjam emps dele (e opcionalmente as que ele criou)
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
    red = _login_required()
    if red:
        return red

    role = _role() or ""
    if role not in ("admin", "supervisor"):
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    with SessionLocal() as db:
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == meta_id).first()
        if not meta:
            flash("Meta não encontrada.", "danger")
            return redirect(url_for("admin_metas"))

        if meta.tipo != "CRESCIMENTO":
            flash("Base manual só se aplica a metas de Crescimento.", "warning")
            return redirect(url_for("admin_metas", ano=meta.ano, mes=meta.mes))

        emps_meta = [r[0] for r in db.query(MetaProgramaEmp.emp).filter(MetaProgramaEmp.meta_id == meta.id).all()]

        # supervisor restringe emps
        if role == "supervisor":
            allowed = set(_allowed_emps())
            emps_meta = [e for e in emps_meta if e in allowed]

        # lista vendedores do período e dessas emps
        vendedores = _get_vendedores_no_periodo(db, meta.ano, meta.mes, emps_meta)

        # bases existentes
        bases = db.query(MetaBaseManual).filter(MetaBaseManual.meta_id == meta.id).all()
        bases_map = {(b.emp, b.vendedor): b for b in bases}

        # prepara linhas
        linhas = []
        for emp in emps_meta:
            for vend in vendedores:
                # total atual (para referência)
                total_atual = _query_valor_mes(db, meta.ano, meta.mes, emp, vend)
                base_auto = _query_valor_mes(db, meta.ano - 1, meta.mes, emp, vend)
                b = bases_map.get((emp, vend))
                linhas.append(
                    {
                        "emp": emp,
                        "vendedor": vend,
                        "total_atual": float(total_atual),
                        "base_auto": float(base_auto),
                        "base_manual": float(b.base_valor) if b else None,
                        "observacao": (b.observacao if b else ""),
                    }
                )

        return render_template(
            "admin_meta_bases.html",
            role=role,
            emp=_emp(),
            meta=meta,
            linhas=linhas,
        )


def admin_meta_bases_salvar(meta_id: int):
    red = _login_required()
    if red:
        return red

    role = _role() or ""
    if role not in ("admin", "supervisor"):
        flash("Acesso negado.", "danger")
        return redirect(url_for("dashboard"))

    with SessionLocal() as db:
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == meta_id).first()
        if not meta or meta.tipo != "CRESCIMENTO":
            flash("Meta inválida.", "danger")
            return redirect(url_for("admin_metas"))

        # supervisor restringe emps
        emps_meta = [r[0] for r in db.query(MetaProgramaEmp.emp).filter(MetaProgramaEmp.meta_id == meta.id).all()]
        if role == "supervisor":
            allowed = set(_allowed_emps())
            emps_meta = [e for e in emps_meta if e in allowed]

        # recebe pares emp|vendedor
        # campos: base__EMP__VENDEDOR e obs__EMP__VENDEDOR
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
            base_str = (val or "").strip().replace(".", "").replace(",", ".")
            obs = (request.form.get(f"obs__{emp}__{vend}") or "").strip()

            if base_str == "":
                # remove manual se existir
                b = (
                    db.query(MetaBaseManual)
                    .filter(MetaBaseManual.meta_id == meta.id, MetaBaseManual.emp == emp, MetaBaseManual.vendedor == vend)
                    .first()
                )
                if b:
                    db.delete(b)
                    updated += 1
                continue

            try:
                base_val = float(base_str)
            except Exception:
                continue

            b = (
                db.query(MetaBaseManual)
                .filter(MetaBaseManual.meta_id == meta.id, MetaBaseManual.emp == emp, MetaBaseManual.vendedor == vend)
                .first()
            )
            if not b:
                b = MetaBaseManual(meta_id=meta.id, emp=emp, vendedor=vend)
            b.base_valor = base_val
            b.observacao = obs
            db.add(b)
            updated += 1

        db.commit()

    flash(f"Bases manuais salvas ({updated} alterações).", "success")
    return redirect(url_for("admin_meta_bases", meta_id=meta_id))
