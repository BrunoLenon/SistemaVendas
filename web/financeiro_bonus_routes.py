# -*- coding: utf-8 -*-
"""Fechamento financeiro dos bônus Varejo e Atacado.

Enquanto uma EMP está ABERTA, a página apresenta os valores vivos das bases
importadas. No fechamento, é criado um snapshot por funcionário; importações e
lançamentos posteriores não alteram esse valor. Uma reabertura volta a exibir a
base viva e também remove o sinalizador de pagamento, pois o total pode mudar.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections import defaultdict
from datetime import date, datetime
from decimal import Decimal
from typing import Any, Iterable
from urllib.parse import urlencode

from flask import current_app, flash, redirect, render_template, request, session, url_for
from sqlalchemy import func

from auth_helpers import _login_required, _role, _usuario_logado
from db import (
    BonusAtacadoUsuario,
    BonusOutroValor,
    BonusUsuarioImportado,
    Emp,
    FinanceiroBonusEvento,
    FinanceiroBonusFechamento,
    FinanceiroBonusFechamentoItem,
    ItensParadosVendaUsuario,
    SessionLocal,
    Usuario,
    ensure_bonus_atacado_schema,
    ensure_bonus_importados_schema,
    ensure_bonus_outros_valores_schema,
    ensure_financeiro_bonus_schema,
    ensure_itens_parados_snapshot_schema,
)
from security_utils import audit, normalize_role
from sv_utils import emp_sort_key

ALLOWED_ROLES = {"admin", "financeiro"}
STATUS_FILTERS = {"todos", "aberto", "fechado", "pago", "nao_pago"}
ZERO = Decimal("0")


def register_financeiro_bonus_routes(app) -> None:
    app.add_url_rule(
        "/financeiro",
        endpoint="financeiro_bonus",
        view_func=financeiro_bonus,
        methods=["GET"],
    )
    app.add_url_rule(
        "/financeiro/fechar",
        endpoint="financeiro_bonus_fechar",
        view_func=financeiro_bonus_fechar,
        methods=["POST"],
    )
    app.add_url_rule(
        "/financeiro/reabrir",
        endpoint="financeiro_bonus_reabrir",
        view_func=financeiro_bonus_reabrir,
        methods=["POST"],
    )
    app.add_url_rule(
        "/financeiro/pagamento",
        endpoint="financeiro_bonus_pagamento",
        view_func=financeiro_bonus_pagamento,
        methods=["POST"],
    )


def _financeiro_required():
    red = _login_required()
    if red:
        return red
    if normalize_role(_role()) not in ALLOWED_ROLES:
        flash("Acesso restrito ao Financeiro e ao Administrador.", "warning")
        return redirect(url_for("dashboard"))
    return None


def _strip_accents(value: object) -> str:
    raw = str(value or "")
    return "".join(
        ch for ch in unicodedata.normalize("NFKD", raw) if not unicodedata.combining(ch)
    )


def _canonical_name(value: object) -> str:
    return re.sub(r"[^A-Z0-9]", "", _strip_accents(value).upper())


def _display_name(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).upper()


def _norm_emp(value: object) -> str:
    raw = str(value or "").strip()
    if re.fullmatch(r"[+-]?\d+[.,]0+", raw):
        return raw.split(".", 1)[0].split(",", 1)[0]
    return raw.upper()


def _money(value: object) -> Decimal:
    try:
        return Decimal(str(value or 0))
    except Exception:
        return ZERO


def _safe_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(str(value).strip())
    except Exception:
        return default
    return max(minimum, min(maximum, parsed))


def _selected_emps_from_values(values: Iterable[object]) -> list[str]:
    selected: set[str] = set()
    for value in values:
        for part in str(value or "").split(","):
            emp = _norm_emp(part)
            if emp:
                selected.add(emp)
    return sorted(selected, key=emp_sort_key)


def _selected_emps_from_request(source) -> list[str]:
    return _selected_emps_from_values(source.getlist("emps") + source.getlist("emp"))


def _period_options(db) -> list[tuple[int, int]]:
    values: set[tuple[int, int]] = set()
    for model in (
        BonusUsuarioImportado,
        BonusAtacadoUsuario,
        ItensParadosVendaUsuario,
        BonusOutroValor,
        FinanceiroBonusFechamento,
    ):
        try:
            rows = db.query(model.ano, model.mes).distinct().all()
            values.update((int(row[0]), int(row[1])) for row in rows)
        except Exception:
            current_app.logger.exception("Falha ao listar competências do Financeiro")
    return sorted(values, reverse=True)


def _period_source_emps(db, ano: int, mes: int) -> list[str]:
    values: set[str] = set()
    for model in (
        BonusUsuarioImportado,
        BonusAtacadoUsuario,
        ItensParadosVendaUsuario,
        BonusOutroValor,
        FinanceiroBonusFechamento,
    ):
        rows = (
            db.query(model.emp)
            .filter(model.ano == ano, model.mes == mes)
            .distinct()
            .all()
        )
        values.update(_norm_emp(row[0]) for row in rows if row and _norm_emp(row[0]))
    return sorted(values, key=emp_sort_key)


def _emp_options(db, period_emps: Iterable[str]) -> list[dict[str, str]]:
    period_set = {_norm_emp(emp) for emp in period_emps if _norm_emp(emp)}
    registered = db.query(Emp).filter(Emp.ativo.is_(True)).all()
    names = {_norm_emp(item.codigo): str(item.nome or "").strip() for item in registered}
    codes = set(names) | period_set
    return [
        {"codigo": code, "nome": names.get(code, "")}
        for code in sorted(codes, key=emp_sort_key)
    ]


def _user_maps(db):
    users = db.query(Usuario).all()
    by_id = {int(user.id): user for user in users if user.id is not None}
    by_name = {
        _canonical_name(user.username): user
        for user in users
        if _canonical_name(user.username)
    }
    return by_id, by_name


def _live_rows(db, *, ano: int, mes: int, emps: list[str]) -> list[dict[str, Any]]:
    if not emps:
        return []

    users_by_id, users_by_name = _user_maps(db)
    combined: dict[tuple[str, str], dict[str, Any]] = {}

    def resolve(raw_id: object, raw_name: object):
        user = None
        try:
            if raw_id is not None:
                user = users_by_id.get(int(raw_id))
        except Exception:
            user = None
        if user is None:
            user = users_by_name.get(_canonical_name(raw_name))
        user_id = int(user.id) if user is not None and user.id is not None else None
        username = _display_name(user.username if user is not None else raw_name)
        role = normalize_role(user.role).upper() if user is not None else ""
        key_name = f"ID:{user_id}" if user_id is not None else f"NAME:{_canonical_name(username)}"
        return user_id, username, role, key_name

    def item_for(emp: object, raw_id: object, raw_name: object, fallback_role: object = ""):
        emp_code = _norm_emp(emp)
        user_id, username, role, key_name = resolve(raw_id, raw_name)
        key = (emp_code, key_name)
        item = combined.get(key)
        if item is None:
            fallback = normalize_role(str(fallback_role or "")).upper() if fallback_role else ""
            item = {
                "usuario_id": user_id,
                "usuario_nome": username,
                "funcao": role or fallback or "USUARIO",
                "emp": emp_code,
                "bonus_varejo": ZERO,
                "bonus_atacado": ZERO,
                "itens_parados": ZERO,
                "outros_varejo": ZERO,
                "outros_atacado": ZERO,
                "outros_detalhes": [],
            }
            combined[key] = item
        elif role and item["funcao"] in {"", "USUARIO", "VENDEDOR"}:
            item["funcao"] = role
        return item

    varejo = (
        db.query(BonusUsuarioImportado)
        .filter(
            BonusUsuarioImportado.ano == ano,
            BonusUsuarioImportado.mes == mes,
            BonusUsuarioImportado.emp.in_(emps),
        )
        .all()
    )
    for row in varejo:
        item = item_for(row.emp, row.usuario_id, row.usuario_nome, row.funcao)
        item["bonus_varejo"] += _money(row.bonus_final)

    atacado = (
        db.query(BonusAtacadoUsuario)
        .filter(
            BonusAtacadoUsuario.ano == ano,
            BonusAtacadoUsuario.mes == mes,
            BonusAtacadoUsuario.emp.in_(emps),
        )
        .all()
    )
    for row in atacado:
        item = item_for(row.emp, row.usuario_id, row.usuario_nome, row.funcao_planilha)
        item["bonus_atacado"] += _money(row.total_produtos)

    stopped = (
        db.query(ItensParadosVendaUsuario)
        .filter(
            ItensParadosVendaUsuario.ano == ano,
            ItensParadosVendaUsuario.mes == mes,
            ItensParadosVendaUsuario.emp.in_(emps),
        )
        .all()
    )
    for row in stopped:
        item = item_for(row.emp, row.usuario_id, row.usuario_nome)
        # No Financeiro, Itens Parados é contado uma única vez por funcionário/EMP.
        item["itens_parados"] += _money(row.valor_total)

    others = (
        db.query(BonusOutroValor)
        .filter(
            BonusOutroValor.ano == ano,
            BonusOutroValor.mes == mes,
            BonusOutroValor.emp.in_(emps),
        )
        .order_by(BonusOutroValor.criado_em.asc(), BonusOutroValor.id.asc())
        .all()
    )
    for row in others:
        item = item_for(row.emp, row.usuario_id, row.usuario_nome)
        origin = str(row.origem or "").strip().upper()
        value = _money(row.valor)
        if origin == "ATACADO":
            item["outros_atacado"] += value
        else:
            item["outros_varejo"] += value
        item["outros_detalhes"].append(
            {
                "origem": origin or "VAREJO",
                "descricao": str(row.descricao or "").strip(),
                "valor": value,
            }
        )

    rows: list[dict[str, Any]] = []
    for item in combined.values():
        item["outros_total"] = item["outros_varejo"] + item["outros_atacado"]
        item["total_geral"] = (
            item["bonus_varejo"]
            + item["bonus_atacado"]
            + item["itens_parados"]
            + item["outros_total"]
        )
        item["outros_tooltip"] = " | ".join(
            f"{entry['origem']}: {entry['descricao']} ({entry['valor']})"
            for entry in item["outros_detalhes"]
        )
        rows.append(item)

    rows.sort(key=lambda row: (emp_sort_key(row["emp"]), row["usuario_nome"]))
    return rows


def _snapshot_rows(db, closures: list[FinanceiroBonusFechamento]) -> list[dict[str, Any]]:
    if not closures:
        return []
    by_id = {int(item.id): item for item in closures}
    items = (
        db.query(FinanceiroBonusFechamentoItem)
        .filter(FinanceiroBonusFechamentoItem.fechamento_id.in_(list(by_id)))
        .all()
    )
    rows: list[dict[str, Any]] = []
    for item in items:
        closure = by_id.get(int(item.fechamento_id))
        details = []
        if item.outros_detalhes_json:
            try:
                parsed = json.loads(item.outros_detalhes_json)
                details = parsed if isinstance(parsed, list) else []
            except Exception:
                details = []
        row = {
            "usuario_id": item.usuario_id,
            "usuario_nome": item.usuario_nome,
            "funcao": item.funcao or "USUARIO",
            "emp": _norm_emp(item.emp),
            "bonus_varejo": _money(item.bonus_varejo),
            "bonus_atacado": _money(item.bonus_atacado),
            "itens_parados": _money(item.itens_parados),
            "outros_varejo": _money(item.outros_varejo),
            "outros_atacado": _money(item.outros_atacado),
            "outros_total": _money(item.outros_varejo) + _money(item.outros_atacado),
            "total_geral": _money(item.total_geral),
            "outros_detalhes": details,
            "outros_tooltip": " | ".join(
                f"{entry.get('origem', '')}: {entry.get('descricao', '')} ({entry.get('valor', 0)})"
                for entry in details
            ),
            "status": "FECHADO",
            "pago": bool(closure.pago) if closure else False,
        }
        rows.append(row)
    rows.sort(key=lambda row: (emp_sort_key(row["emp"]), row["usuario_nome"]))
    return rows


def _status_matches(status_filter: str, status: str, paid: bool) -> bool:
    if status_filter == "aberto":
        return status == "ABERTO"
    if status_filter == "fechado":
        return status == "FECHADO"
    if status_filter == "pago":
        return status == "FECHADO" and paid
    if status_filter == "nao_pago":
        return not paid
    return True


def _redirect_after_action(ano: int, mes: int, emps: list[str]):
    params: list[tuple[str, object]] = [("ano", ano), ("mes", mes)]
    params.extend(("emp", emp) for emp in emps)
    return redirect(f"{url_for('financeiro_bonus')}?{urlencode(params)}")


def _actor() -> tuple[int | None, str]:
    try:
        user_id = int(session.get("user_id")) if session.get("user_id") else None
    except Exception:
        user_id = None
    return user_id, _display_name(_usuario_logado())


def _event(
    db,
    closure: FinanceiroBonusFechamento,
    *,
    action: str,
    status_before: str | None,
    status_after: str | None,
    paid_before: bool | None,
    paid_after: bool | None,
    details: str = "",
) -> None:
    user_id, username = _actor()
    db.add(
        FinanceiroBonusEvento(
            fechamento_id=closure.id,
            acao=action,
            status_anterior=status_before,
            status_novo=status_after,
            pago_anterior=paid_before,
            pago_novo=paid_after,
            total_geral=_money(closure.total_geral),
            usuario_id=user_id,
            usuario_nome=username,
            detalhes=details or None,
            criado_em=datetime.utcnow(),
        )
    )


def _ensure_all_schemas() -> None:
    ensure_bonus_importados_schema()
    ensure_bonus_atacado_schema()
    ensure_itens_parados_snapshot_schema()
    ensure_bonus_outros_valores_schema()
    ensure_financeiro_bonus_schema()


def financeiro_bonus():
    red = _financeiro_required()
    if red:
        return red

    today = date.today()
    try:
        _ensure_all_schemas()
    except Exception:
        current_app.logger.exception("Falha ao garantir schema do Financeiro")
        flash(
            "A estrutura do Financeiro ainda não está disponível. Execute o SQL de implantação no Supabase.",
            "danger",
        )
        return render_template(
            "financeiro_bonus.html",
            role=normalize_role(_role()),
            ano=today.year,
            mes=today.month,
            periods=[],
            emp_options=[],
            selected_emps=[],
            groups=[],
            summary={},
            status_filter="todos",
            search="",
            db_unavailable=True,
        )

    with SessionLocal() as db:
        periods = _period_options(db)
        default_year, default_month = periods[0] if periods else (today.year, today.month)
        ano = _safe_int(request.args.get("ano"), default_year, 2000, 2100)
        mes = _safe_int(request.args.get("mes"), default_month, 1, 12)
        source_emps = _period_source_emps(db, ano, mes)
        emp_options = _emp_options(db, source_emps)
        available_codes = {item["codigo"] for item in emp_options}

        requested_emps = _selected_emps_from_request(request.args)
        selected_emps = [emp for emp in requested_emps if emp in available_codes]
        filter_was_applied = str(request.args.get("emp_aplicado") or "") == "1"
        if not selected_emps and not filter_was_applied:
            selected_emps = source_emps

        status_filter = str(request.args.get("status") or "todos").strip().lower()
        if status_filter not in STATUS_FILTERS:
            status_filter = "todos"
        search = _display_name(request.args.get("busca"))

        closures = []
        if selected_emps:
            closures = (
                db.query(FinanceiroBonusFechamento)
                .filter(
                    FinanceiroBonusFechamento.ano == ano,
                    FinanceiroBonusFechamento.mes == mes,
                    FinanceiroBonusFechamento.emp.in_(selected_emps),
                )
                .all()
            )
        closure_by_emp = {_norm_emp(item.emp): item for item in closures}
        closed = [item for item in closures if str(item.status).upper() == "FECHADO"]
        closed_emps = {_norm_emp(item.emp) for item in closed}
        open_emps = [emp for emp in selected_emps if emp not in closed_emps]

        rows = _snapshot_rows(db, closed)
        for row in _live_rows(db, ano=ano, mes=mes, emps=open_emps):
            row["status"] = "ABERTO"
            row["pago"] = False
            rows.append(row)

        visible_rows = []
        for row in rows:
            closure = closure_by_emp.get(row["emp"])
            status = "FECHADO" if closure and str(closure.status).upper() == "FECHADO" else "ABERTO"
            paid = bool(closure.pago) if status == "FECHADO" and closure else False
            row["status"] = status
            row["pago"] = paid
            if search and search not in row["usuario_nome"]:
                continue
            if not _status_matches(status_filter, status, paid):
                continue
            visible_rows.append(row)

        emp_names = {item["codigo"]: item["nome"] for item in emp_options}
        grouped: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in visible_rows:
            grouped[row["emp"]].append(row)

        groups = []
        for emp in sorted(grouped, key=emp_sort_key):
            group_rows = sorted(grouped[emp], key=lambda item: item["usuario_nome"])
            closure = closure_by_emp.get(emp)
            status = "FECHADO" if closure and str(closure.status).upper() == "FECHADO" else "ABERTO"
            paid = bool(closure.pago) if status == "FECHADO" and closure else False
            totals = {
                "varejo": sum((row["bonus_varejo"] for row in group_rows), ZERO),
                "atacado": sum((row["bonus_atacado"] for row in group_rows), ZERO),
                "itens_parados": sum((row["itens_parados"] for row in group_rows), ZERO),
                "outros": sum((row["outros_total"] for row in group_rows), ZERO),
                "geral": sum((row["total_geral"] for row in group_rows), ZERO),
            }
            groups.append(
                {
                    "emp": emp,
                    "nome": emp_names.get(emp, ""),
                    "rows": group_rows,
                    "status": status,
                    "pago": paid,
                    "closure": closure,
                    "totals": totals,
                }
            )

        all_rows = [row for group in groups for row in group["rows"]]
        summary = {
            "funcionarios": len(all_rows),
            "lojas": len(groups),
            "varejo": sum((row["bonus_varejo"] for row in all_rows), ZERO),
            "atacado": sum((row["bonus_atacado"] for row in all_rows), ZERO),
            "itens_parados": sum((row["itens_parados"] for row in all_rows), ZERO),
            "outros": sum((row["outros_total"] for row in all_rows), ZERO),
            "total": sum((row["total_geral"] for row in all_rows), ZERO),
            "abertas": sum(1 for group in groups if group["status"] == "ABERTO"),
            "fechadas": sum(1 for group in groups if group["status"] == "FECHADO"),
            "pagas": sum(1 for group in groups if group["pago"]),
            "nao_pagas": sum(1 for group in groups if not group["pago"]),
            "valor_pago": sum(
                (group["totals"]["geral"] for group in groups if group["pago"]), ZERO
            ),
            "valor_pendente": sum(
                (group["totals"]["geral"] for group in groups if not group["pago"]), ZERO
            ),
        }

    return render_template(
        "financeiro_bonus.html",
        role=normalize_role(_role()),
        ano=ano,
        mes=mes,
        periods=periods,
        emp_options=emp_options,
        selected_emps=selected_emps,
        groups=groups,
        summary=summary,
        status_filter=status_filter,
        search=search,
        db_unavailable=False,
    )


def financeiro_bonus_fechar():
    red = _financeiro_required()
    if red:
        return red
    today = date.today()
    ano = _safe_int(request.form.get("ano"), today.year, 2000, 2100)
    mes = _safe_int(request.form.get("mes"), today.month, 1, 12)
    emps = _selected_emps_from_request(request.form)
    if not emps:
        flash("Selecione ao menos uma loja para fechar.", "warning")
        return _redirect_after_action(ano, mes, emps)

    try:
        _ensure_all_schemas()
        closed_count = 0
        skipped_count = 0
        no_data_count = 0
        user_id, username = _actor()
        now = datetime.utcnow()
        with SessionLocal() as db:
            for emp in emps:
                closure = (
                    db.query(FinanceiroBonusFechamento)
                    .filter(
                        FinanceiroBonusFechamento.ano == ano,
                        FinanceiroBonusFechamento.mes == mes,
                        FinanceiroBonusFechamento.emp == emp,
                    )
                    .with_for_update()
                    .first()
                )
                if closure and str(closure.status).upper() == "FECHADO":
                    skipped_count += 1
                    continue

                rows = _live_rows(db, ano=ano, mes=mes, emps=[emp])
                if not rows:
                    no_data_count += 1
                    continue

                if closure is None:
                    closure = FinanceiroBonusFechamento(
                        ano=ano,
                        mes=mes,
                        emp=emp,
                        status="ABERTO",
                        pago=False,
                        versao=0,
                        atualizado_em=now,
                    )
                    db.add(closure)
                    db.flush()

                previous_status = str(closure.status or "ABERTO").upper()
                previous_paid = bool(closure.pago)
                db.query(FinanceiroBonusFechamentoItem).filter(
                    FinanceiroBonusFechamentoItem.fechamento_id == closure.id
                ).delete(synchronize_session=False)

                for row in rows:
                    details = [
                        {
                            "origem": entry.get("origem", ""),
                            "descricao": entry.get("descricao", ""),
                            "valor": str(entry.get("valor", 0)),
                        }
                        for entry in row["outros_detalhes"]
                    ]
                    db.add(
                        FinanceiroBonusFechamentoItem(
                            fechamento_id=closure.id,
                            usuario_id=row["usuario_id"],
                            usuario_nome=row["usuario_nome"],
                            funcao=row["funcao"],
                            emp=emp,
                            bonus_varejo=row["bonus_varejo"],
                            bonus_atacado=row["bonus_atacado"],
                            itens_parados=row["itens_parados"],
                            outros_varejo=row["outros_varejo"],
                            outros_atacado=row["outros_atacado"],
                            total_geral=row["total_geral"],
                            outros_detalhes_json=json.dumps(details, ensure_ascii=False),
                            criado_em=now,
                        )
                    )

                closure.status = "FECHADO"
                closure.pago = False
                closure.pago_em = None
                closure.pago_por = None
                closure.pago_por_user_id = None
                closure.versao = int(closure.versao or 0) + 1
                closure.total_varejo = sum((row["bonus_varejo"] for row in rows), ZERO)
                closure.total_atacado = sum((row["bonus_atacado"] for row in rows), ZERO)
                closure.total_itens_parados = sum((row["itens_parados"] for row in rows), ZERO)
                closure.total_outros_varejo = sum((row["outros_varejo"] for row in rows), ZERO)
                closure.total_outros_atacado = sum((row["outros_atacado"] for row in rows), ZERO)
                closure.total_geral = sum((row["total_geral"] for row in rows), ZERO)
                closure.fechado_por_user_id = user_id
                closure.fechado_por = username
                closure.fechado_em = now
                closure.atualizado_em = now
                db.flush()
                _event(
                    db,
                    closure,
                    action="FECHAR",
                    status_before=previous_status,
                    status_after="FECHADO",
                    paid_before=previous_paid,
                    paid_after=False,
                    details=f"Snapshot v{closure.versao} com {len(rows)} funcionário(s).",
                )
                closed_count += 1
            db.commit()

        audit("financeiro_bonus_closed", ano=ano, mes=mes, emps=emps, quantidade=closed_count)
        if closed_count:
            flash(f"{closed_count} loja(s) fechada(s). Os valores foram congelados.", "success")
        if skipped_count:
            flash(f"{skipped_count} loja(s) já estavam fechadas e não foram alteradas.", "info")
        if no_data_count:
            flash(f"{no_data_count} loja(s) não possuem valores para fechar nesta competência.", "warning")
    except Exception as exc:
        current_app.logger.exception("Falha ao fechar bônus financeiro")
        flash(f"Não foi possível concluir o fechamento: {exc}", "danger")

    return _redirect_after_action(ano, mes, emps)


def financeiro_bonus_reabrir():
    red = _financeiro_required()
    if red:
        return red
    today = date.today()
    ano = _safe_int(request.form.get("ano"), today.year, 2000, 2100)
    mes = _safe_int(request.form.get("mes"), today.month, 1, 12)
    emps = _selected_emps_from_request(request.form)
    if not emps:
        flash("Selecione ao menos uma loja para reabrir.", "warning")
        return _redirect_after_action(ano, mes, emps)

    changed = 0
    try:
        _ensure_all_schemas()
        user_id, username = _actor()
        now = datetime.utcnow()
        with SessionLocal() as db:
            closures = (
                db.query(FinanceiroBonusFechamento)
                .filter(
                    FinanceiroBonusFechamento.ano == ano,
                    FinanceiroBonusFechamento.mes == mes,
                    FinanceiroBonusFechamento.emp.in_(emps),
                )
                .with_for_update()
                .all()
            )
            for closure in closures:
                if str(closure.status or "").upper() != "FECHADO":
                    continue
                previous_paid = bool(closure.pago)
                closure.status = "ABERTO"
                closure.pago = False
                closure.pago_em = None
                closure.pago_por = None
                closure.pago_por_user_id = None
                closure.reaberto_por_user_id = user_id
                closure.reaberto_por = username
                closure.reaberto_em = now
                closure.atualizado_em = now
                _event(
                    db,
                    closure,
                    action="REABRIR",
                    status_before="FECHADO",
                    status_after="ABERTO",
                    paid_before=previous_paid,
                    paid_after=False,
                    details="A reabertura voltou a competência para os valores vivos e removeu o status de pago.",
                )
                changed += 1
            db.commit()
        audit("financeiro_bonus_reopened", ano=ano, mes=mes, emps=emps, quantidade=changed)
        if changed:
            flash(
                f"{changed} loja(s) reaberta(s). Os valores voltaram a acompanhar as importações; o status Pago foi removido.",
                "success",
            )
        else:
            flash("Nenhuma loja fechada foi encontrada na seleção.", "info")
    except Exception as exc:
        current_app.logger.exception("Falha ao reabrir bônus financeiro")
        flash(f"Não foi possível reabrir o fechamento: {exc}", "danger")
    return _redirect_after_action(ano, mes, emps)


def financeiro_bonus_pagamento():
    red = _financeiro_required()
    if red:
        return red
    today = date.today()
    ano = _safe_int(request.form.get("ano"), today.year, 2000, 2100)
    mes = _safe_int(request.form.get("mes"), today.month, 1, 12)
    emps = _selected_emps_from_request(request.form)
    paid_value = str(request.form.get("pago") or "1").strip().lower() in {"1", "true", "on", "sim"}
    if not emps:
        flash("Selecione ao menos uma loja para alterar o pagamento.", "warning")
        return _redirect_after_action(ano, mes, emps)

    changed = 0
    skipped = 0
    try:
        _ensure_all_schemas()
        user_id, username = _actor()
        now = datetime.utcnow()
        with SessionLocal() as db:
            closures = (
                db.query(FinanceiroBonusFechamento)
                .filter(
                    FinanceiroBonusFechamento.ano == ano,
                    FinanceiroBonusFechamento.mes == mes,
                    FinanceiroBonusFechamento.emp.in_(emps),
                )
                .with_for_update()
                .all()
            )
            found = {_norm_emp(item.emp) for item in closures}
            skipped += len([emp for emp in emps if emp not in found])
            for closure in closures:
                if str(closure.status or "").upper() != "FECHADO":
                    skipped += 1
                    continue
                previous = bool(closure.pago)
                if previous == paid_value:
                    continue
                closure.pago = paid_value
                closure.pago_em = now if paid_value else None
                closure.pago_por_user_id = user_id if paid_value else None
                closure.pago_por = username if paid_value else None
                closure.atualizado_em = now
                _event(
                    db,
                    closure,
                    action="PAGAR" if paid_value else "ESTORNAR_PAGO",
                    status_before="FECHADO",
                    status_after="FECHADO",
                    paid_before=previous,
                    paid_after=paid_value,
                )
                changed += 1
            db.commit()
        audit(
            "financeiro_bonus_payment_changed",
            ano=ano,
            mes=mes,
            emps=emps,
            pago=paid_value,
            quantidade=changed,
        )
        if changed:
            flash(
                f"{changed} loja(s) marcada(s) como {'PAGO' if paid_value else 'NÃO PAGO'}.",
                "success",
            )
        if skipped:
            flash(
                f"{skipped} loja(s) foram ignoradas porque ainda não estão fechadas.",
                "warning",
            )
        if not changed and not skipped:
            flash("A seleção já estava com o status solicitado.", "info")
    except Exception as exc:
        current_app.logger.exception("Falha ao alterar pagamento do Financeiro")
        flash(f"Não foi possível alterar o pagamento: {exc}", "danger")
    return _redirect_after_action(ano, mes, emps)
