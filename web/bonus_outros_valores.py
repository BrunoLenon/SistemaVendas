# -*- coding: utf-8 -*-
"""Lançamentos manuais de Outros Valores vinculados aos módulos de Bônus.

Cada lançamento pertence a uma competência, a uma origem (VAREJO ou ATACADO),
a um usuário e a uma EMP. O valor não é recalculado: o sistema apenas soma os
lançamentos ativos ao bônus importado e ao saldo de Itens Parados.
"""

from __future__ import annotations

import re
import unicodedata
from collections import defaultdict
from datetime import date, datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Iterable

from flask import current_app, flash, redirect, request, session, url_for
from sqlalchemy import or_

from auth_helpers import _login_required, _role, _usuario_logado
from db import (
    BonusAtacadoUsuario,
    BonusOutroValor,
    BonusUsuarioImportado,
    SessionLocal,
    Usuario,
    UsuarioEmp,
    ensure_bonus_outros_valores_schema,
)
from security_utils import audit, normalize_role
from sv_utils import emp_sort_key


VALID_ORIGINS = {"VAREJO", "ATACADO"}


def register_bonus_outros_valores_routes(app) -> None:
    app.add_url_rule(
        "/admin/bonus/outros-valores/lancar",
        endpoint="admin_bonus_outro_valor_lancar",
        view_func=admin_bonus_outro_valor_lancar,
        methods=["POST"],
    )
    app.add_url_rule(
        "/admin/bonus/outros-valores/<int:lancamento_id>/excluir",
        endpoint="admin_bonus_outro_valor_excluir",
        view_func=admin_bonus_outro_valor_excluir,
        methods=["POST"],
    )


def _strip_accents(value: object) -> str:
    raw = str(value or "")
    return "".join(
        ch for ch in unicodedata.normalize("NFKD", raw) if not unicodedata.combining(ch)
    )


def norm_username(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).upper()


def norm_emp(value: object) -> str:
    raw = str(value or "").strip()
    if re.fullmatch(r"[+-]?\d+[.,]0+", raw):
        return raw.split(".", 1)[0].split(",", 1)[0]
    return raw.upper()


def _safe_period(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(str(value).strip())
    except Exception:
        return default
    return max(minimum, min(maximum, parsed))


def _origin(value: object) -> str:
    origin = re.sub(r"[^A-Z]", "", _strip_accents(value).upper())
    return origin if origin in VALID_ORIGINS else ""


def _decimal_value(value: object) -> Decimal:
    raw = str(value or "").strip().replace("R$", "").replace(" ", "")
    if not raw:
        raise ValueError("Informe o valor do lançamento.")
    if "," in raw:
        raw = raw.replace(".", "").replace(",", ".")
    elif raw.count(".") > 1:
        raw = raw.replace(".", "")
    try:
        number = Decimal(raw)
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError("Informe um valor monetário válido.") from exc
    if not number.is_finite() or number <= 0:
        raise ValueError("O valor de Outros Valores deve ser maior que zero.")
    return number.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)


def _redirect_for(origin: str, ano: int, mes: int):
    endpoint = "bonus_atacado" if origin == "ATACADO" else "bonus_importados"
    return redirect(url_for(endpoint, ano=ano, mes=mes))


def _parse_user_emp(value: object) -> tuple[int, str]:
    raw = str(value or "").strip()
    match = re.fullmatch(r"(\d+)::(.+)", raw)
    if not match:
        raise ValueError("Selecione um usuário e uma EMP válidos.")
    return int(match.group(1)), norm_emp(match.group(2))


def _linked_emps(db, user: Usuario) -> set[str]:
    emps = {
        norm_emp(row[0])
        for row in (
            db.query(UsuarioEmp.emp)
            .filter(
                UsuarioEmp.usuario_id == int(user.id),
                UsuarioEmp.ativo.is_(True),
            )
            .all()
        )
        if row and norm_emp(row[0])
    }
    if norm_emp(user.emp):
        emps.add(norm_emp(user.emp))
    return emps


def _matching_bonus_row_exists(
    db,
    *,
    origin: str,
    ano: int,
    mes: int,
    user: Usuario,
    emp: str,
) -> bool:
    model = BonusAtacadoUsuario if origin == "ATACADO" else BonusUsuarioImportado
    query = db.query(model.id).filter(
        model.ano == ano,
        model.mes == mes,
        model.emp == emp,
    )
    filters = [model.usuario_nome == norm_username(user.username)]
    if getattr(model, "usuario_id", None) is not None:
        filters.append(model.usuario_id == int(user.id))
    return query.filter(or_(*filters)).first() is not None


def admin_bonus_outro_valor_lancar():
    red = _login_required()
    if red:
        return red
    if normalize_role(_role()) != "admin":
        flash("Acesso restrito ao administrador.", "warning")
        return redirect(url_for("dashboard"))

    today = date.today()
    origin = _origin(request.form.get("origem"))
    ano = _safe_period(request.form.get("ano"), today.year, 2000, 2100)
    mes = _safe_period(request.form.get("mes"), today.month, 1, 12)

    if not origin:
        flash("A origem do bônus é inválida.", "danger")
        return redirect(url_for("dashboard"))

    try:
        user_id, emp = _parse_user_emp(request.form.get("usuario_emp"))
        description = re.sub(r"\s+", " ", str(request.form.get("descricao") or "").strip())
        if len(description) < 3:
            raise ValueError("Informe uma descrição com pelo menos 3 caracteres.")
        if len(description) > 255:
            raise ValueError("A descrição pode ter no máximo 255 caracteres.")
        value = _decimal_value(request.form.get("valor"))

        ensure_bonus_outros_valores_schema()
        with SessionLocal() as db:
            user = db.query(Usuario).filter(Usuario.id == user_id).first()
            if not user:
                raise ValueError("O usuário selecionado não existe mais no cadastro.")
            if emp not in _linked_emps(db, user):
                raise ValueError(
                    f"A EMP {emp} não está vinculada ao usuário {user.username}."
                )
            if not _matching_bonus_row_exists(
                db,
                origin=origin,
                ano=ano,
                mes=mes,
                user=user,
                emp=emp,
            ):
                raise ValueError(
                    "O usuário não possui registro de bônus nesta competência e EMP. "
                    "Importe primeiro a planilha correspondente."
                )

            entry = BonusOutroValor(
                origem=origin,
                ano=ano,
                mes=mes,
                usuario_id=int(user.id),
                usuario_nome=norm_username(user.username),
                emp=emp,
                descricao=description,
                valor=value,
                criado_por_user_id=(int(session["user_id"]) if session.get("user_id") else None),
                criado_por=norm_username(_usuario_logado()),
                criado_em=datetime.utcnow(),
            )
            db.add(entry)
            db.commit()
            entry_id = int(entry.id)

        audit(
            "bonus_outro_valor_created",
            id=entry_id,
            origem=origin,
            ano=ano,
            mes=mes,
            usuario_id=user_id,
            emp=emp,
            descricao=description,
            valor=str(value),
        )
        flash(
            f"Outro valor lançado para {norm_username(user.username)} · EMP {emp}: "
            f"R$ {value:,.2f}".replace(",", "X").replace(".", ",").replace("X", "."),
            "success",
        )
    except Exception as exc:
        current_app.logger.exception("Falha ao lançar Outro Valor")
        audit(
            "bonus_outro_valor_create_failed",
            origem=origin,
            ano=ano,
            mes=mes,
            erro=str(exc),
        )
        flash(str(exc), "danger")

    return _redirect_for(origin, ano, mes)


def admin_bonus_outro_valor_excluir(lancamento_id: int):
    red = _login_required()
    if red:
        return red
    if normalize_role(_role()) != "admin":
        flash("Acesso restrito ao administrador.", "warning")
        return redirect(url_for("dashboard"))

    today = date.today()
    fallback_origin = _origin(request.form.get("origem")) or "VAREJO"
    fallback_year = _safe_period(request.form.get("ano"), today.year, 2000, 2100)
    fallback_month = _safe_period(request.form.get("mes"), today.month, 1, 12)

    try:
        ensure_bonus_outros_valores_schema()
        with SessionLocal() as db:
            entry = (
                db.query(BonusOutroValor)
                .filter(BonusOutroValor.id == int(lancamento_id))
                .first()
            )
            if not entry:
                raise ValueError("O lançamento não foi encontrado.")
            origin = _origin(entry.origem) or fallback_origin
            ano = int(entry.ano)
            mes = int(entry.mes)
            audit_payload = {
                "id": int(entry.id),
                "origem": origin,
                "ano": ano,
                "mes": mes,
                "usuario_id": entry.usuario_id,
                "usuario": entry.usuario_nome,
                "emp": entry.emp,
                "descricao": entry.descricao,
                "valor": str(entry.valor),
            }
            db.delete(entry)
            db.commit()

        audit("bonus_outro_valor_deleted", **audit_payload)
        flash("Lançamento de Outros Valores excluído.", "success")
        return _redirect_for(origin, ano, mes)
    except Exception as exc:
        current_app.logger.exception("Falha ao excluir Outro Valor")
        audit(
            "bonus_outro_valor_delete_failed",
            id=lancamento_id,
            erro=str(exc),
        )
        flash(str(exc), "danger")
        return _redirect_for(fallback_origin, fallback_year, fallback_month)


def bonus_row_options(rows: Iterable[Any]) -> list[dict[str, Any]]:
    """Opções seguras do formulário: somente linhas já importadas e vinculadas."""
    options: dict[tuple[int, str], dict[str, Any]] = {}
    for row in rows:
        user_id = getattr(row, "usuario_id", None)
        emp = norm_emp(getattr(row, "emp", ""))
        username = norm_username(getattr(row, "usuario_nome", ""))
        if not user_id or not emp or not username:
            continue
        role_value = (
            getattr(row, "funcao_exibicao", None)
            or getattr(row, "funcao", None)
            or getattr(row, "funcao_planilha", None)
            or "USUARIO"
        )
        role_label = _strip_accents(role_value).strip().upper() or "USUARIO"
        options[(int(user_id), emp)] = {
            "value": f"{int(user_id)}::{emp}",
            "usuario_id": int(user_id),
            "usuario_nome": username,
            "emp": emp,
            "funcao": role_label,
        }
    return sorted(
        options.values(),
        key=lambda item: (emp_sort_key(item["emp"]), item["usuario_nome"]),
    )


def attach_outros_valores_to_bonus_rows(
    db,
    rows: Iterable[Any],
    *,
    ano: int,
    mes: int,
    origem: str,
    bonus_field: str,
) -> dict[str, Decimal | int]:
    """Anexa lançamentos e o total geral a cada linha de bônus visível."""
    rows = list(rows)
    origin = _origin(origem)
    emps = sorted(
        {
            norm_emp(getattr(row, "emp", ""))
            for row in rows
            if norm_emp(getattr(row, "emp", ""))
        },
        key=emp_sort_key,
    )
    if not rows or not origin or not emps:
        for row in rows:
            setattr(row, "outros_valores_total", Decimal("0"))
            setattr(row, "outros_valores_detalhes", [])
            base = Decimal(str(getattr(row, bonus_field, 0) or 0))
            stopped = Decimal(str(getattr(row, "saldo_itens_parados", 0) or 0))
            setattr(row, "valor_bonus_base", base)
            setattr(row, "total_geral", base + stopped)
        return {"total_visivel": Decimal("0"), "quantidade": 0}

    entries = (
        db.query(BonusOutroValor)
        .filter(
            BonusOutroValor.origem == origin,
            BonusOutroValor.ano == int(ano),
            BonusOutroValor.mes == int(mes),
            BonusOutroValor.emp.in_(emps),
        )
        .order_by(BonusOutroValor.criado_em.asc(), BonusOutroValor.id.asc())
        .all()
    )

    by_id: defaultdict[tuple[str, int], list[BonusOutroValor]] = defaultdict(list)
    by_name: defaultdict[tuple[str, str], list[BonusOutroValor]] = defaultdict(list)
    for entry in entries:
        emp = norm_emp(entry.emp)
        if entry.usuario_id is not None:
            by_id[(emp, int(entry.usuario_id))].append(entry)
        by_name[(emp, norm_username(entry.usuario_nome))].append(entry)

    attached_ids: set[int] = set()
    for row in rows:
        emp = norm_emp(getattr(row, "emp", ""))
        user_id = getattr(row, "usuario_id", None)
        username = norm_username(getattr(row, "usuario_nome", ""))
        matched = by_id.get((emp, int(user_id)), []) if user_id is not None else []
        if not matched:
            matched = by_name.get((emp, username), [])
        details = []
        other_total = Decimal("0")
        for entry in matched:
            entry_value = Decimal(str(entry.valor or 0))
            other_total += entry_value
            attached_ids.add(int(entry.id))
            details.append(
                {
                    "id": int(entry.id),
                    "descricao": str(entry.descricao or ""),
                    "valor": entry_value,
                    "criado_em": entry.criado_em,
                    "criado_por": entry.criado_por,
                }
            )

        base = Decimal(str(getattr(row, bonus_field, 0) or 0))
        stopped = Decimal(str(getattr(row, "saldo_itens_parados", 0) or 0))
        setattr(row, "outros_valores_total", other_total)
        setattr(row, "outros_valores_detalhes", details)
        setattr(row, "valor_bonus_base", base)
        setattr(row, "total_geral", base + stopped + other_total)

    total_visible = sum(
        (Decimal(str(entry.valor or 0)) for entry in entries if int(entry.id) in attached_ids),
        Decimal("0"),
    )
    return {"total_visivel": total_visible, "quantidade": len(attached_ids)}
