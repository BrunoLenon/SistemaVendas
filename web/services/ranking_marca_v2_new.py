# -*- coding: utf-8 -*-
"""
Ranking por Marca (V2 NEW schema)

- Config em campanhas_v2_master (CampanhaV2MasterNew)
- Escopo por EMP em campanhas_scope_emp_v2 (CampanhaV2ScopeEMPNew)
- Snapshot em campanhas_v2_resultados (CampanhaV2ResultadoNew)
- Integra com Financeiro via services.financeiro_service.sync_pagamentos_v2

Objetivo: cálculo rápido em tela (sempre lê snapshot) e cálculo pesado sob demanda (admin).
"""

from __future__ import annotations

import json
import calendar
import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Iterable

from sqlalchemy import func, and_, or_

from db import (
    SessionLocal,
    Venda,
    CampanhaV2MasterNewSchema as CampanhaV2MasterNew,
    CampanhaV2ScopeEMPNewSchema as CampanhaV2ScopeEMPNew,
    CampanhaV2ResultadoNewSchema as CampanhaV2ResultadoNew,
    FinanceiroPagamento,
)

from services.financeiro_service import sync_pagamentos_v2


TIPO_RANKING_MARCA = "RANKING_MARCA"


def _upper(s: str | None) -> str:
    return (s or "").strip().upper()


def _to_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None or v == "":
            return float(default)
        return float(str(v).replace(".", "").replace(",", "."))
    except Exception:
        return float(default)


def _to_int(v: Any, default: int = 0) -> int:
    try:
        if v is None or v == "":
            return int(default)
        return int(v)
    except Exception:
        return int(default)


def _parse_date(v: Any) -> date | None:
    if not v:
        return None
    if isinstance(v, date) and not isinstance(v, datetime):
        return v
    if isinstance(v, datetime):
        return v.date()
    # HTML date input => YYYY-MM-DD
    try:
        return datetime.strptime(str(v), "%Y-%m-%d").date()
    except Exception:
        return None


def _month_bounds(ano: int, mes: int) -> tuple[date, date]:
    ano = int(ano)
    mes = int(mes)
    ini = date(ano, mes, 1)
    last = calendar.monthrange(ano, mes)[1]
    fim = date(ano, mes, last)
    return ini, fim


def _json_dumps(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return "{}"


def _json_load(s: str | None, default: Any) -> Any:
    if not s:
        return default
    try:
        return json.loads(s)
    except Exception:
        return default


def list_campaigns_for_admin(db) -> list[CampanhaV2MasterNew]:
    return (
        db.query(CampanhaV2MasterNew)
        .filter(CampanhaV2MasterNew.tipo == TIPO_RANKING_MARCA)
        .order_by(CampanhaV2MasterNew.id.desc())
        .all()
    )


def list_campaigns_for_user(db, *, role: str, allowed_emps: list[str]) -> list[CampanhaV2MasterNew]:
    """Lista campanhas visíveis ao usuário.

    Regra:
    - ADMIN: todas
    - GLOBAL: todos veem
    - POR_EMP: somente se intersectar com allowed_emps do usuário
    """
    role = (role or "").lower()
    if role == "admin":
        return list_campaigns_for_admin(db)

    camps = (
        db.query(CampanhaV2MasterNew)
        .filter(CampanhaV2MasterNew.tipo == TIPO_RANKING_MARCA)
        .filter(CampanhaV2MasterNew.ativo.is_(True))
        .order_by(CampanhaV2MasterNew.id.desc())
        .all()
    )

    if not allowed_emps:
        # admin_all_emps ou algo equivalente; para supervisor/vendedor não deveria acontecer,
        # mas mantemos como "vê tudo".
        return camps

    allowed_set = {int(e) for e in allowed_emps if str(e).isdigit()}
    visible: list[CampanhaV2MasterNew] = []

    for c in camps:
        if (c.scope_mode or "GLOBAL").upper() == "GLOBAL":
            visible.append(c)
            continue
        # POR_EMP
        emps = (
            db.query(CampanhaV2ScopeEMPNew.emp)
            .filter(CampanhaV2ScopeEMPNew.campanha_id == int(c.id))
            .all()
        )
        emps_set = {int(r[0]) for r in emps if r and r[0] is not None}
        if emps_set.intersection(allowed_set):
            visible.append(c)

    return visible


def get_scope_emps(db, campanha_id: int) -> list[int]:
    rows = (
        db.query(CampanhaV2ScopeEMPNew.emp)
        .filter(CampanhaV2ScopeEMPNew.campanha_id == int(campanha_id))
        .order_by(CampanhaV2ScopeEMPNew.emp.asc())
        .all()
    )
    return [int(r[0]) for r in rows if r and r[0] is not None]


def set_scope_emps(db, campanha_id: int, emps: Iterable[int]) -> None:
    campanha_id = int(campanha_id)
    # remove antigos
    db.query(CampanhaV2ScopeEMPNew).filter(CampanhaV2ScopeEMPNew.campanha_id == campanha_id).delete()
    # insere novos
    seen = set()
    for e in emps or []:
        try:
            ei = int(e)
        except Exception:
            continue
        if ei in seen:
            continue
        seen.add(ei)
        db.add(CampanhaV2ScopeEMPNew(campanha_id=campanha_id, emp=ei))


def create_or_update_campaign(
    db,
    *,
    campanha_id: int | None,
    nome: str,
    marca_alvo: str,
    vigencia_inicio: date | None,
    vigencia_fim: date | None,
    scope_mode: str,
    emps: list[int] | None,
    base_minima_valor: float,
    premio_top1: float,
    premio_top2: float,
    premio_top3: float,
    ativo: bool,
) -> CampanhaV2MasterNew:
    scope_mode = (scope_mode or "GLOBAL").upper()
    if scope_mode not in ("GLOBAL", "POR_EMP"):
        scope_mode = "GLOBAL"

    if campanha_id:
        c = db.query(CampanhaV2MasterNew).filter(CampanhaV2MasterNew.id == int(campanha_id)).first()
        if not c:
            raise ValueError("Campanha não encontrada.")
    else:
        c = CampanhaV2MasterNew(tipo=TIPO_RANKING_MARCA)

    c.nome = (nome or "").strip()
    c.marca_alvo = _upper(marca_alvo)
    c.vigencia_inicio = vigencia_inicio
    c.vigencia_fim = vigencia_fim
    c.scope_mode = scope_mode
    c.base_minima_valor = float(base_minima_valor or 0.0)
    c.premio_tipo = "FIXO"
    c.premio_top1 = float(premio_top1 or 0.0)
    c.premio_top2 = float(premio_top2 or 0.0)
    c.premio_top3 = float(premio_top3 or 0.0)
    c.ativo = bool(ativo)

    if not campanha_id:
        db.add(c)
        db.flush()  # gera ID

    if scope_mode == "POR_EMP":
        set_scope_emps(db, int(c.id), emps or [])
    else:
        # limpa escopo se não for por emp
        db.query(CampanhaV2ScopeEMPNew).filter(CampanhaV2ScopeEMPNew.campanha_id == int(c.id)).delete()

    return c


def delete_campaign(db, campanha_id: int) -> None:
    campanha_id = int(campanha_id)
    db.query(CampanhaV2ScopeEMPNew).filter(CampanhaV2ScopeEMPNew.campanha_id == campanha_id).delete()
    db.query(CampanhaV2ResultadoNew).filter(CampanhaV2ResultadoNew.campanha_id == campanha_id).delete()
    # remove pagamentos vinculados (origem_id = campanha_id)
    db.query(FinanceiroPagamento).filter(
        and_(FinanceiroPagamento.origem_tipo == "V2", FinanceiroPagamento.origem_id == campanha_id)
    ).delete(synchronize_session=False)
    db.query(CampanhaV2MasterNew).filter(CampanhaV2MasterNew.id == campanha_id).delete()


@dataclass
class RankingRow:
    vendedor: str
    total: float
    emp_hint: int | None
    por_emp: dict[int, float]


def recalc_ranking_marca(
    db,
    *,
    campanha_id: int,
    ano: int,
    mes: int,
    actor: str = "",
) -> dict[str, Any]:
    """Calcula e grava snapshot em campanhas_v2_resultados para a competência."""
    campanha_id = int(campanha_id)
    ano = int(ano)
    mes = int(mes)

    camp = db.query(CampanhaV2MasterNew).filter(CampanhaV2MasterNew.id == campanha_id).first()
    if not camp:
        raise ValueError("Campanha não encontrada.")
    if (camp.tipo or "").upper() != TIPO_RANKING_MARCA:
        raise ValueError("Tipo de campanha inválido para ranking por marca.")

    marca = _upper(getattr(camp, "marca_alvo", "") or "")
    if not marca:
        raise ValueError("Campanha sem marca definida (marca_alvo).")

    minimo = float(getattr(camp, "base_minima_valor", 0.0) or 0.0)
    scope_mode = (getattr(camp, "scope_mode", "GLOBAL") or "GLOBAL").upper()

    ini_mes, fim_mes = _month_bounds(ano, mes)

    # Ajusta pela vigência (se definida)
    vig_ini = getattr(camp, "vigencia_inicio", None)
    vig_fim = getattr(camp, "vigencia_fim", None)
    if vig_ini:
        ini = max(ini_mes, vig_ini)
    else:
        ini = ini_mes
    if vig_fim:
        fim = min(fim_mes, vig_fim)
    else:
        fim = fim_mes

    # Escopo EMPs (se POR_EMP)
    scope_emps: list[int] = []
    if scope_mode == "POR_EMP":
        scope_emps = get_scope_emps(db, campanha_id)
        if not scope_emps:
            # segurança: sem EMPs não calcula nada
            scope_emps = []

    # Query base: soma valor_total por vendedor e emp (para montar emp_hint)
    q = (
        db.query(
            Venda.vendedor.label("vendedor"),
            Venda.emp.label("emp"),
            func.sum(Venda.valor_total).label("total"),
        )
        .filter(Venda.movimento >= ini)
        .filter(Venda.movimento <= fim)
        .filter(or_(marca_col == marca, marca_col.like(f"%{marca}%")))
    )

    if scope_mode == "POR_EMP":
        if scope_emps:
            q = q.filter(Venda.emp.in_(scope_emps))
        else:
            # sem escopo => nenhum resultado
            rows = []
            ranked: list[RankingRow] = []
            # limpa snapshot do mês
            db.query(CampanhaV2ResultadoNew).filter(
                and_(CampanhaV2ResultadoNew.campanha_id == campanha_id,
                     CampanhaV2ResultadoNew.ano == ano,
                     CampanhaV2ResultadoNew.mes == mes)
            ).delete(synchronize_session=False)
            db.flush()
            sync_pagamentos_v2(db, ano, mes, actor=actor or "")
            return {"ok": True, "rows": 0, "ini": str(ini), "fim": str(fim)}

    q = q.group_by(Venda.vendedor, Venda.emp)

    per_emp = {}
    for vend, emp, total in q.all():
        vend_u = _upper(vend)
        if not vend_u:
            continue
        emp_i = int(emp) if emp is not None else None
        tot = float(total or 0.0)
        per_emp.setdefault(vend_u, {})
        per_emp[vend_u][emp_i] = per_emp[vend_u].get(emp_i, 0.0) + tot

    ranked: list[RankingRow] = []
    for vend_u, m in per_emp.items():
        total = sum(float(x or 0.0) for x in m.values())
        if total < minimo:
            continue
        # emp_hint: se só um emp, usa ele; senão None
        emps_nonnull = [e for e in m.keys() if e is not None]
        emp_hint = emps_nonnull[0] if len(set(emps_nonnull)) == 1 else None
        ranked.append(RankingRow(vendedor=vend_u, total=total, emp_hint=emp_hint, por_emp={int(k) if k is not None else 0: float(v) for k, v in m.items()}))

    ranked.sort(key=lambda r: r.total, reverse=True)

    # Prêmios
    p1 = float(getattr(camp, "premio_top1", 0.0) or 0.0)
    p2 = float(getattr(camp, "premio_top2", 0.0) or 0.0)
    p3 = float(getattr(camp, "premio_top3", 0.0) or 0.0)

    # Remove snapshot anterior dessa competência
    db.query(CampanhaV2ResultadoNew).filter(
        and_(
            CampanhaV2ResultadoNew.campanha_id == campanha_id,
            CampanhaV2ResultadoNew.ano == ano,
            CampanhaV2ResultadoNew.mes == mes,
        )
    ).delete(synchronize_session=False)
    db.flush()

    # Insere snapshot
    for idx, r in enumerate(ranked, start=1):
        premio = 0.0
        if idx == 1:
            premio = p1
        elif idx == 2:
            premio = p2
        elif idx == 3:
            premio = p3

        detalhes = {
            "tipo": TIPO_RANKING_MARCA,
            "marca": marca,
            "minimo": minimo,
            "periodo": {"ini": str(ini), "fim": str(fim)},
            "scope_mode": scope_mode,
            "scope_emps": scope_emps if scope_mode == "POR_EMP" else None,
            "por_emp": r.por_emp,
        }

        db.add(
            CampanhaV2ResultadoNew(
                campanha_id=campanha_id,
                ano=ano,
                mes=mes,
                emp=r.emp_hint if scope_mode == "POR_EMP" else None,
                vendedor=r.vendedor,
                valor_atual=float(r.total),
                posicao=int(idx),
                atingiu=True,
                premio=float(premio or 0.0),
                detalhes_json=_json_dumps(detalhes),
            )
        )

    # Sincroniza com financeiro
    sync_pagamentos_v2(db, ano, mes, actor=actor or "")

    return {"ok": True, "rows": len(ranked), "ini": str(ini), "fim": str(fim)}
