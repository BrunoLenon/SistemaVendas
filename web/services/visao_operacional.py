# -*- coding: utf-8 -*-
"""Regras compartilhadas de visão operacional aberta/histórico.

Objetivo: por padrão, páginas de campanhas/metas mostram somente o que ainda está
operacionalmente aberto para a competência. Histórico continua acessível por filtro.
"""
from __future__ import annotations

import calendar
from datetime import date
from typing import Any, Iterable

from db import FechamentoMensal

STATUS_ABERTAS = "abertas"
STATUS_ENCERRADAS = "encerradas"
STATUS_TODAS = "todas"
STATUS_VALIDOS = {STATUS_ABERTAS, STATUS_ENCERRADAS, STATUS_TODAS}


def normalize_status_filter(value: object, default: str = STATUS_ABERTAS) -> str:
    """Normaliza o filtro de situação usado nas telas.

    Aceita aliases para manter a URL amigável e tolerante.
    """
    raw = str(value or "").strip().lower()
    aliases = {
        "": default,
        "aberta": STATUS_ABERTAS,
        "abertas": STATUS_ABERTAS,
        "ativo": STATUS_ABERTAS,
        "ativos": STATUS_ABERTAS,
        "operacional": STATUS_ABERTAS,
        "operacionais": STATUS_ABERTAS,
        "historico": STATUS_ENCERRADAS,
        "histórico": STATUS_ENCERRADAS,
        "encerrada": STATUS_ENCERRADAS,
        "encerradas": STATUS_ENCERRADAS,
        "fechada": STATUS_ENCERRADAS,
        "fechadas": STATUS_ENCERRADAS,
        "pago": STATUS_ENCERRADAS,
        "pagas": STATUS_ENCERRADAS,
        "todos": STATUS_TODAS,
        "todas": STATUS_TODAS,
        "all": STATUS_TODAS,
    }
    out = aliases.get(raw, raw)
    return out if out in STATUS_VALIDOS else default


def status_filter_label(status: object) -> str:
    s = normalize_status_filter(status)
    if s == STATUS_ABERTAS:
        return "Abertas"
    if s == STATUS_ENCERRADAS:
        return "Histórico"
    return "Todas"


def periodo_bounds_ym(ano: int, mes: int) -> tuple[date, date]:
    ano = int(ano)
    mes = int(mes)
    return date(ano, mes, 1), date(ano, mes, calendar.monthrange(ano, mes)[1])


def get_fechamento_status_map(db: Any, ano: int, mes: int) -> dict[str, dict[str, Any]]:
    """Retorna status do fechamento por EMP para a competência.

    Ausência de registro é tratada como aberto na função is_emp_period_open().
    """
    out: dict[str, dict[str, Any]] = {}
    try:
        rows = (
            db.query(FechamentoMensal)
            .filter(FechamentoMensal.ano == int(ano), FechamentoMensal.mes == int(mes))
            .all()
        )
    except Exception:
        rows = []
    for r in rows or []:
        emp = str(getattr(r, "emp", "") or "").strip()
        if not emp:
            continue
        status = str(getattr(r, "status", "") or "aberto").strip().lower()
        fechado = bool(getattr(r, "fechado", False))
        out[emp] = {
            "status": status or "aberto",
            "fechado": fechado,
            "fechado_em": getattr(r, "fechado_em", None),
        }
    return out


def is_emp_period_open(status_map: dict[str, dict[str, Any]] | None, emp: object) -> bool:
    """True quando a EMP ainda está aberta operacionalmente.

    EMP sem registro de fechamento = aberta. EMP global/sem código = aberta.
    Se status for a_pagar/pago ou fechado=True, consideramos encerrada para telas operacionais.
    """
    emp_s = str(emp or "").strip()
    if not emp_s or emp_s.upper() in {"ALL", "*", "GLOBAL"}:
        return True
    rec = (status_map or {}).get(emp_s)
    if not rec:
        return True
    status = str(rec.get("status") or "aberto").strip().lower()
    fechado = bool(rec.get("fechado"))
    if status in {"a_pagar", "pago", "fechado", "encerrado"}:
        return False
    if fechado and status != "aberto":
        return False
    # Em bases antigas, fechado=True pode existir sem status atualizado; também escondemos.
    if fechado and status in {"", "aberto"}:
        return False
    return True


def filter_emps_by_status(emps: Iterable[object], status_filter: object, status_map: dict[str, dict[str, Any]] | None) -> list[str]:
    status = normalize_status_filter(status_filter)
    clean = []
    seen = set()
    for e in emps or []:
        emp = str(e or "").strip()
        if not emp or emp in seen:
            continue
        seen.add(emp)
        clean.append(emp)
    if status == STATUS_TODAS:
        return clean
    if status == STATUS_ABERTAS:
        return [e for e in clean if is_emp_period_open(status_map, e)]
    return [e for e in clean if not is_emp_period_open(status_map, e)]


def campaign_overlaps_month(campanha: Any, ano: int, mes: int) -> bool:
    ini_mes, fim_mes = periodo_bounds_ym(ano, mes)
    di = getattr(campanha, "data_inicio", None)
    df = getattr(campanha, "data_fim", None)
    if not di or not df:
        return False
    try:
        return di <= fim_mes and df >= ini_mes
    except Exception:
        return False


def is_campaign_open_operational(campanha: Any, ano: int, mes: int, status_map: dict[str, dict[str, Any]] | None) -> bool:
    ativo = int(getattr(campanha, "ativo", 0) or 0) == 1
    if not ativo:
        return False
    if not campaign_overlaps_month(campanha, ano, mes):
        return False
    return is_emp_period_open(status_map, getattr(campanha, "emp", ""))


def filter_campaigns_operational(campanhas: Iterable[Any], ano: int, mes: int, status_filter: object, status_map: dict[str, dict[str, Any]] | None) -> list[Any]:
    status = normalize_status_filter(status_filter)
    rows = list(campanhas or [])
    if status == STATUS_TODAS:
        return rows
    if status == STATUS_ABERTAS:
        return [c for c in rows if is_campaign_open_operational(c, ano, mes, status_map)]
    return [c for c in rows if not is_campaign_open_operational(c, ano, mes, status_map)]
