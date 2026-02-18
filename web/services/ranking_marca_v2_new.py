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
import logging
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

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TIPO_RANKING_MARCA = "RANKING_MARCA"


def _upper(s: str | None) -> str:
    return (s or "").strip().upper()


def _to_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None or v == "":
            return float(default)
        # Remove pontos de milhar e substitui vírgula por ponto
        return float(str(v).replace(".", "").replace(",", "."))
    except Exception as e:
        logger.error(f"Erro ao converter para float: {v} - {e}")
        return float(default)


def _to_int(v: Any, default: int = 0) -> int:
    try:
        if v is None or v == "":
            return int(default)
        return int(v)
    except Exception as e:
        logger.error(f"Erro ao converter para int: {v} - {e}")
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
    except Exception as e:
        logger.error(f"Erro ao converter data: {v} - {e}")
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


def list_campaigns_for_admin(db) -> list[CampanhaV2MasterNew]:
    """Lista todas as campanhas para o admin"""
    logger.info("Listando campanhas para admin")
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
    logger.info(f"Listando campanhas para usuário role={role}, allowed_emps={allowed_emps}")
    
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
        # Se não tem EMPs permitidas, retorna apenas campanhas GLOBAL
        logger.info("Usuário sem EMPs permitidas, retornando apenas campanhas GLOBAL")
        return [c for c in camps if (c.scope_mode or "GLOBAL").upper() == "GLOBAL"]

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

    logger.info(f"Total de campanhas visíveis: {len(visible)}")
    return visible


def get_scope_emps(db, campanha_id: int) -> list[int]:
    """Retorna lista de EMPs do escopo da campanha"""
    logger.info(f"Buscando EMPs do escopo para campanha {campanha_id}")
    rows = (
        db.query(CampanhaV2ScopeEMPNew.emp)
        .filter(CampanhaV2ScopeEMPNew.campanha_id == int(campanha_id))
        .order_by(CampanhaV2ScopeEMPNew.emp.asc())
        .all()
    )
    emps = [int(r[0]) for r in rows if r and r[0] is not None]
    logger.info(f"EMPs encontradas: {emps}")
    return emps


def set_scope_emps(db, campanha_id: int, emps: Iterable[int]) -> None:
    """Define as EMPs do escopo da campanha"""
    campanha_id = int(campanha_id)
    logger.info(f"Definindo escopo EMPs para campanha {campanha_id}: {list(emps) if emps else []}")
    
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
    db.flush()
    logger.info(f"Escopo atualizado com {len(seen)} EMPs")


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
    """Cria ou atualiza uma campanha"""
    logger.info(f"Salvando campanha: id={campanha_id}, nome={nome}, scope_mode={scope_mode}")
    
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
        logger.info(f"Nova campanha criada com ID: {c.id}")

    if scope_mode == "POR_EMP":
        set_scope_emps(db, int(c.id), emps or [])
    else:
        # limpa escopo se não for por emp
        db.query(CampanhaV2ScopeEMPNew).filter(CampanhaV2ScopeEMPNew.campanha_id == int(c.id)).delete()
        db.flush()

    return c


def delete_campaign(db, campanha_id: int) -> None:
    """Remove campanha e todos os registros relacionados"""
    campanha_id = int(campanha_id)
    logger.info(f"Iniciando exclusão da campanha {campanha_id}")
    
    # 1. Remove escopo EMPs
    q1 = db.query(CampanhaV2ScopeEMPNew).filter(CampanhaV2ScopeEMPNew.campanha_id == campanha_id).delete()
    logger.info(f"Removidos {q1} registros de escopo EMP")
    
    # 2. Remove resultados/snapshots
    q2 = db.query(CampanhaV2ResultadoNew).filter(CampanhaV2ResultadoNew.campanha_id == campanha_id).delete()
    logger.info(f"Removidos {q2} registros de resultados")
    
    # 3. Remove pagamentos vinculados
    q3 = db.query(FinanceiroPagamento).filter(
        and_(FinanceiroPagamento.origem_tipo == "V2", 
             FinanceiroPagamento.origem_id == campanha_id)
    ).delete(synchronize_session=False)
    logger.info(f"Removidos {q3} registros de pagamentos")
    
    # 4. Remove a campanha
    q4 = db.query(CampanhaV2MasterNew).filter(CampanhaV2MasterNew.id == campanha_id).delete()
    logger.info(f"Campanha removida: {q4}")
    
    db.flush()
    logger.info(f"Exclusão da campanha {campanha_id} concluída")


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
    logger.info(
        f"Iniciando recálculo: campanha={campanha_id}, ano={ano}, mes={mes}, actor={actor}"
    )

    campanha_id = int(campanha_id)
    ano = int(ano)
    mes = int(mes)

    # Validações básicas
    if ano < 2000 or ano > 2100:
        logger.error(f"Ano inválido: {ano}")
        return {"ok": False, "error": f"Ano inválido: {ano}", "rows": 0}

    if mes < 1 or mes > 12:
        logger.error(f"Mês inválido: {mes}")
        return {"ok": False, "error": f"Mês inválido: {mes}", "rows": 0}

    camp = (
        db.query(CampanhaV2MasterNew)
        .filter(CampanhaV2MasterNew.id == campanha_id)
        .first()
    )
    if not camp:
        logger.error(f"Campanha não encontrada: {campanha_id}")
        raise ValueError("Campanha não encontrada.")

    if (getattr(camp, "tipo", "") or "").upper() != TIPO_RANKING_MARCA:
        logger.error(f"Tipo de campanha inválido: {getattr(camp, 'tipo', None)}")
        raise ValueError("Tipo de campanha inválido para ranking por marca.")

    marca = _upper(getattr(camp, "marca_alvo", "") or "")
    if not marca:
        logger.error("Campanha sem marca definida (marca_alvo)")
        raise ValueError("Campanha sem marca definida (marca_alvo).")

    minimo = float(getattr(camp, "base_minima_valor", 0.0) or 0.0)
    scope_mode = (getattr(camp, "scope_mode", "GLOBAL") or "GLOBAL").upper()

    logger.info(
        f"Parâmetros da campanha: marca={marca}, minimo={minimo}, scope_mode={scope_mode}"
    )

    # Período base do mês
    ini_mes, fim_mes = _month_bounds(ano, mes)
    logger.info(f"Período base: {ini_mes} até {fim_mes}")

    # Ajusta pela vigência (se definida)
    vig_ini = getattr(camp, "vigencia_inicio", None)
    vig_fim = getattr(camp, "vigencia_fim", None)

    ini = max(ini_mes, vig_ini) if vig_ini else ini_mes
    fim = min(fim_mes, vig_fim) if vig_fim else fim_mes

    logger.info(f"Período ajustado pela vigência: {ini} até {fim}")

    # Escopo EMPs (se POR_EMP)
    scope_emps: list[int] = []
    if scope_mode == "POR_EMP":
        scope_emps = get_scope_emps(db, campanha_id)
        logger.info(f"EMPs do escopo: {scope_emps}")

        if not scope_emps:
            logger.warning("Campanha POR_EMP sem EMPs definidas no escopo")

            # Limpa snapshot do mês
            db.query(CampanhaV2ResultadoNew).filter(
                and_(
                    CampanhaV2ResultadoNew.campanha_id == campanha_id,
                    CampanhaV2ResultadoNew.ano == ano,
                    CampanhaV2ResultadoNew.mes == mes,
                )
            ).delete(synchronize_session=False)
            db.flush()

            sync_pagamentos_v2(db, ano, mes, actor=actor or "")
            return {
                "ok": True,
                "rows": 0,
                "ini": str(ini),
                "fim": str(fim),
                "motivo": "Sem EMPs definidas no escopo",
                "scope_emps": [],
            }

    # PRIMEIRO: verificar se existem vendas da marca no período
    logger.info("Verificando vendas da marca %s no período...", marca)
    count_vendas = (
        db.query(func.count())
        .select_from(Venda)
        .filter(Venda.movimento >= ini)
        .filter(Venda.movimento <= fim)
        .filter(func.upper(Venda.marca) == marca)
        .scalar()
    ) or 0

    logger.info(f"Total de vendas da marca {marca} no período: {count_vendas}")

    if int(count_vendas) == 0:
        logger.warning(
            f"NENHUMA venda encontrada para a marca {marca} no período {ini}..{fim}!"
        )

        # Limpa snapshot do mês
        db.query(CampanhaV2ResultadoNew).filter(
            and_(
                CampanhaV2ResultadoNew.campanha_id == campanha_id,
                CampanhaV2ResultadoNew.ano == ano,
                CampanhaV2ResultadoNew.mes == mes,
            )
        ).delete(synchronize_session=False)
        db.flush()

        sync_pagamentos_v2(db, ano, mes, actor=actor or "")

        return {
            "ok": True,
            "rows": 0,
            "ini": str(ini),
            "fim": str(fim),
            "motivo": f"Nenhuma venda encontrada para a marca {marca} no período",
            "total_vendas_marca": int(count_vendas),
            "scope_emps": scope_emps if scope_mode == "POR_EMP" else [],
        }

    # Query base: soma valor_total por vendedor e emp
    logger.info("Executando query de vendas por vendedor...")

    q = (
        db.query(
            Venda.vendedor.label("vendedor"),
            Venda.emp.label("emp"),
            func.sum(Venda.valor_total).label("total"),
        )
        .filter(Venda.movimento >= ini)
        .filter(Venda.movimento <= fim)
        .filter(func.upper(Venda.marca) == marca)
    )

    # Aplica filtro de escopo EMP
    if scope_mode == "POR_EMP" and scope_emps:
        q = q.filter(Venda.emp.in_(scope_emps))
        logger.info(f"Aplicado filtro de EMPs: {scope_emps}")

    q = q.group_by(Venda.vendedor, Venda.emp)

    results = q.all()
    logger.info(f"Query executada, retornou {len(results)} linhas")

    # Processa resultados
    per_emp: dict[str, dict[int | None, float]] = {}
    for vend, emp, total in results:
        vend_u = _upper(vend)
        if not vend_u:
            continue
        emp_i = int(emp) if emp is not None else None
        tot = float(total or 0.0)
        if vend_u not in per_emp:
            per_emp[vend_u] = {}
        per_emp[vend_u][emp_i] = per_emp[vend_u].get(emp_i, 0.0) + tot

    logger.info(f"Processados {len(per_emp)} vendedores únicos")

    ranked: list[RankingRow] = []
    for vend_u, emp_dict in per_emp.items():
        total = sum(float(x or 0.0) for x in emp_dict.values())

        if total < minimo:
            logger.debug(
                f"Vendedor {vend_u} NÃO atingiu mínimo: {total:.2f} < {minimo:.2f}"
            )
            continue

        emps_nonnull = [e for e in emp_dict.keys() if e is not None]
        emp_hint = emps_nonnull[0] if len(emps_nonnull) == 1 else None

        ranked.append(
            RankingRow(
                vendedor=vend_u,
                total=float(total),
                emp_hint=emp_hint,
                por_emp={
                    int(k) if k is not None else 0: float(v)
                    for k, v in emp_dict.items()
                },
            )
        )

    logger.info(
        f"Vendedores qualificados (atingiram mínimo R$ {minimo:.2f}): {len(ranked)}"
    )

    ranked.sort(key=lambda r: r.total, reverse=True)

    # Prêmios
    p1 = float(getattr(camp, "premio_top1", 0.0) or 0.0)
    p2 = float(getattr(camp, "premio_top2", 0.0) or 0.0)
    p3 = float(getattr(camp, "premio_top3", 0.0) or 0.0)
    logger.info(f"Prêmios configurados: 1º={p1}, 2º={p2}, 3º={p3}")

    # Remove snapshot anterior dessa competência
    deleted = db.query(CampanhaV2ResultadoNew).filter(
        and_(
            CampanhaV2ResultadoNew.campanha_id == campanha_id,
            CampanhaV2ResultadoNew.ano == ano,
            CampanhaV2ResultadoNew.mes == mes,
        )
    ).delete(synchronize_session=False)
    logger.info(f"Removidos {deleted} snapshots anteriores")
    db.flush()

    inseridos = 0
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

        resultado = CampanhaV2ResultadoNew(
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
        db.add(resultado)
        inseridos += 1
        logger.info(
            f"Inserido resultado: posição {idx}, vendedor {r.vendedor}, prêmio R$ {premio:.2f}"
        )

    db.flush()
    logger.info(f"Inseridos {inseridos} novos snapshots")

    # Sincroniza com financeiro
    logger.info("Sincronizando com financeiro...")
    sync_pagamentos_v2(db, ano, mes, actor=actor or "")
    logger.info("Sincronização concluída")

    resultado = {
        "ok": True,
        "rows": len(ranked),
        "inseridos": inseridos,
        "ini": str(ini),
        "fim": str(fim),
        "scope_emps": scope_emps,
        "total_vendas_marca": int(count_vendas),
    }

    logger.info(f"Recálculo finalizado: {resultado}")
    return resultado

