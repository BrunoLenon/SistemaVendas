# -*- coding: utf-8 -*-
"""Metas helpers (Crescimento / MIX / Share de Marcas).

Evolução leve do módulo para suportar metas de lojas, com:
- escopo por vendedor ou gerente/loja
- margem manual por mês
- gate de faturamento mínimo
- teto opcional de % de premiação
- bônus extra manual (ex.: checklist/avaliação)
"""

from __future__ import annotations

import calendar
from datetime import date, datetime
from decimal import Decimal, ROUND_HALF_UP

from sqlalchemy import text

from sv_utils import _emp_norm

from db import (
    VendasResumoPeriodo,
    MetaPrograma,
    MetaEscala,
    MetaMarca,
    MetaBaseManual,
    MetaResultado,
)

META_GERENTE_ALIAS = "__GERENTE__"
META_GERENTE_LABEL = "GERENTE"


def _periodo_bounds_ym(ano: int, mes: int) -> tuple[date, date]:
    inicio = date(int(ano), int(mes), 1)
    fim = date(int(ano), int(mes), calendar.monthrange(int(ano), int(mes))[1])
    return inicio, fim


def _as_decimal(v) -> Decimal:
    try:
        if v is None:
            return Decimal("0")
        return Decimal(str(v))
    except Exception:
        return Decimal("0")


def _money2(v: Decimal) -> Decimal:
    return v.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _normalize_limit_percent(limit_value: float | int | None) -> float:
    """Aceita 5 (=5%) ou 0.05 (=5%)."""
    try:
        v = float(limit_value or 0.0)
    except Exception:
        return 0.0
    if abs(v) < 1.0:
        return v * 100.0
    return v


def _normalize_bonus_percent(bonus_value: float | int | None) -> float:
    """Retorna bônus em pontos percentuais.

    Aceita:
    - 0.10  => 0,10%
    - 0.001 => 0,10% (estilo fórmula Excel multiplicada direto pelo valor)
    - 1.25  => 1,25%
    """
    try:
        v = float(bonus_value or 0.0)
    except Exception:
        return 0.0
    if abs(v) < 0.01:
        return v * 100.0
    return v


def _normalize_manual_pct(v) -> float | None:
    """Aceita 8 ou 0.08 e retorna 8.0. Campo vazio => None."""
    if v is None:
        return None
    try:
        raw = float(v)
    except Exception:
        return None
    if abs(raw) <= 1.0:
        return raw * 100.0
    return raw


def _meta_pick_bonus(escalas: list[MetaEscala], valor_metric: float) -> float:
    """Retorna o bonus_percentual da maior faixa cujo limite_min <= valor_metric.

    valor retornado em pontos percentuais (0,10 => 0,10%).
    """
    try:
        metric = float(valor_metric or 0.0)
    except Exception:
        metric = 0.0

    best = 0.0
    for esc in sorted(escalas, key=lambda x: (x.limite_min, x.ordem)):
        lim = _normalize_limit_percent(getattr(esc, "limite_min", 0.0))
        bon = _normalize_bonus_percent(getattr(esc, "bonus_percentual", 0.0))
        if metric >= lim:
            best = bon
    return float(best or 0.0)


def _sql_valor_mes_signed(vendedor_filter: bool = True):
    filtro_vendedor = "AND vendedor = :vendedor" if vendedor_filter else ""
    return f"""
        SELECT
          SUM(
            CASE
              WHEN mov_tipo_movto IN ('CA','DS') THEN -COALESCE(valor_total,0)
              ELSE COALESCE(valor_total,0)
            END
          )::double precision AS valor_mes
        FROM vendas
        WHERE emp = :emp
          {filtro_vendedor}
          AND movimento BETWEEN :ini AND :fim
    """


def _sql_valor_marcas_signed(vendedor_filter: bool = True):
    filtro_vendedor = "AND vendedor = :vendedor" if vendedor_filter else ""
    return f"""
      SELECT
        SUM(
          CASE
            WHEN UPPER(COALESCE(marca,'')) = ANY(:marcas)
              THEN CASE WHEN mov_tipo_movto IN ('CA','DS') THEN -COALESCE(valor_total,0) ELSE COALESCE(valor_total,0) END
            ELSE 0
          END
        )::double precision AS valor_marcas,
        SUM(
          CASE
            WHEN mov_tipo_movto IN ('CA','DS') THEN -COALESCE(valor_total,0)
            ELSE COALESCE(valor_total,0)
          END
        )::double precision AS valor_mes
      FROM vendas
      WHERE emp = :emp
        {filtro_vendedor}
        AND movimento BETWEEN :ini AND :fim
    """


def _query_valor_mes(db, ano: int, mes: int, emp: str, vendedor: str) -> float:
    vend = (vendedor or '').strip().upper()
    emp_n = _emp_norm(emp)

    try:
        q = (
            db.query(VendasResumoPeriodo.valor_venda)
            .filter(
                VendasResumoPeriodo.vendedor == vend,
                VendasResumoPeriodo.ano == ano,
                VendasResumoPeriodo.mes == mes,
            )
        )
        if emp_n:
            q_emp = q.filter(VendasResumoPeriodo.emp == emp_n).one_or_none()
            if q_emp is not None:
                return float(q_emp[0] or 0.0)
            q_fallback = q.filter(VendasResumoPeriodo.emp.in_(['', 'EMPTY'])).one_or_none()
            if q_fallback is not None:
                return float(q_fallback[0] or 0.0)
        else:
            q_fallback = q.filter(VendasResumoPeriodo.emp.in_(['', 'EMPTY'])).one_or_none()
            if q_fallback is not None:
                return float(q_fallback[0] or 0.0)
    except Exception:
        pass

    inicio, fim = _periodo_bounds_ym(ano, mes)
    sql = _sql_valor_mes_signed(vendedor_filter=True)
    row = db.execute(text(sql), {"emp": emp_n, "vendedor": vend, "ini": inicio, "fim": fim}).fetchone()
    return float(row[0] or 0.0) if row else 0.0


def _query_valor_emp_mes(db, ano: int, mes: int, emp: str) -> float:
    emp_n = _emp_norm(emp)
    inicio, fim = _periodo_bounds_ym(ano, mes)

    try:
        row = db.execute(
            text(
                """
                SELECT COALESCE(SUM(valor_venda), 0)::double precision
                FROM vendas_resumo_periodo
                WHERE emp = :emp
                  AND ano = :ano
                  AND mes = :mes
                """
            ),
            {"emp": emp_n, "ano": ano, "mes": mes},
        ).fetchone()
        if row is not None and row[0] is not None:
            return float(row[0] or 0.0)
    except Exception:
        pass

    sql = _sql_valor_mes_signed(vendedor_filter=False)
    row = db.execute(text(sql), {"emp": emp_n, "ini": inicio, "fim": fim}).fetchone()
    return float(row[0] or 0.0) if row else 0.0


def _query_mix_itens(db, ano: int, mes: int, emp: str, vendedor: str) -> float:
    vend = (vendedor or '').strip().upper()
    emp_n = _emp_norm(emp)

    try:
        q = (
            db.query(VendasResumoPeriodo.mix_produtos)
            .filter(
                VendasResumoPeriodo.vendedor == vend,
                VendasResumoPeriodo.ano == ano,
                VendasResumoPeriodo.mes == mes,
            )
        )
        if emp_n:
            q_emp = q.filter(VendasResumoPeriodo.emp == emp_n).one_or_none()
            if q_emp is not None:
                return float(q_emp[0] or 0.0)
            q_fallback = q.filter(VendasResumoPeriodo.emp.in_(['', 'EMPTY'])).one_or_none()
            if q_fallback is not None:
                return float(q_fallback[0] or 0.0)
        else:
            q_fallback = q.filter(VendasResumoPeriodo.emp.in_(['', 'EMPTY'])).one_or_none()
            if q_fallback is not None:
                return float(q_fallback[0] or 0.0)
    except Exception:
        pass

    inicio, fim = _periodo_bounds_ym(ano, mes)
    sql = """
      WITH por_produto AS (
        SELECT
          mestre,
          SUM(
            CASE
              WHEN mov_tipo_movto = 'CA' THEN -COALESCE(qtdade_vendida,0)
              WHEN mov_tipo_movto = 'DS' THEN 0
              ELSE COALESCE(qtdade_vendida,0)
            END
          ) AS qtd_liquida
        FROM vendas
        WHERE emp = :emp
          AND vendedor = :vendedor
          AND movimento BETWEEN :ini AND :fim
          AND mestre IS NOT NULL AND mestre <> ''
        GROUP BY mestre
      )
      SELECT COUNT(*)::double precision
      FROM por_produto
      WHERE qtd_liquida > 0
    """
    row = db.execute(text(sql), {"emp": emp_n, "vendedor": vend, "ini": inicio, "fim": fim}).fetchone()
    return float(row[0] or 0.0) if row else 0.0


def _query_share_marca(db, ano: int, mes: int, emp: str, vendedor: str, marcas: list[str]) -> tuple[float, float, float]:
    inicio, fim = _periodo_bounds_ym(ano, mes)
    marcas_norm = [str(m).strip().upper() for m in (marcas or []) if str(m).strip()]
    sql = _sql_valor_marcas_signed(vendedor_filter=True)
    params = {"emp": _emp_norm(emp), "vendedor": (vendedor or '').strip().upper(), "ini": inicio, "fim": fim, "marcas": marcas_norm}
    row = db.execute(text(sql), params).fetchone()
    valor_marcas = float((row[0] or 0.0)) if row else 0.0
    valor_mes = float((row[1] or 0.0)) if row else 0.0
    share = (valor_marcas / valor_mes * 100.0) if valor_mes else 0.0
    return float(share), float(valor_marcas), float(valor_mes)


def _query_share_marca_emp(db, ano: int, mes: int, emp: str, marcas: list[str]) -> tuple[float, float, float]:
    inicio, fim = _periodo_bounds_ym(ano, mes)
    marcas_norm = [str(m).strip().upper() for m in (marcas or []) if str(m).strip()]
    sql = _sql_valor_marcas_signed(vendedor_filter=False)
    params = {"emp": _emp_norm(emp), "ini": inicio, "fim": fim, "marcas": marcas_norm}
    row = db.execute(text(sql), params).fetchone()
    valor_marcas = float((row[0] or 0.0)) if row else 0.0
    valor_mes = float((row[1] or 0.0)) if row else 0.0
    share = (valor_marcas / valor_mes * 100.0) if valor_mes else 0.0
    return float(share), float(valor_marcas), float(valor_mes)


def _get_vendedores_no_periodo(db, ano: int, mes: int, emps: list[str]) -> list[str]:
    inicio, fim = _periodo_bounds_ym(ano, mes)
    if emps:
        rows = db.execute(
            text("""
                SELECT DISTINCT vendedor
                FROM vendas
                WHERE emp = ANY(:emps)
                  AND movimento BETWEEN :ini AND :fim
                ORDER BY vendedor
            """),
            {"emps": emps, "ini": inicio, "fim": fim},
        ).fetchall()
    else:
        rows = db.execute(
            text("""
                SELECT DISTINCT vendedor
                FROM vendas
                WHERE movimento BETWEEN :ini AND :fim
                ORDER BY vendedor
            """),
            {"ini": inicio, "fim": fim},
        ).fetchall()
    return [str(r[0]).strip().upper() for r in rows if r and r[0] is not None and str(r[0]).strip()]


def _get_emps_no_periodo(db, ano: int, mes: int, emps_allowed: list[str]) -> list[str]:
    inicio, fim = _periodo_bounds_ym(ano, mes)
    if emps_allowed:
        rows = db.execute(
            text("""
                SELECT DISTINCT emp
                FROM vendas
                WHERE emp = ANY(:emps)
                  AND movimento BETWEEN :ini AND :fim
                ORDER BY emp
            """),
            {"emps": emps_allowed, "ini": inicio, "fim": fim},
        ).fetchall()
    else:
        rows = db.execute(
            text("""
                SELECT DISTINCT emp
                FROM vendas
                WHERE movimento BETWEEN :ini AND :fim
                ORDER BY emp
            """),
            {"ini": inicio, "fim": fim},
        ).fetchall()
    return [str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip()]


def _manual_inputs(db, meta_id: int, emp: str, vendedor: str):
    vend = (vendedor or '').strip().upper()
    return (
        db.query(MetaBaseManual)
        .filter(MetaBaseManual.meta_id == meta_id, MetaBaseManual.emp == emp, MetaBaseManual.vendedor == vend)
        .first()
    )


def _calc_and_upsert_meta_result(db, meta: MetaPrograma, emp: str, vendedor: str) -> MetaResultado:
    escalas = db.query(MetaEscala).filter(MetaEscala.meta_id == meta.id).order_by(MetaEscala.ordem.asc()).all() or []
    scope = (getattr(meta, "escopo", None) or "VENDEDOR").strip().upper()
    vendedor_ref = META_GERENTE_ALIAS if scope == "GERENTE" else (vendedor or '').strip().upper()
    vendedor_label = META_GERENTE_LABEL if scope == "GERENTE" else vendedor_ref

    res = (
        db.query(MetaResultado)
        .filter(
            MetaResultado.meta_id == meta.id,
            MetaResultado.emp == emp,
            MetaResultado.vendedor == vendedor_label,
            MetaResultado.ano == meta.ano,
            MetaResultado.mes == meta.mes,
        )
        .first()
    )
    if not res:
        res = MetaResultado(meta_id=meta.id, emp=emp, vendedor=vendedor_label, ano=meta.ano, mes=meta.mes)

    insumo = _manual_inputs(db, meta.id, emp, vendedor_ref)
    margem_pct = _normalize_manual_pct(getattr(insumo, "margem_percentual", None))
    bonus_extra_pct = _normalize_manual_pct(getattr(insumo, "bonus_extra_percentual", None)) or 0.0

    bonus = 0.0
    premio = Decimal("0.00")
    valor_mes = Decimal("0")

    if meta.tipo == "MIX":
        valor_mes = _as_decimal(_query_valor_mes(db, meta.ano, meta.mes, emp, vendedor_ref))
        mix = float(_query_mix_itens(db, meta.ano, meta.mes, emp, vendedor_ref))
        bonus = _meta_pick_bonus(escalas, mix)
        res.valor_mes = float(valor_mes)
        res.mix_itens_unicos = float(mix)
        res.valor_marcas = None
        res.share_pct = None
        res.base_valor = None
        res.crescimento_pct = None

    elif meta.tipo == "SHARE_MARCA":
        marcas = [m.marca for m in db.query(MetaMarca).filter(MetaMarca.meta_id == meta.id).all()]
        if scope == "GERENTE":
            share_pct, valor_marcas, valor_mes_f = _query_share_marca_emp(db, meta.ano, meta.mes, emp, marcas)
        else:
            share_pct, valor_marcas, valor_mes_f = _query_share_marca(db, meta.ano, meta.mes, emp, vendedor_ref, marcas)
        valor_mes = _as_decimal(valor_mes_f)
        bonus = _meta_pick_bonus(escalas, share_pct)
        res.valor_mes = float(valor_mes)
        res.valor_marcas = float(valor_marcas)
        res.share_pct = float(share_pct)
        res.mix_itens_unicos = None
        res.base_valor = None
        res.crescimento_pct = None

    else:  # CRESCIMENTO
        if scope == "GERENTE":
            valor_mes = _as_decimal(_query_valor_emp_mes(db, meta.ano, meta.mes, emp))
            base_auto = _as_decimal(_query_valor_emp_mes(db, meta.ano - 1, meta.mes, emp))
        else:
            valor_mes = _as_decimal(_query_valor_mes(db, meta.ano, meta.mes, emp, vendedor_ref))
            base_auto = _as_decimal(_query_valor_mes(db, meta.ano - 1, meta.mes, emp, vendedor_ref))

        if insumo and getattr(insumo, "base_valor", None) not in (None, 0, 0.0):
            base_val = _as_decimal(insumo.base_valor)
        else:
            base_val = base_auto

        crescimento_pct = 0.0
        if base_val != 0:
            crescimento_pct = float((valor_mes - base_val) / base_val * Decimal("100"))

        bonus = _meta_pick_bonus(escalas, crescimento_pct)
        res.valor_mes = float(valor_mes)
        res.base_valor = float(base_val)
        res.crescimento_pct = float(crescimento_pct)
        res.mix_itens_unicos = None
        res.share_pct = None
        res.valor_marcas = None

    try:
        faturamento_minimo = float(getattr(meta, "faturamento_minimo", 0.0) or 0.0)
    except Exception:
        faturamento_minimo = 0.0
    try:
        margem_minima = _normalize_manual_pct(getattr(meta, "margem_minima", 0.0)) or 0.0
    except Exception:
        margem_minima = 0.0
    try:
        teto_faturamento = float(getattr(meta, "teto_faturamento", 0.0) or 0.0)
    except Exception:
        teto_faturamento = 0.0
    try:
        teto_bonus_pct = _normalize_bonus_percent(getattr(meta, "teto_bonus_percentual", 0.0) or 0.0)
    except Exception:
        teto_bonus_pct = 0.0

    if faturamento_minimo > 0 and float(valor_mes) < faturamento_minimo:
        bonus = 0.0
    if margem_minima > 0:
        if margem_pct is None or margem_pct < margem_minima:
            bonus = 0.0
    if teto_faturamento > 0 and teto_bonus_pct > 0 and float(valor_mes) >= teto_faturamento:
        bonus = min(float(bonus or 0.0), float(teto_bonus_pct))

    premio = _money2(valor_mes * (Decimal(str(float(bonus or 0.0))) / Decimal("100")))
    if bonus_extra_pct > 0:
        premio = _money2(premio * (Decimal("1") + (Decimal(str(bonus_extra_pct)) / Decimal("100"))))

    res.bonus_percentual = float(bonus or 0.0)
    res.premio = float(premio)
    res.calculado_em = datetime.utcnow()
    db.add(res)
    db.commit()
    return res
