"""Metas helpers (Crescimento / MIX / Share de Marcas).

Extraído do app.py como **refatoração pura** (sem mudança de comportamento).
Mantém os mesmos nomes/assinaturas usados pelas rotas.
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


def _meta_pick_bonus(escalas: list[MetaEscala], valor_metric: float) -> float:
    """Retorna o bonus_percentual da maior faixa cujo limite_min <= valor_metric."""
    try:
        v = float(valor_metric or 0.0)
    except Exception:
        v = 0.0
    best = 0.0
    for esc in sorted(escalas, key=lambda x: (x.limite_min, x.ordem)):
        try:
            lim = float(esc.limite_min or 0.0)
        except Exception:
            lim = 0.0
        if v >= lim:
            best = float(esc.bonus_percentual or 0.0)
    return float(best or 0.0)


def _sql_valor_mes_signed():
    # CA e DS deduzem do valor. Outros somam.
    return """
        SUM(
          CASE
            WHEN mov_tipo_movto IN ('CA','DS') THEN -COALESCE(valor_total,0)
            ELSE COALESCE(valor_total,0)
          END
        )::double precision
    """


def _sql_valor_marcas_signed(marcas: list[str]):
    # marcas: lista já normalizada para UPPER
    # Faz match exato em vendas.marca (que no seu banco costuma estar em maiúsculo)
    if not marcas:
        return "0::double precision"
    # usa ANY(:marcas) para evitar string concat insegura
    return f"""
        SUM(
          CASE
            WHEN UPPER(COALESCE(marca,'')) = ANY(:marcas)
              THEN CASE WHEN mov_tipo_movto IN ('CA','DS') THEN -COALESCE(valor_total,0) ELSE COALESCE(valor_total,0) END
            ELSE 0
          END
        )::double precision
    """


def _query_valor_mes(db, ano: int, mes: int, emp: str, vendedor: str) -> float:
    """Retorna o valor líquido do mês para (EMP, vendedor).
    Prioridade:
      1) Base manual/importada em vendas_resumo_periodo (ano/mes do registro)
      2) Fallback: cálculo direto na tabela vendas (signed OA/DS/CA)
    Observação: versões antigas gravaram emp como ''/EMPTY; fazemos fallback seguro.
    """
    vend = (vendedor or '').strip().upper()
    emp_n = _emp_norm(emp)

    # 1) tenta base manual (resumo)
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
            # fallback compat: registros antigos sem emp
            q_fallback = q.filter(VendasResumoPeriodo.emp.in_(['', 'EMPTY'])).one_or_none()
            if q_fallback is not None:
                return float(q_fallback[0] or 0.0)
        else:
            # se emp vier vazio, tenta pegar qualquer um (mas preferimos ''/EMPTY)
            q_fallback = q.filter(VendasResumoPeriodo.emp.in_(['', 'EMPTY'])).one_or_none()
            if q_fallback is not None:
                return float(q_fallback[0] or 0.0)
    except Exception:
        pass

    # 2) fallback: cálculo na tabela vendas
    inicio, fim = _periodo_bounds_ym(ano, mes)
    sql = f"""
      SELECT {_sql_valor_mes_signed()} AS valor_mes
      FROM vendas
      WHERE emp = :emp
        AND vendedor = :vendedor
        AND movimento BETWEEN :ini AND :fim
    """
    row = db.execute(text(sql), {"emp": emp_n, "vendedor": vend, "ini": inicio, "fim": fim}).fetchone()
    return float(row[0] or 0.0) if row else 0.0


def _query_mix_itens(db, ano: int, mes: int, emp: str, vendedor: str) -> float:
    """Retorna MIX (qtd de itens/produtos) do mês para (EMP, vendedor).
    Prioridade:
      1) Base manual/importada em vendas_resumo_periodo.mix_produtos
      2) Fallback: cálculo na tabela vendas (qtd_liquida > 0 por mestre)
    Compat: emp antigo ''/EMPTY.
    """
    vend = (vendedor or '').strip().upper()
    emp_n = _emp_norm(emp)

    # 1) tenta base manual (resumo)
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

    # 2) fallback: calcula no detalhe em vendas
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
    """Retorna (share_pct, valor_marcas, valor_total_mes)."""
    inicio, fim = _periodo_bounds_ym(ano, mes)
    marcas_norm = [str(m).strip().upper() for m in (marcas or []) if str(m).strip()]
    sql = f"""
      SELECT
        ({_sql_valor_marcas_signed(marcas_norm)}) AS valor_marcas,
        ({_sql_valor_mes_signed()}) AS valor_mes
      FROM vendas
      WHERE emp = :emp
        AND vendedor = :vendedor
        AND movimento BETWEEN :ini AND :fim
    """
    params = {"emp": emp, "vendedor": vendedor, "ini": inicio, "fim": fim, "marcas": marcas_norm}
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
    return [str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip()]


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


def _calc_and_upsert_meta_result(db, meta: MetaPrograma, emp: str, vendedor: str) -> MetaResultado:
    # Carrega escalas e configurações
    escalas = db.query(MetaEscala).filter(MetaEscala.meta_id == meta.id).order_by(MetaEscala.ordem.asc()).all()
    if not escalas:
        escalas = []

    # Resultado existente
    res = (
        db.query(MetaResultado)
        .filter(
            MetaResultado.meta_id == meta.id,
            MetaResultado.emp == emp,
            MetaResultado.vendedor == vendedor,
            MetaResultado.ano == meta.ano,
            MetaResultado.mes == meta.mes,
        )
        .first()
    )
    if not res:
        res = MetaResultado(meta_id=meta.id, emp=emp, vendedor=vendedor, ano=meta.ano, mes=meta.mes)

    # calcula conforme tipo
    bonus = 0.0
    premio = Decimal("0.00")

    if meta.tipo == "MIX":
        valor_mes = _as_decimal(_query_valor_mes(db, meta.ano, meta.mes, emp, vendedor))
        mix = float(_query_mix_itens(db, meta.ano, meta.mes, emp, vendedor))
        bonus = _meta_pick_bonus(escalas, mix)
        premio = _money2(valor_mes * (Decimal(str(bonus)) / Decimal("100")))
        res.valor_mes = float(valor_mes)
        res.base_valor = 0.0
        res.crescimento_pct = mix
        res.bonus_percentual = float(bonus)
        res.premio = float(premio)

    elif meta.tipo == "SHARE":
        # marcas alvo
        marcas = [m.marca for m in db.query(MetaMarca).filter(MetaMarca.meta_id == meta.id).all()]
        share_pct, valor_marcas, valor_mes_total = _query_share_marca(db, meta.ano, meta.mes, emp, vendedor, marcas)
        valor_mes = _as_decimal(valor_mes_total)
        bonus = _meta_pick_bonus(escalas, share_pct)
        premio = _money2(valor_mes * (Decimal(str(bonus)) / Decimal("100")))
        res.valor_mes = float(valor_mes_total)
        res.base_valor = float(valor_marcas)
        res.crescimento_pct = float(share_pct)
        res.bonus_percentual = float(bonus)
        res.premio = float(premio)

    else:
        # Crescimento por valor: compara com base manual ou mês do ano passado
        valor_mes = _as_decimal(_query_valor_mes(db, meta.ano, meta.mes, emp, vendedor))

        bm = (
            db.query(MetaBaseManual)
            .filter(MetaBaseManual.meta_id == meta.id, MetaBaseManual.emp == emp, MetaBaseManual.vendedor == vendedor)
            .first()
        )
        if bm and bm.base_valor is not None:
            base_val = _as_decimal(bm.base_valor)
        else:
            # base automática: mesmo mês do ano passado
            base_val = _as_decimal(_query_valor_mes(db, meta.ano - 1, meta.mes, emp, vendedor))

        base_f = float(base_val)
        if base_val != 0:
            crescimento_pct = float((valor_mes - base_val) / base_val * Decimal("100"))
        else:
            crescimento_pct = 0.0

        bonus = _meta_pick_bonus(escalas, crescimento_pct)
        premio = _money2(valor_mes * (Decimal(str(bonus)) / Decimal("100")))

        res.valor_mes = float(valor_mes)
        res.base_valor = float(base_val)
        res.crescimento_pct = float(crescimento_pct)
        res.bonus_percentual = float(bonus)
        res.premio = float(premio)

    res.calculado_em = datetime.utcnow()
    db.add(res)
    db.commit()
    return res
