# -*- coding: utf-8 -*-
"""Motor oficial de Metas.

Regras contempladas:
- Crescimento: compara venda liquida do mes contra Meta Base manual.
- Mix: conta codigos MESTRE unicos vendidos, considerando saldo liquido de quantidade.
- Marcas: mede a participacao de um grupo de marcas sobre a venda total do vendedor.

Movimentos:
- OA, VV e SV = venda positiva.
- DS e CA = devolucao/cancelamento, entram como negativo.
- Outros movimentos sao ignorados para manter o pagamento auditavel.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal, ROUND_HALF_UP
from typing import Iterable

from sqlalchemy import text

from sv_utils import _emp_norm
from db import (
    Emp,
    MetaBaseManual,
    MetaEscala,
    MetaMarca,
    MetaMargemVendedor,
    MetaPrograma,
    MetaProgramaEmp,
    MetaResultado,
    Usuario,
    UsuarioEmp,
)

POSITIVE_MOV_TYPES = ("OA", "VV", "SV")
NEGATIVE_MOV_TYPES = ("DS", "CA")
META_GERENTE_ALIAS = "__GERENTE__"  # mantido por compatibilidade com telas antigas
META_GERENTE_LABEL = "GERENTE"


def periodo_bounds_ym(ano: int, mes: int) -> tuple[date, date]:
    ano = int(ano)
    mes = int(mes)
    inicio = date(ano, mes, 1)
    fim = date(ano, mes, calendar.monthrange(ano, mes)[1])
    return inicio, fim


# Alias antigo usado por partes legadas.
_periodo_bounds_ym = periodo_bounds_ym


def normalize_text(value: object) -> str:
    return str(value or "").strip().upper()


def normalize_emp(value: object) -> str:
    return _emp_norm(str(value or "").strip())


def as_decimal(value: object) -> Decimal:
    try:
        if value is None or value == "":
            return Decimal("0")
        return Decimal(str(value))
    except Exception:
        return Decimal("0")


def money2(value: Decimal | float | int) -> Decimal:
    return as_decimal(value).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def percent2(value: Decimal | float | int) -> Decimal:
    return as_decimal(value).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _mov_params() -> dict[str, tuple[str, ...]]:
    return {"positivos": list(POSITIVE_MOV_TYPES), "negativos": list(NEGATIVE_MOV_TYPES)}


def signed_value_sql(column_name: str = "valor_total") -> str:
    """Expressao SQL de valor assinado conforme regra comercial de vendas."""
    return f"""
        CASE
          WHEN COALESCE(qtdade_vendida,0) > 0
           AND UPPER(COALESCE(mov_tipo_movto,'')) = ANY(:negativos)
            THEN -ABS(COALESCE({column_name},0))
          WHEN COALESCE(qtdade_vendida,0) > 0
           AND UPPER(COALESCE(mov_tipo_movto,'')) = ANY(:positivos)
            THEN COALESCE({column_name},0)
          ELSE 0
        END
    """


def _scope_emp_clause(emps: list[str]) -> tuple[str, dict]:
    clean = [normalize_emp(e) for e in (emps or []) if normalize_emp(e)]
    if not clean:
        return "", {}
    return "AND emp = ANY(:emps)", {"emps": clean}


def query_valor_mes(db, ano: int, mes: int, emp: str, vendedor: str | None = None) -> float:
    """Venda liquida do mes para EMP e opcionalmente vendedor."""
    inicio, fim = periodo_bounds_ym(ano, mes)
    emp_n = normalize_emp(emp)
    vendedor_n = normalize_text(vendedor)
    vendedor_clause = "AND UPPER(COALESCE(vendedor,'')) = :vendedor" if vendedor_n else ""
    sql = f"""
        SELECT COALESCE(SUM({signed_value_sql('valor_total')}),0)::double precision
          FROM vendas
         WHERE emp = :emp
           {vendedor_clause}
           AND movimento BETWEEN :ini AND :fim
    """
    params = {"emp": emp_n, "vendedor": vendedor_n, "ini": inicio, "fim": fim, **_mov_params()}
    row = db.execute(text(sql), params).fetchone()
    return float(row[0] or 0.0) if row else 0.0


# Aliases legados.
def _query_valor_mes(db, ano: int, mes: int, emp: str, vendedor: str) -> float:
    return query_valor_mes(db, ano, mes, emp, vendedor)


def _query_valor_emp_mes(db, ano: int, mes: int, emp: str) -> float:
    return query_valor_mes(db, ano, mes, emp, None)


def query_valor_marcas(db, ano: int, mes: int, emp: str, vendedor: str, marcas: list[str]) -> tuple[float, float, float]:
    """Retorna (share_pct, valor_marcas, valor_total_vendedor)."""
    inicio, fim = periodo_bounds_ym(ano, mes)
    marcas_norm = [normalize_text(m) for m in (marcas or []) if normalize_text(m)]
    if not marcas_norm:
        return 0.0, 0.0, query_valor_mes(db, ano, mes, emp, vendedor)

    sql = f"""
        SELECT
          COALESCE(SUM(CASE WHEN UPPER(COALESCE(marca,'')) = ANY(:marcas)
                            THEN {signed_value_sql('valor_total')}
                            ELSE 0 END),0)::double precision AS valor_marcas,
          COALESCE(SUM({signed_value_sql('valor_total')}),0)::double precision AS valor_total
          FROM vendas
         WHERE emp = :emp
           AND UPPER(COALESCE(vendedor,'')) = :vendedor
           AND movimento BETWEEN :ini AND :fim
    """
    params = {
        "emp": normalize_emp(emp),
        "vendedor": normalize_text(vendedor),
        "marcas": marcas_norm,
        "ini": inicio,
        "fim": fim,
        **_mov_params(),
    }
    row = db.execute(text(sql), params).fetchone()
    valor_marcas = float(row[0] or 0.0) if row else 0.0
    valor_total = float(row[1] or 0.0) if row else 0.0
    share = (valor_marcas / valor_total * 100.0) if valor_total > 0 else 0.0
    return float(share), float(valor_marcas), float(valor_total)


# Alias legado.
def _query_share_marca(db, ano: int, mes: int, emp: str, vendedor: str, marcas: list[str]) -> tuple[float, float, float]:
    return query_valor_marcas(db, ano, mes, emp, vendedor, marcas)


def query_mix_itens_unicos(db, ano: int, mes: int, emp: str, vendedor: str) -> int:
    """Conta MESTRE unico com quantidade liquida positiva no periodo."""
    inicio, fim = periodo_bounds_ym(ano, mes)
    sql = """
      WITH por_produto AS (
        SELECT
          UPPER(TRIM(COALESCE(mestre,''))) AS mestre_norm,
          SUM(
            CASE
              WHEN UPPER(COALESCE(mov_tipo_movto,'')) = ANY(:negativos)
                THEN -ABS(COALESCE(qtdade_vendida,0))
              WHEN UPPER(COALESCE(mov_tipo_movto,'')) = ANY(:positivos)
                THEN COALESCE(qtdade_vendida,0)
              ELSE 0
            END
          ) AS qtd_liquida
        FROM vendas
        WHERE emp = :emp
          AND UPPER(COALESCE(vendedor,'')) = :vendedor
          AND movimento BETWEEN :ini AND :fim
          AND COALESCE(mestre,'') <> ''
        GROUP BY UPPER(TRIM(COALESCE(mestre,'')))
      )
      SELECT COUNT(*)::integer
        FROM por_produto
       WHERE mestre_norm <> ''
         AND qtd_liquida > 0
    """
    params = {
        "emp": normalize_emp(emp),
        "vendedor": normalize_text(vendedor),
        "ini": inicio,
        "fim": fim,
        **_mov_params(),
    }
    row = db.execute(text(sql), params).fetchone()
    return int(row[0] or 0) if row else 0


# Alias legado.
def _query_mix_itens(db, ano: int, mes: int, emp: str, vendedor: str) -> float:
    return float(query_mix_itens_unicos(db, ano, mes, emp, vendedor))


def get_active_emps(db, allowed_emps: list[str] | None = None) -> list[str]:
    q = db.query(Emp.codigo).filter(Emp.ativo.is_(True))
    allowed = [normalize_emp(e) for e in (allowed_emps or []) if normalize_emp(e)]
    if allowed:
        q = q.filter(Emp.codigo.in_(allowed))
    rows = q.order_by(Emp.codigo.asc()).all()
    return [str(r[0]).strip() for r in rows if r and str(r[0]).strip()]


def get_meta_emps(db, meta_id: int, incluir_inativas: bool = False) -> list[str]:
    q = db.query(MetaProgramaEmp.emp).filter(MetaProgramaEmp.meta_id == int(meta_id))
    if not incluir_inativas and hasattr(MetaProgramaEmp, "ativo"):
        q = q.filter(MetaProgramaEmp.ativo.is_(True))
    rows = q.order_by(MetaProgramaEmp.emp.asc()).all()
    return [normalize_emp(r[0]) for r in rows if r and normalize_emp(r[0])]


def get_meta_escalas(db, meta_id: int) -> list[MetaEscala]:
    return (
        db.query(MetaEscala)
        .filter(MetaEscala.meta_id == int(meta_id))
        .order_by(MetaEscala.limite_min.asc(), MetaEscala.ordem.asc())
        .all()
    )


def get_meta_marcas(db, meta_id: int) -> list[str]:
    rows = (
        db.query(MetaMarca.marca)
        .filter(MetaMarca.meta_id == int(meta_id))
        .order_by(MetaMarca.marca.asc())
        .all()
    )
    return [normalize_text(r[0]) for r in rows if r and normalize_text(r[0])]


def get_vendedores_no_periodo(db, ano: int, mes: int, emps: list[str] | None = None) -> list[str]:
    inicio, fim = periodo_bounds_ym(ano, mes)
    emp_clause, extra = _scope_emp_clause(emps or [])
    sql = f"""
        SELECT DISTINCT UPPER(TRIM(COALESCE(vendedor,''))) AS vendedor
          FROM vendas
         WHERE movimento BETWEEN :ini AND :fim
           {emp_clause}
           AND COALESCE(vendedor,'') <> ''
         ORDER BY vendedor
    """
    rows = db.execute(text(sql), {"ini": inicio, "fim": fim, **extra}).fetchall()
    return [normalize_text(r[0]) for r in rows if r and normalize_text(r[0])]


# Alias legado.
def _get_vendedores_no_periodo(db, ano: int, mes: int, emps: list[str]) -> list[str]:
    return get_vendedores_no_periodo(db, ano, mes, emps)


def get_emps_no_periodo(db, ano: int, mes: int, allowed_emps: list[str] | None = None) -> list[str]:
    inicio, fim = periodo_bounds_ym(ano, mes)
    emp_clause, extra = _scope_emp_clause(allowed_emps or [])
    sql = f"""
        SELECT DISTINCT emp
          FROM vendas
         WHERE movimento BETWEEN :ini AND :fim
           {emp_clause}
           AND COALESCE(emp,'') <> ''
         ORDER BY emp
    """
    rows = db.execute(text(sql), {"ini": inicio, "fim": fim, **extra}).fetchall()
    return [normalize_emp(r[0]) for r in rows if r and normalize_emp(r[0])]


# Alias legado.
def _get_emps_no_periodo(db, ano: int, mes: int, emps_allowed: list[str]) -> list[str]:
    return get_emps_no_periodo(db, ano, mes, emps_allowed)


def get_vendedores_cadastrados(db, emps: list[str] | None = None) -> list[str]:
    allowed = [normalize_emp(e) for e in (emps or []) if normalize_emp(e)]
    q = (
        db.query(Usuario.username)
        .join(UsuarioEmp, UsuarioEmp.usuario_id == Usuario.id)
        .filter(UsuarioEmp.ativo.is_(True))
        .filter(Usuario.role.ilike("vendedor"))
    )
    if allowed:
        q = q.filter(UsuarioEmp.emp.in_(allowed))
    rows = q.order_by(Usuario.username.asc()).all()
    return [normalize_text(r[0]) for r in rows if r and normalize_text(r[0])]


def get_vendedores_para_metas(db, ano: int, mes: int, emps: list[str] | None = None) -> list[str]:
    """Une vendedores cadastrados, vendedores com venda e vendedores com base manual."""
    nomes: list[str] = []
    nomes.extend(get_vendedores_cadastrados(db, emps))
    nomes.extend(get_vendedores_no_periodo(db, ano, mes, emps))

    emp_clause = ""
    params: dict[str, object] = {"ano": ano, "mes": mes}
    # MetaBaseManual nao tem ano/mes; buscamos por metas do periodo.
    allowed = [normalize_emp(e) for e in (emps or []) if normalize_emp(e)]
    if allowed:
        emp_clause = "AND b.emp = ANY(:emps)"
        params["emps"] = allowed
    sql = f"""
      SELECT DISTINCT UPPER(TRIM(COALESCE(b.vendedor,'')))
        FROM metas_bases_manuais b
        JOIN metas_programas m ON m.id = b.meta_id
       WHERE m.ano = :ano AND m.mes = :mes
         {emp_clause}
         AND COALESCE(b.vendedor,'') <> ''
    """
    try:
        rows = db.execute(text(sql), params).fetchall()
        nomes.extend([normalize_text(r[0]) for r in rows if r and normalize_text(r[0])])
    except Exception:
        pass

    seen: set[str] = set()
    out: list[str] = []
    for n in nomes:
        n = normalize_text(n)
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return sorted(out)


def get_base_manual(db, meta_id: int, emp: str, vendedor: str) -> MetaBaseManual | None:
    return (
        db.query(MetaBaseManual)
        .filter(
            MetaBaseManual.meta_id == int(meta_id),
            MetaBaseManual.emp == normalize_emp(emp),
            MetaBaseManual.vendedor == normalize_text(vendedor),
        )
        .first()
    )


def get_margem_vendedor(db, ano: int, mes: int, emp: str, vendedor: str) -> MetaMargemVendedor | None:
    """Retorna a margem percentual vigente do vendedor na competência.

    A regra atual da margem é individual por vendedor, não por EMP.
    Portanto a busca usa apenas ANO + MÊS + VENDEDOR e considera a última
    margem importada. O parâmetro ``emp`` fica preservado por compatibilidade
    com chamadas antigas, mas não restringe o resultado.
    """
    vendedor_n = normalize_text(vendedor)
    if not vendedor_n:
        return None
    return (
        db.query(MetaMargemVendedor)
        .filter(
            MetaMargemVendedor.ano == int(ano),
            MetaMargemVendedor.mes == int(mes),
            MetaMargemVendedor.vendedor == vendedor_n,
        )
        .order_by(MetaMargemVendedor.importado_em.desc(), MetaMargemVendedor.id.desc())
        .first()
    )


def upsert_base_manual(db, meta_id: int, emp: str, vendedor: str, base_valor: float, observacao: str | None = None, margem_minima_individual: float | None = None) -> MetaBaseManual:
    item = get_base_manual(db, meta_id, emp, vendedor)
    if not item:
        item = MetaBaseManual(meta_id=int(meta_id), emp=normalize_emp(emp), vendedor=normalize_text(vendedor))
    item.base_valor = float(base_valor or 0.0)
    # Neste módulo, metas_bases_manuais.margem_percentual representa a margem mínima individual
    # exigida para este vendedor na Meta Crescimento. Se ficar vazia/zero, usa a margem padrão da meta.
    margem_ind = float(margem_minima_individual or 0.0) if margem_minima_individual is not None else 0.0
    item.margem_percentual = margem_ind if margem_ind > 0 else None
    item.observacao = (observacao or "").strip()[:200]
    db.add(item)
    return item


def pick_scale(escalas: Iterable[MetaEscala], metric: float) -> MetaEscala | None:
    best = None
    metric_f = float(metric or 0.0)
    for esc in sorted(list(escalas or []), key=lambda e: (float(e.limite_min or 0.0), int(e.ordem or 0))):
        if metric_f >= float(esc.limite_min or 0.0):
            best = esc
    return best


def max_scale(escalas: Iterable[MetaEscala]) -> MetaEscala | None:
    ordered = sorted(list(escalas or []), key=lambda e: (float(e.limite_min or 0.0), int(e.ordem or 0)))
    return ordered[-1] if ordered else None


@dataclass
class MetaCalc:
    meta_id: int
    tipo: str
    emp: str
    vendedor: str
    valor_mes: float = 0.0
    base_valor: float | None = None
    crescimento_pct: float | None = None
    mix_itens_unicos: int | None = None
    valor_marcas: float | None = None
    share_pct: float | None = None
    faixa_limite: float | None = None
    bonus_percentual: float = 0.0
    premio: float = 0.0
    regra_teto_aplicada: bool = False
    faturamento_minimo: float = 0.0
    faturamento_minimo_atingido: bool = True
    bloqueado_minimo: bool = False
    margem_minima: float = 0.0
    margem_minima_origem: str = ""  # "individual", "padrao" ou vazio
    margem_percentual: float | None = None
    margem_importada_em: datetime | None = None
    margem_atingida: bool = True
    bloqueado_margem: bool = False
    margem_faltante_pp: float = 0.0


def calcular_meta(db, meta: MetaPrograma, emp: str, vendedor: str, persist: bool = False) -> MetaCalc:
    """Calcula uma meta para EMP+vendedor. Se persist=True, atualiza metas_resultados."""
    tipo = normalize_text(meta.tipo)
    emp_n = normalize_emp(emp)
    vendedor_n = normalize_text(vendedor)
    escalas = get_meta_escalas(db, int(meta.id))

    calc = MetaCalc(meta_id=int(meta.id), tipo=tipo, emp=emp_n, vendedor=vendedor_n)
    faturamento_minimo = float(getattr(meta, "faturamento_minimo", 0.0) or 0.0)
    margem_minima_padrao = float(getattr(meta, "margem_minima", 0.0) or 0.0)
    margem_minima = margem_minima_padrao
    calc.faturamento_minimo = faturamento_minimo

    if tipo == "CRESCIMENTO":
        valor_mes = Decimal(str(query_valor_mes(db, meta.ano, meta.mes, emp_n, vendedor_n)))
        base = get_base_manual(db, int(meta.id), emp_n, vendedor_n)
        base_valor = Decimal(str(getattr(base, "base_valor", 0.0) or 0.0)) if base else Decimal("0")

        margem_individual = float(getattr(base, "margem_percentual", 0.0) or 0.0) if base else 0.0
        if margem_individual > 0:
            margem_minima = margem_individual
            calc.margem_minima_origem = "individual"
        elif margem_minima_padrao > 0:
            margem_minima = margem_minima_padrao
            calc.margem_minima_origem = "padrao"
        else:
            margem_minima = 0.0
            calc.margem_minima_origem = ""
        calc.margem_minima = margem_minima

        margem_row = get_margem_vendedor(db, meta.ano, meta.mes, emp_n, vendedor_n) if margem_minima > 0 else None
        if margem_row is not None:
            calc.margem_percentual = float(getattr(margem_row, "margem_percentual", 0.0) or 0.0)
            calc.margem_importada_em = getattr(margem_row, "importado_em", None)
        elif margem_minima > 0:
            calc.margem_percentual = None
        crescimento = Decimal("0")
        if base_valor > 0:
            crescimento = (valor_mes - base_valor) / base_valor * Decimal("100")

        teto = float(getattr(meta, "teto_faturamento", 0.0) or 0.0)
        escala = None
        teto_aplicado = False
        if teto > 0 and float(valor_mes) >= teto:
            escala = max_scale(escalas)
            teto_aplicado = escala is not None
        else:
            escala = pick_scale(escalas, float(crescimento))

        bonus_pct = float(getattr(escala, "bonus_percentual", 0.0) or 0.0) if escala else 0.0
        premio = money2(valor_mes * Decimal(str(bonus_pct)) / Decimal("100"))

        calc.valor_mes = float(valor_mes)
        calc.base_valor = float(base_valor)
        calc.crescimento_pct = float(percent2(crescimento))
        calc.faixa_limite = float(getattr(escala, "limite_min", 0.0) or 0.0) if escala else None
        calc.bonus_percentual = bonus_pct
        calc.premio = float(premio)
        calc.regra_teto_aplicada = bool(teto_aplicado)

    elif tipo == "MIX":
        valor_mes = Decimal(str(query_valor_mes(db, meta.ano, meta.mes, emp_n, vendedor_n)))
        mix = query_mix_itens_unicos(db, meta.ano, meta.mes, emp_n, vendedor_n)
        escala = pick_scale(escalas, mix)
        premio_fixo = float(getattr(escala, "bonus_percentual", 0.0) or 0.0) if escala else 0.0

        calc.valor_mes = float(valor_mes)
        calc.mix_itens_unicos = int(mix)
        calc.faixa_limite = float(getattr(escala, "limite_min", 0.0) or 0.0) if escala else None
        calc.bonus_percentual = premio_fixo  # no MIX este campo guarda o valor fixo da faixa
        calc.premio = float(money2(Decimal(str(premio_fixo))))

    elif tipo == "SHARE_MARCA":
        marcas = get_meta_marcas(db, int(meta.id))
        share_pct, valor_marcas, valor_mes_f = query_valor_marcas(db, meta.ano, meta.mes, emp_n, vendedor_n, marcas)
        escala = pick_scale(escalas, share_pct)
        bonus_pct = float(getattr(escala, "bonus_percentual", 0.0) or 0.0) if escala else 0.0
        premio = money2(Decimal(str(valor_mes_f)) * Decimal(str(bonus_pct)) / Decimal("100"))

        calc.valor_mes = float(valor_mes_f)
        calc.valor_marcas = float(valor_marcas)
        calc.share_pct = float(percent2(share_pct))
        calc.faixa_limite = float(getattr(escala, "limite_min", 0.0) or 0.0) if escala else None
        calc.bonus_percentual = bonus_pct
        calc.premio = float(premio)

    if faturamento_minimo > 0 and float(calc.valor_mes or 0.0) < faturamento_minimo:
        calc.faturamento_minimo_atingido = False
        calc.bloqueado_minimo = True
        # Mantém as métricas/faixas para conferência, mas zera o pagamento porque não atingiu o faturamento mínimo.
        calc.premio = 0.0
    else:
        calc.faturamento_minimo_atingido = True
        calc.bloqueado_minimo = False

    if tipo == "CRESCIMENTO" and margem_minima > 0:
        margem_atual = calc.margem_percentual
        if margem_atual is None:
            calc.margem_atingida = False
            calc.bloqueado_margem = True
            calc.margem_faltante_pp = float(margem_minima)
            calc.premio = 0.0
        elif float(margem_atual) < float(margem_minima):
            calc.margem_atingida = False
            calc.bloqueado_margem = True
            calc.margem_faltante_pp = round(float(margem_minima) - float(margem_atual), 2)
            calc.premio = 0.0
        else:
            calc.margem_atingida = True
            calc.bloqueado_margem = False
            calc.margem_faltante_pp = 0.0
    else:
        calc.margem_atingida = True
        calc.bloqueado_margem = False
        calc.margem_faltante_pp = 0.0

    if persist:
        upsert_resultado(db, calc)

    return calc


def upsert_resultado(db, calc: MetaCalc) -> MetaResultado:
    res = (
        db.query(MetaResultado)
        .filter(
            MetaResultado.meta_id == calc.meta_id,
            MetaResultado.emp == calc.emp,
            MetaResultado.vendedor == calc.vendedor,
        )
        .first()
    )
    if not res:
        # ano/mes sao buscados pela meta para manter compatibilidade com constraint antiga.
        meta = db.query(MetaPrograma).filter(MetaPrograma.id == calc.meta_id).first()
        res = MetaResultado(
            meta_id=calc.meta_id,
            emp=calc.emp,
            vendedor=calc.vendedor,
            ano=int(getattr(meta, "ano", 0) or 0),
            mes=int(getattr(meta, "mes", 0) or 0),
        )
    res.valor_mes = float(calc.valor_mes or 0.0)
    res.base_valor = calc.base_valor
    res.crescimento_pct = calc.crescimento_pct
    res.mix_itens_unicos = float(calc.mix_itens_unicos) if calc.mix_itens_unicos is not None else None
    res.valor_marcas = calc.valor_marcas
    res.share_pct = calc.share_pct
    if hasattr(res, "margem_percentual"):
        res.margem_percentual = calc.margem_percentual
    if hasattr(res, "margem_minima"):
        res.margem_minima = float(calc.margem_minima or 0.0)
    if hasattr(res, "margem_atingida"):
        res.margem_atingida = bool(calc.margem_atingida)
    if hasattr(res, "bloqueado_margem"):
        res.bloqueado_margem = bool(calc.bloqueado_margem)
    res.bonus_percentual = float(calc.bonus_percentual or 0.0)
    res.premio = float(calc.premio or 0.0)
    res.calculado_em = datetime.utcnow()
    db.add(res)
    return res


# Alias antigo.
def _calc_and_upsert_meta_result(db, meta: MetaPrograma, emp: str, vendedor: str) -> MetaResultado:
    calc = calcular_meta(db, meta, emp, vendedor, persist=True)
    db.commit()
    return (
        db.query(MetaResultado)
        .filter(MetaResultado.meta_id == calc.meta_id, MetaResultado.emp == calc.emp, MetaResultado.vendedor == calc.vendedor)
        .first()
    )


def metas_ativas_periodo(db, ano: int, mes: int, only_active: bool = True) -> list[MetaPrograma]:
    q = db.query(MetaPrograma).filter(MetaPrograma.ano == int(ano), MetaPrograma.mes == int(mes))
    if only_active:
        q = q.filter(MetaPrograma.ativo.is_(True))
    return q.order_by(MetaPrograma.tipo.asc(), MetaPrograma.nome.asc(), MetaPrograma.id.asc()).all()


def montar_resultados_periodo(
    db,
    ano: int,
    mes: int,
    emps: list[str] | None = None,
    vendedor: str | None = None,
    persist: bool = False,
) -> tuple[list[MetaPrograma], list[dict]]:
    """Monta matriz EMP+Vendedor com metas calculadas para a tela de acompanhamento."""
    metas = metas_ativas_periodo(db, ano, mes, only_active=True)
    if not metas:
        return [], []

    emps_filter = [normalize_emp(e) for e in (emps or []) if normalize_emp(e)]
    vendedor_filter = normalize_text(vendedor)

    rows_by_key: dict[tuple[str, str], dict] = {}
    metas_visiveis: list[MetaPrograma] = []

    for meta in metas:
        meta_emps = get_meta_emps(db, int(meta.id))
        if emps_filter:
            meta_emps = [e for e in meta_emps if e in set(emps_filter)]
        if not meta_emps:
            continue
        metas_visiveis.append(meta)

        for emp in meta_emps:
            vendedores = [vendedor_filter] if vendedor_filter else get_vendedores_para_metas(db, ano, mes, [emp])
            for vend in vendedores:
                if not vend:
                    continue
                calc = calcular_meta(db, meta, emp, vend, persist=persist)
                key = (emp, vend)
                row = rows_by_key.setdefault(
                    key,
                    {
                        "emp": emp,
                        "vendedor": vend,
                        "valor_mes": float(calc.valor_mes or 0.0),
                        "metas": {},
                        "detalhes": {},
                        "total_premios": 0.0,
                    },
                )
                row["valor_mes"] = max(float(row.get("valor_mes") or 0.0), float(calc.valor_mes or 0.0))
                row["metas"][int(meta.id)] = float(calc.premio or 0.0)
                row["detalhes"][int(meta.id)] = calc
                row["total_premios"] = round(float(row.get("total_premios") or 0.0) + float(calc.premio or 0.0), 2)

    rows = sorted(rows_by_key.values(), key=lambda r: (str(r["emp"]), str(r["vendedor"])))
    return metas_visiveis, rows
