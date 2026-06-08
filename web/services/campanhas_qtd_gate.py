from __future__ import annotations

"""Regras de trava de faturamento mínimo da EMP para Campanhas QTD.

A campanha continua calculando o prêmio potencial por item vendido, mas o
valor só é liberado se a loja/EMP atingir o faturamento mínimo cadastrado na
campanha. Sem mínimo cadastrado, mantém o comportamento antigo.
"""

from decimal import Decimal, ROUND_HALF_UP
from typing import Any

from sqlalchemy import func

from db import Venda

MOVIMENTOS_BLOQUEADOS = ("DS", "CA")


def _safe_float(v: Any) -> float:
    try:
        return float(v or 0.0)
    except Exception:
        return 0.0


def _round_money(v: Any) -> float:
    try:
        return float(Decimal(str(v if v is not None else 0)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    except Exception:
        return 0.0


def calcular_faturamento_emp_periodo(db: Any, *, emp: str, periodo_ini: Any, periodo_fim: Any) -> float:
    """Soma o faturamento da EMP no período usando a regra padrão do sistema.

    Mantém compatibilidade com a apuração atual de campanhas: considera vendas
    que não sejam DS/CA. Isso preserva SV/VV e demais movimentos positivos já
    usados historicamente pelo sistema.
    """
    emp_s = str(emp or "").strip()
    if not emp_s or not periodo_ini or not periodo_fim:
        return 0.0

    key = (emp_s, str(periodo_ini), str(periodo_fim))
    cache = getattr(db, "_campanha_qtd_gate_cache", None)
    if cache is None:
        cache = {}
        try:
            setattr(db, "_campanha_qtd_gate_cache", cache)
        except Exception:
            cache = {}
    if key in cache:
        return _safe_float(cache[key])

    row = (
        db.query(func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor"))
        .filter(
            Venda.emp == emp_s,
            Venda.movimento >= periodo_ini,
            Venda.movimento <= periodo_fim,
            ~Venda.mov_tipo_movto.in_(MOVIMENTOS_BLOQUEADOS),
            func.coalesce(Venda.qtdade_vendida, 0.0) > 0,
        )
        .first()
    )
    valor = _round_money(getattr(row, "valor", 0.0) if row is not None else 0.0)
    try:
        cache[key] = valor
    except Exception:
        pass
    return valor


def aplicar_trava_faturamento_emp(
    *,
    campanha: Any,
    emp: str,
    faturamento_emp: float,
    premio_potencial: float,
    atingiu_regras_item: bool,
) -> dict[str, Any]:
    """Aplica a trava de faturamento da loja e retorna os campos de auditoria."""
    minimo = _safe_float(getattr(campanha, "faturamento_minimo_emp", 0.0) or 0.0)
    faturamento = _round_money(faturamento_emp)
    potencial = _round_money(premio_potencial)

    faltante = 0.0
    bloqueado = False
    liberado = potencial if atingiu_regras_item else 0.0

    if minimo > 0:
        faltante = _round_money(max(0.0, minimo - faturamento))
        if atingiu_regras_item and potencial > 0 and faturamento < minimo:
            bloqueado = True
            liberado = 0.0

    return {
        "emp": str(emp or "").strip(),
        "faturamento_minimo_emp": _round_money(minimo),
        "faturamento_emp": faturamento,
        "faltante_faturamento_emp": faltante,
        "premio_potencial": potencial,
        "valor_recompensa": _round_money(liberado),
        "bloqueado_faturamento_emp": bool(bloqueado),
        "atingiu_final": bool(atingiu_regras_item and not bloqueado and liberado > 0),
    }
