from __future__ import annotations

"""Helpers compartilhados de campanhas/relatórios.

Fase 1 da refatoração: mover utilidades de escopo para fora do app.py sem
alterar comportamento.
"""

from typing import Any, Callable


def get_emps_com_vendas_no_periodo(*, SessionLocal: Any, Venda: Any, periodo_bounds: Callable[[int, int], tuple], filter_emps_cadastradas: Callable[..., list[str]], ano: int, mes: int) -> list[str]:
    inicio_mes, fim_mes = periodo_bounds(int(ano), int(mes))
    with SessionLocal() as db:
        rows = (
            db.query(Venda.emp)
            .filter(Venda.movimento >= inicio_mes, Venda.movimento <= fim_mes)
            .distinct()
            .all()
        )
    emps = sorted({
        str(r[0]).strip()
        for r in rows
        if r and r[0] is not None and str(r[0]).strip() != ""
    })
    return filter_emps_cadastradas(emps, apenas_ativas=True)


def get_vendedores_emp_no_periodo(*, SessionLocal: Any, Venda: Any, periodo_bounds: Callable[[int, int], tuple], emp: str, ano: int, mes: int) -> list[str]:
    inicio_mes, fim_mes = periodo_bounds(int(ano), int(mes))
    emp = str(emp)
    with SessionLocal() as db:
        rows = (
            db.query(Venda.vendedor)
            .filter(Venda.emp == emp, Venda.movimento >= inicio_mes, Venda.movimento <= fim_mes)
            .distinct()
            .all()
        )
    return sorted({
        (r[0] or "").strip().upper()
        for r in rows
        if r and (r[0] or "").strip()
    })
