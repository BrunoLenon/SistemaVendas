from __future__ import annotations

"""
Relatório Unificado de Campanhas

Objetivo:
- Normalizar resultados de campanhas QTD, COMBO e ITENS PARADOS em um único "dataset"
  para renderização em uma tabela/dash consolidada.

Observações:
- Mantém compatibilidade com o banco atual.
- Itens Parados: tenta ler snapshot (itens_parados_resultados). Se não existir ou não houver dados,
  calcula ao vivo (pode ser pesado). Recomenda-se rodar recálculo (recalc=1) para persistir snapshot.
"""

from dataclasses import dataclass
from datetime import date
from typing import Any, Iterable

from sqlalchemy import or_, func, cast, String

from db import (
    SessionLocal,
    Venda,
    CampanhaQtdResultado,
    CampanhaComboResultado,
    ItemParado,
)

# Snapshot novo (pode não existir no banco antigo). Import defensivo.
try:
    from db import ItemParadoResultado  # type: ignore
except Exception:  # pragma: no cover
    ItemParadoResultado = None  # type: ignore


@dataclass(frozen=True)
class UnifiedRow:
    tipo: str               # "QTD" | "COMBO" | "PARADO"
    competencia_ano: int
    competencia_mes: int
    emp: str
    vendedor: str
    titulo: str

    atingiu_gate: bool | None
    qtd_base: float | None
    qtd_premiada: float | None

    valor_recompensa: float
    status_pagamento: str
    pago_em: Any | None

    # ids para drilldown
    origem_id: int | None


def _safe_float(v: Any) -> float:
    try:
        return float(v or 0.0)
    except Exception:
        return 0.0

def _emp_equals(col, emp_value: Any):
    """Compare EMP safely regardless of column type (int/varchar)."""
    return cast(col, String) == str(emp_value)



def _periodo_bounds(ano: int, mes: int) -> tuple[date, date]:
    # evita import circular com app.py (que tem helper semelhante)
    from calendar import monthrange
    di = date(int(ano), int(mes), 1)
    df = date(int(ano), int(mes), monthrange(int(ano), int(mes))[1])
    return di, df


def build_unified_rows(
    *,
    ano: int,
    mes: int,
    emps: list[str],
    vendedores_por_emp: dict[str, list[str]],
    incluir_zerados: bool = False,
    usar_snapshot_itens_parados: bool = True,
) -> list[UnifiedRow]:
    """
    Retorna linhas unificadas (QTD + COMBO + ITENS PARADOS) para a competência informada.

    - `emps`: lista de EMPs a incluir (já sanitizada no caller).
    - `vendedores_por_emp`: dict emp -> lista de vendedores permitidos/selecionados.
    - `incluir_zerados`: se False, filtra valor_recompensa <= 0.
    - `usar_snapshot_itens_parados`: tenta ler tabela de snapshot (se existir).
    """
    periodo_ini, periodo_fim = _periodo_bounds(ano, mes)

    rows: list[UnifiedRow] = []

    with SessionLocal() as db:
        for emp in emps:
            vendedores = [v.strip().upper() for v in (vendedores_por_emp.get(emp) or []) if (v or "").strip()]
            if not vendedores:
                continue

            # -------- QTD (snapshot) --------
            q_qtd = (
                db.query(CampanhaQtdResultado)
                .filter(
                    CampanhaQtdResultado.competencia_ano == int(ano),
                    CampanhaQtdResultado.competencia_mes == int(mes),
                    cast(CampanhaQtdResultado.emp, String) == str(emp),
                    CampanhaQtdResultado.vendedor.in_(vendedores),
                )
            )
            if not incluir_zerados:
                q_qtd = q_qtd.filter(CampanhaQtdResultado.valor_recompensa > 0)

            try:
                qtd_all = q_qtd.all()
            except Exception as e:
                db.rollback()
                print(f"[RELATORIO_UNIFICADO] QTD query failed emp={{emp}}: {{e}}")
                qtd_all = []
            for r in qtd_all:
                recompensa_unit = _safe_float(getattr(r, "recompensa_unit", 0.0))
                valor_recompensa = _safe_float(getattr(r, "valor_recompensa", 0.0))
                qtd_prem = None
                if recompensa_unit > 0 and valor_recompensa > 0:
                    qtd_prem = valor_recompensa / recompensa_unit

                rows.append(
                    UnifiedRow(
                        tipo="QTD",
                        competencia_ano=int(getattr(r, "competencia_ano", ano)),
                        competencia_mes=int(getattr(r, "competencia_mes", mes)),
                        emp=str(getattr(r, "emp", emp)),
                        vendedor=str(getattr(r, "vendedor", "")).strip().upper(),
                        titulo=str(getattr(r, "titulo", "") or "").strip() or f"Campanha #{getattr(r,'campanha_id', '')}",
                        atingiu_gate=bool(int(getattr(r, "atingiu_minimo", 0) or 0)),
                        qtd_base=_safe_float(getattr(r, "qtd_vendida", None)),
                        qtd_premiada=qtd_prem,
                        valor_recompensa=valor_recompensa,
                        status_pagamento=str(getattr(r, "status_pagamento", "PENDENTE") or "PENDENTE"),
                        pago_em=getattr(r, "pago_em", None),
                        origem_id=int(getattr(r, "campanha_id", 0) or 0),
                    )
                )

            # -------- COMBO (snapshot) --------
            q_combo = (
                db.query(CampanhaComboResultado)
                .filter(
                    CampanhaComboResultado.competencia_ano == int(ano),
                    CampanhaComboResultado.competencia_mes == int(mes),
                    cast(CampanhaComboResultado.emp, String) == str(emp),
                    CampanhaComboResultado.vendedor.in_(vendedores),
                )
            )
            if not incluir_zerados:
                q_combo = q_combo.filter(CampanhaComboResultado.valor_recompensa > 0)

            try:
                combo_all = q_combo.all()
            except Exception as e:
                db.rollback()
                print(f"[RELATORIO_UNIFICADO] COMBO query failed emp={{emp}}: {{e}}")
                combo_all = []
            for r in combo_all:
                rows.append(
                    UnifiedRow(
                        tipo="COMBO",
                        competencia_ano=int(getattr(r, "competencia_ano", ano)),
                        competencia_mes=int(getattr(r, "competencia_mes", mes)),
                        emp=str(getattr(r, "emp", emp)),
                        vendedor=str(getattr(r, "vendedor", "")).strip().upper(),
                        titulo=str(getattr(r, "titulo", "") or "").strip() or f"Combo #{getattr(r,'combo_id','')}",
                        atingiu_gate=bool(int(getattr(r, "atingiu_gate", 0) or 0)),
                        qtd_base=None,
                        qtd_premiada=None,
                        valor_recompensa=_safe_float(getattr(r, "valor_recompensa", 0.0)),
                        status_pagamento=str(getattr(r, "status_pagamento", "PENDENTE") or "PENDENTE"),
                        pago_em=getattr(r, "pago_em", None),
                        origem_id=int(getattr(r, "combo_id", 0) or 0),
                    )
                )

            # -------- ITENS PARADOS --------
            # Preferência: snapshot novo
            if usar_snapshot_itens_parados and ItemParadoResultado is not None:
                try:
                    q_par = (
                        db.query(ItemParadoResultado)
                        .filter(
                            ItemParadoResultado.competencia_ano == int(ano),
                            ItemParadoResultado.competencia_mes == int(mes),
                            cast(ItemParadoResultado.emp, String) == str(emp),
                            ItemParadoResultado.vendedor.in_(vendedores),
                        )
                    )
                    if not incluir_zerados:
                        q_par = q_par.filter(ItemParadoResultado.valor_recompensa > 0)
                    par_all = q_par.all()
                except Exception:
                    db.rollback()
                    par_all = []
                for r in par_all:
                    rows.append(
                        UnifiedRow(
                            tipo="PARADO",
                            competencia_ano=int(getattr(r, "competencia_ano", ano)),
                            competencia_mes=int(getattr(r, "competencia_mes", mes)),
                            emp=str(getattr(r, "emp", emp)),
                            vendedor=str(getattr(r, "vendedor", "")).strip().upper(),
                            titulo=str(getattr(r, "titulo", "") or "").strip() or "Item Parado",
                            atingiu_gate=True if _safe_float(getattr(r, "base_valor_vendido", 0.0)) > 0 else False,
                            qtd_base=_safe_float(getattr(r, "base_valor_vendido", 0.0)),
                            qtd_premiada=None,
                            valor_recompensa=_safe_float(getattr(r, "valor_recompensa", 0.0)),
                            status_pagamento=str(getattr(r, "status_pagamento", "PENDENTE") or "PENDENTE"),
                            pago_em=getattr(r, "pago_em", None),
                            origem_id=int(getattr(r, "item_parado_id", 0) or 0),
                        )
                    )

            # Fallback: ao vivo (sem status_pagamento persistente)
            else:
                try:
                    parados_defs = (
                        db.query(ItemParado)
                        .filter(ItemParado.ativo.is_(True), cast(ItemParado.emp, String) == str(emp))
                        .order_by(ItemParado.descricao.asc())
                        .all()
                except Exception as e:
                    db.rollback()
                    print(f"[RELATORIO_UNIFICADO] PARADO defs query failed emp={{emp}}: {{e}}")
                    parados_defs = []
                )
                for ip in parados_defs:
                    codigo = (getattr(ip, "codigo", "") or "").strip()
                    if not codigo:
                        continue
                    pct = _safe_float(getattr(ip, "recompensa_pct", 0.0))
                    if pct <= 0:
                        continue

                    base_rows = (
                        db.query(Venda.vendedor, func.sum(Venda.valor_total))
                        .filter(
                            Venda.emp == str(emp),
                            Venda.movimento >= periodo_ini,
                            Venda.movimento <= periodo_fim,
                            ~Venda.mov_tipo_movto.in_(["DS", "CA"]),
                            Venda.mestre == codigo,
                            Venda.vendedor.in_(vendedores),
                        )
                        .group_by(Venda.vendedor)
                        .all()
                    )

                    for vend, base_val in base_rows:
                        vend_u = (vend or "").strip().upper()
                        base_val_f = _safe_float(base_val)
                        valor = base_val_f * (pct / 100.0)
                        if (not incluir_zerados) and valor <= 0:
                            continue
                        rows.append(
                            UnifiedRow(
                                tipo="PARADO",
                                competencia_ano=int(ano),
                                competencia_mes=int(mes),
                                emp=str(emp),
                                vendedor=vend_u,
                                titulo=str(getattr(ip, "descricao", "") or "").strip() or f"Item {codigo}",
                                atingiu_gate=True if base_val_f > 0 else False,
                                qtd_base=base_val_f,
                                qtd_premiada=None,
                                valor_recompensa=valor,
                                status_pagamento="PENDENTE",
                                pago_em=None,
                                origem_id=int(getattr(ip, "id", 0) or 0),
                            )
                        )

    # Ordena: EMP, Vendedor, Tipo, Título
    rows.sort(key=lambda r: (r.emp, r.vendedor, r.tipo, r.titulo))
    return rows


def aggregate_for_charts(rows: list[UnifiedRow]) -> dict[str, Any]:
    """Agregações simples para gráficos (por tipo e por EMP)."""
    by_tipo: dict[str, float] = {}
    by_emp: dict[str, float] = {}
    total = 0.0

    for r in rows:
        val = _safe_float(r.valor_recompensa)
        total += val
        by_tipo[r.tipo] = by_tipo.get(r.tipo, 0.0) + val
        by_emp[r.emp] = by_emp.get(r.emp, 0.0) + val

    return {
        "total_recompensa": total,
        "by_tipo": [{"label": k, "value": float(v)} for k, v in sorted(by_tipo.items())],
        "by_emp": [{"label": k, "value": float(v)} for k, v in sorted(by_emp.items())],
    }