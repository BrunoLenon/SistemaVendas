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
    CampanhaCombo,
    CampanhaComboItem,
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

    # extras para relatório de campanhas (detalhado)
    item_codigo: str | None = None
    qtd_minima: float | None = None
    recompensa_unit: float | None = None
    valor_vendido: float | None = None

    # Compat: alguns templates/rotas antigos esperam `r.atingiu`.
    # Mantemos `atingiu_gate` como fonte de verdade e oferecemos um alias.
    @property
    def atingiu(self) -> bool:
        try:
            return bool(self.atingiu_gate or False)
        except Exception:
            return False


    # campos calculados (defaults evitam erro de ordem no dataclass)
    atingiu_gate: bool | None = None
    qtd_base: float | None = None
    qtd_premiada: float | None = None

    valor_recompensa: float = 0.0
    status_pagamento: str = "PENDENTE"
    pago_em: Any | None = None

    # ids para drilldown
    origem_id: int | None = None

    # Compatibilidade: permite tratar UnifiedRow como dict em alguns pontos do app/templates
    # (ex.: r.get('emp'), r['emp']).
    def get(self, key: str, default: Any = None) -> Any:
        if key is None:
            return default
        k = str(key)
        # tenta direto, depois variações de caixa
        for kk in (k, k.lower(), k.upper()):
            if hasattr(self, kk):
                return getattr(self, kk)
        return default

    def __getitem__(self, key: str) -> Any:
        sentinel = object()
        v = self.get(key, sentinel)
        if v is sentinel:
            raise KeyError(key)
        return v



def _safe_float(v: Any) -> float:
    try:
        return float(v or 0.0)
    except Exception:
        return 0.0


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

    def _sum_valor_vendido_item(emp: str, vendedor: str, item_codigo: str | None) -> float:
        """Soma do valor_total vendido (R$) para um item (mestre) na competência."""
        if not item_codigo:
            return 0.0
        try:
            val = (
                db.query(func.coalesce(func.sum(Venda.valor_total), 0))
                .filter(Venda.emp == emp)
                .filter(Venda.vendedor == vendedor)
                .filter(Venda.data >= periodo_ini, Venda.data <= periodo_fim)
                .filter(Venda.mestre == item_codigo)
                .scalar()
            )
            return float(val or 0)
        except Exception:
            return 0.0


    with SessionLocal() as db:
        for emp in emps:
            # Evita sessão ficar "abortada" se uma query anterior falhou (InFailedSqlTransaction)
            try:
                db.rollback()
            except Exception:
                pass
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

            for r in q_qtd.all():
                recompensa_unit = _safe_float(getattr(r, "recompensa_unit", 0.0))
                valor_recompensa = _safe_float(getattr(r, "valor_recompensa", 0.0))
                qtd_minima = getattr(r, "qtd_minima", None)
                valor_vendido = _safe_float(getattr(r, "valor_vendido", 0.0))
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
                        # campos usados no relatório detalhado (/relatorios/campanhas)
                        item_codigo=str(getattr(r, "produto_prefixo", "") or "").strip() or None,
                        qtd_minima=_safe_float(qtd_minima) if qtd_minima is not None else None,
                        recompensa_unit=recompensa_unit,
                        valor_vendido=valor_vendido,
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
            # Importante: para COMBO, queremos exibir também "parciais" (não atingiu),
            # então NÃO filtramos por valor_recompensa > 0.
            q_combo = (
                db.query(CampanhaComboResultado)
                .filter(
                    CampanhaComboResultado.competencia_ano == int(ano),
                    CampanhaComboResultado.competencia_mes == int(mes),
                    cast(CampanhaComboResultado.emp, String) == str(emp),
                    CampanhaComboResultado.vendedor.in_(vendedores),
                )
            )

            # Carrega definições/itens dos combos encontrados (1 batch)
            combo_rows = q_combo.all()
            combo_ids = sorted({int(getattr(r, "combo_id", 0) or 0) for r in combo_rows if int(getattr(r, "combo_id", 0) or 0) > 0})

            combos_def_map: dict[int, Any] = {}
            combos_itens_map: dict[int, list[Any]] = {}
            if combo_ids:
                try:
                    defs = (
                        db.query(CampanhaCombo)
                        .filter(CampanhaCombo.id.in_(combo_ids))
                        .all()
                    )
                    combos_def_map = {int(getattr(c, "id", 0) or 0): c for c in defs}
                except Exception:
                    combos_def_map = {}

                try:
                    itens_all = (
                        db.query(CampanhaComboItem)
                        .filter(CampanhaComboItem.combo_id.in_(combo_ids))
                        .order_by(CampanhaComboItem.combo_id.asc(), CampanhaComboItem.ordem.asc(), CampanhaComboItem.id.asc())
                        .all()
                    )
                    for it in itens_all:
                        combos_itens_map.setdefault(int(getattr(it, "combo_id", 0) or 0), []).append(it)
                except Exception:
                    combos_itens_map = {}

            def _combo_item_filters(item: Any, marca: str, vend: str) -> list[Any]:
                conds: list[Any] = [
                    Venda.emp == str(emp),
                    Venda.vendedor == vend,
                    Venda.data >= periodo_ini,
                    Venda.data <= periodo_fim,
                    ~Venda.mov_tipo_movto.in_(["DS", "CA"]),
                ]

                marca_up = (marca or "").strip().upper()
                if marca_up:
                    conds.append(Venda.marca.ilike(marca_up))

                mp = (getattr(item, "mestre_prefixo", None) or "").strip()
                dc = (getattr(item, "descricao_contains", None) or "").strip()

                if not mp and not dc:
                    mm = (getattr(item, "match_mestre", None) or "").strip()
                    if mm:
                        if " " not in mm and len(mm) <= 40:
                            mp = mm
                        else:
                            dc = mm

                if mp:
                    conds.append(Venda.mestre.ilike(f"{mp}%"))
                if dc:
                    conds.append(or_(Venda.descricao_norm.ilike(f"%{dc}%"), Venda.descricao.ilike(f"%{dc}%")))

                return conds

            for r in combo_rows:
                combo_id = int(getattr(r, "combo_id", 0) or 0)
                if combo_id <= 0:
                    continue

                vendedor = str(getattr(r, "vendedor", "") or "").strip().upper()
                if not vendedor:
                    continue

                titulo_combo = str(getattr(r, "titulo", "") or "").strip() or f"Combo #{combo_id}"
                st_pag = str(getattr(r, "status_pagamento", "PENDENTE") or "PENDENTE")
                pago_em = getattr(r, "pago_em", None)

                cdef = combos_def_map.get(combo_id)
                marca = (getattr(cdef, "marca", "") or "").strip() if cdef is not None else ""
                valor_unit_global = _safe_float(getattr(cdef, "valor_unitario_global", 0.0)) if cdef is not None else 0.0

                itens = combos_itens_map.get(combo_id) or []
                if not itens:
                    # Sem itens cadastrados -> mantém uma linha "resumo" (compatibilidade)
                    atingiu_gate = bool(int(getattr(r, "atingiu_gate", 0) or 0))
                    val = _safe_float(getattr(r, "valor_recompensa", 0.0)) if atingiu_gate else 0.0
                    if incluir_zerados or val > 0:
                        rows.append(
                            UnifiedRow(
                                tipo="COMBO",
                                competencia_ano=int(getattr(r, "competencia_ano", ano)),
                                competencia_mes=int(getattr(r, "competencia_mes", mes)),
                                emp=str(getattr(r, "emp", emp)),
                                vendedor=vendedor,
                                titulo=titulo_combo,
                                atingiu_gate=atingiu_gate,
                                qtd_base=0.0,
                                qtd_premiada=None,
                                valor_recompensa=val,
                                status_pagamento=st_pag,
                                pago_em=pago_em,
                                origem_id=combo_id,
                            )
                        )
                    continue

                # Calcula "gate" ao vivo: precisa bater todos os mínimos
                itens_calc: list[tuple[Any, float, float, float, int]] = []  # (item, qtd, vendeu_rs, recompensa_unit, minimo)
                atingiu_gate = True
                for it in itens:
                    minimo = int(getattr(it, "minimo_qtd", 0) or 0)
                    recompensa_unit = _safe_float(getattr(it, "valor_unitario", 0.0)) or valor_unit_global

                    conds = _combo_item_filters(it, marca, vendedor)
                    try:
                        res = (
                            db.query(
                                func.coalesce(func.sum(Venda.qtdade_vendida), 0),
                                func.coalesce(func.sum(Venda.valor_total), 0),
                            )
                            .filter(*conds)
                            .first()
                        )
                        qtd = float((res[0] if res else 0) or 0)
                        vendeu_rs = float((res[1] if res else 0) or 0)
                    except Exception:
                        qtd = 0.0
                        vendeu_rs = 0.0

                    if minimo > 0 and qtd < float(minimo):
                        atingiu_gate = False

                    itens_calc.append((it, qtd, vendeu_rs, recompensa_unit, minimo))

                # Gera 1 linha por item (para exibição no relatório detalhado)
                for it, qtd, vendeu_rs, recompensa_unit, minimo in itens_calc:
                    # Identificação do item no relatório: prioriza mestre_prefixo (código), senão match_mestre
                    item_codigo = (getattr(it, "mestre_prefixo", None) or "").strip()
                    if not item_codigo:
                        mm = (getattr(it, "match_mestre", None) or "").strip()
                        item_codigo = mm if mm else (getattr(it, "nome_item", None) or "Item")

                    # Premiação só "liga" quando atingiu o combo
                    valor_recompensa = float(qtd * recompensa_unit) if (atingiu_gate and recompensa_unit > 0) else 0.0

                    # Se incluir_zerados=False, mantemos linhas com venda (parcial) ou com premiação
                    if (not incluir_zerados) and (vendeu_rs <= 0 and valor_recompensa <= 0 and qtd <= 0):
                        continue

                    rows.append(
                        UnifiedRow(
                            tipo="COMBO",
                            competencia_ano=int(getattr(r, "competencia_ano", ano)),
                            competencia_mes=int(getattr(r, "competencia_mes", mes)),
                            emp=str(getattr(r, "emp", emp)),
                            vendedor=vendedor,
                            titulo=titulo_combo,
                            item_codigo=str(item_codigo),
                            qtd_minima=float(minimo) if minimo else 0.0,
                            recompensa_unit=float(recompensa_unit or 0.0),
                            valor_vendido=float(vendeu_rs or 0.0),
                            atingiu_gate=bool(atingiu_gate),
                            qtd_base=float(qtd or 0.0),
                            qtd_premiada=float(qtd or 0.0) if atingiu_gate else 0.0,
                            valor_recompensa=float(valor_recompensa or 0.0),
                            status_pagamento=st_pag,
                            pago_em=pago_em,
                            origem_id=combo_id,
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
                            ItemParadoResultado.emp == str(emp),
                            ItemParadoResultado.vendedor.in_(vendedores),
                        )
                    )
                    if not incluir_zerados:
                        q_par = q_par.filter(ItemParadoResultado.valor_recompensa > 0)
                    par_all = q_par.all()
                except Exception:
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
                parados_defs = (
                    db.query(ItemParado)
                    .filter(ItemParado.ativo.is_(True), ItemParado.emp == str(emp))
                    .order_by(ItemParado.descricao.asc())
                    .all()
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