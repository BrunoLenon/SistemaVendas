from __future__ import annotations

"""
Relatório Unificado de Campanhas

Objetivo:
- Normalizar resultados de campanhas QTD, COMBO e ITENS PARADOS em um único "dataset"
  para renderização em uma tabela/dash consolidada.
- Mostrar COMBO mesmo sem atingir, com itens detalhados por vendedor.
- Evitar regressão/performance ruim no /relatorios/campanhas, principalmente para
  supervisor e vendedor, reduzindo queries N+1.
"""

from dataclasses import dataclass
from datetime import date
from typing import Any

from sqlalchemy import String, cast, func, or_

from db import (
    SessionLocal,
    Venda,
    CampanhaQtdResultado,
    CampanhaComboResultado,
    CampanhaCombo,
    CampanhaComboItem,
    ItemParado,
)

try:
    from db import ItemParadoResultado  # type: ignore
except Exception:  # pragma: no cover
    ItemParadoResultado = None  # type: ignore


@dataclass(frozen=True)
class UnifiedRow:
    tipo: str
    competencia_ano: int
    competencia_mes: int
    emp: str
    vendedor: str
    titulo: str

    item_codigo: str | None = None
    qtd_minima: float | None = None
    recompensa_unit: float | None = None
    valor_vendido: float | None = None

    @property
    def atingiu(self) -> bool:
        try:
            return bool(self.atingiu_gate or False)
        except Exception:
            return False

    atingiu_gate: bool | None = None
    qtd_base: float | None = None
    qtd_premiada: float | None = None

    valor_recompensa: float = 0.0
    status_pagamento: str = "PENDENTE"
    pago_em: Any | None = None
    origem_id: int | None = None

    def get(self, key: str, default: Any = None) -> Any:
        if key is None:
            return default
        k = str(key)
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
    from calendar import monthrange
    di = date(int(ano), int(mes), 1)
    df = date(int(ano), int(mes), monthrange(int(ano), int(mes))[1])
    return di, df


def _upper(v: Any) -> str:
    return str(v or "").strip().upper()


def build_unified_rows(
    *,
    ano: int,
    mes: int,
    emps: list[str],
    vendedores_por_emp: dict[str, list[str]],
    incluir_zerados: bool = False,
    usar_snapshot_itens_parados: bool = True,
) -> list[UnifiedRow]:
    periodo_ini, periodo_fim = _periodo_bounds(ano, mes)
    rows: list[UnifiedRow] = []

    with SessionLocal() as db:
        for emp in emps:
            try:
                db.rollback()
            except Exception:
                pass

            vendedores = [_upper(v) for v in (vendedores_por_emp.get(emp) or []) if str(v or '').strip()]
            vendedores = [v for v in vendedores if v]
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
                recompensa_unit = _safe_float(getattr(r, 'recompensa_unit', 0.0))
                valor_recompensa = _safe_float(getattr(r, 'valor_recompensa', 0.0))
                qtd_minima = getattr(r, 'qtd_minima', None)
                valor_vendido = _safe_float(getattr(r, 'valor_vendido', 0.0))
                qtd_prem = None
                if recompensa_unit > 0 and valor_recompensa > 0:
                    qtd_prem = valor_recompensa / recompensa_unit

                rows.append(
                    UnifiedRow(
                        tipo='QTD',
                        competencia_ano=int(getattr(r, 'competencia_ano', ano)),
                        competencia_mes=int(getattr(r, 'competencia_mes', mes)),
                        emp=str(getattr(r, 'emp', emp)),
                        vendedor=_upper(getattr(r, 'vendedor', '')),
                        titulo=str(getattr(r, 'titulo', '') or '').strip() or f"Campanha #{getattr(r, 'campanha_id', '')}",
                        item_codigo=str(getattr(r, 'produto_prefixo', '') or '').strip() or None,
                        qtd_minima=_safe_float(qtd_minima) if qtd_minima is not None else None,
                        recompensa_unit=recompensa_unit,
                        valor_vendido=valor_vendido,
                        atingiu_gate=bool(int(getattr(r, 'atingiu_minimo', 0) or 0)),
                        qtd_base=_safe_float(getattr(r, 'qtd_vendida', None)),
                        qtd_premiada=qtd_prem,
                        valor_recompensa=valor_recompensa,
                        status_pagamento=str(getattr(r, 'status_pagamento', 'PENDENTE') or 'PENDENTE'),
                        pago_em=getattr(r, 'pago_em', None),
                        origem_id=int(getattr(r, 'campanha_id', 0) or 0),
                    )
                )

            # -------- COMBO (ativo + itens detalhados + snapshot para pagamento) --------
            combos_ativos = (
                db.query(CampanhaCombo)
                .filter(CampanhaCombo.ativo == True)  # noqa: E712
                .filter(CampanhaCombo.ano == int(ano), CampanhaCombo.mes == int(mes))
                .filter(
                    or_(
                        cast(CampanhaCombo.emp, String) == str(emp),
                        CampanhaCombo.emp.is_(None),
                        cast(CampanhaCombo.emp, String) == '',
                    )
                )
                .all()
            )

            if combos_ativos:
                combo_ids = [int(getattr(c, 'id', 0) or 0) for c in combos_ativos if int(getattr(c, 'id', 0) or 0) > 0]

                snap_map: dict[tuple[int, str], Any] = {}
                if combo_ids:
                    try:
                        snaps = (
                            db.query(CampanhaComboResultado)
                            .filter(
                                CampanhaComboResultado.competencia_ano == int(ano),
                                CampanhaComboResultado.competencia_mes == int(mes),
                                cast(CampanhaComboResultado.emp, String) == str(emp),
                                CampanhaComboResultado.vendedor.in_(vendedores),
                                CampanhaComboResultado.combo_id.in_(combo_ids),
                            )
                            .all()
                        )
                        for s in snaps:
                            snap_map[(int(getattr(s, 'combo_id', 0) or 0), _upper(getattr(s, 'vendedor', '')))] = s
                    except Exception:
                        snap_map = {}

                itens_por_combo: dict[int, list[Any]] = {cid: [] for cid in combo_ids}
                if combo_ids:
                    try:
                        itens_all = (
                            db.query(CampanhaComboItem)
                            .filter(CampanhaComboItem.combo_id.in_(combo_ids))
                            .order_by(CampanhaComboItem.combo_id.asc(), CampanhaComboItem.ordem.asc(), CampanhaComboItem.id.asc())
                            .all()
                        )
                        for it in itens_all:
                            itens_por_combo.setdefault(int(getattr(it, 'combo_id', 0) or 0), []).append(it)
                    except Exception:
                        itens_por_combo = {cid: [] for cid in combo_ids}

                # Pré-carrega vendas do período em UMA query por EMP
                vendas_rows = (
                    db.query(
                        Venda.vendedor,
                        Venda.mestre,
                        func.coalesce(Venda.descricao, ''),
                        func.coalesce(func.sum(Venda.qtdade_vendida), 0),
                        func.coalesce(func.sum(Venda.valor_total), 0),
                    )
                    .filter(Venda.emp == str(emp))
                    .filter(Venda.vendedor.in_(vendedores))
                    .filter(Venda.movimento >= periodo_ini, Venda.movimento <= periodo_fim)
                    .filter(~Venda.mov_tipo_movto.in_(['DS', 'CA']))
                    .group_by(Venda.vendedor, Venda.mestre, func.coalesce(Venda.descricao, ''))
                    .all()
                )

                sales_by_vendor: dict[str, list[dict[str, Any]]] = {v: [] for v in vendedores}
                for vend, mestre, descricao, qtd, val in vendas_rows:
                    vend_u = _upper(vend)
                    sales_by_vendor.setdefault(vend_u, []).append({
                        'mestre': str(mestre or '').strip(),
                        'descricao': _upper(descricao),
                        'qtd': float(qtd or 0),
                        'valor': float(val or 0),
                    })

                def _sum_vendas_item(vend_u: str, mestre_prefixo: str | None, descricao_contains: str | None) -> tuple[float, float]:
                    prefix = str(mestre_prefixo or '').strip()
                    desc_need = _upper(descricao_contains)
                    qtd_total = 0.0
                    val_total = 0.0
                    for sale in sales_by_vendor.get(vend_u, []):
                        if prefix and not sale['mestre'].startswith(prefix):
                            continue
                        if desc_need and desc_need not in sale['descricao']:
                            continue
                        if not prefix and not desc_need:
                            continue
                        qtd_total += float(sale['qtd'] or 0)
                        val_total += float(sale['valor'] or 0)
                    return qtd_total, val_total

                for vend in vendedores:
                    for combo in combos_ativos:
                        combo_id = int(getattr(combo, 'id', 0) or 0)
                        if combo_id <= 0:
                            continue
                        itens = itens_por_combo.get(combo_id) or []
                        if not itens:
                            continue

                        titulo_combo = (
                            str(getattr(combo, 'titulo', '') or '').strip()
                            or str(getattr(combo, 'nome', '') or '').strip()
                            or f'Combo #{combo_id}'
                        )
                        titulo_combo_ui = f'COMBO {emp} {titulo_combo}'.strip()

                        item_rows: list[UnifiedRow] = []
                        total_vendeu = 0.0
                        total_premio_potencial = 0.0
                        itens_atingidos = 0

                        for it in itens:
                            minimo = int(getattr(it, 'minimo_qtd', 0) or 0)
                            mestre_prefixo = str(getattr(it, 'mestre_prefixo', None) or getattr(it, 'match_mestre', None) or '').strip() or None
                            descricao_contains = str(getattr(it, 'descricao_contains', None) or '').strip() or None

                            qtd_vendida, vendeu_rs = _sum_vendas_item(vend, mestre_prefixo, descricao_contains)
                            total_vendeu += vendeu_rs

                            item_ok = bool(minimo <= 0 or qtd_vendida >= float(minimo))
                            if item_ok:
                                itens_atingidos += 1

                            recompensa_unit = _safe_float(getattr(it, 'valor_unitario', None))
                            if recompensa_unit <= 0:
                                recompensa_unit = _safe_float(getattr(combo, 'valor_unitario_global', None))

                            valor_potencial = float(qtd_vendida or 0) * float(recompensa_unit or 0)
                            total_premio_potencial += valor_potencial

                            item_codigo = mestre_prefixo or (str(getattr(it, 'match_mestre', '') or '').strip() or None)
                            item_titulo = f'↳ {item_codigo}' if item_codigo else f'↳ {str(getattr(it, "nome_item", "") or "Item").strip() or "Item"}'

                            item_rows.append(
                                UnifiedRow(
                                    tipo='COMBO',
                                    competencia_ano=int(ano),
                                    competencia_mes=int(mes),
                                    emp=str(emp),
                                    vendedor=vend,
                                    titulo=item_titulo,
                                    item_codigo=item_codigo,
                                    qtd_minima=float(minimo) if minimo > 0 else None,
                                    recompensa_unit=float(recompensa_unit or 0.0),
                                    qtd_base=float(qtd_vendida or 0.0),
                                    valor_vendido=float(vendeu_rs or 0.0),
                                    atingiu_gate=item_ok,
                                    valor_recompensa=float(valor_potencial or 0.0),
                                    status_pagamento='PENDENTE',
                                    pago_em=None,
                                    origem_id=combo_id,
                                )
                            )

                        combo_atingiu = bool(item_rows) and itens_atingidos == len(item_rows)
                        snap = snap_map.get((combo_id, vend))
                        st_pag = str(getattr(snap, 'status_pagamento', 'PENDENTE') or 'PENDENTE') if snap else 'PENDENTE'
                        pago_em = getattr(snap, 'pago_em', None) if snap else None

                        rows.append(
                            UnifiedRow(
                                tipo='COMBO',
                                competencia_ano=int(ano),
                                competencia_mes=int(mes),
                                emp=str(emp),
                                vendedor=vend,
                                titulo=titulo_combo_ui,
                                item_codigo=None,
                                qtd_minima=None,
                                recompensa_unit=0.0,
                                qtd_base=float(itens_atingidos),
                                valor_vendido=float(total_vendeu or 0.0),
                                atingiu_gate=combo_atingiu,
                                valor_recompensa=float(total_premio_potencial or 0.0),
                                status_pagamento=st_pag,
                                pago_em=pago_em,
                                origem_id=combo_id,
                            )
                        )
                        rows.extend(item_rows)

            # -------- ITENS PARADOS --------
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
                            tipo='PARADO',
                            competencia_ano=int(getattr(r, 'competencia_ano', ano)),
                            competencia_mes=int(getattr(r, 'competencia_mes', mes)),
                            emp=str(getattr(r, 'emp', emp)),
                            vendedor=_upper(getattr(r, 'vendedor', '')),
                            titulo=str(getattr(r, 'titulo', '') or '').strip() or 'Item Parado',
                            atingiu_gate=True if _safe_float(getattr(r, 'base_valor_vendido', 0.0)) > 0 else False,
                            qtd_base=_safe_float(getattr(r, 'base_valor_vendido', 0.0)),
                            qtd_premiada=None,
                            valor_recompensa=_safe_float(getattr(r, 'valor_recompensa', 0.0)),
                            status_pagamento=str(getattr(r, 'status_pagamento', 'PENDENTE') or 'PENDENTE'),
                            pago_em=getattr(r, 'pago_em', None),
                            origem_id=int(getattr(r, 'item_parado_id', 0) or 0),
                        )
                    )
            else:
                parados_defs = (
                    db.query(ItemParado)
                    .filter(ItemParado.ativo.is_(True), ItemParado.emp == str(emp))
                    .order_by(ItemParado.descricao.asc())
                    .all()
                )
                for ip in parados_defs:
                    codigo = (getattr(ip, 'codigo', '') or '').strip()
                    if not codigo:
                        continue
                    pct = _safe_float(getattr(ip, 'recompensa_pct', 0.0))
                    if pct <= 0:
                        continue

                    base_rows = (
                        db.query(Venda.vendedor, func.sum(Venda.valor_total))
                        .filter(
                            Venda.emp == str(emp),
                            Venda.movimento >= periodo_ini,
                            Venda.movimento <= periodo_fim,
                            ~Venda.mov_tipo_movto.in_(['DS', 'CA']),
                            Venda.mestre == codigo,
                            Venda.vendedor.in_(vendedores),
                        )
                        .group_by(Venda.vendedor)
                        .all()
                    )

                    for vend, base_val in base_rows:
                        vend_u = _upper(vend)
                        base_val_f = _safe_float(base_val)
                        valor = base_val_f * (pct / 100.0)
                        if (not incluir_zerados) and valor <= 0:
                            continue
                        rows.append(
                            UnifiedRow(
                                tipo='PARADO',
                                competencia_ano=int(ano),
                                competencia_mes=int(mes),
                                emp=str(emp),
                                vendedor=vend_u,
                                titulo=str(getattr(ip, 'descricao', '') or '').strip() or f'Item {codigo}',
                                atingiu_gate=True if base_val_f > 0 else False,
                                qtd_base=base_val_f,
                                qtd_premiada=None,
                                valor_recompensa=valor,
                                status_pagamento='PENDENTE',
                                pago_em=None,
                                origem_id=int(getattr(ip, 'id', 0) or 0),
                            )
                        )

    rows.sort(key=lambda r: (r.emp, r.vendedor, r.tipo, r.titulo))
    return rows


def aggregate_for_charts(rows: list[UnifiedRow]) -> dict[str, Any]:
    by_tipo: dict[str, float] = {}
    by_emp: dict[str, float] = {}
    total = 0.0
    for r in rows:
        val = _safe_float(r.valor_recompensa)
        total += val
        by_tipo[r.tipo] = by_tipo.get(r.tipo, 0.0) + val
        by_emp[r.emp] = by_emp.get(r.emp, 0.0) + val
    return {
        'total_recompensa': total,
        'by_tipo': [{'label': k, 'value': float(v)} for k, v in sorted(by_tipo.items())],
        'by_emp': [{'label': k, 'value': float(v)} for k, v in sorted(by_emp.items())],
    }
