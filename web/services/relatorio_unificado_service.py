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
import json
from decimal import Decimal, ROUND_FLOOR, ROUND_HALF_UP
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
    ItensParadosPontosConfig,
    ItensParadosPontosBonus,
    MetaPrograma,
    MetaProgramaEmp,
    MetaResultado,
    FinanceiroPagamento,
    CampanhaV2MasterNew,
    CampanhaV2ResultadoNew,
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
    info_aux: str | None = None
    metrica_display: str | None = None

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


def _d(v: Any) -> Decimal:
    try:
        return Decimal(str(v if v is not None else 0))
    except Exception:
        return Decimal("0")


MIN_PONTOS_PAGAMENTO_ITENS_PARADOS = Decimal("10")
ITENS_PARADOS_MOV_TIPOS_VENDA = ("OA", "VV", "SV")


def _bonus_base_from_pontos(pontos: Any, valor_por_ponto: Any) -> Decimal:
    pontos_validos = _d(pontos)
    if pontos_validos <= 0:
        return Decimal("0")
    pontos_fechados = pontos_validos.quantize(Decimal("1"), rounding=ROUND_FLOOR)
    if pontos_fechados <= 0:
        return Decimal("0")
    return pontos_fechados * _d(valor_por_ponto)


def _round2(v: Any) -> float:
    try:
        return float(_d(v).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    except Exception:
        return 0.0


def _fmt_float_br(v: Any, decimals: int = 2) -> str:
    try:
        num = float(v or 0)
    except Exception:
        num = 0.0
    return f"{num:.{decimals}f}".replace(".", ",")


def _safe_json_loads(v: Any) -> dict[str, Any]:
    if not v:
        return {}
    try:
        data = json.loads(v)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def build_unified_rows(
    *,
    ano: int,
    mes: int,
    emps: list[str],
    vendedores_por_emp: dict[str, list[str]],
    incluir_zerados: bool = False,
    usar_snapshot_itens_parados: bool = True,
    role: str | None = None,
) -> list[UnifiedRow]:
    periodo_ini, periodo_fim = _periodo_bounds(ano, mes)
    rows: list[UnifiedRow] = []
    role_l = (role or '').strip().lower()
    all_vendedores_scope = sorted({_upper(v) for vs in (vendedores_por_emp or {}).values() for v in (vs or []) if str(v or '').strip()})

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

                        # Regra de negócio do COMBO:
                        # - vendedor só recebe premiação se atingir o combo completo
                        # - enquanto estiver parcial, mostramos a evolução de venda,
                        #   mas a recompensa permanece zerada
                        if not combo_atingiu:
                            total_premio_potencial = 0.0
                            item_rows = [
                                UnifiedRow(
                                    tipo=ir.tipo,
                                    competencia_ano=ir.competencia_ano,
                                    competencia_mes=ir.competencia_mes,
                                    emp=ir.emp,
                                    vendedor=ir.vendedor,
                                    titulo=ir.titulo,
                                    item_codigo=ir.item_codigo,
                                    qtd_minima=ir.qtd_minima,
                                    recompensa_unit=ir.recompensa_unit,
                                    qtd_base=ir.qtd_base,
                                    valor_vendido=ir.valor_vendido,
                                    atingiu_gate=ir.atingiu_gate,
                                    valor_recompensa=0.0,
                                    status_pagamento=ir.status_pagamento,
                                    pago_em=ir.pago_em,
                                    origem_id=ir.origem_id,
                                )
                                for ir in item_rows
                            ]

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


            # -------- METAS --------
            try:
                from metas_helpers import (
                    META_GERENTE_ALIAS,
                    META_GERENTE_LABEL,
                    _calc_and_upsert_meta_result,
                )
            except Exception:
                META_GERENTE_ALIAS = '__GERENTE__'
                META_GERENTE_LABEL = 'GERENTE'
                _calc_and_upsert_meta_result = None

            metas_ativas = (
                db.query(MetaPrograma)
                .filter(MetaPrograma.ano == int(ano), MetaPrograma.mes == int(mes), MetaPrograma.ativo.is_(True))
                .order_by(MetaPrograma.escopo.asc(), MetaPrograma.tipo.asc(), MetaPrograma.nome.asc())
                .all()
            )
            if metas_ativas:
                meta_ids = [int(getattr(m, 'id', 0) or 0) for m in metas_ativas if int(getattr(m, 'id', 0) or 0) > 0]
                meta_emps_map: dict[int, set[str]] = {mid: set() for mid in meta_ids}
                if meta_ids:
                    for mid, emp_meta in (
                        db.query(MetaProgramaEmp.meta_id, MetaProgramaEmp.emp)
                        .filter(MetaProgramaEmp.meta_id.in_(meta_ids))
                        .all()
                    ):
                        mid_i = int(mid or 0)
                        emp_s = str(emp_meta or '').strip()
                        if mid_i and emp_s:
                            meta_emps_map.setdefault(mid_i, set()).add(emp_s)

                res_existentes = (
                    db.query(MetaResultado)
                    .filter(MetaResultado.ano == int(ano), MetaResultado.mes == int(mes), MetaResultado.emp == str(emp))
                    .filter(MetaResultado.meta_id.in_(meta_ids) if meta_ids else True)
                    .all()
                )
                meta_res_map = {
                    (int(getattr(r, 'meta_id', 0) or 0), str(getattr(r, 'emp', '') or '').strip(), _upper(getattr(r, 'vendedor', ''))): r
                    for r in (res_existentes or [])
                }

                for meta in metas_ativas:
                    meta_id = int(getattr(meta, 'id', 0) or 0)
                    if meta_id <= 0:
                        continue
                    emps_meta = meta_emps_map.get(meta_id) or set()
                    if emps_meta and str(emp) not in emps_meta:
                        continue

                    scope_meta = str(getattr(meta, 'escopo', 'VENDEDOR') or 'VENDEDOR').strip().upper()
                    tipo_meta = str(getattr(meta, 'tipo', '') or '').strip().upper()
                    nome_meta = str(getattr(meta, 'nome', '') or '').strip() or f'Meta #{meta_id}'

                    metas_vendedores: list[tuple[str, str]] = []
                    if scope_meta == 'GERENTE':
                        if role_l in ('admin', 'supervisor', 'financeiro'):
                            metas_vendedores = [(META_GERENTE_ALIAS, META_GERENTE_LABEL)]
                    else:
                        metas_vendedores = [(v, v) for v in vendedores]

                    for vendedor_ref, vendedor_label in metas_vendedores:
                        key = (meta_id, str(emp), _upper(vendedor_label))
                        res = meta_res_map.get(key)
                        if res is None and _calc_and_upsert_meta_result is not None:
                            try:
                                res = _calc_and_upsert_meta_result(db, meta, str(emp), vendedor_ref)
                            except Exception:
                                res = None
                            if res is not None:
                                meta_res_map[(meta_id, str(emp), _upper(getattr(res, 'vendedor', vendedor_label)))] = res

                        if res is None:
                            continue

                        premio = _safe_float(getattr(res, 'premio', 0.0))
                        valor_mes = _safe_float(getattr(res, 'valor_mes', 0.0))
                        bonus_pct = _safe_float(getattr(res, 'bonus_percentual', 0.0))
                        crescimento_pct = getattr(res, 'crescimento_pct', None)
                        mix_itens = getattr(res, 'mix_itens_unicos', None)
                        share_pct = getattr(res, 'share_pct', None)

                        if (not incluir_zerados) and premio <= 0:
                            continue

                        metrica_display = None
                        info_aux = None
                        if tipo_meta == 'CRESCIMENTO':
                            if crescimento_pct is not None:
                                metrica_display = f"{_fmt_float_br(crescimento_pct)}%"
                            base_val = getattr(res, 'base_valor', None)
                            info_aux = f"Tipo: Crescimento • Bônus: {_fmt_float_br(bonus_pct)}%"
                            if base_val not in (None, ''):
                                info_aux += f" • Base: R$ {_fmt_float_br(base_val)}"
                        elif tipo_meta == 'MIX':
                            if mix_itens is not None:
                                try:
                                    metrica_display = f"{int(round(float(mix_itens or 0)))} itens"
                                except Exception:
                                    metrica_display = f"{_fmt_float_br(mix_itens, 0)} itens"
                            info_aux = f"Tipo: MIX • Bônus: {_fmt_float_br(bonus_pct)}%"
                        elif tipo_meta == 'SHARE_MARCA':
                            if share_pct is not None:
                                metrica_display = f"{_fmt_float_br(share_pct)}%"
                            valor_marcas = getattr(res, 'valor_marcas', None)
                            info_aux = f"Tipo: Share de Marcas • Bônus: {_fmt_float_br(bonus_pct)}%"
                            if valor_marcas not in (None, ''):
                                info_aux += f" • Marcas: R$ {_fmt_float_br(valor_marcas)}"
                        else:
                            info_aux = f"Bônus: {_fmt_float_br(bonus_pct)}%"

                        rows.append(
                            UnifiedRow(
                                tipo='META',
                                competencia_ano=int(getattr(res, 'ano', ano) or ano),
                                competencia_mes=int(getattr(res, 'mes', mes) or mes),
                                emp=str(getattr(res, 'emp', emp) or emp),
                                vendedor=_upper(getattr(res, 'vendedor', vendedor_label) or vendedor_label),
                                titulo=f"Meta • {nome_meta}",
                                qtd_minima=None,
                                recompensa_unit=None,
                                valor_vendido=valor_mes,
                                atingiu_gate=bool(premio > 0),
                                qtd_base=_safe_float(crescimento_pct if crescimento_pct is not None else (share_pct if share_pct is not None else (mix_itens if mix_itens is not None else 0))),
                                qtd_premiada=None,
                                valor_recompensa=premio,
                                status_pagamento='PENDENTE',
                                pago_em=None,
                                origem_id=meta_id,
                                info_aux=info_aux,
                                metrica_display=metrica_display,
                            )
                        )

            # -------- RANKING POR MARCA (POR_EMP) --------
            ranking_rows_emp = (
                db.query(CampanhaV2ResultadoNew, CampanhaV2MasterNew)
                .join(CampanhaV2MasterNew, CampanhaV2MasterNew.id == CampanhaV2ResultadoNew.campanha_id)
                .filter(CampanhaV2ResultadoNew.ano == int(ano), CampanhaV2ResultadoNew.mes == int(mes))
                .filter(CampanhaV2MasterNew.tipo == 'RANKING_MARCA')
                .filter(CampanhaV2ResultadoNew.emp == int(emp) if str(emp).isdigit() else False)
                .filter(CampanhaV2ResultadoNew.vendedor.in_(vendedores))
                .all()
            )
            fin_v2_map_emp: dict[tuple[int, str, int | None], Any] = {}
            if ranking_rows_emp:
                campanha_ids_v2 = sorted({int(getattr(res, 'campanha_id', 0) or 0) for res, _camp in ranking_rows_emp if int(getattr(res, 'campanha_id', 0) or 0) > 0})
                fin_rows = (
                    db.query(FinanceiroPagamento)
                    .filter(FinanceiroPagamento.ano == int(ano), FinanceiroPagamento.mes == int(mes), FinanceiroPagamento.origem_tipo == 'V2')
                    .filter(FinanceiroPagamento.origem_id.in_(campanha_ids_v2) if campanha_ids_v2 else True)
                    .filter(FinanceiroPagamento.emp == int(emp) if str(emp).isdigit() else False)
                    .filter(FinanceiroPagamento.vendedor.in_(vendedores))
                    .all()
                )
                fin_v2_map_emp = {
                    (int(getattr(f, 'origem_id', 0) or 0), _upper(getattr(f, 'vendedor', '')), getattr(f, 'emp', None)): f
                    for f in (fin_rows or [])
                }

            for res, camp in ranking_rows_emp:
                premio = _safe_float(getattr(res, 'premio', 0.0))
                if (not incluir_zerados) and premio <= 0:
                    continue
                detalhes = _safe_json_loads(getattr(res, 'detalhes_json', None))
                marca = str(detalhes.get('marca') or getattr(camp, 'marca_alvo', '') or '').strip().upper()
                minimo = _safe_float(detalhes.get('minimo') if isinstance(detalhes, dict) else 0.0)
                posicao = getattr(res, 'posicao', None)
                fin = fin_v2_map_emp.get((int(getattr(res, 'campanha_id', 0) or 0), _upper(getattr(res, 'vendedor', '')), getattr(res, 'emp', None)))
                status_pag = str(getattr(fin, 'status', 'PENDENTE') or 'PENDENTE') if fin is not None else 'PENDENTE'
                rows.append(
                    UnifiedRow(
                        tipo='RANKING_MARCA',
                        competencia_ano=int(getattr(res, 'ano', ano) or ano),
                        competencia_mes=int(getattr(res, 'mes', mes) or mes),
                        emp=str(getattr(res, 'emp', emp) or emp),
                        vendedor=_upper(getattr(res, 'vendedor', '')),
                        titulo=f"Ranking por Marca • {str(getattr(camp, 'nome', '') or '').strip() or ('Campanha #' + str(getattr(camp, 'id', '')))}",
                        qtd_minima=None,
                        recompensa_unit=None,
                        valor_vendido=_safe_float(getattr(res, 'valor_atual', 0.0)),
                        atingiu_gate=bool(getattr(res, 'atingiu', False)),
                        qtd_base=_safe_float(getattr(res, 'posicao', 0) or 0),
                        qtd_premiada=None,
                        valor_recompensa=premio,
                        status_pagamento=status_pag,
                        pago_em=getattr(fin, 'atualizado_em', None) if fin is not None else None,
                        origem_id=int(getattr(res, 'campanha_id', 0) or 0),
                        info_aux=(f"Marca: {marca}" + (f" • Mínimo: R$ {_fmt_float_br(minimo)}" if minimo > 0 else "")),
                        metrica_display=(f"{int(posicao)}º lugar" if posicao not in (None, '') else None),
                    )
                )
            # -------- ITENS PARADOS --------
            # Prioridade:
            # 1) snapshot legado (itens_parados_resultados), se existir e tiver linhas no mês
            # 2) cálculo novo por pontos (ao vivo), agrupado em uma única linha por vendedor/EMP
            # 3) fallback legado percentual, se houver cadastro antigo com recompensa_pct
            par_rows_added = 0
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
                        q_par = q_par.filter(or_(ItemParadoResultado.valor_recompensa > 0, ItemParadoResultado.base_valor_vendido > 0))
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
                            titulo='Itens Parados',
                            recompensa_unit=_safe_float(getattr(r, 'recompensa_pct', 0.0)),
                            valor_vendido=_safe_float(getattr(r, 'base_valor_vendido', 0.0)),
                            atingiu_gate=True if _safe_float(getattr(r, 'valor_recompensa', 0.0)) > 0 else False,
                            qtd_base=_safe_float(getattr(r, 'base_valor_vendido', 0.0)),
                            qtd_premiada=None,
                            valor_recompensa=_safe_float(getattr(r, 'valor_recompensa', 0.0)),
                            status_pagamento=str(getattr(r, 'status_pagamento', 'PENDENTE') or 'PENDENTE'),
                            pago_em=getattr(r, 'pago_em', None),
                            origem_id=int(getattr(r, 'item_parado_id', 0) or 0),
                        )
                    )
                    par_rows_added += 1

            if par_rows_added == 0:
                parados_defs = (
                    db.query(ItemParado)
                    .filter(ItemParado.ativo.is_(True), ItemParado.emp == str(emp))
                    .filter(or_(ItemParado.data_inicio.is_(None), ItemParado.data_inicio <= periodo_fim))
                    .filter(or_(ItemParado.data_fim.is_(None), ItemParado.data_fim >= periodo_ini))
                    .order_by(ItemParado.descricao.asc(), ItemParado.codigo.asc(), ItemParado.id.asc())
                    .all()
                )

                # Novo modelo por pontos
                codigos = sorted({str(getattr(ip, 'codigo', '') or '').strip() for ip in parados_defs if str(getattr(ip, 'codigo', '') or '').strip()})
                if codigos:
                    cfg_rows = (
                        db.query(ItensParadosPontosConfig)
                        .filter(ItensParadosPontosConfig.ativo.is_(True))
                        .order_by(ItensParadosPontosConfig.id.desc())
                        .all()
                    )
                    bonus_rows = (
                        db.query(ItensParadosPontosBonus)
                        .filter(ItensParadosPontosBonus.ativo.is_(True))
                        .order_by(ItensParadosPontosBonus.emp.asc().nullsfirst(), ItensParadosPontosBonus.min_pontos.asc())
                        .all()
                    )

                    cfg_global = next((c for c in cfg_rows if getattr(c, 'emp', None) in (None, '', 'NULL')), None)
                    cfg_emp = next((c for c in cfg_rows if str(getattr(c, 'emp', '') or '').strip() == str(emp)), None)
                    bonus_global = [b for b in bonus_rows if getattr(b, 'emp', None) in (None, '', 'NULL')]
                    bonus_emp = [b for b in bonus_rows if str(getattr(b, 'emp', '') or '').strip() == str(emp)]
                    bonus_list = bonus_emp or bonus_global

                    itens_por_codigo: dict[str, list[Any]] = {}
                    for ip in parados_defs:
                        codigo = str(getattr(ip, 'codigo', '') or '').strip()
                        if not codigo:
                            continue
                        itens_por_codigo.setdefault(codigo, []).append(ip)

                    vendas_rows = (
                        db.query(
                            Venda.vendedor,
                            Venda.mestre,
                            Venda.movimento,
                            func.coalesce(func.sum(Venda.valor_total), 0.0),
                        )
                        .filter(
                            Venda.emp == str(emp),
                            Venda.movimento >= periodo_ini,
                            Venda.movimento <= periodo_fim,
                            func.upper(func.coalesce(Venda.mov_tipo_movto, '')).in_(ITENS_PARADOS_MOV_TIPOS_VENDA),
                            Venda.mestre.in_(codigos),
                            Venda.vendedor.in_(vendedores),
                        )
                        .group_by(Venda.vendedor, Venda.mestre, Venda.movimento)
                        .all()
                    )

                    acc: dict[str, dict[str, Decimal]] = {}
                    for vend, mestre, movimento, total in vendas_rows:
                        vend_u = _upper(vend)
                        codigo = str(mestre or '').strip()
                        if not vend_u or not codigo:
                            continue
                        total_dec = _d(total)
                        if total_dec <= 0:
                            continue
                        pontos_sale = Decimal('0')
                        elegivel = False
                        mov_date = movimento if isinstance(movimento, date) else None
                        for ip in itens_por_codigo.get(codigo, []):
                            di = getattr(ip, 'data_inicio', None)
                            df = getattr(ip, 'data_fim', None)
                            if mov_date and di and mov_date < di:
                                continue
                            if mov_date and df and mov_date > df:
                                continue
                            mult = _d(getattr(ip, 'multiplicador_pontos', 1.0) or 1.0)
                            if mult <= 0:
                                mult = Decimal('1')
                            base_reais = _d(getattr(cfg_emp, 'base_reais', None) or getattr(cfg_global, 'base_reais', 100.0) or 100.0)
                            if base_reais <= 0:
                                base_reais = Decimal('100')
                            pontos_sale += (total_dec / base_reais) * mult
                            elegivel = True
                        if not elegivel:
                            continue
                        cur = acc.setdefault(vend_u, {'valor_vendido': Decimal('0'), 'pontos': Decimal('0')})
                        cur['valor_vendido'] += total_dec
                        cur['pontos'] += pontos_sale

                    valor_por_ponto = _d(getattr(cfg_emp, 'valor_por_ponto', None) or getattr(cfg_global, 'valor_por_ponto', 10.0) or 10.0)
                    for vend_u, data in acc.items():
                        pontos = data['pontos']
                        bonus_base = _bonus_base_from_pontos(pontos, valor_por_ponto)
                        bonus_extra = Decimal('0')
                        for faixa in bonus_list:
                            min_pontos = _d(getattr(faixa, 'min_pontos', 0) or 0)
                            if pontos >= min_pontos:
                                bonus_extra = _d(getattr(faixa, 'bonus_valor', 0) or 0)
                        valor_total = bonus_base + bonus_extra
                        if (not incluir_zerados) and valor_total <= 0 and pontos <= 0:
                            continue
                        rows.append(
                            UnifiedRow(
                                tipo='PARADO',
                                competencia_ano=int(ano),
                                competencia_mes=int(mes),
                                emp=str(emp),
                                vendedor=vend_u,
                                titulo='Itens Parados',
                                qtd_minima=None,
                                recompensa_unit=_round2(valor_por_ponto),
                                valor_vendido=_round2(data['valor_vendido']),
                                atingiu_gate=bool(valor_total > 0),
                                qtd_base=_round2(pontos),
                                qtd_premiada=None,
                                valor_recompensa=_round2(valor_total),
                                status_pagamento='PENDENTE',
                                pago_em=None,
                                origem_id=0,
                            )
                        )
                        par_rows_added += 1

                # Fallback legado percentual, apenas se nada do modelo novo foi gerado
                if par_rows_added == 0:
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
                                    titulo='Itens Parados',
                                    recompensa_unit=pct,
                                    valor_vendido=base_val_f,
                                    atingiu_gate=True if base_val_f > 0 else False,
                                    qtd_base=base_val_f,
                                    qtd_premiada=None,
                                    valor_recompensa=valor,
                                    status_pagamento='PENDENTE',
                                    pago_em=None,
                                    origem_id=int(getattr(ip, 'id', 0) or 0),
                                )
                            )

    # -------- RANKING POR MARCA (GLOBAL) --------
    with SessionLocal() as db:
        if all_vendedores_scope:
            ranking_rows_global = (
                db.query(CampanhaV2ResultadoNew, CampanhaV2MasterNew)
                .join(CampanhaV2MasterNew, CampanhaV2MasterNew.id == CampanhaV2ResultadoNew.campanha_id)
                .filter(CampanhaV2ResultadoNew.ano == int(ano), CampanhaV2ResultadoNew.mes == int(mes))
                .filter(CampanhaV2MasterNew.tipo == 'RANKING_MARCA')
                .filter(CampanhaV2ResultadoNew.emp.is_(None))
                .filter(CampanhaV2ResultadoNew.vendedor.in_(all_vendedores_scope))
                .all()
            )
            fin_rows_global = (
                db.query(FinanceiroPagamento)
                .filter(FinanceiroPagamento.ano == int(ano), FinanceiroPagamento.mes == int(mes), FinanceiroPagamento.origem_tipo == 'V2')
                .filter(FinanceiroPagamento.emp.is_(None))
                .filter(FinanceiroPagamento.vendedor.in_(all_vendedores_scope))
                .all()
            )
            fin_v2_map_global = {
                (int(getattr(f, 'origem_id', 0) or 0), _upper(getattr(f, 'vendedor', '')), None): f
                for f in (fin_rows_global or [])
            }
            for res, camp in ranking_rows_global:
                premio = _safe_float(getattr(res, 'premio', 0.0))
                if (not incluir_zerados) and premio <= 0:
                    continue
                detalhes = _safe_json_loads(getattr(res, 'detalhes_json', None))
                marca = str(detalhes.get('marca') or getattr(camp, 'marca_alvo', '') or '').strip().upper()
                minimo = _safe_float(detalhes.get('minimo') if isinstance(detalhes, dict) else 0.0)
                posicao = getattr(res, 'posicao', None)
                fin = fin_v2_map_global.get((int(getattr(res, 'campanha_id', 0) or 0), _upper(getattr(res, 'vendedor', '')), None))
                status_pag = str(getattr(fin, 'status', 'PENDENTE') or 'PENDENTE') if fin is not None else 'PENDENTE'
                rows.append(
                    UnifiedRow(
                        tipo='RANKING_MARCA',
                        competencia_ano=int(getattr(res, 'ano', ano) or ano),
                        competencia_mes=int(getattr(res, 'mes', mes) or mes),
                        emp='GLOBAL',
                        vendedor=_upper(getattr(res, 'vendedor', '')),
                        titulo=f"Ranking por Marca • {str(getattr(camp, 'nome', '') or '').strip() or ('Campanha #' + str(getattr(camp, 'id', '')))}",
                        qtd_minima=None,
                        recompensa_unit=None,
                        valor_vendido=_safe_float(getattr(res, 'valor_atual', 0.0)),
                        atingiu_gate=bool(getattr(res, 'atingiu', False)),
                        qtd_base=_safe_float(getattr(res, 'posicao', 0) or 0),
                        qtd_premiada=None,
                        valor_recompensa=premio,
                        status_pagamento=status_pag,
                        pago_em=getattr(fin, 'atualizado_em', None) if fin is not None else None,
                        origem_id=int(getattr(res, 'campanha_id', 0) or 0),
                        info_aux=(f"Marca: {marca}" + (f" • Mínimo: R$ {_fmt_float_br(minimo)}" if minimo > 0 else "")),
                        metrica_display=(f"{int(posicao)}º lugar" if posicao not in (None, '') else None),
                    )
                )

    rows.sort(key=lambda r: (r.emp, r.vendedor, r.tipo, r.titulo))
    return rows


def aggregate_for_charts(rows: list[UnifiedRow] | None) -> dict[str, Any]:
    rows = rows or []
    by_tipo: dict[str, float] = {}
    by_emp: dict[str, float] = {}
    total = 0.0
    for r in rows:
        val = _safe_float(getattr(r, 'valor_recompensa', 0.0))
        total += val
        tipo = str(getattr(r, 'tipo', '') or '')
        emp = str(getattr(r, 'emp', '') or '')
        by_tipo[tipo] = by_tipo.get(tipo, 0.0) + val
        by_emp[emp] = by_emp.get(emp, 0.0) + val
    return {
        'total_recompensa': total,
        'by_tipo': [{'label': k, 'value': float(v)} for k, v in sorted(by_tipo.items()) if k],
        'by_emp': [{'label': k, 'value': float(v)} for k, v in sorted(by_emp.items()) if k],
    }
