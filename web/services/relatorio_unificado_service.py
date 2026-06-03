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
from datetime import date, datetime
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


def _d(v: Any) -> Decimal:
    try:
        return Decimal(str(v if v is not None else 0))
    except Exception:
        return Decimal("0")


ITENS_PARADOS_MOV_TIPOS_VENDA = ("OA", "VV", "SV")


def _bonus_base_from_pontos(pontos: Decimal, valor_por_ponto: Decimal) -> Decimal:
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



def _snapshot_rows_from_itens_parados_resultados(
    db,
    *,
    ano: int,
    mes: int,
    emp: str,
    vendedores: list[str],
    incluir_zerados: bool = False,
) -> list[UnifiedRow]:
    """Lê o snapshot mensal de Itens Parados.

    Retorna lista vazia quando a tabela/modelo ainda não existir ou quando o
    snapshot da competência ainda não foi gerado. Nesse caso o relatório faz
    fallback para cálculo ao vivo para não alterar o resultado exibido.
    """
    if ItemParadoResultado is None:
        return []

    try:
        q = (
            db.query(ItemParadoResultado)
            .filter(
                ItemParadoResultado.competencia_ano == int(ano),
                ItemParadoResultado.competencia_mes == int(mes),
                cast(ItemParadoResultado.emp, String) == str(emp),
                ItemParadoResultado.vendedor.in_(vendedores),
            )
        )
        if not incluir_zerados:
            q = q.filter(ItemParadoResultado.valor_recompensa > 0)

        out: list[UnifiedRow] = []
        for r in q.order_by(ItemParadoResultado.vendedor.asc(), ItemParadoResultado.titulo.asc()).all():
            titulo = str(getattr(r, 'titulo', '') or '').strip() or 'Itens Parados'
            item_id = int(getattr(r, 'item_parado_id', 0) or 0)
            recompensa_unit = _safe_float(getattr(r, 'recompensa_unit', None))
            if recompensa_unit <= 0:
                recompensa_unit = _safe_float(getattr(r, 'recompensa_pct', 0.0))
            valor_vendido = _safe_float(getattr(r, 'base_valor_vendido', 0.0))
            qtd_base = _safe_float(getattr(r, 'qtd_base', None))
            if qtd_base <= 0:
                qtd_base = valor_vendido
            valor_recompensa = _safe_float(getattr(r, 'valor_recompensa', 0.0))
            out.append(
                UnifiedRow(
                    tipo='PARADO',
                    competencia_ano=int(getattr(r, 'competencia_ano', ano)),
                    competencia_mes=int(getattr(r, 'competencia_mes', mes)),
                    emp=str(getattr(r, 'emp', emp)),
                    vendedor=_upper(getattr(r, 'vendedor', '')),
                    titulo=titulo,
                    item_codigo=None,
                    qtd_minima=None,
                    recompensa_unit=recompensa_unit,
                    valor_vendido=valor_vendido,
                    atingiu_gate=bool(valor_recompensa > 0 or valor_vendido > 0),
                    qtd_base=qtd_base,
                    qtd_premiada=None,
                    valor_recompensa=valor_recompensa,
                    status_pagamento=str(getattr(r, 'status_pagamento', 'PENDENTE') or 'PENDENTE'),
                    pago_em=getattr(r, 'pago_em', None),
                    origem_id=item_id,
                )
            )
        return out
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        print(f"[RELATORIO_UNIFICADO] snapshot_itens_parados_read_fallback emp={emp} erro={exc}")
        return []


def _compute_itens_parados_rows_live(
    db,
    *,
    ano: int,
    mes: int,
    emp: str,
    vendedores: list[str],
    periodo_ini: date,
    periodo_fim: date,
    incluir_zerados: bool = False,
) -> list[UnifiedRow]:
    """Calcula Itens Parados ao vivo mantendo a regra já existente.

    Usado como fallback quando ainda não existe snapshot. Também é usado pelo
    rebuild do snapshot para persistir exatamente a mesma apuração que a tela
    vinha exibindo.
    """
    out: list[UnifiedRow] = []
    par_rows_added = 0

    parados_defs = (
        db.query(ItemParado)
        .filter(ItemParado.ativo.is_(True), ItemParado.emp == str(emp))
        .filter(or_(ItemParado.data_inicio.is_(None), ItemParado.data_inicio <= periodo_fim))
        .filter(or_(ItemParado.data_fim.is_(None), ItemParado.data_fim >= periodo_ini))
        .order_by(ItemParado.descricao.asc(), ItemParado.codigo.asc(), ItemParado.id.asc())
        .all()
    )

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
        base_reais = _d(getattr(cfg_emp, 'base_reais', None) or getattr(cfg_global, 'base_reais', 100.0) or 100.0)
        if base_reais <= 0:
            base_reais = Decimal('100')
        valor_por_ponto = _d(getattr(cfg_emp, 'valor_por_ponto', None) or getattr(cfg_global, 'valor_por_ponto', 10.0) or 10.0)

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
                pontos_sale += (total_dec / base_reais) * mult
                elegivel = True
            if not elegivel:
                continue
            cur = acc.setdefault(vend_u, {'valor_vendido': Decimal('0'), 'pontos': Decimal('0')})
            cur['valor_vendido'] += total_dec
            cur['pontos'] += pontos_sale

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
            out.append(
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
                out.append(
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

    return out


def rebuild_itens_parados_snapshot(
    *,
    ano: int,
    mes: int,
    emps: list[str],
    vendedores_por_emp: dict[str, list[str]],
) -> dict[str, int]:
    """Recalcula e persiste snapshot mensal de Itens Parados.

    A regra de cálculo continua sendo a mesma de `_compute_itens_parados_rows_live`.
    O ganho é que `/relatorios/campanhas` passa a ler `itens_parados_resultados`
    nas próximas aberturas, evitando varrer `vendas` toda vez.
    """
    stats = {'emps': 0, 'rows': 0, 'skipped': 0}
    if ItemParadoResultado is None:
        stats['skipped'] = len(emps or [])
        return stats

    periodo_ini, periodo_fim = _periodo_bounds(ano, mes)
    now = datetime.utcnow()

    with SessionLocal() as db:
        for emp in emps or []:
            emp_s = str(emp or '').strip()
            if not emp_s:
                continue
            vendedores = [_upper(v) for v in (vendedores_por_emp.get(emp_s) or []) if str(v or '').strip()]
            vendedores = [v for v in vendedores if v]
            if not vendedores:
                continue

            try:
                existing = (
                    db.query(ItemParadoResultado)
                    .filter(
                        ItemParadoResultado.competencia_ano == int(ano),
                        ItemParadoResultado.competencia_mes == int(mes),
                        cast(ItemParadoResultado.emp, String) == emp_s,
                        ItemParadoResultado.vendedor.in_(vendedores),
                    )
                    .all()
                )
                status_map: dict[tuple[int, str], tuple[str, Any]] = {}
                for old in existing:
                    status_map[(int(getattr(old, 'item_parado_id', 0) or 0), _upper(getattr(old, 'vendedor', '')))] = (
                        str(getattr(old, 'status_pagamento', 'PENDENTE') or 'PENDENTE'),
                        getattr(old, 'pago_em', None),
                    )

                snapshot_rows = _compute_itens_parados_rows_live(
                    db,
                    ano=int(ano),
                    mes=int(mes),
                    emp=emp_s,
                    vendedores=vendedores,
                    periodo_ini=periodo_ini,
                    periodo_fim=periodo_fim,
                    incluir_zerados=False,
                )

                # Rebuild completo do escopo: remove linhas antigas do período para
                # evitar sobras de vendedor/item que deixou de vender ou regra removida.
                (
                    db.query(ItemParadoResultado)
                    .filter(
                        ItemParadoResultado.competencia_ano == int(ano),
                        ItemParadoResultado.competencia_mes == int(mes),
                        cast(ItemParadoResultado.emp, String) == emp_s,
                        ItemParadoResultado.vendedor.in_(vendedores),
                    )
                    .delete(synchronize_session=False)
                )

                objects = []
                for row in snapshot_rows:
                    item_id = int(getattr(row, 'origem_id', 0) or 0)
                    st, pago_em = status_map.get((item_id, _upper(getattr(row, 'vendedor', ''))), ('PENDENTE', None))
                    objects.append(
                        ItemParadoResultado(
                            item_parado_id=item_id,
                            competencia_ano=int(ano),
                            competencia_mes=int(mes),
                            emp=str(getattr(row, 'emp', emp_s)),
                            vendedor=_upper(getattr(row, 'vendedor', '')),
                            titulo=str(getattr(row, 'titulo', '') or 'Itens Parados'),
                            base_valor_vendido=_safe_float(getattr(row, 'valor_vendido', 0.0)),
                            recompensa_pct=_safe_float(getattr(row, 'recompensa_unit', 0.0)),
                            qtd_base=_safe_float(getattr(row, 'qtd_base', 0.0)),
                            recompensa_unit=_safe_float(getattr(row, 'recompensa_unit', 0.0)),
                            valor_recompensa=_safe_float(getattr(row, 'valor_recompensa', 0.0)),
                            status_pagamento=st,
                            pago_em=pago_em,
                            atualizado_em=now,
                        )
                    )

                if objects:
                    db.bulk_save_objects(objects)
                db.commit()
                stats['emps'] += 1
                stats['rows'] += len(objects)
            except Exception as exc:
                db.rollback()
                stats['skipped'] += 1
                print(f"[RELATORIO_UNIFICADO] snapshot_itens_parados_rebuild_error emp={emp_s} erro={exc}")

    return stats


def _meta_unified_title(meta: Any, calc: Any) -> str:
    tipo = str(getattr(meta, 'tipo', '') or '').strip().upper()
    nome = str(getattr(meta, 'nome', '') or '').strip()
    if tipo == 'CRESCIMENTO':
        prefix = 'Meta Crescimento'
    elif tipo == 'MIX':
        prefix = 'Meta Mix'
    elif tipo == 'SHARE_MARCA':
        prefix = 'Meta Marcas'
    else:
        prefix = 'Meta'
    return f"{prefix} • {nome}" if nome else prefix


def _append_metas_unificadas(
    db: Any,
    rows: list[UnifiedRow],
    *,
    ano: int,
    mes: int,
    emp: str,
    vendedores: list[str],
    incluir_zerados: bool,
) -> None:
    """Integra Metas no dataset unificado usado por /relatorios/campanhas e /financeiro/campanhas."""
    try:
        from metas_helpers import calcular_meta, get_meta_emps, metas_ativas_periodo
    except Exception as exc:
        try:
            print(f"[RELATORIO_UNIFICADO] metas indisponiveis: {exc}")
        except Exception:
            pass
        return

    emp_s = str(emp or '').strip()
    if not emp_s or not vendedores:
        return

    try:
        metas = metas_ativas_periodo(db, int(ano), int(mes), only_active=True) or []
    except Exception as exc:
        try:
            print(f"[RELATORIO_UNIFICADO] erro ao listar metas: {exc}")
        except Exception:
            pass
        metas = []

    if not metas:
        return

    meta_emps_cache: dict[int, set[str]] = {}
    for meta in metas:
        try:
            meta_id = int(getattr(meta, 'id', 0) or 0)
            meta_emps_cache[meta_id] = {str(e).strip() for e in (get_meta_emps(db, meta_id) or []) if str(e).strip()}
        except Exception:
            meta_emps_cache[int(getattr(meta, 'id', 0) or 0)] = set()

    for meta in metas:
        meta_id = int(getattr(meta, 'id', 0) or 0)
        if meta_id <= 0:
            continue
        emps_meta = meta_emps_cache.get(meta_id) or set()
        if emps_meta and emp_s not in emps_meta:
            continue

        tipo_meta = str(getattr(meta, 'tipo', '') or '').strip().upper()
        for vend in vendedores:
            vend_u = _upper(vend)
            if not vend_u:
                continue
            try:
                calc = calcular_meta(db, meta, emp_s, vend_u, persist=True)
            except Exception as exc:
                try:
                    print(f"[RELATORIO_UNIFICADO] erro meta emp={emp_s} vendedor={vend_u} meta={meta_id}: {exc}")
                except Exception:
                    pass
                continue

            valor_premio = _safe_float(getattr(calc, 'premio', 0.0) or 0.0)
            if valor_premio <= 0 and not incluir_zerados:
                continue

            if tipo_meta == 'CRESCIMENTO':
                qtd_base = _safe_float(getattr(calc, 'crescimento_pct', 0.0) or 0.0)
                qtd_minima = _safe_float(getattr(calc, 'faixa_limite', 0.0) or 0.0) if getattr(calc, 'faixa_limite', None) is not None else None
                recompensa_unit = _safe_float(getattr(calc, 'bonus_percentual', 0.0) or 0.0)
                valor_vendido = _safe_float(getattr(calc, 'valor_mes', 0.0) or 0.0)
                item_codigo = 'CRESCIMENTO'
            elif tipo_meta == 'MIX':
                qtd_base = _safe_float(getattr(calc, 'mix_itens_unicos', 0.0) or 0.0)
                qtd_minima = _safe_float(getattr(calc, 'faixa_limite', 0.0) or 0.0) if getattr(calc, 'faixa_limite', None) is not None else None
                recompensa_unit = _safe_float(getattr(calc, 'bonus_percentual', 0.0) or 0.0)
                valor_vendido = _safe_float(getattr(calc, 'valor_mes', 0.0) or 0.0)
                item_codigo = 'MIX'
            elif tipo_meta == 'SHARE_MARCA':
                qtd_base = _safe_float(getattr(calc, 'share_pct', 0.0) or 0.0)
                qtd_minima = _safe_float(getattr(calc, 'faixa_limite', 0.0) or 0.0) if getattr(calc, 'faixa_limite', None) is not None else None
                recompensa_unit = _safe_float(getattr(calc, 'bonus_percentual', 0.0) or 0.0)
                valor_vendido = _safe_float(getattr(calc, 'valor_marcas', 0.0) or 0.0)
                item_codigo = 'MARCAS'
            else:
                qtd_base = 0.0
                qtd_minima = None
                recompensa_unit = _safe_float(getattr(calc, 'bonus_percentual', 0.0) or 0.0)
                valor_vendido = _safe_float(getattr(calc, 'valor_mes', 0.0) or 0.0)
                item_codigo = 'META'

            atingiu = bool(valor_premio > 0 and not bool(getattr(calc, 'bloqueado_minimo', False)) and not bool(getattr(calc, 'bloqueado_margem', False)))
            rows.append(
                UnifiedRow(
                    tipo='META',
                    competencia_ano=int(ano),
                    competencia_mes=int(mes),
                    emp=emp_s,
                    vendedor=vend_u,
                    titulo=_meta_unified_title(meta, calc),
                    item_codigo=item_codigo,
                    qtd_minima=qtd_minima,
                    recompensa_unit=recompensa_unit,
                    valor_vendido=valor_vendido,
                    atingiu_gate=atingiu,
                    qtd_base=qtd_base,
                    qtd_premiada=None,
                    valor_recompensa=valor_premio,
                    status_pagamento='PENDENTE',
                    pago_em=None,
                    origem_id=meta_id,
                )
            )

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
            # As metas ativas do período entram no mesmo dataset unificado.
            # Dessa forma /relatorios/campanhas, CSV/PDF e /financeiro/campanhas passam
            # a considerar Crescimento, Mix e Marcas sem duplicar regra de cálculo.
            _append_metas_unificadas(
                db,
                rows,
                ano=int(ano),
                mes=int(mes),
                emp=str(emp),
                vendedores=vendedores,
                incluir_zerados=incluir_zerados,
            )

            # -------- ITENS PARADOS --------
            # Passo 3: lê snapshot mensal quando existir. Se ainda não foi gerado,
            # cai automaticamente para o cálculo ao vivo para preservar resultado.
            snapshot_rows = []
            if usar_snapshot_itens_parados:
                snapshot_rows = _snapshot_rows_from_itens_parados_resultados(
                    db,
                    ano=int(ano),
                    mes=int(mes),
                    emp=str(emp),
                    vendedores=vendedores,
                    incluir_zerados=incluir_zerados,
                )

            if snapshot_rows:
                rows.extend(snapshot_rows)
            else:
                rows.extend(
                    _compute_itens_parados_rows_live(
                        db,
                        ano=int(ano),
                        mes=int(mes),
                        emp=str(emp),
                        vendedores=vendedores,
                        periodo_ini=periodo_ini,
                        periodo_fim=periodo_fim,
                        incluir_zerados=incluir_zerados,
                    )
                )

        # Persiste snapshots de metas calculados com persist=True.
        try:
            db.commit()
        except Exception as exc:
            try:
                db.rollback()
            except Exception:
                pass
            try:
                print(f"[RELATORIO_UNIFICADO] erro ao persistir snapshots de metas: {exc}")
            except Exception:
                pass

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
