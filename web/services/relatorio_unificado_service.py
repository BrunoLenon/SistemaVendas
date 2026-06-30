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
from sv_utils import MOVIMENTOS_VENDA
from services.campanhas_qtd_gate import calcular_faturamento_emp_periodo, aplicar_trava_faturamento_emp

from db import (
    SessionLocal,
    Venda,
    CampanhaQtd,
    CampanhaQtdResultado,
    CampanhaComboResultado,
    CampanhaCombo,
    CampanhaComboItem,
    MetaPrograma,
    MetaResultado,
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
    item_descricao: str | None = None
    item_marca: str | None = None
    item_match_tipo: str | None = None
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
    premio_potencial: float | None = None
    faturamento_minimo_emp: float | None = None
    faturamento_emp: float | None = None
    faltante_faturamento_emp: float | None = None
    bloqueado_faturamento_emp: bool | None = None
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


def _campaign_gate_periodo(campanha: Any | None, periodo_ini: date, periodo_fim: date) -> tuple[date, date]:
    """Período usado para auditar a trava de faturamento da campanha.

    O snapshot oficial é calculado pelo recorte entre a vigência da campanha e
    a competência. Ao exibir o relatório, repetimos a mesma regra para corrigir
    snapshots antigos que foram gravados antes da importação de oficina.
    """
    di = getattr(campanha, "data_inicio", None) if campanha is not None else None
    df = getattr(campanha, "data_fim", None) if campanha is not None else None
    try:
        if isinstance(di, datetime):
            di = di.date()
        if isinstance(df, datetime):
            df = df.date()
    except Exception:
        pass
    if not isinstance(di, date):
        di = periodo_ini
    if not isinstance(df, date):
        df = periodo_fim
    try:
        di = max(di, periodo_ini)
        df = min(df, periodo_fim)
    except Exception:
        di, df = periodo_ini, periodo_fim
    return di, df




def _get_faturamento_emp_cached(
    db: Any,
    cache: dict[tuple[str, date, date], float] | None,
    *,
    emp: str,
    periodo_ini: date,
    periodo_fim: date,
) -> float:
    """Soma faturamento da EMP uma única vez por período dentro do relatório.

    Campanhas diferentes costumam compartilhar o mesmo recorte mensal. Sem este
    cache, uma tela com dezenas de vendedores executa a mesma soma de faturamento
    várias vezes, gerando SLOW_REQUEST/cache_miss.
    """
    emp_s = str(emp or '').strip()
    key = (emp_s, periodo_ini, periodo_fim)
    if cache is not None and key in cache:
        return _safe_float(cache.get(key))
    valor = calcular_faturamento_emp_periodo(db, emp=emp_s, periodo_ini=periodo_ini, periodo_fim=periodo_fim)
    if cache is not None:
        cache[key] = _safe_float(valor)
    return _safe_float(valor)


def _corrigir_gate_qtd_com_faturamento_atual(
    db: Any,
    *,
    resultado: Any,
    campanha: Any | None,
    emp: str,
    periodo_ini: date,
    periodo_fim: date,
    faturamento_cache: dict[tuple[str, date, date], float] | None = None,
) -> dict[str, Any]:
    """Retorna campos de trava EMP usando o faturamento atual balcão + oficina.

    Corrige a tela quando o snapshot de CampanhaQtdResultado foi gerado antes
    da importação da oficina. Sem essa auditoria, o relatório pode mostrar
    `faturamento_emp` apenas com balcão, enquanto o card da loja já mostra
    balcão + oficina.
    """
    minimo_raw = getattr(campanha, "faturamento_minimo_emp", None) if campanha is not None else None
    if minimo_raw is None:
        minimo_raw = getattr(resultado, "faturamento_minimo_emp", None)
    minimo = _safe_float(minimo_raw)

    potencial_raw = getattr(resultado, "premio_potencial", None)
    if potencial_raw is None:
        potencial_raw = getattr(resultado, "valor_recompensa", 0.0)
    premio_potencial = _safe_float(potencial_raw)

    if minimo <= 0:
        return {
            "faturamento_minimo_emp": None,
            "faturamento_emp": getattr(resultado, "faturamento_emp", None),
            "faltante_faturamento_emp": getattr(resultado, "faltante_faturamento_emp", None),
            "bloqueado_faturamento_emp": bool(int(getattr(resultado, "bloqueado_faturamento_emp", 0) or 0)),
            "valor_recompensa": _safe_float(getattr(resultado, "valor_recompensa", 0.0)),
            "premio_potencial": premio_potencial,
            "atingiu_gate": bool(int(getattr(resultado, "atingiu_minimo", 0) or 0)),
        }

    gate_ini, gate_fim = _campaign_gate_periodo(campanha, periodo_ini, periodo_fim)
    faturamento_atual = _get_faturamento_emp_cached(db, faturamento_cache, emp=str(emp), periodo_ini=gate_ini, periodo_fim=gate_fim)

    # Em CampanhaQtdResultado, premio_potencial > 0 representa que as regras do
    # item foram atingidas. O bloqueio de EMP não deve apagar esse potencial.
    atingiu_regras_item = premio_potencial > 0

    class _CampanhaGate:
        faturamento_minimo_emp = minimo

    gate = aplicar_trava_faturamento_emp(
        campanha=_CampanhaGate(),
        emp=str(emp),
        faturamento_emp=faturamento_atual,
        premio_potencial=premio_potencial,
        atingiu_regras_item=atingiu_regras_item,
    )
    return {
        "faturamento_minimo_emp": _safe_float(gate.get("faturamento_minimo_emp")),
        "faturamento_emp": _safe_float(gate.get("faturamento_emp")),
        "faltante_faturamento_emp": _safe_float(gate.get("faltante_faturamento_emp")),
        "bloqueado_faturamento_emp": bool(gate.get("bloqueado_faturamento_emp")),
        "valor_recompensa": _safe_float(gate.get("valor_recompensa")),
        "premio_potencial": _safe_float(gate.get("premio_potencial")),
        "atingiu_gate": bool(gate.get("atingiu_final")),
    }


def _upper(v: Any) -> str:
    return str(v or "").strip().upper()


def _clean_text(v: Any) -> str:
    return str(v or "").strip()


def _campanha_qtd_item_meta(resultado: Any, campanha: Any | None) -> dict[str, str | None]:
    """Retorna os dados de exibição do critério da campanha QTD.

    A tabela de resultados guarda o prefixo usado no cálculo, mas em bancos antigos
    não guarda `campo_match`/`descricao_prefixo`. Por isso buscamos a campanha-mãe
    quando disponível para mostrar corretamente Código x Descrição e a Marca referência.
    """
    campo_match = _clean_text(getattr(campanha, "campo_match", None) or getattr(resultado, "campo_match", None) or "codigo").lower()
    marca = _clean_text(getattr(resultado, "marca", None) or getattr(campanha, "marca", None)).upper() or None

    produto_prefixo = _clean_text(getattr(resultado, "produto_prefixo", None) or getattr(campanha, "produto_prefixo", None))
    descricao_prefixo = _clean_text(getattr(campanha, "descricao_prefixo", None) or getattr(resultado, "descricao_prefixo", None))

    if campo_match == "descricao":
        descricao = descricao_prefixo or produto_prefixo
        return {
            "item_codigo": None,
            "item_descricao": descricao or None,
            "item_marca": marca,
            "item_match_tipo": "descricao",
        }

    return {
        "item_codigo": produto_prefixo or None,
        "item_descricao": None,
        "item_marca": marca,
        "item_match_tipo": "codigo",
    }


def _d(v: Any) -> Decimal:
    try:
        return Decimal(str(v if v is not None else 0))
    except Exception:
        return Decimal("0")


ITENS_PARADOS_MOV_TIPOS_VENDA = MOVIMENTOS_VENDA


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
                    func.upper(func.coalesce(Venda.mov_tipo_movto, "")).in_(MOVIMENTOS_VENDA),
                    func.coalesce(Venda.qtdade_vendida, 0.0) > 0,
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




def _meta_rows_from_snapshots(
    db: Any,
    rows: list[UnifiedRow],
    *,
    ano: int,
    mes: int,
    emp: str,
    vendedores: list[str],
    incluir_zerados: bool,
) -> int:
    """Lê metas_resultados já persistido, sem recalcular venda/mix/marca ao vivo.

    Em abertura comum de /relatorios/campanhas isso evita recalcular metas para
    cada vendedor. O recálculo manual em background continua usando o motor vivo
    para atualizar esses snapshots.
    """
    emp_s = str(emp or '').strip()
    vendedores_u = [_upper(v) for v in (vendedores or []) if _upper(v)]
    if not emp_s or not vendedores_u:
        return 0

    try:
        q = (
            db.query(MetaResultado, MetaPrograma)
            .join(MetaPrograma, MetaPrograma.id == MetaResultado.meta_id)
            .filter(
                MetaResultado.ano == int(ano),
                MetaResultado.mes == int(mes),
                cast(MetaResultado.emp, String) == emp_s,
                MetaResultado.vendedor.in_(vendedores_u),
                MetaPrograma.ativo.is_(True),
            )
        )
        if not incluir_zerados:
            q = q.filter(MetaResultado.premio > 0)
        snap_rows = q.order_by(MetaResultado.vendedor.asc(), MetaPrograma.nome.asc(), MetaResultado.meta_id.asc()).all()
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        try:
            print(f"[RELATORIO_UNIFICADO] metas_snapshot_read_error emp={emp_s}: {exc}")
        except Exception:
            pass
        return 0

    count = 0
    for calc, meta in snap_rows:
        tipo_meta = str(getattr(meta, 'tipo', '') or '').strip().upper()
        valor_premio = _safe_float(getattr(calc, 'premio', 0.0) or 0.0)
        if valor_premio <= 0 and not incluir_zerados:
            continue

        if tipo_meta == 'CRESCIMENTO':
            qtd_base = _safe_float(getattr(calc, 'crescimento_pct', 0.0) or 0.0)
            valor_vendido = _safe_float(getattr(calc, 'valor_mes', 0.0) or 0.0)
            item_codigo = 'CRESCIMENTO'
        elif tipo_meta == 'MIX':
            qtd_base = _safe_float(getattr(calc, 'mix_itens_unicos', 0.0) or 0.0)
            valor_vendido = _safe_float(getattr(calc, 'valor_mes', 0.0) or 0.0)
            item_codigo = 'MIX'
        elif tipo_meta == 'SHARE_MARCA':
            qtd_base = _safe_float(getattr(calc, 'share_pct', 0.0) or 0.0)
            valor_vendido = _safe_float(getattr(calc, 'valor_marcas', 0.0) or 0.0)
            item_codigo = 'MARCAS'
        else:
            qtd_base = 0.0
            valor_vendido = _safe_float(getattr(calc, 'valor_mes', 0.0) or 0.0)
            item_codigo = tipo_meta or 'META'

        faturamento_minimo_meta = _safe_float(getattr(meta, 'faturamento_minimo', 0.0) or 0.0)
        faturamento_meta_atual = _safe_float(getattr(calc, 'valor_mes', 0.0) or 0.0)
        faltante_meta = max(0.0, faturamento_minimo_meta - faturamento_meta_atual) if faturamento_minimo_meta > 0 else 0.0
        bloqueado_minimo = bool(faturamento_minimo_meta > 0 and faturamento_meta_atual < faturamento_minimo_meta)
        bloqueado_margem = bool(getattr(calc, 'bloqueado_margem', False))

        rows.append(
            UnifiedRow(
                tipo='META',
                competencia_ano=int(ano),
                competencia_mes=int(mes),
                emp=emp_s,
                vendedor=_upper(getattr(calc, 'vendedor', '')),
                titulo=_meta_unified_title(meta, calc),
                item_codigo=item_codigo,
                qtd_minima=None,
                recompensa_unit=_safe_float(getattr(calc, 'bonus_percentual', 0.0) or 0.0),
                valor_vendido=valor_vendido,
                atingiu_gate=bool(valor_premio > 0),
                qtd_base=qtd_base,
                qtd_premiada=None,
                valor_recompensa=valor_premio,
                faturamento_minimo_emp=faturamento_minimo_meta if faturamento_minimo_meta > 0 else None,
                faturamento_emp=faturamento_meta_atual,
                faltante_faturamento_emp=faltante_meta if faturamento_minimo_meta > 0 else None,
                bloqueado_faturamento_emp=bool(bloqueado_minimo or bloqueado_margem),
                status_pagamento='PENDENTE',
                pago_em=None,
                origem_id=int(getattr(calc, 'meta_id', 0) or getattr(meta, 'id', 0) or 0),
            )
        )
        count += 1
    return count


def _append_metas_unificadas(
    db: Any,
    rows: list[UnifiedRow],
    *,
    ano: int,
    mes: int,
    emp: str,
    vendedores: list[str],
    incluir_zerados: bool,
    metas_live: bool = False,
) -> None:
    """Integra Metas no dataset unificado usado por /relatorios/campanhas e /financeiro/campanhas."""
    emp_s = str(emp or '').strip()
    if not emp_s or not vendedores:
        return

    if not metas_live:
        _meta_rows_from_snapshots(
            db,
            rows,
            ano=int(ano),
            mes=int(mes),
            emp=emp_s,
            vendedores=vendedores,
            incluir_zerados=bool(incluir_zerados),
        )
        return

    try:
        from metas_helpers import calcular_meta, get_meta_emps, get_gerentes_para_metas, is_meta_gerente, metas_ativas_periodo
    except Exception as exc:
        try:
            print(f"[RELATORIO_UNIFICADO] metas indisponiveis: {exc}")
        except Exception:
            pass
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
        participantes_meta = vendedores
        try:
            if is_meta_gerente(meta):
                gerentes_emp = {_upper(g) for g in (get_gerentes_para_metas(db, int(ano), int(mes), [emp_s]) or []) if _upper(g)}
                participantes_meta = [v for v in vendedores if _upper(v) in gerentes_emp]
        except Exception:
            participantes_meta = vendedores
        for vend in participantes_meta:
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

            atingiu = bool(valor_premio > 0 and not bool(getattr(calc, 'bloqueado_minimo', False)))

            # Transparência no relatório: a coluna Requisitos deve mostrar o
            # alvo financeiro real da meta, quanto o vendedor já vendeu e o que
            # falta. Reaproveitamos os campos de faturamento_* já usados nas
            # travas de campanha de produto para manter o template simples.
            faturamento_minimo_meta = _safe_float(getattr(calc, 'faturamento_minimo', 0.0) or 0.0)
            faturamento_meta_atual = _safe_float(getattr(calc, 'valor_mes', 0.0) or 0.0)
            faltante_meta = max(0.0, faturamento_minimo_meta - faturamento_meta_atual) if faturamento_minimo_meta > 0 else 0.0

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
                    faturamento_minimo_emp=faturamento_minimo_meta if faturamento_minimo_meta > 0 else None,
                    faturamento_emp=faturamento_meta_atual,
                    faltante_faturamento_emp=faltante_meta if faturamento_minimo_meta > 0 else None,
                    bloqueado_faturamento_emp=bool(getattr(calc, 'bloqueado_minimo', False)),
                    status_pagamento='PENDENTE',
                    pago_em=None,
                    origem_id=meta_id,
                )
            )


def _get_gerentes_emp_relatorio(db: Any, emp: str) -> list[str]:
    """Retorna gerentes vinculados à EMP para garantir exibição no relatório.

    O gerente pode não ter venda própria no período; mesmo assim deve receber
    campanha de loja quando houver campanha GERENTE cadastrada.
    """
    emp_s = str(emp or '').strip()
    if not emp_s:
        return []
    try:
        from db import Usuario, UsuarioEmp  # import local para evitar acoplamento no boot
        rows = (
            db.query(Usuario.username)
            .join(UsuarioEmp, UsuarioEmp.usuario_id == Usuario.id)
            .filter(func.lower(func.trim(cast(Usuario.role, String))) == 'gerente')
            .filter(UsuarioEmp.ativo.is_(True))
            .filter(cast(UsuarioEmp.emp, String) == emp_s)
            .order_by(Usuario.username.asc())
            .all()
        )
        out = sorted({str(r[0] or '').strip().upper() for r in rows if r and str(r[0] or '').strip()})
        if out:
            return out
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    try:
        from db import Usuario
        rows = (
            db.query(Usuario.username)
            .filter(func.lower(func.trim(cast(Usuario.role, String))) == 'gerente')
            .filter(cast(Usuario.emp, String) == emp_s)
            .order_by(Usuario.username.asc())
            .all()
        )
        return sorted({str(r[0] or '').strip().upper() for r in rows if r and str(r[0] or '').strip()})
    except Exception:
        return []


def _campanha_tipo_qtd_relatorio(campanha: Any) -> str:
    return str(getattr(campanha, 'campanha_tipo', '') or 'VENDEDOR').strip().upper()


def _norm_prefix_relatorio(s: Any) -> str:
    """Normaliza prefixo de descrição igual ao cálculo oficial de Campanha QTD."""
    import re
    import unicodedata

    txt = str(s or '').strip()
    txt = ''.join(c for c in unicodedata.normalize('NFKD', txt) if not unicodedata.combining(c))
    txt = re.sub(r'\s+', ' ', txt).strip().lower()
    return txt


def _campanha_qtd_key_relatorio(campanha: Any) -> tuple[str, str, str]:
    campo_match = str(getattr(campanha, 'campo_match', None) or 'codigo').strip().lower()
    marca = _clean_text(getattr(campanha, 'marca', None)).upper()
    if campo_match == 'descricao':
        pref = _clean_text(getattr(campanha, 'descricao_prefixo', None)) or _clean_text(getattr(campanha, 'produto_prefixo', None))
        return ('descricao', pref.lower().strip(), marca)
    return ('codigo', _clean_text(getattr(campanha, 'produto_prefixo', None)).upper(), marca)


def _build_campanhas_qtd_escolhidas_por_vendedor(campanhas: list[Any], vendedores: list[str]) -> dict[str, list[Any]]:
    """Aplica prioridade da campanha específica do vendedor sobre a geral.

    Isso evita duplicar campanha quando existe uma regra geral da loja e uma regra
    específica para um vendedor com o mesmo item/marca/período.
    """
    geral_by_key: dict[tuple[str, str, str], Any] = {}
    especificas: dict[str, dict[tuple[str, str, str], Any]] = {}

    for c in campanhas or []:
        if _campanha_tipo_qtd_relatorio(c) == 'GERENTE':
            continue
        key = _campanha_qtd_key_relatorio(c)
        vend = _upper(getattr(c, 'vendedor', None))
        if vend:
            especificas.setdefault(vend, {})[key] = c
        else:
            geral_by_key.setdefault(key, c)

    escolhidas: dict[str, list[Any]] = {}
    for vend in vendedores or []:
        vend_u = _upper(vend)
        if not vend_u:
            continue
        base = dict(geral_by_key)
        if vend_u in especificas:
            base.update(especificas[vend_u])
        escolhidas[vend_u] = list(base.values())
    return escolhidas


def _cond_campanha_qtd_venda(campanha: Any):
    """Condição de item/marca para campanha QTD usada nas linhas de participação."""
    campo_match = str(getattr(campanha, 'campo_match', None) or 'codigo').strip().lower()
    if campo_match == 'descricao':
        prefix_raw = _clean_text(getattr(campanha, 'descricao_prefixo', None)) or _clean_text(getattr(campanha, 'produto_prefixo', None))
        prefix = _norm_prefix_relatorio(prefix_raw)
        campo_item = func.lower(func.trim(func.coalesce(Venda.descricao_norm, '')))
        cond_prefix = campo_item.like(prefix + '%') if prefix else None
    else:
        prefix_raw = _clean_text(getattr(campanha, 'produto_prefixo', None))
        prefix = prefix_raw.upper()
        campo_item = func.upper(func.trim(cast(Venda.mestre, String)))
        cond_prefix = campo_item.like(prefix + '%') if prefix else None

    conds = []
    if cond_prefix is not None:
        conds.append(cond_prefix)

    marca_ref = _clean_text(getattr(campanha, 'marca', None)).upper()
    if marca_ref:
        conds.append(func.upper(func.trim(cast(Venda.marca, String))) == marca_ref)
    return conds


def _calc_vendas_por_vendedor_campanha_qtd_live(
    db: Any,
    *,
    emp: str,
    campanha: Any,
    vendedores: list[str],
    periodo_ini: date,
    periodo_fim: date,
) -> dict[str, tuple[float, float]]:
    """Soma qtd/valor por vendedor para uma campanha ativa, sem depender de snapshot.

    Usado no /relatorios/campanhas para mostrar campanhas em andamento mesmo
    quando o vendedor ainda não vendeu nada daquele item.
    """
    vendedores_u = [_upper(v) for v in (vendedores or []) if _upper(v)]
    if not vendedores_u:
        return {}

    conds_item = _cond_campanha_qtd_venda(campanha)
    if not conds_item:
        return {v: (0.0, 0.0) for v in vendedores_u}

    filtros = [
        Venda.emp == str(emp),
        Venda.movimento >= periodo_ini,
        Venda.movimento <= periodo_fim,
        func.upper(func.coalesce(Venda.mov_tipo_movto, '')).in_(MOVIMENTOS_VENDA),
        func.coalesce(Venda.qtdade_vendida, 0.0) > 0,
        Venda.vendedor.in_(vendedores_u),
    ]
    filtros.extend(conds_item)

    try:
        rows = (
            db.query(
                Venda.vendedor,
                func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label('qtd'),
                func.coalesce(func.sum(Venda.valor_total), 0.0).label('valor'),
            )
            .filter(*filtros)
            .group_by(Venda.vendedor)
            .all()
        )
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        rows = []

    out = {v: (0.0, 0.0) for v in vendedores_u}
    for vend, qtd, valor in rows:
        vend_u = _upper(vend)
        if vend_u:
            out[vend_u] = (_safe_float(qtd), _safe_float(valor))
    return out


def _calc_vendas_loja_campanha_qtd_live(
    db: Any,
    *,
    emp: str,
    campanha: Any,
    periodo_ini: date,
    periodo_fim: date,
) -> tuple[float, float]:
    """Soma qtd/valor da loja inteira para campanha do tipo GERENTE."""
    conds_item = _cond_campanha_qtd_venda(campanha)
    if not conds_item:
        return 0.0, 0.0
    filtros = [
        Venda.emp == str(emp),
        Venda.movimento >= periodo_ini,
        Venda.movimento <= periodo_fim,
        func.upper(func.coalesce(Venda.mov_tipo_movto, '')).in_(MOVIMENTOS_VENDA),
        func.coalesce(Venda.qtdade_vendida, 0.0) > 0,
    ]
    filtros.extend(conds_item)
    try:
        row = (
            db.query(
                func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label('qtd'),
                func.coalesce(func.sum(Venda.valor_total), 0.0).label('valor'),
            )
            .filter(*filtros)
            .first()
        )
        return _safe_float(getattr(row, 'qtd', 0.0) if row is not None else 0.0), _safe_float(getattr(row, 'valor', 0.0) if row is not None else 0.0)
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return 0.0, 0.0


def _build_campanha_qtd_participacao_row(
    db: Any,
    *,
    ano: int,
    mes: int,
    emp: str,
    vendedor: str,
    campanha: Any,
    qtd_vendida: float,
    valor_vendido: float,
    periodo_ini: date,
    periodo_fim: date,
    faturamento_cache: dict[tuple[str, date, date], float] | None = None,
) -> UnifiedRow:
    """Cria linha visual de campanha ativa ainda sem resultado salvo/atingido."""
    gate_ini, gate_fim = _campaign_gate_periodo(campanha, periodo_ini, periodo_fim)
    minimo_qtd = getattr(campanha, 'qtd_minima', None)
    minimo_val = getattr(campanha, 'valor_minimo', None)

    atingiu_regras_item = True
    if minimo_qtd is not None and _safe_float(minimo_qtd) > 0:
        atingiu_regras_item = bool(_safe_float(qtd_vendida) >= _safe_float(minimo_qtd))
    if atingiu_regras_item and minimo_val is not None and _safe_float(minimo_val) > 0:
        atingiu_regras_item = bool(_safe_float(valor_vendido) >= _safe_float(minimo_val))

    recompensa_unit = _safe_float(getattr(campanha, 'recompensa_unit', 0.0))
    premio_potencial = (_safe_float(qtd_vendida) * recompensa_unit) if atingiu_regras_item else 0.0
    faturamento_emp = _get_faturamento_emp_cached(db, faturamento_cache, emp=str(emp), periodo_ini=gate_ini, periodo_fim=gate_fim)
    gate = aplicar_trava_faturamento_emp(
        campanha=campanha,
        emp=str(emp),
        faturamento_emp=faturamento_emp,
        premio_potencial=premio_potencial,
        atingiu_regras_item=bool(atingiu_regras_item),
    )

    faturamento_minimo_emp = _safe_float(gate.get('faturamento_minimo_emp')) or None
    faltante_emp = _safe_float(gate.get('faltante_faturamento_emp'))
    # Para transparência visual, mostra EMP ABAIXO sempre que a loja ainda não
    # atingiu a trava, mesmo antes do vendedor gerar prêmio potencial no item.
    bloqueado_emp_display = bool(faturamento_minimo_emp and faltante_emp > 0)

    item_meta = _campanha_qtd_item_meta(type('ResultadoCampanhaAtiva', (), {})(), campanha)
    tipo_campanha = _campanha_tipo_qtd_relatorio(campanha)
    valor_recompensa = _safe_float(gate.get('valor_recompensa'))
    premio_final = _safe_float(gate.get('premio_potencial'))

    qtd_premiada = None
    if recompensa_unit > 0 and premio_final > 0:
        qtd_premiada = premio_final / recompensa_unit

    return UnifiedRow(
        tipo=('GERENTE' if tipo_campanha == 'GERENTE' else 'QTD'),
        competencia_ano=int(ano),
        competencia_mes=int(mes),
        emp=str(emp),
        vendedor=_upper(vendedor),
        titulo=_clean_text(getattr(campanha, 'titulo', None)) or f"Campanha #{getattr(campanha, 'id', '')}",
        item_codigo=item_meta.get('item_codigo'),
        item_descricao=item_meta.get('item_descricao'),
        item_marca=item_meta.get('item_marca'),
        item_match_tipo=item_meta.get('item_match_tipo'),
        qtd_minima=_safe_float(minimo_qtd) if minimo_qtd is not None else None,
        recompensa_unit=recompensa_unit,
        valor_vendido=_safe_float(valor_vendido),
        atingiu_gate=bool(gate.get('atingiu_final')),
        qtd_base=_safe_float(qtd_vendida),
        qtd_premiada=qtd_premiada,
        valor_recompensa=valor_recompensa,
        premio_potencial=premio_final,
        faturamento_minimo_emp=faturamento_minimo_emp,
        faturamento_emp=_safe_float(gate.get('faturamento_emp')),
        faltante_faturamento_emp=faltante_emp,
        bloqueado_faturamento_emp=bloqueado_emp_display,
        status_pagamento='PENDENTE',
        pago_em=None,
        origem_id=int(getattr(campanha, 'id', 0) or 0),
    )


def _append_campanhas_qtd_participacao_ativa(
    db: Any,
    rows: list[UnifiedRow],
    *,
    ano: int,
    mes: int,
    emp: str,
    vendedores: list[str],
    periodo_ini: date,
    periodo_fim: date,
    existing_keys: set[tuple[int, str]],
    faturamento_cache: dict[tuple[str, date, date], float] | None = None,
) -> None:
    """Inclui campanhas QTD/GERENTE ativas mesmo sem venda/prêmio no período."""
    emp_s = str(emp or '').strip()
    vendedores_u = [_upper(v) for v in (vendedores or []) if _upper(v)]
    if not emp_s or not vendedores_u:
        return

    try:
        campanhas = (
            db.query(CampanhaQtd)
            .filter(CampanhaQtd.ativo == 1)
            .filter(or_(cast(CampanhaQtd.emp, String) == emp_s, CampanhaQtd.emp.in_(['ALL', '*', ''])))
            .filter(CampanhaQtd.data_inicio <= periodo_fim)
            .filter(CampanhaQtd.data_fim >= periodo_ini)
            .order_by(CampanhaQtd.emp.asc(), CampanhaQtd.data_inicio.asc(), CampanhaQtd.id.asc())
            .all()
        )
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        try:
            print(f"[RELATORIO_UNIFICADO] erro campanhas_qtd_participacao emp={emp_s}: {exc}")
        except Exception:
            pass
        return

    if not campanhas:
        return

    gerentes_set = set(_get_gerentes_emp_relatorio(db, emp_s) or [])
    vendedores_base = [v for v in vendedores_u if v not in gerentes_set]
    if not vendedores_base:
        vendedores_base = vendedores_u[:]

    campanhas_vendedor = [c for c in campanhas if _campanha_tipo_qtd_relatorio(c) != 'GERENTE']
    escolhidas_por_vendedor = _build_campanhas_qtd_escolhidas_por_vendedor(campanhas_vendedor, vendedores_base)

    vendas_vendedor_cache: dict[int, dict[str, tuple[float, float]]] = {}
    for vend_u, campanhas_vend in (escolhidas_por_vendedor or {}).items():
        for campanha in campanhas_vend or []:
            cid = int(getattr(campanha, 'id', 0) or 0)
            if cid <= 0 or (cid, vend_u) in existing_keys:
                continue
            gate_ini, gate_fim = _campaign_gate_periodo(campanha, periodo_ini, periodo_fim)
            if cid not in vendas_vendedor_cache:
                vendas_vendedor_cache[cid] = _calc_vendas_por_vendedor_campanha_qtd_live(
                    db,
                    emp=emp_s,
                    campanha=campanha,
                    vendedores=vendedores_base,
                    periodo_ini=gate_ini,
                    periodo_fim=gate_fim,
                )
            qtd, valor = vendas_vendedor_cache.get(cid, {}).get(vend_u, (0.0, 0.0))
            rows.append(_build_campanha_qtd_participacao_row(
                db,
                ano=int(ano),
                mes=int(mes),
                emp=emp_s,
                vendedor=vend_u,
                campanha=campanha,
                qtd_vendida=qtd,
                valor_vendido=valor,
                periodo_ini=periodo_ini,
                periodo_fim=periodo_fim,
                faturamento_cache=faturamento_cache,
            ))
            existing_keys.add((cid, vend_u))

    campanhas_gerente = [c for c in campanhas if _campanha_tipo_qtd_relatorio(c) == 'GERENTE']
    gerentes_no_escopo = [v for v in vendedores_u if v in gerentes_set]
    if campanhas_gerente and gerentes_no_escopo:
        for campanha in campanhas_gerente:
            cid = int(getattr(campanha, 'id', 0) or 0)
            if cid <= 0:
                continue
            gate_ini, gate_fim = _campaign_gate_periodo(campanha, periodo_ini, periodo_fim)
            qtd, valor = _calc_vendas_loja_campanha_qtd_live(
                db,
                emp=emp_s,
                campanha=campanha,
                periodo_ini=gate_ini,
                periodo_fim=gate_fim,
            )
            for gerente_u in gerentes_no_escopo:
                if (cid, gerente_u) in existing_keys:
                    continue
                rows.append(_build_campanha_qtd_participacao_row(
                    db,
                    ano=int(ano),
                    mes=int(mes),
                    emp=emp_s,
                    vendedor=gerente_u,
                    campanha=campanha,
                    qtd_vendida=qtd,
                    valor_vendido=valor,
                    periodo_ini=periodo_ini,
                    periodo_fim=periodo_fim,
                    faturamento_cache=faturamento_cache,
                ))
                existing_keys.add((cid, gerente_u))


def _ensure_snapshots_gerente_loja(
    db: Any,
    *,
    ano: int,
    mes: int,
    emp: str,
    vendedores_escopo: list[str],
    periodo_ini: date,
    periodo_fim: date,
) -> None:
    """Garante snapshots de campanha GERENTE antes de montar /relatorios/campanhas.

    O recálculo principal é feito em app.py; esta proteção evita que a linha do
    gerente suma quando o relatório é aberto sem recalc ou quando o gerente não
    teve venda própria no mês.
    """
    emp_s = str(emp or '').strip()
    if not emp_s:
        return
    try:
        gerentes = _get_gerentes_emp_relatorio(db, emp_s)
        if not gerentes:
            return
        escopo = {_upper(v) for v in (vendedores_escopo or []) if str(v or '').strip()}
        gerentes = [g for g in gerentes if (not escopo or g in escopo)]
        if not gerentes:
            return

        campanhas = (
            db.query(CampanhaQtd)
            .filter(CampanhaQtd.ativo == 1)
            .filter(or_(cast(CampanhaQtd.emp, String) == emp_s, CampanhaQtd.emp.in_(['ALL', '*', ''])))
            .filter(CampanhaQtd.data_inicio <= periodo_fim)
            .filter(CampanhaQtd.data_fim >= periodo_ini)
            .filter(func.upper(func.trim(cast(CampanhaQtd.campanha_tipo, String))) == 'GERENTE')
            .order_by(CampanhaQtd.emp.asc(), CampanhaQtd.data_inicio.asc())
            .all()
        )
        if not campanhas:
            return

        campanha_ids = [int(getattr(c, 'id', 0) or 0) for c in campanhas if int(getattr(c, 'id', 0) or 0) > 0]
        if not campanha_ids:
            return

        # Modo rápido: em abertura comum da página, NÃO recalcula snapshots que já existem.
        # A atualização oficial continua sendo feita pelo botão "Recalcular" após importar vendas.
        # Aqui só geramos o que estiver faltando para evitar que campanha GERENTE suma da tela.
        existing_keys: set[tuple[int, str]] = set()
        try:
            existing = (
                db.query(CampanhaQtdResultado.campanha_id, CampanhaQtdResultado.vendedor)
                .filter(
                    CampanhaQtdResultado.competencia_ano == int(ano),
                    CampanhaQtdResultado.competencia_mes == int(mes),
                    cast(CampanhaQtdResultado.emp, String) == emp_s,
                    CampanhaQtdResultado.campanha_id.in_(campanha_ids),
                    CampanhaQtdResultado.vendedor.in_(gerentes),
                )
                .all()
            )
            for cid, vend in existing:
                existing_keys.add((int(cid or 0), _upper(vend)))
        except Exception:
            existing_keys = set()

        missing_pairs: list[tuple[str, Any]] = []
        for gerente in gerentes:
            gerente_u = _upper(gerente)
            for c in campanhas:
                cid = int(getattr(c, 'id', 0) or 0)
                if cid <= 0:
                    continue
                if (cid, gerente_u) not in existing_keys:
                    missing_pairs.append((gerente_u, c))

        if not missing_pairs:
            return

        # Reutiliza a regra oficial da campanha QTD, que para GERENTE soma a EMP inteira.
        try:
            from campanhas_qtd_helpers import _upsert_resultado as _upsert_qtd_resultado
        except Exception:
            _upsert_qtd_resultado = None
        if _upsert_qtd_resultado is None:
            return

        changed = False
        for gerente, c in missing_pairs:
            pi = max(getattr(c, 'data_inicio'), periodo_ini)
            pf = min(getattr(c, 'data_fim'), periodo_fim)
            res = _upsert_qtd_resultado(db, c, gerente, emp_s, int(ano), int(mes), pi, pf)
            try:
                res.campanha_tipo = 'GERENTE'
            except Exception:
                pass
            changed = True
        if changed:
            db.commit()

    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        try:
            print(f"[RELATORIO_UNIFICADO] erro snapshot gerente emp={emp}: {exc}")
        except Exception:
            pass


def build_unified_rows(
    *,
    ano: int,
    mes: int,
    emps: list[str],
    vendedores_por_emp: dict[str, list[str]],
    incluir_zerados: bool = False,
    usar_snapshot_itens_parados: bool = True,
    incluir_participacao_ativa: bool = False,
    metas_live: bool = False,
    ensure_missing_gerente_snapshots: bool = False,
) -> list[UnifiedRow]:
    periodo_ini, periodo_fim = _periodo_bounds(ano, mes)
    rows: list[UnifiedRow] = []
    faturamento_cache: dict[tuple[str, date, date], float] = {}

    with SessionLocal() as db:
        for emp in emps:
            try:
                db.rollback()
            except Exception:
                pass

            vendedores = [_upper(v) for v in (vendedores_por_emp.get(emp) or []) if str(v or '').strip()]
            vendedores = [v for v in vendedores if v]

            # Garante que o gerente da loja entre no relatório mesmo quando ele não
            # aparece como vendedor nas vendas do período. Isso é indispensável para
            # campanhas do tipo GERENTE, que pagam sobre a venda total da EMP.
            try:
                for _g in _get_gerentes_emp_relatorio(db, str(emp)):
                    if _g and _g not in vendedores:
                        vendedores.append(_g)
            except Exception:
                pass

            if not vendedores:
                continue

            if ensure_missing_gerente_snapshots:
                _ensure_snapshots_gerente_loja(
                    db,
                    ano=int(ano),
                    mes=int(mes),
                    emp=str(emp),
                    vendedores_escopo=vendedores,
                    periodo_ini=periodo_ini,
                    periodo_fim=periodo_fim,
                )

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
            if not incluir_zerados and not incluir_participacao_ativa:
                q_qtd = q_qtd.filter(
                    or_(
                        CampanhaQtdResultado.valor_recompensa > 0,
                        CampanhaQtdResultado.premio_potencial > 0,
                        CampanhaQtdResultado.bloqueado_faturamento_emp == 1,
                    )
                )
            # Quando incluir_participacao_ativa=True, preferimos ler os snapshots
            # completos gerados no pós-importação, inclusive campanhas zeradas.
            # Assim a abertura normal do relatório não precisa recalcular
            # participação QTD ao vivo para cada vendedor/campanha.

            qtd_rows = q_qtd.all()
            qtd_existing_keys: set[tuple[int, str]] = {
                (int(getattr(r, 'campanha_id', 0) or 0), _upper(getattr(r, 'vendedor', '')))
                for r in (qtd_rows or [])
                if int(getattr(r, 'campanha_id', 0) or 0) > 0 and _upper(getattr(r, 'vendedor', ''))
            }
            qtd_camp_map: dict[int, Any] = {}
            try:
                qtd_ids = {int(getattr(r, 'campanha_id', 0) or 0) for r in qtd_rows if int(getattr(r, 'campanha_id', 0) or 0) > 0}
                if qtd_ids:
                    qtd_camp_map = {int(getattr(c, 'id', 0) or 0): c for c in db.query(CampanhaQtd).filter(CampanhaQtd.id.in_(qtd_ids)).all()}
            except Exception:
                qtd_camp_map = {}

            for r in qtd_rows:
                campanha_def = qtd_camp_map.get(int(getattr(r, 'campanha_id', 0) or 0))
                item_meta = _campanha_qtd_item_meta(r, campanha_def)
                recompensa_unit = _safe_float(getattr(r, 'recompensa_unit', 0.0))
                valor_recompensa_snapshot = _safe_float(getattr(r, 'valor_recompensa', 0.0))
                qtd_minima = getattr(r, 'qtd_minima', None)
                valor_vendido = _safe_float(getattr(r, 'valor_vendido', 0.0))

                gate_atual = _corrigir_gate_qtd_com_faturamento_atual(
                    db,
                    resultado=r,
                    campanha=campanha_def,
                    emp=str(emp),
                    periodo_ini=periodo_ini,
                    periodo_fim=periodo_fim,
                    faturamento_cache=faturamento_cache,
                )
                valor_recompensa = _safe_float(gate_atual.get('valor_recompensa', valor_recompensa_snapshot))
                premio_potencial = _safe_float(gate_atual.get('premio_potencial', valor_recompensa_snapshot))
                faturamento_minimo_emp = gate_atual.get('faturamento_minimo_emp')
                faturamento_emp = gate_atual.get('faturamento_emp')
                faltante_faturamento_emp = gate_atual.get('faltante_faturamento_emp')
                bloqueado_faturamento_emp = bool(gate_atual.get('bloqueado_faturamento_emp'))
                atingiu_gate = bool(gate_atual.get('atingiu_gate'))

                qtd_prem = None
                if recompensa_unit > 0 and premio_potencial > 0:
                    qtd_prem = premio_potencial / recompensa_unit

                rows.append(
                    UnifiedRow(
                        tipo=('GERENTE' if str(getattr(r, 'campanha_tipo', '') or '').strip().upper() == 'GERENTE' else 'QTD'),
                        competencia_ano=int(getattr(r, 'competencia_ano', ano)),
                        competencia_mes=int(getattr(r, 'competencia_mes', mes)),
                        emp=str(getattr(r, 'emp', emp)),
                        vendedor=_upper(getattr(r, 'vendedor', '')),
                        titulo=str(getattr(r, 'titulo', '') or '').strip() or f"Campanha #{getattr(r, 'campanha_id', '')}",
                        item_codigo=item_meta.get('item_codigo'),
                        item_descricao=item_meta.get('item_descricao'),
                        item_marca=item_meta.get('item_marca'),
                        item_match_tipo=item_meta.get('item_match_tipo'),
                        qtd_minima=_safe_float(qtd_minima) if qtd_minima is not None else None,
                        recompensa_unit=recompensa_unit,
                        valor_vendido=valor_vendido,
                        atingiu_gate=atingiu_gate,
                        qtd_base=_safe_float(getattr(r, 'qtd_vendida', None)),
                        qtd_premiada=qtd_prem,
                        valor_recompensa=valor_recompensa,
                        premio_potencial=premio_potencial,
                        faturamento_minimo_emp=faturamento_minimo_emp,
                        faturamento_emp=faturamento_emp,
                        faltante_faturamento_emp=faltante_faturamento_emp,
                        bloqueado_faturamento_emp=bloqueado_faturamento_emp,
                        status_pagamento=str(getattr(r, 'status_pagamento', 'PENDENTE') or 'PENDENTE'),
                        pago_em=getattr(r, 'pago_em', None),
                        origem_id=int(getattr(r, 'campanha_id', 0) or 0),
                    )
                )

            if incluir_participacao_ativa:
                _append_campanhas_qtd_participacao_ativa(
                    db,
                    rows,
                    ano=int(ano),
                    mes=int(mes),
                    emp=str(emp),
                    vendedores=vendedores,
                    periodo_ini=periodo_ini,
                    periodo_fim=periodo_fim,
                    existing_keys=qtd_existing_keys,
                    faturamento_cache=faturamento_cache,
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
                    .filter(func.upper(func.coalesce(Venda.mov_tipo_movto, "")).in_(MOVIMENTOS_VENDA))
                    .filter(func.coalesce(Venda.qtdade_vendida, 0.0) > 0)
                    .group_by(Venda.vendedor, Venda.mestre, func.coalesce(Venda.descricao, ''))
                    .all()
                )

                sales_by_vendor: dict[str, list[dict[str, Any]]] = {v: [] for v in vendedores}
                for vend, mestre, descricao, qtd, val in vendas_rows:
                    if float(qtd or 0.0) <= 0:
                        continue
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
                        combo_marca = _clean_text(getattr(combo, 'marca', None)).upper() or None

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
                                    item_descricao=(descricao_contains or None) if not item_codigo else None,
                                    item_marca=combo_marca,
                                    item_match_tipo='descricao' if (descricao_contains and not item_codigo) else 'codigo',
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
                                    item_descricao=ir.item_descricao,
                                    item_marca=ir.item_marca,
                                    item_match_tipo=ir.item_match_tipo,
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
                                item_descricao=None,
                                item_marca=combo_marca,
                                item_match_tipo=None,
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
                incluir_zerados=bool(incluir_zerados or incluir_participacao_ativa),
                metas_live=bool(metas_live),
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
