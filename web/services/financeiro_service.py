import json
from datetime import datetime
from sqlalchemy import and_

from db import (
    FinanceiroPagamento,
    FinanceiroAudit,
    CampanhaV2ResultadoNew,
    CampanhaV2MasterNew,
)


def _safe_meta_json(v):
    """Converte meta (dict/list) para JSON string, compatível com coluna TEXT no Postgres."""
    if v is None:
        return None
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, default=str)
    # garante string (evita tipos não adaptáveis no psycopg2)
    return str(v)


def sync_pagamentos_v2(db, ano: int, mes: int, actor: str = "") -> dict:
    """Cria/atualiza pagamentos do Financeiro com base em campanhas_v2_resultados (NEW schema).

    Regras:
    - Só cria pagamento quando premio > 0
    - Upsert pela chave uq_fin_pag_key (ano,mes,origem_tipo,origem_id,emp,vendedor)
    - Não altera status se já estiver A_PAGAR/PAGO (mantém status atual), só atualiza valores/nome.
    """
    actor = (actor or "").strip() or None

    # rows: (resultado, nome_campanha)
    rows = (
        db.query(CampanhaV2ResultadoNew, CampanhaV2MasterNew.nome)
        .join(CampanhaV2MasterNew, CampanhaV2MasterNew.id == CampanhaV2ResultadoNew.campanha_id)
        .filter(CampanhaV2ResultadoNew.ano == int(ano))
        .filter(CampanhaV2ResultadoNew.mes == int(mes))
        .all()
    )

    created = 0
    updated = 0
    skipped = 0

    for res, nome in rows:
        premio = float(getattr(res, "premio", 0.0) or 0.0)
        if premio <= 0:
            skipped += 1
            continue

        emp = getattr(res, "emp", None)
        vendedor = (getattr(res, "vendedor", "") or "").strip().upper()
        if not vendedor:
            skipped += 1
            continue

        origem_tipo = "V2"
        origem_id = int(getattr(res, "campanha_id"))
        campanha_nome = (nome or "").strip() or None

        existing = (
            db.query(FinanceiroPagamento)
            .filter(FinanceiroPagamento.ano == int(ano))
            .filter(FinanceiroPagamento.mes == int(mes))
            .filter(FinanceiroPagamento.origem_tipo == origem_tipo)
            .filter(FinanceiroPagamento.origem_id == origem_id)
            .filter(FinanceiroPagamento.vendedor == vendedor)
            .filter(FinanceiroPagamento.emp.is_(None) if emp is None else (FinanceiroPagamento.emp == int(emp)))
            .first()
        )

        if existing:
            # Atualiza valor e nome; preserva status se já avançado
            existing.valor_premio = premio
            if campanha_nome:
                existing.campanha_nome = campanha_nome
            if existing.status not in ("A_PAGAR", "PAGO"):
                existing.status = "PENDENTE"
            existing.atualizado_por = actor
            existing.atualizado_em = datetime.utcnow()
            updated += 1

            db.add(FinanceiroAudit(
                pagamento_id=existing.id,
                acao="UPSERT_V2",
                de_status=None,
                para_status=existing.status,
                usuario=actor,
                meta=_safe_meta_json({"ano": int(ano), "mes": int(mes), "origem": "V2", "campanha_id": origem_id, "premio": premio}),
            ))
        else:
            p = FinanceiroPagamento(
                ano=int(ano),
                mes=int(mes),
                origem_tipo=origem_tipo,
                origem_id=origem_id,
                campanha_nome=campanha_nome,
                emp=int(emp) if emp is not None else None,
                vendedor=vendedor,
                valor_premio=premio,
                status="PENDENTE",
                atualizado_por=actor,
                atualizado_em=datetime.utcnow(),
                criado_em=datetime.utcnow(),
            )
            db.add(p)
            db.flush()
            created += 1

            db.add(FinanceiroAudit(
                pagamento_id=p.id,
                acao="CREATE_FROM_V2",
                de_status=None,
                para_status="PENDENTE",
                usuario=actor,
                meta=_safe_meta_json({"ano": int(ano), "mes": int(mes), "origem": "V2", "campanha_id": origem_id, "premio": premio}),
            ))

    return {"created": created, "updated": updated, "skipped": skipped, "total": len(rows)}


def atualizar_status_pagamentos(db, pagamento_ids: list[int], novo_status: str, actor: str = "") -> int:
    novo_status = (novo_status or "").strip().upper()
    if novo_status not in ("PENDENTE", "A_PAGAR", "PAGO"):
        raise ValueError("Status inválido.")
    actor = (actor or "").strip() or None

    count = 0
    for pid in pagamento_ids:
        p = db.query(FinanceiroPagamento).filter(FinanceiroPagamento.id == int(pid)).first()
        if not p:
            continue
        de = p.status
        if de == novo_status:
            continue

        p.status = novo_status
        p.atualizado_por = actor
        p.atualizado_em = datetime.utcnow()
        db.add(p)

        db.add(FinanceiroAudit(
            pagamento_id=p.id,
            acao="STATUS_CHANGE",
            de_status=de,
            para_status=novo_status,
            usuario=actor,
            meta=_safe_meta_json({"ids": pagamento_ids[:50], "novo_status": novo_status}),
        ))
        count += 1
    return count


from typing import Any, Callable
from decimal import Decimal, ROUND_HALF_UP
from sqlalchemy import cast, String

from db import (
    SessionLocal,
    FechamentoMensal,
)
from services.relatorio_unificado_service import build_unified_rows


def _norm_status(v: str | None) -> str:
    s = (v or 'PENDENTE').strip().upper()
    if s in ('A PAGAR', 'A_PAGAR', 'APAGAR'):
        return 'A_PAGAR'
    if s == 'PAGO':
        return 'PAGO'
    return 'PENDENTE'


def _norm_tipo(v: str | None) -> str:
    s = (v or '').strip().upper()
    if s in ('QTD', 'CAMPANHA', 'PRODUTO'):
        return 'QTD'
    if s in ('COMBO', 'COMBO_CARD'):
        return 'COMBO'
    if s in ('PARADO', 'ITENS_PARADOS', 'ITEM_PARADO'):
        return 'PARADO'
    if s in ('META', 'METAS'):
        return 'META'
    return s or 'OUTROS'


def _tipo_to_origem(tipo: str | None) -> str:
    t = _norm_tipo(tipo)
    return {
        'QTD': 'V1_QTD',
        'COMBO': 'V1_COMBO',
        'PARADO': 'V1_PARADOS',
        'META': 'V1_META',
        'RANKING': 'V2',
    }.get(t, t or 'OUTROS')


def _safe_emp_int(emp: Any) -> int:
    s = str(emp or '').strip()
    return int(s) if s.isdigit() else 0


def _round2(v: Any) -> float:
    try:
        return float(Decimal(str(v if v is not None else 0)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP))
    except Exception:
        return 0.0


def ensure_pagamento_from_row(
    db,
    *,
    ano: int,
    mes: int,
    tipo: str,
    origem_id: int,
    emp: Any,
    vendedor: str,
    campanha_nome: str,
    valor_premio: float,
    actor: str = '',
    novo_status: str | None = None,
):
    """Cria/atualiza um pagamento financeiro a partir de uma linha consolidada."""
    origem_tipo = _tipo_to_origem(tipo)
    vendedor_u = (vendedor or '').strip().upper()
    if not vendedor_u:
        raise ValueError('Vendedor inválido.')

    emp_i = _safe_emp_int(emp)
    origem_i = int(origem_id or 0)
    valor_f = _round2(valor_premio)
    status_final = _norm_status(novo_status or 'PENDENTE')
    actor = (actor or '').strip() or None

    existing = (
        db.query(FinanceiroPagamento)
        .filter(FinanceiroPagamento.ano == int(ano))
        .filter(FinanceiroPagamento.mes == int(mes))
        .filter(FinanceiroPagamento.origem_tipo == origem_tipo)
        .filter(FinanceiroPagamento.origem_id == origem_i)
        .filter(FinanceiroPagamento.emp == emp_i)
        .filter(FinanceiroPagamento.vendedor == vendedor_u)
        .first()
    )

    if existing:
        de = existing.status
        existing.campanha_nome = (campanha_nome or existing.campanha_nome or '').strip() or existing.campanha_nome
        existing.valor_premio = valor_f
        existing.status = status_final
        existing.atualizado_por = actor
        existing.atualizado_em = datetime.utcnow()
        db.add(existing)
        if de != status_final:
            db.add(FinanceiroAudit(
                pagamento_id=existing.id,
                acao='STATUS_CHANGE',
                de_status=de,
                para_status=status_final,
                usuario=actor,
                meta=_safe_meta_json({'ano': int(ano), 'mes': int(mes), 'origem_tipo': origem_tipo, 'origem_id': origem_i, 'valor': valor_f}),
            ))
        return existing

    p = FinanceiroPagamento(
        ano=int(ano),
        mes=int(mes),
        origem_tipo=origem_tipo,
        origem_id=origem_i,
        campanha_nome=(campanha_nome or '').strip() or None,
        emp=emp_i,
        vendedor=vendedor_u,
        valor_premio=valor_f,
        status=status_final,
        atualizado_por=actor,
        atualizado_em=datetime.utcnow(),
        criado_em=datetime.utcnow(),
    )
    db.add(p)
    db.flush()
    db.add(FinanceiroAudit(
        pagamento_id=p.id,
        acao='CREATE_MANUAL',
        de_status=None,
        para_status=status_final,
        usuario=actor,
        meta=_safe_meta_json({'ano': int(ano), 'mes': int(mes), 'origem_tipo': origem_tipo, 'origem_id': origem_i, 'valor': valor_f}),
    ))
    return p


def collect_financeiro_items(relatorio: list[dict[str, Any]] | None, *, emp: str | None = None, vendedor: str | None = None) -> list[dict[str, Any]]:
    """Coleta itens financeiros visíveis no contexto atual, com filtro opcional por EMP e vendedor."""
    emp_s = str(emp or '').strip()
    vendedor_u = (vendedor or '').strip().upper()
    items: list[dict[str, Any]] = []

    for eg in (relatorio or []):
        if emp_s and str(eg.get('emp') or '').strip() != emp_s:
            continue
        for vg in (eg.get('vendedores') or []):
            if vendedor_u and str(vg.get('vendedor') or '').strip().upper() != vendedor_u:
                continue
            for it in (vg.get('itens') or []):
                items.append(it)
    return items


def apply_bulk_status_from_relatorio(
    db,
    *,
    ano: int,
    mes: int,
    relatorio: list[dict[str, Any]] | None,
    novo_status: str,
    actor: str = '',
    emp: str | None = None,
    vendedor: str | None = None,
) -> tuple[int, int]:
    """Aplica status em lote usando exatamente os itens visíveis no contexto financeiro atual."""
    items = collect_financeiro_items(relatorio, emp=emp, vendedor=vendedor)
    changed = 0
    total = 0
    status_final = _norm_status(novo_status)

    for it in items:
        total += 1
        status_atual = _norm_status(it.get('status'))
        if status_atual == status_final:
            continue
        ensure_pagamento_from_row(
            db,
            ano=int(ano),
            mes=int(mes),
            tipo=it.get('tipo') or '',
            origem_id=int(it.get('origem_id') or 0),
            emp=it.get('emp') or '',
            vendedor=it.get('vendedor') or '',
            campanha_nome=it.get('titulo') or '',
            valor_premio=float(it.get('valor') or 0),
            actor=actor,
            novo_status=status_final,
        )
        changed += 1

    return changed, total


def build_financeiro_campanhas_context(
    deps,
    *,
    role: str,
    vendedor_logado: str,
    ano: int,
    mes: int,
    emps_scope: list[str],
    emps_sel: list[str],
    vendedores_sel: list[str],
    vendedores_por_emp: dict[str, list[str]],
    recalc: bool,
    status_sel: str,
    tipo_sel: str,
    flash: Callable[[str, str], None],
) -> dict[str, Any]:
    role_l = (role or '').strip().lower()
    emps_scope = [str(e).strip() for e in (emps_scope or []) if str(e).strip()]
    emps_sel = [str(e).strip() for e in (emps_sel or []) if str(e).strip()]
    vendedores_sel = [str(v).strip().upper() for v in (vendedores_sel or []) if str(v).strip()]

    if role_l != 'admin' and not emps_sel and emps_scope:
        emps_sel = emps_scope[:]
    if not emps_sel:
        emps_sel = emps_scope[:]

    if recalc:
        try:
            try:
                deps.recalcular_resultados_campanhas_para_scope(ano=ano, mes=mes, emps=emps_sel, vendedores_por_emp=vendedores_por_emp)
            except TypeError:
                deps.recalcular_resultados_campanhas_para_scope(ano=ano, mes=mes, emps_scope=emps_sel, vendedores_por_emp=vendedores_por_emp)
            try:
                deps.recalcular_resultados_combos_para_scope(ano=ano, mes=mes, emps=emps_sel, vendedores_por_emp=vendedores_por_emp)
            except TypeError:
                deps.recalcular_resultados_combos_para_scope(ano=ano, mes=mes, emps_scope=emps_sel, vendedores_por_emp=vendedores_por_emp)
        except Exception as e:
            flash('Não foi possível recalcular agora. Exibindo dados já existentes.', 'warning')
            print(f'[FINANCEIRO_CAMPANHAS] erro recalc: {e}')

    try:
        rows = build_unified_rows(
            ano=ano,
            mes=mes,
            emps=emps_sel,
            vendedores_por_emp=vendedores_por_emp,
            incluir_zerados=False,
            usar_snapshot_itens_parados=True,
        ) or []
    except Exception as e:
        print(f'[FINANCEIRO_CAMPANHAS] erro rows: {e}')
        rows = []

    status_sel = _norm_status(status_sel) if status_sel else ''
    tipo_sel = _norm_tipo(tipo_sel) if tipo_sel else ''

    emps_int = [_safe_emp_int(e) for e in emps_sel]
    vend_all = sorted({str(v or '').strip().upper() for vals in (vendedores_por_emp or {}).values() for v in (vals or []) if str(v or '').strip()})
    if role_l == 'vendedor' and vendedor_logado:
        vend_all = [vendedor_logado]

    payments_map = {}
    fech_map = {}
    with SessionLocal() as db:
        try:
            q = db.query(FinanceiroPagamento).filter(FinanceiroPagamento.ano == int(ano), FinanceiroPagamento.mes == int(mes))
            if emps_int:
                q = q.filter(FinanceiroPagamento.emp.in_(emps_int))
            if vend_all:
                q = q.filter(FinanceiroPagamento.vendedor.in_(vend_all))
            for p in q.all():
                key = (str(p.origem_tipo or '').strip().upper(), int(p.origem_id or 0), _safe_emp_int(p.emp), (p.vendedor or '').strip().upper())
                payments_map[key] = p
        except Exception as e:
            print(f'[FINANCEIRO_CAMPANHAS] erro pagamentos_map: {e}')
            payments_map = {}

        try:
            qf = db.query(FechamentoMensal.emp, FechamentoMensal.fechado).filter(FechamentoMensal.ano == int(ano), FechamentoMensal.mes == int(mes))
            if emps_sel:
                qf = qf.filter(cast(FechamentoMensal.emp, String).in_([str(e) for e in emps_sel]))
            fech_map = {str(emp): bool(f) for emp, f in qf.all()}
        except Exception as e:
            print(f'[FINANCEIRO_CAMPANHAS] erro fech_map: {e}')
            fech_map = {}

    emp_groups = {}
    totals_by_status = {'PENDENTE': 0.0, 'A_PAGAR': 0.0, 'PAGO': 0.0}
    total_geral = 0.0
    total_linhas = 0

    def _sort_emp_key(emp: str):
        s = str(emp or '').strip()
        return (0, int(s)) if s.isdigit() else (1, s)

    for r in rows:
        tipo = _norm_tipo(getattr(r, 'tipo', None))
        origem_tipo = _tipo_to_origem(tipo)
        origem_id = int(getattr(r, 'origem_id', 0) or 0)
        emp = str(getattr(r, 'emp', '') or '').strip() or '0'
        vendedor = (getattr(r, 'vendedor', '') or '').strip().upper()
        valor = _round2(getattr(r, 'valor_recompensa', 0) or 0)
        # Segurança: campanhas QTD bloqueadas por faturamento mínimo da EMP
        # não entram no financeiro, mesmo que apareçam no relatório como potencial.
        if bool(getattr(r, 'bloqueado_faturamento_emp', False)):
            continue
        if valor <= 0:
            continue
        pay = payments_map.get((origem_tipo, origem_id, _safe_emp_int(emp), vendedor))
        status = _norm_status(getattr(pay, 'status', None) or getattr(r, 'status_pagamento', 'PENDENTE'))
        if status_sel and status != status_sel:
            continue
        if tipo_sel and tipo != tipo_sel:
            continue

        total_linhas += 1
        total_geral += valor
        if status in totals_by_status:
            totals_by_status[status] += valor

        eg = emp_groups.setdefault(emp, {
            'emp': emp,
            'fechada': bool(fech_map.get(emp, False)),
            'total': 0.0,
            'status': {'PENDENTE': 0.0, 'A_PAGAR': 0.0, 'PAGO': 0.0},
            'vendedores_map': {},
        })
        eg['total'] += valor
        eg['status'][status] += valor

        vg = eg['vendedores_map'].setdefault(vendedor, {
            'vendedor': vendedor,
            'total': 0.0,
            'status': {'PENDENTE': 0.0, 'A_PAGAR': 0.0, 'PAGO': 0.0},
            'itens': [],
        })
        vg['total'] += valor
        vg['status'][status] += valor

        vg['itens'].append({
            'titulo': str(getattr(r, 'titulo', '') or '').strip() or 'Campanha',
            'tipo': tipo,
            'origem_tipo': origem_tipo,
            'origem_id': origem_id,
            'emp': emp,
            'vendedor': vendedor,
            'base': _round2(getattr(r, 'qtd_base', 0) or 0),
            'vendeu_rs': _round2(getattr(r, 'valor_vendido', 0) or 0),
            'valor': valor,
            'status': status,
            'atingiu': bool(getattr(r, 'atingiu', False)),
            'financeiro_id': int(getattr(pay, 'id', 0) or 0) if pay else 0,
            'can_change': True,
        })

    relatorio = []
    for emp, eg in sorted(emp_groups.items(), key=lambda kv: _sort_emp_key(kv[0])):
        vendedores = list(eg.pop('vendedores_map').values())
        for v in vendedores:
            v['itens'].sort(key=lambda it: ({'PENDENTE': 0, 'A_PAGAR': 1, 'PAGO': 2}.get(it['status'], 9), -float(it['valor'] or 0), str(it['titulo'] or '')))
        vendedores.sort(key=lambda x: (-float(x['total'] or 0), str(x['vendedor'] or '')))
        eg['vendedores'] = vendedores
        relatorio.append(eg)

    return {
        'ano': ano,
        'mes': mes,
        'role': role_l,
        'emps_scope': sorted({str(e) for e in emps_scope}, key=_sort_emp_key),
        'emps_sel': sorted({str(e) for e in emps_sel}, key=_sort_emp_key),
        'vendedores_scope': vend_all,
        'vendedores_sel': vendedores_sel,
        'status_sel': status_sel,
        'tipo_sel': tipo_sel,
        'relatorio': relatorio,
        'totais': {
            'geral': _round2(total_geral),
            'pendente': _round2(totals_by_status['PENDENTE']),
            'a_pagar': _round2(totals_by_status['A_PAGAR']),
            'pago': _round2(totals_by_status['PAGO']),
            'linhas': int(total_linhas),
        },
        'recalc': bool(recalc),
    }
