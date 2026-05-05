# -*- coding: utf-8 -*-
"""Rotas do Relatório de Campanhas (unificado).

Extraído do app.py como refatoração pura (sem alterar comportamento externo).
- Mantém os mesmos paths
- Mantém os mesmos nomes de endpoint usados em url_for(...)
"""

from __future__ import annotations

from io import BytesIO
from typing import Any, Callable

from werkzeug.datastructures import MultiDict

from flask import Response, flash, render_template, request, send_file, url_for

from services.campanhas_service import build_relatorio_campanhas_scope
from services.relatorio_campanhas_service import build_relatorio_campanhas_unificado_context


def _pick(obj, *keys):
    for k in keys:
        try:
            v = obj.get(k) if isinstance(obj, dict) else getattr(obj, k, None)
            if v is None:
                continue
            if isinstance(v, str) and not v.strip():
                continue
            return v
        except Exception:
            continue
    return None


def _to_float(x):
    try:
        return float(x or 0)
    except Exception:
        return 0.0


def _norm_status(s: str) -> str:
    s = (s or "PENDENTE").strip().upper()
    if s in ("A PAGAR", "A_PAGAR", "APAGAR"):
        return "A_PAGAR"
    if s == "PAGO":
        return "PAGO"
    if s == "PENDENTE":
        return "PENDENTE"
    return s


def _norm_tipo(tipo: str) -> str:
    t = str(tipo or '').strip().upper()
    if t in ('COMBO_CARD', 'COMBO'):
        return 'COMBO'
    if t in ('PARADO', 'ITENS_PARADOS', 'ITEM_PARADO'):
        return 'PARADO'
    if t in ('QTD', 'CAMPANHA', 'PRODUTO'):
        return 'QTD'
    if t in ('META', 'METAS'):
        return 'META'
    if t in ('RANKING', 'RANKING_MARCA', 'MARCA'):
        return 'RANKING'
    return t or 'OUTROS'


def _tipo_meta(tipo: str) -> dict[str, str]:
    t = _norm_tipo(tipo)
    mapping = {
        'QTD': {'label': 'CAMPANHA', 'class': 'sv-type--qtd', 'short': 'QTD'},
        'COMBO': {'label': 'COMBO', 'class': 'sv-type--combo', 'short': 'COMBO'},
        'PARADO': {'label': 'ITENS PARADOS', 'class': 'sv-type--parado', 'short': 'PARADO'},
        'META': {'label': 'META', 'class': 'sv-type--meta', 'short': 'META'},
        'RANKING': {'label': 'RANKING', 'class': 'sv-type--ranking', 'short': 'RANKING'},
        'OUTROS': {'label': 'OUTROS', 'class': 'sv-type--outros', 'short': 'OUTROS'},
    }
    return {'key': t, **mapping.get(t, mapping['OUTROS'])}


def _build_tipo_summary(camps):
    buckets = {}
    for c in (camps or []):
        meta = _tipo_meta(c.get('tipo'))
        key = meta['key']
        item = buckets.get(key)
        if not item:
            item = {
                'key': key,
                'label': meta['label'],
                'class': meta['class'],
                'short': meta['short'],
                'count': 0,
                'valor': 0.0,
            }
            buckets[key] = item
        item['count'] += 1
        item['valor'] += _to_float(c.get('valor') or 0)
    order = {'PARADO': 0, 'QTD': 1, 'COMBO': 2, 'META': 3, 'RANKING': 4, 'OUTROS': 9}
    return sorted(buckets.values(), key=lambda x: (order.get(x['key'], 9), x['label']))


def _agg_status(counts):
    if counts.get('PENDENTE'):
        return 'PENDENTE'
    if counts.get('A_PAGAR'):
        return 'A_PAGAR'
    if counts.get('PAGO'):
        return 'PAGO'
    return 'OUTROS'


def _emp_sort_key(val):
    s = str(val or '').strip()
    try:
        return (0, int(s))
    except Exception:
        return (1, s)


def _group_rows(rows):
    groups_map = {}
    for r in (rows or []):
        emp_r = str(_pick(r, 'emp', 'EMP') or '').strip() or '—'
        vend_r = str(_pick(r, 'vendedor', 'VENDEDOR') or '').strip() or '—'
        titulo = str(_pick(r, 'titulo', 'campanha', 'CAMPANHA') or '').strip() or '—'
        valor = _to_float(_pick(r, 'valor_recompensa', 'valor', 'VALOR_RECOMPENSA') or 0)
        st = _norm_status(_pick(r, 'status_pagamento', 'status', 'STATUS_PAGAMENTO') or 'PENDENTE')

        key = (emp_r, vend_r)
        g = groups_map.get(key)
        if not g:
            g = {
                'emp': emp_r,
                'vendedor': vend_r,
                'total': 0.0,
                'status_counts': {'PENDENTE': 0, 'A_PAGAR': 0, 'PAGO': 0, 'OUTROS': 0},
                'campanhas': [],
            }
            groups_map[key] = g

        g['total'] += valor
        g['status_counts'][st if st in g['status_counts'] else 'OUTROS'] += 1
        tipo_raw = str(getattr(r, 'tipo', '') or '').strip().upper()
        tipo_meta = _tipo_meta(tipo_raw)
        g['campanhas'].append({
            'titulo': titulo,
            'item_codigo': getattr(r, 'item_codigo', None),
            'qtd_minima': getattr(r, 'qtd_minima', None),
            'recompensa_unit': getattr(r, 'recompensa_unit', None),
            'qtd_vendida': float(getattr(r, 'qtd_base', 0) or 0),
            'vendeu_rs': float(getattr(r, 'valor_vendido', 0) or 0),
            'valor': valor,
            'status': st,
            'atingiu': bool(getattr(r, 'atingiu', False)),
            'tipo': tipo_raw,
            'tipo_key': tipo_meta['key'],
            'tipo_label': tipo_meta['label'],
            'tipo_class': tipo_meta['class'],
            'tipo_short': tipo_meta['short'],
            'origem_id': int(getattr(r, 'origem_id', 0) or 0),
        })

    rows_grouped = list(groups_map.values())
    for g in rows_grouped:
        camps = g.get('campanhas') or []
        combo_items = [c for c in camps if str(c.get('titulo') or '').lstrip().startswith('↳')]
        combo_headers = [c for c in camps if str(c.get('titulo') or '').strip().upper().startswith('COMBO')]
        resto = [c for c in camps if c not in combo_items and c not in combo_headers]

        combo_cards = []
        for header in combo_headers:
            combo_id = int(header.get('origem_id') or 0)
            itens = [i for i in combo_items if int(i.get('origem_id') or 0) == combo_id]
            combo_meta = _tipo_meta('COMBO')
            combo_cards.append({
                **header,
                'tipo': 'COMBO_CARD',
                'tipo_key': combo_meta['key'],
                'tipo_label': combo_meta['label'],
                'tipo_class': combo_meta['class'],
                'tipo_short': combo_meta['short'],
                'itens': itens,
                'vendeu_rs': sum(float(i.get('vendeu_rs') or 0) for i in itens) or float(header.get('vendeu_rs') or 0),
                'valor': sum(float(i.get('valor') or 0) for i in itens) or float(header.get('valor') or 0),
                'atingiu': bool(header.get('atingiu')),
            })

        g['campanhas'] = resto + combo_cards

        def _camp_sort_key(c):
            tipo = str(c.get('tipo') or '').strip().upper()
            tipo_ord = 9 if tipo == 'PARADO' else (5 if tipo == 'COMBO_CARD' else 1)
            status_ord = {'PENDENTE': 0, 'A_PAGAR': 1, 'PAGO': 2}.get(c.get('status'), 9)
            return (tipo_ord, status_ord, -float(c.get('valor') or 0), str(c.get('titulo') or ''))

        g['campanhas'].sort(key=_camp_sort_key)
        g['status'] = _agg_status(g['status_counts'])
        g['campanhas_count'] = len(g['campanhas'])
        g['tipos_resumo'] = _build_tipo_summary(g['campanhas'])

    rows_grouped.sort(key=lambda gg: (_emp_sort_key(gg.get('emp')), -float(gg.get('total') or 0), str(gg.get('vendedor') or '')))
    return rows_grouped


def _build_emp_cards(rows_grouped):
    emp_cards_map = {}
    for g in (rows_grouped or []):
        emp_key = str(g.get('emp') or '—').strip() or '—'
        card = emp_cards_map.get(emp_key)
        if not card:
            card = {
                'emp': emp_key,
                'rows': [],
                'total': 0.0,
                'campanhas_count': 0,
                'status_counts': {'PENDENTE': 0, 'A_PAGAR': 0, 'PAGO': 0, 'OUTROS': 0},
                'campanhas': [],
            }
            emp_cards_map[emp_key] = card
        card['rows'].append(g)
        card['total'] += float(g.get('total') or 0)
        card['campanhas_count'] += int(g.get('campanhas_count') or 0)
        card['campanhas'].extend(g.get('campanhas') or [])
        st = str(g.get('status') or 'PENDENTE').strip().upper()
        card['status_counts'][st if st in card['status_counts'] else 'OUTROS'] += 1

    emp_cards = []
    for emp_key in sorted(emp_cards_map.keys(), key=_emp_sort_key):
        card = emp_cards_map[emp_key]
        card['rows'].sort(key=lambda gg: (-float(gg.get('total') or 0), str(gg.get('vendedor') or '')))
        card['vendedores_count'] = len(card['rows'])
        card['status'] = _agg_status(card['status_counts'])
        card['tipos_resumo'] = _build_tipo_summary(card.get('campanhas') or [])
        emp_cards.append(card)
    return emp_cards


def _calc_resumo_financeiro(rows):
    resumo = {
        'linhas': 0,
        'total_valor': 0.0,
        'status': {'PENDENTE': 0.0, 'A_PAGAR': 0.0, 'PAGO': 0.0, 'OUTROS': 0.0},
        'por_emp': {},
    }
    for r in (rows or []):
        emp = str(_pick(r, 'emp', 'EMP') or '').strip() or '—'
        vendedor = str(_pick(r, 'vendedor', 'VENDEDOR') or '').strip() or '—'
        valor = _to_float(_pick(r, 'valor_recompensa', 'valor', 'VALOR_RECOMPENSA') or 0)
        st = _norm_status(_pick(r, 'status_pagamento', 'status', 'STATUS_PAGAMENTO') or 'PENDENTE')
        st_key = st if st in ('PENDENTE', 'A_PAGAR', 'PAGO') else 'OUTROS'
        resumo['linhas'] += 1
        resumo['total_valor'] += valor
        resumo['status'][st_key] += valor
        empd = resumo['por_emp'].setdefault(emp, {'total': 0.0, 'status': {'PENDENTE': 0.0, 'A_PAGAR': 0.0, 'PAGO': 0.0, 'OUTROS': 0.0}, 'vendedores': {}})
        empd['total'] += valor
        empd['status'][st_key] += valor
        vd = empd['vendedores'].setdefault(vendedor, {'total': 0.0, 'status': {'PENDENTE': 0.0, 'A_PAGAR': 0.0, 'PAGO': 0.0, 'OUTROS': 0.0}, 'linhas': 0})
        vd['linhas'] += 1
        vd['total'] += valor
        vd['status'][st_key] += valor
    resumo['por_emp_ordenado'] = sorted(resumo['por_emp'].items(), key=lambda kv: kv[1].get('total', 0.0), reverse=True)
    return resumo


def _augment_ctx(ctx, *, role: str, vendedor_logado: str, vendedores_por_emp: dict[str, list[str]], request_args, include_pagination: bool):
    ctx['role'] = role
    ctx['is_admin'] = role == 'admin'
    ctx['is_supervisor'] = role == 'supervisor'
    ctx['is_vendedor'] = role == 'vendedor'
    ctx['is_financeiro'] = role == 'financeiro'
    try:
        vendedores_scope = sorted({str(v or '').strip().upper() for vs in (vendedores_por_emp or {}).values() for v in (vs or []) if str(v or '').strip()})
    except Exception:
        vendedores_scope = []
    if role == 'vendedor' and vendedor_logado:
        vendedores_scope = [vendedor_logado]
    ctx['vendedores_scope'] = vendedores_scope

    rows = ctx.get('rows') or []
    rows_grouped = _group_rows(rows)
    ctx['rows_grouped'] = rows_grouped
    ctx['resumo'] = _calc_resumo_financeiro(rows)

    if include_pagination:
        try:
            default_per_page = 100 if role in ('admin', 'supervisor') else 50
            page = int(request_args.get('page') or 1)
            per_page = int(request_args.get('per_page') or default_per_page)
            page = max(page, 1)
            per_page = max(25, min(per_page, 500))
        except Exception:
            page = 1
            per_page = 100 if role in ('admin', 'supervisor') else 50
        total_rows = len(rows_grouped)
        start = (page - 1) * per_page
        end = start + per_page
        rows_grouped_page = rows_grouped[start:end]
        ctx['rows_grouped_page'] = rows_grouped_page
        ctx['rows_page'] = rows_grouped_page
        ctx['emp_cards_page'] = _build_emp_cards(rows_grouped_page)
        ctx['page'] = page
        ctx['per_page'] = per_page
        ctx['total_rows'] = total_rows
        ctx['total_pages'] = (total_rows + per_page - 1) // per_page if per_page else 1
    else:
        ctx['rows_grouped_page'] = rows_grouped
        ctx['rows_page'] = rows_grouped
        ctx['emp_cards_page'] = _build_emp_cards(rows_grouped)
        ctx['page'] = 1
        ctx['per_page'] = len(rows_grouped) or 1
        ctx['total_rows'] = len(rows_grouped)
        ctx['total_pages'] = 1

    from urllib.parse import urlencode
    base_args = request_args.to_dict(flat=False) if request_args else {}

    def _make_url(endpoint: str, **updates):
        d = dict(base_args)
        for k, v in updates.items():
            if v is None:
                d.pop(k, None)
            else:
                d[k] = str(v)
        qs = urlencode(d, doseq=True)
        return url_for(endpoint) + (("?" + qs) if qs else '')

    ctx['recalc_url'] = _make_url('relatorio_campanhas', recalc=1, page=1)
    ctx['export_url'] = _make_url('relatorio_campanhas_export_pdf', page=None, per_page=None)
    ctx['export_csv_url'] = _make_url('relatorio_campanhas_export_csv', page=None, per_page=None)

    # URL sob demanda dos detalhes: a página principal renderiza só o resumo
    # e busca a subtabela quando o usuário clica em "Ver campanhas".
    # Isso reduz o HTML inicial sem alterar cálculo nem permissão.
    try:
        for g in (ctx.get('rows_grouped_page') or []):
            g['detail_url'] = _make_url(
                'relatorio_campanhas_detalhes',
                detail_emp=g.get('emp'),
                detail_vendedor=g.get('vendedor'),
                page=None,
                per_page=None,
            )
    except Exception:
        pass
    per_page_opts = [50, 100, 200, 500]
    ctx['per_page_opts'] = per_page_opts
    ctx['per_page_urls'] = {opt: _make_url('relatorio_campanhas', per_page=opt, page=1) for opt in per_page_opts}
    ctx['prev_url'] = _make_url('relatorio_campanhas', page=max(1, int(ctx.get('page') or 1) - 1))
    ctx['next_url'] = _make_url('relatorio_campanhas', page=min(int(ctx.get('total_pages') or 1), int(ctx.get('page') or 1) + 1))
    return ctx


def _build_relatorio_ctx(deps, *, role: str, emp_usuario: str | None, vendedor_logado: str, request_args, flash_fn, recalc_override: bool | None = None):
    scope = build_relatorio_campanhas_scope(
        deps,
        role=role,
        emp_usuario=emp_usuario,
        vendedor_logado=vendedor_logado,
        args=request_args,
        flash=flash_fn,
    )
    ano = int(scope['ano'])
    mes = int(scope['mes'])
    emps_sel = scope['emps_sel']
    vendedores_sel = scope['vendedores_sel']
    emps_scope = scope['emps_scope']
    vendedores_por_emp = scope['vendedores_por_emp']

    recalc = recalc_override
    if recalc is None:
        recalc = str(request_args.get('recalc') or '').strip() in ('1', 'true', 'True', 'sim', 'SIM', 'yes', 'on')

    ctx = build_relatorio_campanhas_unificado_context(
        deps,
        role=role,
        vendedor_logado=vendedor_logado,
        ano=ano,
        mes=mes,
        emps_scope=emps_scope,
        emps_sel=emps_sel,
        vendedores_sel=vendedores_sel,
        vendedores_por_emp=vendedores_por_emp,
        recalc=recalc,
        flash=flash_fn,
    )
    return ctx, vendedores_por_emp


def register_relatorio_campanhas_routes(
    app,
    *,
    deps: Any,
    login_required_fn: Callable[[], Any],
    role_fn: Callable[[], str | None],
    emp_fn: Callable[[], str | None],
    usuario_logado_fn: Callable[[], str | None],
) -> None:
    """Registra rotas do relatório unificado de campanhas.

    Importante: não usa Blueprint para não alterar nomes de endpoints.
    Endpoints são fixados explicitamente para 100% backward compatibility.
    """

    def relatorio_campanhas():
        red = login_required_fn()
        if red:
            return red

        role = (role_fn() or '').strip().lower()
        emp_usuario = emp_fn()
        vendedor_logado = (usuario_logado_fn() or '').strip().upper()

        ctx, vendedores_por_emp = _build_relatorio_ctx(
            deps,
            role=role,
            emp_usuario=emp_usuario,
            vendedor_logado=vendedor_logado,
            request_args=request.args,
            flash_fn=flash,
        )
        ctx = _augment_ctx(
            ctx,
            role=role,
            vendedor_logado=vendedor_logado,
            vendedores_por_emp=vendedores_por_emp,
            request_args=request.args,
            include_pagination=True,
        )
        return render_template('relatorio_campanhas.html', ctx=ctx, **ctx)

    def relatorio_campanhas_detalhes():
        red = login_required_fn()
        if red:
            return red

        role = (role_fn() or '').strip().lower()
        emp_usuario = emp_fn()
        vendedor_logado = (usuario_logado_fn() or '').strip().upper()

        detail_emp = str(request.args.get('detail_emp') or '').strip()
        detail_vendedor = str(request.args.get('detail_vendedor') or '').strip().upper()
        if not detail_emp or not detail_vendedor:
            return Response('<div class="sv-muted">Detalhe inválido.</div>', mimetype='text/html; charset=utf-8', status=400)

        # Reaplica a regra de escopo usando somente o vendedor/EMP solicitado.
        # A própria função de escopo impede admin/supervisor/vendedor de enxergar fora do permitido.
        detail_args = MultiDict()
        try:
            for key, values in request.args.lists():
                detail_args.setlist(key, list(values or []))
            detail_args.poplist('emp')
            detail_args.poplist('vendedor')
            detail_args.poplist('page')
            detail_args.poplist('per_page')
            detail_args.poplist('recalc')
        except Exception:
            pass
        detail_args.add('emp', detail_emp)
        detail_args.add('vendedor', detail_vendedor)

        ctx, vendedores_por_emp = _build_relatorio_ctx(
            deps,
            role=role,
            emp_usuario=emp_usuario,
            vendedor_logado=vendedor_logado,
            request_args=detail_args,
            flash_fn=flash,
            recalc_override=False,
        )
        ctx = _augment_ctx(
            ctx,
            role=role,
            vendedor_logado=vendedor_logado,
            vendedores_por_emp=vendedores_por_emp,
            request_args=detail_args,
            include_pagination=False,
        )

        group = None
        for g in (ctx.get('rows_grouped') or []):
            if str(g.get('emp') or '').strip() == detail_emp and str(g.get('vendedor') or '').strip().upper() == detail_vendedor:
                group = g
                break

        if group is None:
            group = {
                'emp': detail_emp,
                'vendedor': detail_vendedor,
                'campanhas': [],
                'total': 0.0,
                'campanhas_count': 0,
            }

        html = render_template('_relatorio_campanhas_detalhes.html', g=group)
        return Response(html, mimetype='text/html; charset=utf-8')

    def relatorio_campanhas_export_csv():
        red = login_required_fn()
        if red:
            return red

        role = (role_fn() or '').strip().lower()
        emp_usuario = emp_fn()
        vendedor_logado = (usuario_logado_fn() or '').strip().upper()

        ctx, _ = _build_relatorio_ctx(
            deps,
            role=role,
            emp_usuario=emp_usuario,
            vendedor_logado=vendedor_logado,
            request_args=request.args,
            flash_fn=flash,
        )

        import csv
        from io import StringIO

        sio = StringIO()
        w = csv.writer(sio, delimiter=';')
        w.writerow(['tipo', 'competencia', 'emp', 'vendedor', 'titulo', 'atingiu_gate', 'qtd_base', 'qtd_premiada', 'valor_recompensa', 'status_pagamento', 'pago_em'])
        ano = int(ctx.get('ano') or 0)
        mes = int(ctx.get('mes') or 0)
        for r in (ctx.get('rows') or []):
            comp = f"{getattr(r, 'competencia_mes', mes):02d}/{getattr(r, 'competencia_ano', ano)}"
            w.writerow([
                getattr(r, 'tipo', ''),
                comp,
                getattr(r, 'emp', ''),
                getattr(r, 'vendedor', ''),
                getattr(r, 'titulo', ''),
                'SIM' if getattr(r, 'atingiu_gate', None) else 'NÃO' if getattr(r, 'atingiu_gate', None) is not None else '',
                getattr(r, 'qtd_base', '') if getattr(r, 'qtd_base', None) is not None else '',
                getattr(r, 'qtd_premiada', '') if getattr(r, 'qtd_premiada', None) is not None else '',
                getattr(r, 'valor_recompensa', 0.0),
                getattr(r, 'status_pagamento', 'PENDENTE'),
                getattr(r, 'pago_em', '') or '',
            ])

        out = sio.getvalue().encode('utf-8')
        filename = f'relatorio_campanhas_{ano}_{mes:02d}.csv'
        return send_file(BytesIO(out), mimetype='text/csv', as_attachment=True, download_name=filename)

    def relatorio_campanhas_export_pdf():
        red = login_required_fn()
        if red:
            return red

        role = (role_fn() or '').strip().lower()
        emp_usuario = emp_fn()
        vendedor_logado = (usuario_logado_fn() or '').strip().upper()

        ctx, vendedores_por_emp = _build_relatorio_ctx(
            deps,
            role=role,
            emp_usuario=emp_usuario,
            vendedor_logado=vendedor_logado,
            request_args=request.args,
            flash_fn=flash,
        )
        ctx = _augment_ctx(
            ctx,
            role=role,
            vendedor_logado=vendedor_logado,
            vendedores_por_emp=vendedores_por_emp,
            request_args=request.args,
            include_pagination=False,
        )

        from services.relatorio_campanhas_pdf_service import build_relatorio_campanhas_pdf

        pdf_bytes = build_relatorio_campanhas_pdf(
            ano=int(ctx.get('ano') or 0),
            mes=int(ctx.get('mes') or 0),
            emps_sel=[str(e) for e in (ctx.get('emps_sel') or [])],
            resumo=ctx.get('resumo') or {},
            emp_cards=ctx.get('emp_cards_page') or [],
        )
        filename = f'fechamento_campanhas_{int(ctx.get("ano") or 0)}_{int(ctx.get("mes") or 0):02d}.pdf'
        return send_file(BytesIO(pdf_bytes), mimetype='application/pdf', as_attachment=True, download_name=filename)

    app.add_url_rule('/relatorios/campanhas', endpoint='relatorio_campanhas', view_func=relatorio_campanhas, methods=['GET'])
    app.add_url_rule('/relatorios/campanhas/detalhes', endpoint='relatorio_campanhas_detalhes', view_func=relatorio_campanhas_detalhes, methods=['GET'])
    app.add_url_rule('/relatorios/campanhas/export.csv', endpoint='relatorio_campanhas_export_csv', view_func=relatorio_campanhas_export_csv, methods=['GET'])
    app.add_url_rule('/relatorios/campanhas/export.pdf', endpoint='relatorio_campanhas_export_pdf', view_func=relatorio_campanhas_export_pdf, methods=['GET'])
