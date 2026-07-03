# -*- coding: utf-8 -*-
"""Rotas do Relatório de Campanhas (unificado).

Extraído do app.py como refatoração pura (sem alterar comportamento externo).
- Mantém os mesmos paths
- Mantém os mesmos nomes de endpoint usados em url_for(...)
"""

from __future__ import annotations

from io import BytesIO
from datetime import date
import os
import threading
import time
from typing import Any, Callable
from urllib.parse import urlencode

from werkzeug.datastructures import MultiDict

from flask import Response, flash, redirect, render_template, request, send_file, session, url_for
from sqlalchemy import func

from db import OficinaServico, SessionLocal, Venda
from services.campanhas_service import build_relatorio_campanhas_scope
from services.relatorio_campanhas_service import (
    build_relatorio_campanhas_unificado_context,
    rebuild_relatorio_campanhas_unificado_cache,
)
from sv_utils import MOVIMENTOS_VENDA, emp_sort_key, sort_emp_codes


_RELATORIO_SCOPE_CACHE: dict[tuple, tuple[float, dict[str, Any]]] = {}
_RELATORIO_SCOPE_CACHE_LOCK = threading.Lock()



_RELATORIO_RECALC_JOBS: dict[tuple, dict[str, Any]] = {}
_RELATORIO_RECALC_JOBS_LOCK = threading.Lock()


def _recalc_jobs_ttl_seconds() -> int:
    try:
        return max(60, int(os.environ.get('RELATORIO_CAMPANHAS_RECALC_JOB_TTL_SECONDS', '1800') or 1800))
    except Exception:
        return 1800


def _recalc_job_key(*, role: str, vendedor_logado: str, ano: int, mes: int, emps: list[str], vendedores_por_emp: dict[str, list[str]]) -> tuple:
    vend_key = []
    for emp in sort_emp_codes(emps or []):
        vend_key.append((emp, tuple(sorted({str(v or '').strip().upper() for v in (vendedores_por_emp.get(emp) or []) if str(v or '').strip()}))))
    return (
        'relatorio_campanhas_recalc_job_v1',
        str(role or '').strip().lower(),
        str(vendedor_logado or '').strip().upper(),
        int(ano),
        int(mes),
        tuple(sort_emp_codes(emps or [])),
        tuple(vend_key),
    )


def _cleanup_recalc_jobs(now: float | None = None) -> None:
    now = time.monotonic() if now is None else now
    ttl = _recalc_jobs_ttl_seconds()
    with _RELATORIO_RECALC_JOBS_LOCK:
        for key, job in list(_RELATORIO_RECALC_JOBS.items()):
            if job.get('status') == 'running':
                continue
            ended = float(job.get('ended_at') or job.get('started_at') or 0)
            if ended and now - ended > ttl:
                _RELATORIO_RECALC_JOBS.pop(key, None)


def _start_recalc_background_job(
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
) -> tuple[str, dict[str, Any]]:
    """Inicia recálculo sem bloquear a request do Render.

    Retorna (estado, job), onde estado pode ser started/running/done/error.
    """
    role_l = str(role or '').strip().lower()
    emps_effective = [str(e).strip() for e in (emps_sel or []) if str(e).strip()]
    if role_l == 'vendedor' and not emps_effective:
        emps_effective = [str(e).strip() for e in (emps_scope or []) if str(e).strip()]
    key = _recalc_job_key(
        role=role_l,
        vendedor_logado=vendedor_logado,
        ano=int(ano),
        mes=int(mes),
        emps=emps_effective,
        vendedores_por_emp=vendedores_por_emp,
    )
    now = time.monotonic()
    _cleanup_recalc_jobs(now)
    with _RELATORIO_RECALC_JOBS_LOCK:
        current = _RELATORIO_RECALC_JOBS.get(key)
        if current and current.get('status') == 'running':
            return 'running', dict(current)
        if current and current.get('status') in ('done', 'partial_error') and now - float(current.get('ended_at') or 0) < 10:
            return 'done', dict(current)
        job = {
            'status': 'running',
            'started_at': now,
            'ended_at': None,
            'ano': int(ano),
            'mes': int(mes),
            'emps': list(emps_effective),
            'rows': 0,
            'duration_ms': 0,
            'errors': [],
        }
        _RELATORIO_RECALC_JOBS[key] = job

    def _runner() -> None:
        result: dict[str, Any] = {}
        try:
            result = rebuild_relatorio_campanhas_unificado_cache(
                deps,
                role=role_l,
                vendedor_logado=vendedor_logado,
                ano=int(ano),
                mes=int(mes),
                emps_scope=list(emps_scope or []),
                emps_sel=list(emps_effective or []),
                vendedores_sel=list(vendedores_sel or []),
                vendedores_por_emp={str(emp): list(vs or []) for emp, vs in (vendedores_por_emp or {}).items()},
            )
        except Exception as exc:
            result = {'status': 'error', 'errors': [str(exc)], 'rows': 0, 'duration_ms': 0}
            try:
                print(f'[RELATORIO_UNIFICADO] recalc_background_fatal erro={exc}')
            except Exception:
                pass
        finally:
            with _RELATORIO_RECALC_JOBS_LOCK:
                saved = _RELATORIO_RECALC_JOBS.get(key) or {}
                saved.update(result or {})
                saved['status'] = result.get('status') or ('error' if result.get('errors') else 'done')
                if saved['status'] == 'ok':
                    saved['status'] = 'done'
                saved['ended_at'] = time.monotonic()
                _RELATORIO_RECALC_JOBS[key] = saved

    th = threading.Thread(target=_runner, name=f'relatorio-campanhas-recalc-{int(ano)}-{int(mes)}', daemon=True)
    th.start()
    return 'started', dict(job)

def _scope_cache_ttl_seconds() -> int:
    try:
        return max(0, int(os.environ.get("RELATORIO_CAMPANHAS_SCOPE_CACHE_TTL_SECONDS", "300") or 0))
    except Exception:
        return 300


def _args_values(args, key: str) -> tuple[str, ...]:
    try:
        vals = args.getlist(key)
    except Exception:
        try:
            v = args.get(key)
            vals = [v] if v is not None else []
        except Exception:
            vals = []
    return tuple(sorted({str(v).strip() for v in (vals or []) if str(v).strip()}))


def _scope_cache_key(*, role: str, emp_usuario: str | None, vendedor_logado: str, request_args) -> tuple:
    return (
        "relatorio_campanhas_scope_v2_gate",
        str(role or '').strip().lower(),
        str(emp_usuario or '').strip(),
        str(vendedor_logado or '').strip().upper(),
        str(request_args.get('ano') or '').strip(),
        str(request_args.get('mes') or '').strip(),
        _args_values(request_args, 'emp'),
        _args_values(request_args, 'vendedor'),
    )


def _scope_cache_get(key: tuple) -> dict[str, Any] | None:
    ttl = _scope_cache_ttl_seconds()
    if ttl <= 0:
        return None
    now = time.monotonic()
    with _RELATORIO_SCOPE_CACHE_LOCK:
        item = _RELATORIO_SCOPE_CACHE.get(key)
        if not item:
            return None
        created, scope = item
        if now - created > ttl:
            _RELATORIO_SCOPE_CACHE.pop(key, None)
            return None
        # Cópia rasa + cópias das listas/dicts para evitar mutação entre requests.
        out = dict(scope or {})
        for k in ('emps_sel', 'vendedores_sel', 'emps_scope'):
            out[k] = list(out.get(k) or [])
        out['vendedores_por_emp'] = {str(emp): list(vs or []) for emp, vs in (out.get('vendedores_por_emp') or {}).items()}
        return out


def _scope_cache_set(key: tuple, scope: dict[str, Any]) -> None:
    ttl = _scope_cache_ttl_seconds()
    if ttl <= 0:
        return
    with _RELATORIO_SCOPE_CACHE_LOCK:
        if len(_RELATORIO_SCOPE_CACHE) > 64:
            oldest = sorted(_RELATORIO_SCOPE_CACHE.items(), key=lambda kv: kv[1][0])[:16]
            for old_key, _ in oldest:
                _RELATORIO_SCOPE_CACHE.pop(old_key, None)
        safe = dict(scope or {})
        for k in ('emps_sel', 'vendedores_sel', 'emps_scope'):
            safe[k] = list(safe.get(k) or [])
        safe['vendedores_por_emp'] = {str(emp): list(vs or []) for emp, vs in (safe.get('vendedores_por_emp') or {}).items()}
        _RELATORIO_SCOPE_CACHE[key] = (time.monotonic(), safe)


def _scope_cache_clear() -> None:
    with _RELATORIO_SCOPE_CACHE_LOCK:
        _RELATORIO_SCOPE_CACHE.clear()


def _is_recalc_flag(args) -> bool:
    try:
        return str(args.get('recalc') or '').strip() in ('1', 'true', 'True', 'sim', 'SIM', 'yes', 'on')
    except Exception:
        return False


def _has_emp_filter(args) -> bool:
    return bool(_args_values(args, 'emp'))


def _should_defer_unfiltered_report(*, role: str, request_args) -> bool:
    """Evita carga pesada por padrão para perfis com visão multi-EMP.

    Antes, admin/financeiro/supervisor/gerente sem EMP selecionada acabavam
    calculando todo o escopo permitido. Em produção isso gerou cache_miss de
    ~58s para 17 EMPs. Agora a tela inicial abre leve e exige seleção explícita.
    """
    role_l = str(role or '').strip().lower()
    if role_l == 'vendedor':
        return False
    return role_l in ('admin', 'financeiro', 'supervisor', 'gerente') and not _has_emp_filter(request_args)


def _clean_report_url(args, *, endpoint: str = 'relatorio_campanhas', drop: tuple[str, ...] = ('recalc', 'page')) -> str:
    try:
        d = args.to_dict(flat=False) if args else {}
    except Exception:
        d = {}
    for k in drop:
        d.pop(k, None)
    qs = urlencode(d, doseq=True)
    return url_for(endpoint) + (("?" + qs) if qs else '')


def _empty_relatorio_ctx(scope: dict[str, Any], *, role: str, vendedor_logado: str, recalc: bool, mensagem: str | None = None) -> dict[str, Any]:
    return {
        'ano': int(scope.get('ano') or 0),
        'mes': int(scope.get('mes') or 0),
        'role': str(role or '').strip().lower(),
        'vendedor_logado': vendedor_logado,
        'emps_scope': sort_emp_codes(scope.get('emps_scope') or []),
        'emps_sel': sort_emp_codes(scope.get('emps_sel') or []),
        'vendedores_sel': list(scope.get('vendedores_sel') or []),
        'vendedores_por_emp': dict(scope.get('vendedores_por_emp') or {}),
        'rows': [],
        'charts': {},
        'total_linhas': 0,
        'total_recompensa': 0.0,
        'recalc': bool(recalc),
        'deferred_report': True,
        'deferred_message': mensagem or 'Selecione ao menos uma EMP e aplique os filtros para carregar o relatório.',
    }


def _month_year_from_args(args) -> tuple[int, int]:
    hoje = date.today()
    try:
        mes = int(args.get('mes') or hoje.month)
    except Exception:
        mes = hoje.month
    try:
        ano = int(args.get('ano') or hoje.year)
    except Exception:
        ano = hoje.year
    mes = min(12, max(1, mes))
    ano = max(2000, min(ano, 2100))
    return ano, mes


def _build_deferred_scope(deps, *, role: str, emp_usuario: str | None, vendedor_logado: str, request_args, flash_fn) -> dict[str, Any]:
    """Escopo leve para abrir a tela sem consultar vendedores/relatório completo.

    Usado somente quando multi-EMP não selecionou EMP. A intenção é mostrar
    os checkboxes de EMP sem disparar queries pesadas em vendas/resultados.
    """
    role_l = str(role or '').strip().lower()
    ano, mes = _month_year_from_args(request_args)
    vendedores_sel = [str(v).strip().upper() for v in _args_values(request_args, 'vendedor') if str(v).strip()]
    emps_scope: list[str] = []

    try:
        if role_l in ('admin', 'financeiro'):
            emps_scope = sort_emp_codes(deps.get_emps_com_vendas_no_periodo(ano, mes) or [])
        elif role_l in ('supervisor', 'gerente'):
            allowed = [str(e).strip() for e in (deps.resolver_emp_scope_para_usuario(vendedor_logado, role_l, emp_usuario) or []) if str(e).strip()]
            emps_scope = sort_emp_codes(allowed)
            if not emps_scope:
                flash_fn('Gerente/Supervisor sem EMP vinculada. Ajuste o vínculo do usuário (usuario_emps).', 'warning')
        else:
            base_emps = [str(e).strip() for e in (deps.get_emps_vendedor(vendedor_logado) or []) if str(e).strip()]
            emps_scope = sort_emp_codes(base_emps)
    except Exception as exc:
        print(f'[RELATORIO_CAMPANHAS] erro ao montar escopo leve: {exc}')
        emps_scope = []

    return {
        'ano': ano,
        'mes': mes,
        'emps_sel': [],
        'vendedores_sel': vendedores_sel,
        'emps_scope': emps_scope,
        'vendedores_por_emp': {str(emp): [] for emp in sort_emp_codes(emps_scope)},
    }




def _build_processing_scope_ctx(deps, *, role: str, emp_usuario: str | None, vendedor_logado: str, request_args, flash_fn) -> tuple[dict[str, Any], dict[str, list[str]]]:
    """Renderiza retorno leve para sessões antigas que ainda tinham flag de processamento.

    O fluxo atual de recálculo manual é primeiro plano e não usa mais essa tela.
    Mantemos a função para compatibilidade com usuários que estavam com sessão antiga.
    """
    try:
        scope = build_relatorio_campanhas_scope(
            deps,
            role=role,
            emp_usuario=emp_usuario,
            vendedor_logado=vendedor_logado,
            args=request_args,
            flash=flash_fn,
        )
    except Exception as exc:
        try:
            print(f'[RELATORIO_CAMPANHAS] erro ao montar tela de processamento: {exc}')
        except Exception:
            pass
        scope = _build_deferred_scope(
            deps,
            role=role,
            emp_usuario=emp_usuario,
            vendedor_logado=vendedor_logado,
            request_args=request_args,
            flash_fn=flash_fn,
        )
    ctx = _empty_relatorio_ctx(
        scope,
        role=role,
        vendedor_logado=vendedor_logado,
        recalc=False,
        mensagem='Recálculo anterior finalizado ou sessão antiga detectada. Aplique os filtros para carregar o resultado já gravado/cacheado.',
    )
    ctx['recalc_processing'] = True
    return ctx, dict(scope.get('vendedores_por_emp') or {})


def _default_per_page(role: str) -> int:
    fallback = 50 if str(role or '').strip().lower() in ('admin', 'gerente', 'supervisor', 'financeiro') else 25
    try:
        return max(10, min(500, int(os.environ.get('RELATORIO_CAMPANHAS_DEFAULT_PER_PAGE', str(fallback)) or fallback)))
    except Exception:
        return fallback


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


def _fmt_num_label(x):
    if x is None:
        return None
    try:
        val = float(x)
    except Exception:
        return None
    return f"{val:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


def _fmt_pct_label(x):
    base = _fmt_num_label(x)
    return None if base is None else base + "%"


def _fmt_brl(x):
    base = _fmt_num_label(x)
    return None if base is None else "R$" + base


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
    if t in ('GERENTE', 'GERENTE_LOJA', 'LOJA'):
        return 'GERENTE'
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
        'GERENTE': {'label': 'GERENTE', 'class': 'sv-type--qtd', 'short': 'GER'},
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
    order = {'PARADO': 0, 'QTD': 1, 'GERENTE': 1, 'COMBO': 2, 'META': 3, 'RANKING': 4, 'OUTROS': 9}
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
    return emp_sort_key(val)


def _group_rows(rows):
    groups_map = {}
    for r in (rows or []):
        emp_r = str(_pick(r, 'emp', 'EMP') or '').strip() or '—'
        vend_r = str(_pick(r, 'vendedor', 'VENDEDOR') or '').strip() or '—'
        titulo = str(_pick(r, 'titulo', 'campanha', 'CAMPANHA') or '').strip() or '—'
        valor = _to_float(_pick(r, 'valor_recompensa', 'valor', 'VALOR_RECOMPENSA') or 0)
        premio_potencial = _pick(r, 'premio_potencial', 'POTENCIAL', 'premio_potencial')
        if premio_potencial is None:
            premio_potencial = valor
        premio_potencial = _to_float(premio_potencial or 0)
        faturamento_minimo_emp = _pick(r, 'faturamento_minimo_emp', 'FATURAMENTO_MINIMO_EMP')
        faturamento_emp = _pick(r, 'faturamento_emp', 'FATURAMENTO_EMP')
        faltante_faturamento_emp = _pick(r, 'faltante_faturamento_emp', 'FALTANTE_FATURAMENTO_EMP')
        bloqueado_faturamento_emp = bool(_to_float(_pick(r, 'bloqueado_faturamento_emp', 'BLOQUEADO_FATURAMENTO_EMP') or 0))
        margem_percentual = _pick(r, 'margem_percentual', 'MARGEM_PERCENTUAL')
        margem_minima = _pick(r, 'margem_minima', 'MARGEM_MINIMA')
        margem_faltante = _pick(r, 'margem_faltante_pp', 'MARGEM_FALTANTE_PP')
        bloqueado_margem = bool(_to_float(_pick(r, 'bloqueado_margem', 'BLOQUEADO_MARGEM') or 0))
        margem_atingida_raw = _pick(r, 'margem_atingida', 'MARGEM_ATINGIDA')
        margem_atingida = None if margem_atingida_raw is None else bool(margem_atingida_raw)
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
        meta_tipo_row = str(_pick(r, 'meta_tipo', 'META_TIPO') or '').strip().upper()
        is_meta_mecanico = bool(tipo_raw == 'META' and meta_tipo_row == 'MECANICO_FATURAMENTO')
        g['campanhas'].append({
            'titulo': titulo,
            'item_codigo': _pick(r, 'item_codigo', 'codigo', 'produto_prefixo'),
            'item_descricao': _pick(r, 'item_descricao', 'descricao_prefixo', 'descricao'),
            'item_marca': _pick(r, 'item_marca', 'marca', 'campanha_marca'),
            'item_match_tipo': _pick(r, 'item_match_tipo', 'campo_match'),
            'qtd_minima': getattr(r, 'qtd_minima', None),
            'recompensa_unit': getattr(r, 'recompensa_unit', None),
            'qtd_vendida': float(getattr(r, 'qtd_base', 0) or 0),
            'vendeu_rs': float(getattr(r, 'valor_vendido', 0) or 0),
            'resultado_label': 'Fat.:' if is_meta_mecanico else 'Qtd:',
            'resultado_valor_label': _fmt_brl(float(getattr(r, 'valor_vendido', 0) or 0)) if is_meta_mecanico else None,
            'qtd_minima_label': _fmt_brl(float(getattr(r, 'qtd_minima', 0) or 0)) if (is_meta_mecanico and getattr(r, 'qtd_minima', None) is not None) else None,
            'recompensa_label': (_fmt_pct_label(getattr(r, 'recompensa_unit', None)) if is_meta_mecanico else None),
            'valor': valor,
            'premio_potencial': premio_potencial,
            'faturamento_minimo_emp': _to_float(faturamento_minimo_emp or 0) if faturamento_minimo_emp is not None else None,
            'faturamento_emp': _to_float(faturamento_emp or 0) if faturamento_emp is not None else None,
            'faltante_faturamento_emp': _to_float(faltante_faturamento_emp or 0) if faltante_faturamento_emp is not None else None,
            'bloqueado_faturamento_emp': bloqueado_faturamento_emp,
            'meta_tipo': meta_tipo_row,
            'base_valor': _to_float(_pick(r, 'base_valor', 'BASE_VALOR') or 0) if _pick(r, 'base_valor', 'BASE_VALOR') is not None else None,
            'faturamento_minimo_meta': _to_float(_pick(r, 'faturamento_minimo_meta', 'FATURAMENTO_MINIMO_META') or 0) if _pick(r, 'faturamento_minimo_meta', 'FATURAMENTO_MINIMO_META') is not None else None,
            'bloqueado_minimo': bool(_to_float(_pick(r, 'bloqueado_minimo', 'BLOQUEADO_MINIMO') or 0)),
            'margem_percentual': _to_float(margem_percentual) if margem_percentual is not None else None,
            'margem_percentual_label': _fmt_pct_label(margem_percentual),
            'margem_minima': _to_float(margem_minima) if margem_minima is not None else None,
            'margem_minima_label': _fmt_pct_label(margem_minima),
            'margem_atingida': margem_atingida,
            'bloqueado_margem': bloqueado_margem,
            'margem_faltante': _to_float(margem_faltante or 0) if margem_faltante is not None else None,
            'margem_faltante_label': _fmt_num_label(margem_faltante),
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
    resumo['por_emp_ordenado'] = sorted(resumo['por_emp'].items(), key=lambda kv: _emp_sort_key(kv[0]))
    return resumo




def _calc_faturamento_loja_cards(deps, *, ano: int, mes: int, emps: list[str]) -> dict[str, dict[str, float]]:
    """Calcula balcão + oficina por EMP para conferência visual do relatório.

    Esses valores são faturamento da loja no período, não premiação. A regra segue
    o cálculo usado nas metas/travas: movimentos positivos de balcão + serviços
    de oficina importados na competência.
    """
    emps_clean: list[str] = []
    seen: set[str] = set()
    for e in emps or []:
        emp = str(e or '').strip()
        if not emp or emp in seen or emp == '—':
            continue
        seen.add(emp)
        emps_clean.append(emp)
    emps_clean = sort_emp_codes(emps_clean)

    base = {
        emp: {
            'faturamento_balcao': 0.0,
            'faturamento_oficina': 0.0,
            'faturamento_total': 0.0,
        }
        for emp in emps_clean
    }
    if not emps_clean or not deps:
        return base

    try:
        periodo_ini, periodo_fim = deps.periodo_bounds(int(ano), int(mes))
    except Exception:
        # fallback defensivo para não derrubar a tela caso o helper do período mude
        from calendar import monthrange
        periodo_ini = date(int(ano), int(mes), 1)
        periodo_fim = date(int(ano), int(mes), monthrange(int(ano), int(mes))[1])

    try:
        Session = getattr(deps, 'SessionLocal', None) or SessionLocal
        with Session() as db:
            try:
                rows_balcao = (
                    db.query(Venda.emp, func.coalesce(func.sum(Venda.valor_total), 0.0).label('valor'))
                    .filter(
                        Venda.emp.in_(emps_clean),
                        Venda.movimento >= periodo_ini,
                        Venda.movimento <= periodo_fim,
                        func.upper(func.coalesce(Venda.mov_tipo_movto, '')).in_(MOVIMENTOS_VENDA),
                        func.coalesce(Venda.qtdade_vendida, 0.0) > 0,
                    )
                    .group_by(Venda.emp)
                    .all()
                )
                for emp, valor in rows_balcao:
                    emp_s = str(emp or '').strip()
                    if emp_s in base:
                        base[emp_s]['faturamento_balcao'] = _to_float(valor)
            except Exception as exc:
                print(f'[RELATORIO_CAMPANHAS] erro ao somar venda balcão por loja: {exc}')
                try:
                    db.rollback()
                except Exception:
                    pass

            try:
                rows_oficina = (
                    db.query(OficinaServico.emp, func.coalesce(func.sum(OficinaServico.valor_servico), 0.0).label('valor'))
                    .filter(
                        OficinaServico.ano == int(ano),
                        OficinaServico.mes == int(mes),
                        OficinaServico.emp.in_(emps_clean),
                        OficinaServico.ativo.is_(True),
                    )
                    .group_by(OficinaServico.emp)
                    .all()
                )
                for emp, valor in rows_oficina:
                    emp_s = str(emp or '').strip()
                    if emp_s in base:
                        base[emp_s]['faturamento_oficina'] = _to_float(valor)
            except Exception as exc:
                # Se a migration de oficina ainda não rodou, mantém oficina zerada sem quebrar o relatório.
                print(f'[RELATORIO_CAMPANHAS] erro ao somar oficina por loja: {exc}')
                try:
                    db.rollback()
                except Exception:
                    pass
    except Exception as exc:
        print(f'[RELATORIO_CAMPANHAS] erro ao calcular totalizadores de faturamento: {exc}')

    for emp, vals in base.items():
        vals['faturamento_total'] = _to_float(vals.get('faturamento_balcao', 0.0)) + _to_float(vals.get('faturamento_oficina', 0.0))
    return base


def _attach_faturamento_to_emp_cards(ctx: dict[str, Any], deps) -> None:
    cards = ctx.get('emp_cards_page') or []
    if not cards:
        return
    try:
        ano = int(ctx.get('ano') or 0)
        mes = int(ctx.get('mes') or 0)
    except Exception:
        return
    emps = [str(c.get('emp') or '').strip() for c in cards if isinstance(c, dict)]
    fat_map = _calc_faturamento_loja_cards(deps, ano=ano, mes=mes, emps=emps)
    for card in cards:
        if not isinstance(card, dict):
            continue
        emp = str(card.get('emp') or '').strip()
        vals = fat_map.get(emp) or {'faturamento_balcao': 0.0, 'faturamento_oficina': 0.0, 'faturamento_total': 0.0}
        card['faturamento_balcao'] = _to_float(vals.get('faturamento_balcao', 0.0))
        card['faturamento_oficina'] = _to_float(vals.get('faturamento_oficina', 0.0))
        card['faturamento_total'] = _to_float(vals.get('faturamento_total', 0.0))

def _augment_ctx(ctx, *, deps=None, role: str, vendedor_logado: str, vendedores_por_emp: dict[str, list[str]], request_args, include_pagination: bool):
    ctx['role'] = role
    ctx['is_admin'] = role == 'admin'
    ctx['is_supervisor'] = role in ('supervisor', 'gerente')
    ctx['is_gerente'] = role == 'gerente'
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
            default_per_page = _default_per_page(role)
            page = int(request_args.get('page') or 1)
            per_page = int(request_args.get('per_page') or default_per_page)
            page = max(page, 1)
            per_page = max(10, min(per_page, 500))
        except Exception:
            page = 1
            per_page = _default_per_page(role)
        total_rows = len(rows_grouped)
        start = (page - 1) * per_page
        end = start + per_page
        rows_grouped_page = rows_grouped[start:end]
        ctx['rows_grouped_page'] = rows_grouped_page
        ctx['rows_page'] = rows_grouped_page
        ctx['emp_cards_page'] = _build_emp_cards(rows_grouped_page)
        _attach_faturamento_to_emp_cards(ctx, deps)
        ctx['page'] = page
        ctx['per_page'] = per_page
        ctx['total_rows'] = total_rows
        ctx['total_pages'] = (total_rows + per_page - 1) // per_page if per_page else 1
    else:
        ctx['rows_grouped_page'] = rows_grouped
        ctx['rows_page'] = rows_grouped
        ctx['emp_cards_page'] = _build_emp_cards(rows_grouped)
        _attach_faturamento_to_emp_cards(ctx, deps)
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
    per_page_opts = [25, 50, 100, 200, 500]
    ctx['per_page_opts'] = per_page_opts
    ctx['per_page_urls'] = {opt: _make_url('relatorio_campanhas', per_page=opt, page=1) for opt in per_page_opts}
    ctx['prev_url'] = _make_url('relatorio_campanhas', page=max(1, int(ctx.get('page') or 1) - 1))
    ctx['next_url'] = _make_url('relatorio_campanhas', page=min(int(ctx.get('total_pages') or 1), int(ctx.get('page') or 1) + 1))
    return ctx


def _build_relatorio_ctx(deps, *, role: str, emp_usuario: str | None, vendedor_logado: str, request_args, flash_fn, recalc_override: bool | None = None):
    recalc_flag = _is_recalc_flag(request_args)
    recalc = recalc_override
    if recalc is None:
        recalc = recalc_flag

    if _should_defer_unfiltered_report(role=role, request_args=request_args):
        if recalc_override is True or recalc_flag:
            _scope_cache_clear()
        if recalc:
            flash_fn('Selecione ao menos uma EMP antes de recalcular o relatório.', 'warning')
        scope = _build_deferred_scope(
            deps,
            role=role,
            emp_usuario=emp_usuario,
            vendedor_logado=vendedor_logado,
            request_args=request_args,
            flash_fn=flash_fn,
        )
        ctx = _empty_relatorio_ctx(
            scope,
            role=role,
            vendedor_logado=vendedor_logado,
            recalc=False,
            mensagem='Para evitar travamento, o relatório não calcula todas as EMPs automaticamente. Selecione uma ou mais EMPs e clique em Aplicar filtros.',
        )
        return ctx, scope.get('vendedores_por_emp') or {}

    if recalc_override is True or recalc_flag:
        _scope_cache_clear()

    scope_key = _scope_cache_key(role=role, emp_usuario=emp_usuario, vendedor_logado=vendedor_logado, request_args=request_args)
    scope = None if (recalc_override is True or recalc_flag) else _scope_cache_get(scope_key)
    if scope is None:
        scope = build_relatorio_campanhas_scope(
            deps,
            role=role,
            emp_usuario=emp_usuario,
            vendedor_logado=vendedor_logado,
            args=request_args,
            flash=flash_fn,
        )
        _scope_cache_set(scope_key, scope)

    ano = int(scope['ano'])
    mes = int(scope['mes'])
    emps_sel = scope['emps_sel']
    vendedores_sel = scope['vendedores_sel']
    emps_scope = scope['emps_scope']
    vendedores_por_emp = scope['vendedores_por_emp']

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

        # Compatibilidade com links antigos (?recalc=1), mas sem executar
        # recálculo pesado por GET. O recálculo oficial é POST, exclusivo do ADMIN,
        # e roda em primeiro plano para que o usuário saiba exatamente quando terminou.
        if _is_recalc_flag(request.args):
            flash('Use o botão Recalcular agora dentro do relatório. O recálculo é exclusivo do ADMIN e termina com uma mensagem de confirmação.', 'warning')
            return redirect(_clean_report_url(request.args))

        if session.pop('relatorio_campanhas_recalc_started', None):
            ctx, vendedores_por_emp = _build_processing_scope_ctx(
                deps,
                role=role,
                emp_usuario=emp_usuario,
                vendedor_logado=vendedor_logado,
                request_args=request.args,
                flash_fn=flash,
            )
            ctx = _augment_ctx(
                ctx,
                deps=deps,
                role=role,
                vendedor_logado=vendedor_logado,
                vendedores_por_emp=vendedores_por_emp,
                request_args=request.args,
                include_pagination=True,
            )
            return render_template('relatorio_campanhas.html', ctx=ctx, **ctx)

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
            deps=deps,
            role=role,
            vendedor_logado=vendedor_logado,
            vendedores_por_emp=vendedores_por_emp,
            request_args=request.args,
            include_pagination=True,
        )
        return render_template('relatorio_campanhas.html', ctx=ctx, **ctx)

    def relatorio_campanhas_recalcular():
        red = login_required_fn()
        if red:
            return red

        role = (role_fn() or '').strip().lower()
        emp_usuario = emp_fn()
        vendedor_logado = (usuario_logado_fn() or '').strip().upper()

        post_args = MultiDict()
        try:
            for key, values in request.form.lists():
                if key in ('recalc', 'page'):
                    continue
                post_args.setlist(key, list(values or []))
        except Exception:
            pass

        # Regra operacional: somente ADMIN pode recalcular snapshots/cache.
        # Usuários comuns apenas consultam os resultados já gravados/aquecidos.
        if role != 'admin':
            flash('Recálculo bloqueado: somente o ADMIN pode atualizar a apuração. Você está visualizando os dados já calculados.', 'warning')
            return redirect(_clean_report_url(post_args))

        # Proteção de performance: nunca recalcula todas as EMPs por acidente.
        # O admin pode clicar em "Marcar todas" e recalcular conscientemente.
        if _should_defer_unfiltered_report(role=role, request_args=post_args):
            flash('Selecione ao menos uma EMP antes de recalcular. Para recalcular todas, use Marcar todas e depois Recalcular agora.', 'warning')
            return redirect(_clean_report_url(post_args))

        _scope_cache_clear()
        try:
            scope = build_relatorio_campanhas_scope(
                deps,
                role=role,
                emp_usuario=emp_usuario,
                vendedor_logado=vendedor_logado,
                args=post_args,
                flash=flash,
            )
        except Exception as exc:
            flash('Não foi possível preparar o recálculo agora. Tente novamente em instantes.', 'warning')
            try:
                print(f'[RELATORIO_CAMPANHAS] erro ao preparar recalc inline: {exc}')
            except Exception:
                pass
            return redirect(_clean_report_url(post_args))

        try:
            ano = int(scope.get('ano') or 0)
            mes = int(scope.get('mes') or 0)
        except Exception:
            ano, mes = _month_year_from_args(post_args)

        started = time.perf_counter()
        try:
            stats = rebuild_relatorio_campanhas_unificado_cache(
                deps,
                role='admin',
                vendedor_logado=vendedor_logado,
                ano=int(ano),
                mes=int(mes),
                emps_scope=list(scope.get('emps_scope') or []),
                emps_sel=list(scope.get('emps_sel') or []),
                vendedores_sel=list(scope.get('vendedores_sel') or []),
                vendedores_por_emp=dict(scope.get('vendedores_por_emp') or {}),
                clear_existing=True,
            ) or {}
        except Exception as exc:
            try:
                deps.SessionLocal().rollback()
            except Exception:
                pass
            flash(f'Falha no recálculo: {exc}', 'danger')
            try:
                print(f'[RELATORIO_CAMPANHAS] erro recalc inline fatal: {exc}')
            except Exception:
                pass
            return redirect(_clean_report_url(post_args))

        # A função de rebuild captura falhas parciais de QTD/Combo/Itens Parados/Cache.
        # Se houver qualquer erro interno, avisa claramente para não passar falso positivo.
        duration_ms = int(stats.get('duration_ms') or ((time.perf_counter() - started) * 1000))
        emps_count = int(stats.get('emps') and len(stats.get('emps') or []) or len(scope.get('emps_sel') or []))
        rows_count = int(stats.get('rows') or 0)
        errors = [str(e) for e in (stats.get('errors') or []) if str(e).strip()]
        status = str(stats.get('status') or 'ok')
        segundos = duration_ms / 1000.0

        if errors or status not in ('ok', 'done'):
            detalhe = '; '.join(errors[:3]) if errors else f'status={status}'
            flash(
                f'Recálculo finalizado com alerta em {segundos:.1f}s para {emps_count} EMP(s). Linhas geradas: {rows_count}. Verifique: {detalhe}',
                'warning',
            )
        else:
            flash(
                f'Tudo recalculado com sucesso em {segundos:.1f}s para {emps_count} EMP(s). Linhas geradas: {rows_count}. O relatório já está pronto para uso.',
                'success',
            )

        return redirect(_clean_report_url(post_args))

    def relatorio_campanhas_recalcular_get():
        # Proteção: se alguém abrir a URL de recálculo direto pelo navegador (GET),
        # não executa processamento pesado nem gera 405/502; volta para o relatório.
        flash('Use o botão Recalcular agora dentro do relatório. Ele é exclusivo do ADMIN e roda em primeiro plano.', 'warning')
        return redirect(url_for('relatorio_campanhas'))

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

        def _make_args_for_cached_full_scope():
            out = MultiDict()
            try:
                for key, values in request.args.lists():
                    if key in ('detail_emp', 'detail_vendedor', 'page', 'per_page', 'recalc'):
                        continue
                    out.setlist(key, list(values or []))
            except Exception:
                pass
            return out

        def _make_args_for_single_detail():
            out = _make_args_for_cached_full_scope()
            try:
                out.poplist('emp')
                out.poplist('vendedor')
            except Exception:
                pass
            out.add('emp', detail_emp)
            out.add('vendedor', detail_vendedor)
            return out

        def _load_group(detail_args, *, paginated: bool):
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
                deps=deps,
                role=role,
                vendedor_logado=vendedor_logado,
                vendedores_por_emp=vendedores_por_emp,
                request_args=detail_args,
                include_pagination=paginated,
            )
            for g in (ctx.get('rows_grouped') or []):
                if str(g.get('emp') or '').strip() == detail_emp and str(g.get('vendedor') or '').strip().upper() == detail_vendedor:
                    return g
            return None

        # Primeiro tenta reaproveitar o mesmo escopo da página principal.
        # Normalmente isso bate no cache em memória e evita nova consulta pesada no banco a cada clique.
        group = _load_group(_make_args_for_cached_full_scope(), paginated=False)

        # Fallback seguro: se o usuário abriu o detalhe direto ou o cache expirou, carrega apenas EMP/vendedor pedido.
        if group is None:
            group = _load_group(_make_args_for_single_detail(), paginated=False)

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
            deps=deps,
            role=role,
            vendedor_logado=vendedor_logado,
            vendedores_por_emp=vendedores_por_emp,
            request_args=request.args,
            include_pagination=False,
        )

        from services.relatorio_campanhas_pdf_service import (
            build_relatorio_campanhas_pdf,
            build_relatorio_campanhas_vendedores_pdf,
        )

        ano_pdf = int(ctx.get('ano') or 0)
        mes_pdf = int(ctx.get('mes') or 0)
        emps_pdf = [str(e) for e in (ctx.get('emps_sel') or [])]
        resumo_pdf = ctx.get('resumo') or {}
        view_mode = str(request.args.get('view') or 'detalhado').strip().lower()

        if view_mode == 'vendedores':
            pdf_bytes = build_relatorio_campanhas_vendedores_pdf(
                ano=ano_pdf,
                mes=mes_pdf,
                emps_sel=emps_pdf,
                resumo=resumo_pdf,
            )
            filename = f'recompensas_por_vendedor_{ano_pdf}_{mes_pdf:02d}.pdf'
        else:
            pdf_bytes = build_relatorio_campanhas_pdf(
                ano=ano_pdf,
                mes=mes_pdf,
                emps_sel=emps_pdf,
                resumo=resumo_pdf,
                emp_cards=ctx.get('emp_cards_page') or [],
            )
            filename = f'fechamento_campanhas_{ano_pdf}_{mes_pdf:02d}.pdf'
        return send_file(BytesIO(pdf_bytes), mimetype='application/pdf', as_attachment=True, download_name=filename)

    app.add_url_rule('/relatorios/campanhas', endpoint='relatorio_campanhas', view_func=relatorio_campanhas, methods=['GET'])
    app.add_url_rule('/relatorios/campanhas/recalcular', endpoint='relatorio_campanhas_recalcular', view_func=relatorio_campanhas_recalcular, methods=['POST'])
    app.add_url_rule('/relatorios/campanhas/recalcular', endpoint='relatorio_campanhas_recalcular_get', view_func=relatorio_campanhas_recalcular_get, methods=['GET'])
    app.add_url_rule('/relatorios/campanhas/detalhes', endpoint='relatorio_campanhas_detalhes', view_func=relatorio_campanhas_detalhes, methods=['GET'])
    app.add_url_rule('/relatorios/campanhas/export.csv', endpoint='relatorio_campanhas_export_csv', view_func=relatorio_campanhas_export_csv, methods=['GET'])
    app.add_url_rule('/relatorios/campanhas/export.pdf', endpoint='relatorio_campanhas_export_pdf', view_func=relatorio_campanhas_export_pdf, methods=['GET'])
