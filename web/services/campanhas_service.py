from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Callable
from types import SimpleNamespace
from services.campanhas_v2_service import list_resultados_v2
from services.visao_operacional import (
    filter_emps_by_status,
    get_fechamento_status_map,
    normalize_status_filter,
    status_filter_label,
)


@dataclass(frozen=True)
class CampanhasDeps:
    """Dependências injetadas a partir do app.py.

    Mantemos isso assim (em vez de importar funções do app.py) para evitar
    import circular e permitir migração gradual das regras/consultas para
    uma camada de service.
    """

    # Sessão/DB
    SessionLocal: Any

    # Helpers utilitários
    parse_multi_args: Callable[[Any, str], list[str]]
    get_emp_options: Callable[[list[str]], list[dict[str, str]]]
    get_vendedores_db: Callable[[str, str | None], list[str]]
    get_emps_vendedor: Callable[[str], list[str]]
    get_all_emp_codigos: Callable[[bool], list[str]]
    periodo_bounds: Callable[[int, int], tuple[date, date]]

    # Regras de escopo
    resolver_emp_scope_para_usuario: Callable[[str, str, str | None], list[str]]

    # Campanhas QTD
    campanhas_mes_overlap: Callable[[int, int, str], list[Any]]
    upsert_resultado: Callable[[Any, Any, str, str, int, int, date, date], Any]
    calc_resultado_all_vendedores: Callable[[Any, Any, str, int, int, date, date], Any]

    # Relatório consolidado
    get_emps_com_vendas_no_periodo: Callable[[int, int], list[str]]
    get_vendedores_emp_no_periodo: Callable[[str, int, int], list[str]]
    recalcular_resultados_campanhas_para_scope: Callable[[int, int, list[str], dict[str, list[str]]], None]
    recalcular_resultados_combos_para_scope: Callable[[int, int, list[str], dict[str, list[str]]], None]



def _meta_tipo_label_public(tipo: str) -> str:
    tipo = (tipo or "").strip().upper()
    if tipo == "CRESCIMENTO":
        return "Meta Crescimento"
    if tipo == "MIX":
        return "Meta Mix"
    if tipo == "SHARE_MARCA":
        return "Meta Marcas"
    return "Meta"


def _meta_metric_label(calc: Any) -> str:
    tipo = (getattr(calc, "tipo", "") or "").strip().upper()
    try:
        if tipo == "CRESCIMENTO":
            pct = float(getattr(calc, "crescimento_pct", 0.0) or 0.0)
            return f"{pct:.2f}%"
        if tipo == "MIX":
            mix = int(float(getattr(calc, "mix_itens_unicos", 0) or 0))
            return str(mix)
        if tipo == "SHARE_MARCA":
            pct = float(getattr(calc, "share_pct", 0.0) or 0.0)
            return f"{pct:.2f}%"
    except Exception:
        pass
    return "0"


def _build_meta_cards_for_vendedor(db: Any, *, ano: int, mes: int, emp: str, vendedor: str, incluir_zeradas: bool = True) -> list[Any]:
    """Monta linhas de metas para a tela /campanhas sem acoplar template ao módulo /metas."""
    try:
        from metas_helpers import calcular_meta, get_meta_emps, metas_ativas_periodo
    except Exception:
        return []

    out: list[Any] = []
    vendedor_u = (vendedor or "").strip().upper()
    emp_s = str(emp or "").strip()
    if not vendedor_u or not emp_s:
        return out

    try:
        metas = metas_ativas_periodo(db, int(ano), int(mes), only_active=True) or []
    except Exception:
        metas = []

    for meta in metas:
        try:
            meta_emps = set(str(e).strip() for e in (get_meta_emps(db, int(getattr(meta, "id", 0) or 0)) or []) if str(e).strip())
            if meta_emps and emp_s not in meta_emps:
                continue
            calc = calcular_meta(db, meta, emp_s, vendedor_u, persist=True)
            premio = float(getattr(calc, "premio", 0.0) or 0.0)
            if not incluir_zeradas and premio <= 0:
                continue

            tipo = (getattr(meta, "tipo", "") or "").strip().upper()
            titulo_base = (getattr(meta, "nome", "") or _meta_tipo_label_public(tipo)).strip()
            bloqueado = bool(getattr(calc, "bloqueado_minimo", False))
            subtitulo = "Mínimo não atingido" if bloqueado else "Meta ativa"
            if tipo == "CRESCIMENTO" and getattr(calc, "base_valor", None) is not None:
                subtitulo = f"Base R$ {float(getattr(calc, 'base_valor', 0.0) or 0.0):,.2f}".replace(',', 'X').replace('.', ',').replace('X', '.')
            elif tipo == "MIX":
                subtitulo = "Itens únicos vendidos"
            elif tipo == "SHARE_MARCA":
                subtitulo = "Participação das marcas"

            out.append(SimpleNamespace(
                tipo="META",
                titulo=f"{_meta_tipo_label_public(tipo)} • {titulo_base}",
                nome=titulo_base,
                marca="METAS",
                base=subtitulo,
                qtd_total=_meta_metric_label(calc),
                qtd=_meta_metric_label(calc),
                valor_recompensa=premio,
                inicio=f"{int(mes):02d}/{int(ano)}",
                fim="",
                meta_tipo=tipo,
                meta_id=int(getattr(meta, "id", 0) or 0),
                atingiu=bool(premio > 0),
            ))
        except Exception as exc:
            try:
                print(f"[CAMPANHAS] erro ao calcular meta integrada emp={emp_s} vendedor={vendedor_u}: {exc}")
            except Exception:
                pass
            continue
    return out

def build_campanhas_page_context(
    deps: CampanhasDeps,
    *,
    role: str,
    emp_usuario: str | None,
    vendedor_logado: str,
    args: Any,
) -> dict[str, Any]:
    """Monta o context do template de /campanhas (QTD).

    Layout/UX esperado:
      - Hierarquia: EMP (nome) → vendedores → campanhas
      - Total (R$) = soma de valor_recompensa (não é valor vendido)
      - Mantém filtros de EMP e vendedor (checkbox, sem Ctrl)
    """

    role_l = (role or "").strip().lower()

    # Período
    hoje = date.today()
    mes = int(args.get("mes") or hoje.month)
    ano = int(args.get("ano") or hoje.year)
    inicio_mes, fim_mes = deps.periodo_bounds(ano, mes)

    # Filtros (multi)
    emps_sel = [str(e).strip() for e in deps.parse_multi_args(args, "emp") if str(e).strip()]
    vendedores_sel = [str(v).strip().upper() for v in deps.parse_multi_args(args, "vendedor") if str(v).strip()]

    visao = (args.get("visao") or "detalhado").strip().lower()
    status_visao = normalize_status_filter(args.get("status"), default="abertas")
    por_pagina = int(args.get("por_pagina") or 25)

    # Dropdown/Checklist de vendedores (sem carregar tudo em memória)
    try:
        vendedores_dropdown = deps.get_vendedores_db(role_l, emp_usuario)
    except Exception:
        vendedores_dropdown = []

    # ===== Base de EMPs para opções (dropdown) e escopo efetivo =====
    if role_l == "admin":
        emps_base = [str(e).strip() for e in (deps.get_emps_com_vendas_no_periodo(ano, mes) or []) if str(e).strip()]
        emps_base = list(dict.fromkeys(sorted(emps_base)))
        emps_scope = [e for e in emps_base if (not emps_sel) or (e in set(emps_sel))]
        emps_options_base = emps_base
    else:
        emps_base = [str(e).strip() for e in (deps.resolver_emp_scope_para_usuario(vendedor_logado, role_l, emp_usuario) or []) if str(e).strip()]
        emps_base = list(dict.fromkeys(sorted(emps_base)))
        if emps_sel:
            wanted = {str(x).strip() for x in emps_sel}
            emps_scope = [e for e in emps_base if e in wanted]
        else:
            emps_scope = emps_base[:]
        emps_options_base = emps_base

    # Visão operacional: por padrão exibe apenas EMPs ainda abertas na competência.
    try:
        with deps.SessionLocal() as db_status:
            fechamento_status_map = get_fechamento_status_map(db_status, ano, mes)
    except Exception:
        fechamento_status_map = {}
    emps_scope = filter_emps_by_status(emps_scope, status_visao, fechamento_status_map)

    emps_options = deps.get_emp_options(emps_options_base)

    # Mapa value -> label (para exibir nome da EMP)
    emp_label_map: dict[str, str] = {}
    for o in (emps_options or []):
        try:
            emp_label_map[str(o.get("value"))] = str(o.get("label") or o.get("value") or "")
        except Exception:
            pass

    # ===== Vendedores por EMP (para hierarquia EMP → Vendedor) =====
    vendedores_por_emp: dict[str, list[str]] = {}
    for emp in (emps_scope or []):
        emp_s = str(emp).strip()
        if not emp_s:
            continue

        if role_l in ("admin", "supervisor", "financeiro"):
            vendedores_emp = deps.get_vendedores_emp_no_periodo(emp_s, ano, mes)
            vendedores_emp = [str(v).strip().upper() for v in (vendedores_emp or []) if str(v).strip()]
            if vendedores_sel and "__ALL__" not in set(vendedores_sel):
                allowed = set(vendedores_emp)
                vendedores_emp = [v for v in vendedores_sel if v in allowed]
        else:
            vendedores_emp = [str(vendedor_logado or "").strip().upper()] if vendedor_logado else []
            if vendedores_sel and vendedores_emp:
                if vendedores_emp[0] not in set(vendedores_sel):
                    vendedores_emp = []

        vendedores_por_emp[emp_s] = vendedores_emp

    # ===== Calcula snapshots e monta estrutura EMP -> Vendedores -> Campanhas =====
    emps_data: list[dict[str, Any]] = []
    total_recompensa = 0.0
    total_potencial = 0.0
    total_bloqueado_emp = 0.0
    total_campanhas = 0

    with deps.SessionLocal() as db:
        for emp in (emps_scope or []):
            emp = str(emp).strip()
            if not emp:
                continue

            vendedores_emp = vendedores_por_emp.get(emp) or []
            campanhas = deps.campanhas_mes_overlap(ano, mes, emp) if vendedores_emp else []

            vendedores_rows: list[dict[str, Any]] = []
            emp_total = 0.0
            emp_potencial = 0.0
            emp_bloqueado_emp = 0.0
            emp_faturamento_refs: list[dict[str, Any]] = []

            for vend in (vendedores_emp or []):
                vend = (vend or "").strip().upper()
                if not vend:
                    continue

                # Prioridade por chave (campo_match + prefixo + marca)
                by_key: dict[tuple[str, str, str], Any] = {}
                for c in (campanhas or []):
                    campo_match = (getattr(c, "campo_match", None) or "codigo").strip().lower()
                    if campo_match == "descricao":
                        pref = (getattr(c, "descricao_prefixo", "") or "").strip() or (getattr(c, "produto_prefixo", "") or "").strip()
                        key = ("descricao", pref.lower().strip(), (getattr(c, "marca", "") or "").strip().upper())
                    else:
                        key = ("codigo", (getattr(c, "produto_prefixo", "") or "").strip().upper(), (getattr(c, "marca", "") or "").strip().upper())

                    if getattr(c, "vendedor", None) and str(getattr(c, "vendedor") or "").strip().upper() == vend:
                        by_key[key] = c
                    else:
                        by_key.setdefault(key, c)

                campanhas_final = list(by_key.values())

                resultados_calc: list[Any] = []
                vend_total = 0.0
                vend_potencial = 0.0
                vend_bloqueado_emp = 0.0

                for c in campanhas_final:
                    periodo_ini = max(getattr(c, "data_inicio"), inicio_mes)
                    periodo_fim = min(getattr(c, "data_fim"), fim_mes)
                    res = deps.upsert_resultado(db, c, vend, emp, ano, mes, periodo_ini, periodo_fim)
                    resultados_calc.append(res)
                    valor_liberado = float(getattr(res, "valor_recompensa", 0.0) or 0.0)
                    premio_pot = float(getattr(res, "premio_potencial", None) if getattr(res, "premio_potencial", None) is not None else valor_liberado)
                    bloqueado_emp = bool(int(getattr(res, "bloqueado_faturamento_emp", 0) or 0))
                    vend_total += valor_liberado
                    vend_potencial += premio_pot
                    if bloqueado_emp:
                        vend_bloqueado_emp += max(0.0, premio_pot - valor_liberado)
                        emp_faturamento_refs.append({
                            "campanha": getattr(res, "titulo", None) or f"Campanha #{getattr(res, 'campanha_id', '')}",
                            "minimo": float(getattr(res, "faturamento_minimo_emp", 0.0) or 0.0),
                            "atual": float(getattr(res, "faturamento_emp", 0.0) or 0.0),
                            "faltante": float(getattr(res, "faltante_faturamento_emp", 0.0) or 0.0),
                            "potencial": premio_pot,
                        })

                # Integração oficial: Metas entram na página /campanhas junto das campanhas.
                # Mostramos também metas zeradas para o vendedor acompanhar o que falta atingir,
                # mas somente valores positivos entram no total de recompensa.
                metas_cards = _build_meta_cards_for_vendedor(db, ano=ano, mes=mes, emp=emp, vendedor=vend, incluir_zeradas=True)
                for meta_card in metas_cards:
                    resultados_calc.append(meta_card)
                    meta_valor = float(getattr(meta_card, "valor_recompensa", 0.0) or 0.0)
                    vend_total += meta_valor
                    vend_potencial += meta_valor

                resultados_calc.sort(key=lambda r: (0 if str(getattr(r, "tipo", "") or "").upper() == "META" else 1, -float(getattr(r, "valor_recompensa", 0.0) or 0.0), str(getattr(r, "titulo", "") or getattr(r, "nome", "") or "")))

                total_campanhas += len(resultados_calc)
                total_recompensa += vend_total
                total_potencial += vend_potencial
                total_bloqueado_emp += vend_bloqueado_emp
                emp_total += vend_total
                emp_potencial += vend_potencial
                emp_bloqueado_emp += vend_bloqueado_emp

                vendedores_rows.append({
                    "vendedor": vend,
                    "total_recompensa": vend_total,
                    "total_potencial": vend_potencial,
                    "total_bloqueado_emp": vend_bloqueado_emp,
                    "resultados": resultados_calc,
                    "campanhas": resultados_calc,
                })

            vendedores_rows.sort(key=lambda x: float(x.get("total_recompensa", 0.0) or 0.0), reverse=True)

            emps_data.append({
                "emp": emp,
                "emp_label": emp_label_map.get(emp, emp),
                "emp_total": emp_total,
                "total_recompensa": emp_total,
                "total_potencial": emp_potencial,
                "total_bloqueado_emp": emp_bloqueado_emp,
                "faturamento_refs": emp_faturamento_refs,
                "vendedores": vendedores_rows,
            })

        db.commit()

    emps_data.sort(key=lambda e: float(e.get("emp_total", 0.0) or 0.0), reverse=True)

    # Checklist de vendedores (value/label)
    vendedores_options: list[dict[str, str]] = []
    for v in (vendedores_dropdown or []):
        vv = (v or "").strip().upper()
        if vv:
            vendedores_options.append({"value": vv, "label": vv})

    return {
        "role": role,
        "ano": ano,
        "mes": mes,
        "visao": visao,
        "status_visao": status_visao,
        "status_label": status_filter_label(status_visao),
        "por_pagina": por_pagina,

        "emps_scope": emps_scope,
        "emps_sel": emps_sel,
        "emps_options": emps_options,

        "vendedores_sel": vendedores_sel,
        "vendedores_options": vendedores_options,

        "emps_data": emps_data,
        "total_recompensa": float(total_recompensa or 0.0),
        "total_potencial": float(total_potencial or 0.0),
        "total_bloqueado_emp": float(total_bloqueado_emp or 0.0),
        "total_campanhas": int(total_campanhas or 0),
    }


def build_relatorio_campanhas_scope(
    deps: CampanhasDeps,
    *,
    role: str,
    emp_usuario: str | None,
    vendedor_logado: str,
    args: Any,
    flash: Callable[[str, str], None],
) -> dict[str, Any]:
    """Centraliza definição de escopo (EMPs + vendedores_por_emp) do /relatorios/campanhas.

    Este patch NÃO reescreve a montagem do template ainda; apenas garante que
    todas as rotas usem a mesma regra de escopo antes de recalcular e carregar.
    """

    role_l = (role or "").strip().lower()
    hoje = date.today()
    mes = int(args.get("mes") or hoje.month)
    ano = int(args.get("ano") or hoje.year)

    emps_sel = [str(e).strip() for e in deps.parse_multi_args(args, "emp") if str(e).strip()]
    vendedores_sel = [str(v).strip().upper() for v in deps.parse_multi_args(args, "vendedor") if str(v).strip()]

    emps_scope: list[str] = []
    vendedores_por_emp: dict[str, list[str]] = {}

    if role_l == "admin":
        emps_scope = deps.get_emps_com_vendas_no_periodo(ano, mes)
        # emps_sel é apenas filtro; não deve reduzir emps_scope (senão some do dropdown)
    elif role_l == "supervisor":
        allowed = [str(e).strip() for e in (deps.resolver_emp_scope_para_usuario(vendedor_logado, role_l, emp_usuario) or []) if str(e).strip()]
        allowed = sorted(set(allowed))
        if not allowed:
            flash("Supervisor sem EMP vinculada. Ajuste o vínculo do usuário (usuario_emps).", "warning")
            emps_scope = []
        else:
            if emps_sel:
                pick = [str(e).strip() for e in emps_sel if str(e).strip() in set(allowed)]
                emps_scope = pick if pick else allowed[:]
            else:
                emps_scope = allowed[:]
    else:
        base_emps = [str(e).strip() for e in (deps.get_emps_vendedor(vendedor_logado) or []) if str(e).strip()]
        if not base_emps:
            base_emps = [str(e).strip() for e in (deps.resolver_emp_scope_para_usuario(vendedor_logado, role_l, emp_usuario) or []) if str(e).strip()]
        base_emps = sorted(set(base_emps))
        if emps_sel:
            wanted = {str(x).strip() for x in emps_sel if str(x).strip()}
            emps_scope = [e for e in base_emps if e in wanted]
        else:
            emps_scope = base_emps[:]
        if not emps_scope:
            flash("Não foi possível identificar a EMP do vendedor.", "warning")

    # Vendedores por EMP
    for emp in emps_scope:
        emp = str(emp)
        if role_l == "admin":
            vendedores = deps.get_vendedores_emp_no_periodo(emp, ano, mes)
            if vendedores_sel:
                allowed_set = {v.strip().upper() for v in vendedores}
                pick = [v for v in vendedores_sel if v in allowed_set]
                vendedores = pick if pick else []
        elif role_l == "supervisor":
            vendedores = deps.get_vendedores_emp_no_periodo(emp, ano, mes)
            if vendedores_sel and "__ALL__" not in vendedores_sel:
                allowed_set = {v.strip().upper() for v in vendedores}
                vendedores = [v for v in vendedores_sel if v in allowed_set]
        else:
            vendedores = [vendedor_logado]
        vendedores_por_emp[emp] = vendedores

    return {
        "ano": ano,
        "mes": mes,
        "emps_sel": emps_sel,
        "vendedores_sel": vendedores_sel,
        "emps_scope": emps_scope,
        "vendedores_por_emp": vendedores_por_emp,
    }
