from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Callable
from services.campanhas_v2_service import list_resultados_v2


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

                for c in campanhas_final:
                    periodo_ini = max(getattr(c, "data_inicio"), inicio_mes)
                    periodo_fim = min(getattr(c, "data_fim"), fim_mes)
                    res = deps.upsert_resultado(db, c, vend, emp, ano, mes, periodo_ini, periodo_fim)
                    resultados_calc.append(res)
                    vend_total += float(getattr(res, "valor_recompensa", 0.0) or 0.0)

                resultados_calc.sort(key=lambda r: float(getattr(r, "valor_recompensa", 0.0) or 0.0), reverse=True)

                total_campanhas += len(resultados_calc)
                total_recompensa += vend_total
                emp_total += vend_total

                vendedores_rows.append({
                    "vendedor": vend,
                    "total_recompensa": vend_total,
                    "resultados": resultados_calc,
                })

            vendedores_rows.sort(key=lambda x: float(x.get("total_recompensa", 0.0) or 0.0), reverse=True)

            emps_data.append({
                "emp": emp,
                "emp_label": emp_label_map.get(emp, emp),
                "emp_total": emp_total,
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
        "por_pagina": por_pagina,

        "emps_scope": emps_scope,
        "emps_sel": emps_sel,
        "emps_options": emps_options,

        "vendedores_sel": vendedores_sel,
        "vendedores_options": vendedores_options,

        "emps_data": emps_data,
        "total_recompensa": float(total_recompensa or 0.0),
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
