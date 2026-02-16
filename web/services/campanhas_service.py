from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Callable

from services.filter_scope import apply_selected_filter


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
    """Monta o context do template de /campanhas.

    Mantém o mesmo comportamento atual, mas concentra a lógica aqui.
    """

    role_l = (role or "").strip().lower()

    # período
    hoje = date.today()
    mes = int(args.get("mes") or hoje.month)
    ano = int(args.get("ano") or hoje.year)

    vendedores_req = [v.strip().upper() for v in deps.parse_multi_args(args, "vendedor")]

    # Seleção de vendedor conforme perfil
    if role_l == "supervisor":
        if not vendedores_req or "__ALL__" in vendedores_req:
            vendedor_sel = "__ALL__"
            vendedores_sel: list[str] = []
        else:
            vendedor_sel = "__MULTI__" if len(vendedores_req) > 1 else vendedores_req[0]
            vendedores_sel = vendedores_req
    else:
        if role_l == "admin":
            if not vendedores_req or "__ALL__" in vendedores_req:
                vendedor_sel = "__ALL__"
                vendedores_sel = []
            else:
                vendedor_sel = "__MULTI__" if len(vendedores_req) > 1 else vendedores_req[0]
                vendedores_sel = vendedores_req
        else:
            vendedor_sel = vendedor_logado
            vendedores_sel = [vendedor_logado] if vendedor_logado else []

    # EMP scope
    emp_list = deps.parse_multi_args(args, "emp")
    emp_param = (emp_list[0] if (len(emp_list) == 1) else "")
    emps_sel = [str(e).strip() for e in (emp_list or []) if str(e).strip()]

    if role_l == "admin":
        # base_scope: lista completa de EMPs disponíveis dentro do escopo (ex.: por vendedor), antes do filtro de EMP
        if vendedor_sel == "__ALL__":
            base_scope = deps.get_all_emp_codigos(True)
        else:
            base_v = vendedor_sel if vendedor_sel != "__MULTI__" else (vendedores_sel[0] if vendedores_sel else vendedor_logado)
            base_scope = deps.get_emps_vendedor(base_v)

        if emps_sel:
            wanted = {str(x).strip() for x in emps_sel}
            emps_scope = [e for e in base_scope if str(e) in wanted]
        else:
            emps_scope = base_scope
    else:
        base_scope = deps.resolver_emp_scope_para_usuario(vendedor_logado, role_l, emp_usuario)
        if emps_sel:
            wanted = {str(x).strip() for x in emps_sel}
            emps_scope = [e for e in base_scope if str(e) in wanted]
        else:
            emps_scope = base_scope

    inicio_mes, fim_mes = deps.periodo_bounds(ano, mes)

    try:
        vendedores_dropdown = deps.get_vendedores_db(role_l, emp_usuario)
    except Exception:
        vendedores_dropdown = []

    # Calcula resultados e agrupa por EMP
    blocos: list[dict[str, Any]] = []
    with deps.SessionLocal() as db:
        if (vendedor_sel or "").upper() == "__ALL__":
            vendedores_alvo = ["__ALL__"]
        elif (vendedor_sel or "").upper() == "__MULTI__":
            vendedores_alvo = [v for v in (vendedores_sel or []) if (v or "").strip().upper() != "__ALL__"]
        else:
            vendedores_alvo = [vendedor_sel]

        for emp in emps_scope or ([emp_param] if emp_param else []):
            emp = str(emp)
            campanhas = deps.campanhas_mes_overlap(ano, mes, emp)

            for vend in vendedores_alvo:
                vend = (vend or "").strip().upper()
                if not vend:
                    continue

                # prioridade por chave (campo_match + prefixo + marca)
                by_key: dict[tuple[str, str, str], Any] = {}
                for c in campanhas:
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

                total_recomp = 0.0
                resultados_calc: list[Any] = []
                for c in campanhas_final:
                    periodo_ini = max(getattr(c, "data_inicio"), inicio_mes)
                    periodo_fim = min(getattr(c, "data_fim"), fim_mes)
                    if (vend or "").upper() == "__ALL__":
                        res = deps.calc_resultado_all_vendedores(db, c, emp, ano, mes, periodo_ini, periodo_fim)
                    else:
                        res = deps.upsert_resultado(db, c, vend, emp, ano, mes, periodo_ini, periodo_fim)
                    resultados_calc.append(res)
                    total_recomp += float(getattr(res, "valor_recompensa", 0.0) or 0.0)

                resultados_calc.sort(key=lambda r: float(getattr(r, "valor_recompensa", 0.0) or 0.0), reverse=True)

                blocos.append({
                    "emp": emp,
                    "vendedor": vend,
                    "resultados": resultados_calc,
                    "total": total_recomp,
                })

        db.commit()

    emps_options = deps.get_emp_options(base_scope if 'base_scope' in locals() else emps_scope)
    vendedores_options: list[dict[str, str]] = []
    for v in (vendedores_dropdown or []):
        vv = (v or "").strip().upper()
        if vv:
            vendedores_options.append({"value": vv, "label": vv})

    vendedor_display = (
        ("LOJA TODA" if role_l == "supervisor" else "TODOS VENDEDORES")
        if (vendedor_sel or "").upper() == "__ALL__"
        else (f"{len(vendedores_sel)} selecionados" if (vendedor_sel or "").upper() == "__MULTI__" else vendedor_sel)
    )

    return {
        "role": role,
        "ano": ano,
        "mes": mes,
        "vendedor": vendedor_sel,
        "vendedor_display": vendedor_display,
        "vendedor_logado": vendedor_logado,
        "vendedores": vendedores_dropdown,
        "vendedores_options": vendedores_options,
        "vendedores_sel": vendedores_sel,
        "blocos": blocos,
        "emps_scope": emps_scope,
        "emps_options": emps_options,
        "emps_sel": emps_sel,
        "emp_param": emp_param,
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

    # emps_base: lista completa para dropdown (NUNCA deve encolher após filtro)
    # emps_scope: lista efetiva para consulta/cálculo (pode ser filtrada)
    emps_base: list[str] = []
    emps_scope: list[str] = []
    vendedores_por_emp: dict[str, list[str]] = {}
    vendedores_base_por_emp: dict[str, list[str]] = {}

    if role_l == "admin":
        # ADMIN: base = todas EMPs com vendas no período (fallback: cadastro de EMPs)
        emps_base = deps.get_emps_com_vendas_no_periodo(ano, mes) or []
        if not emps_base:
            try:
                emps_base = deps.get_all_emp_codigos(True) or []
            except Exception:
                emps_base = []

        emps_base, emps_scope = apply_selected_filter(emps_base, emps_sel)
    elif role_l == "supervisor":
        allowed = [str(e).strip() for e in (deps.resolver_emp_scope_para_usuario(vendedor_logado, role_l, emp_usuario) or []) if str(e).strip()]
        allowed = sorted(set(allowed))
        if not allowed:
            flash("Supervisor sem EMP vinculada. Ajuste o vínculo do usuário (usuario_emps).", "warning")
            emps_base = []
            emps_scope = []
        else:
            emps_base = allowed[:]
            # supervisor pode filtrar EMPs dentro do escopo permitido
            emps_base, emps_scope = apply_selected_filter(emps_base, emps_sel)
    else:
        base_emps = [str(e).strip() for e in (deps.get_emps_vendedor(vendedor_logado) or []) if str(e).strip()]
        if not base_emps:
            base_emps = [str(e).strip() for e in (deps.resolver_emp_scope_para_usuario(vendedor_logado, role_l, emp_usuario) or []) if str(e).strip()]
        base_emps = sorted(set(base_emps))
        emps_base = base_emps[:]
        emps_base, emps_scope = apply_selected_filter(emps_base, emps_sel)
        if not emps_scope:
            flash("Não foi possível identificar a EMP do vendedor.", "warning")

    # Vendedores por EMP
    for emp in emps_scope:
        emp = str(emp)

        if role_l == "admin":
            # lista base (para dropdown) = todos vendedores da EMP no período
            vendedores_all = deps.get_vendedores_emp_no_periodo(emp, ano, mes) or []
            vendedores_all = [str(v).strip().upper() for v in vendedores_all if str(v).strip()]
            vendedores_base_por_emp[emp] = vendedores_all

            # scope (para cálculo) pode ser filtrado
            vendedores = vendedores_all
            if vendedores_sel and "__ALL__" not in vendedores_sel:
                allowed_set = set(vendedores_all)
                pick = [v for v in vendedores_sel if v in allowed_set]
                vendedores = pick if pick else []

        elif role_l == "supervisor":
            vendedores_all = deps.get_vendedores_emp_no_periodo(emp, ano, mes) or []
            vendedores_all = [str(v).strip().upper() for v in vendedores_all if str(v).strip()]
            vendedores_base_por_emp[emp] = vendedores_all

            vendedores = vendedores_all
            if vendedores_sel and "__ALL__" not in vendedores_sel:
                allowed_set = set(vendedores_all)
                vendedores = [v for v in vendedores_sel if v in allowed_set]

        else:
            vendedores_base_por_emp[emp] = [vendedor_logado] if vendedor_logado else []
            vendedores = [vendedor_logado]

        vendedores_por_emp[emp] = vendedores

    return {
        "ano": ano,
        "mes": mes,
        "emps_sel": emps_sel,
        "vendedores_sel": vendedores_sel,
        "emps_base": emps_base,
        "emps_scope": emps_scope,
        "vendedores_por_emp": vendedores_por_emp,
        "vendedores_base_por_emp": vendedores_base_por_emp,
    }
