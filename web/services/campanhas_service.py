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
