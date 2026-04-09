from __future__ import annotations

"""Verifica se os índices da Fase 3 do /relatorios/campanhas existem no banco.

Uso:
  python -m web.scripts.check_relatorio_campanhas_indexes

Saída:
  - lista índices encontrados
  - lista índices ausentes
  - retorna código 0 se todos existirem; 1 caso falte algum
"""

from sqlalchemy import inspect

from db import engine

EXPECTED = {
    "ix_vendas_relatorio_ativos_emp_vendedor_mov_mestre": "public.vendas",
    "ix_vendas_relatorio_oa_emp_mestre_mov_vendedor": "public.vendas",
    "ix_camp_qtd_res_periodo_emp_vendedor_campanha": "public.campanhas_qtd_resultados",
    "ix_combo_res_periodo_emp_vendedor_combo": "public.campanhas_combo_resultados",
    "ix_combo_ativo_periodo_emp": "public.campanhas_combo",
    "ix_combo_ativo_periodo_global": "public.campanhas_combo",
    "ix_combo_itens_combo_ordem_id": "public.campanhas_combo_itens",
    "ix_itens_parados_emp_ativo_vigencia_codigo": "public.itens_parados",
    "ix_meta_resultados_periodo_emp_vendedor_meta": "public.metas_resultados",
    "ix_camp_v2_result_periodo_emp_vendedor_campanha": "public.campanhas_v2_resultados",
    "ix_fin_pag_periodo_origem_emp_vendedor_origemid": "public.financeiro_pagamentos",
}


def main() -> int:
    insp = inspect(engine)
    found: set[str] = set()

    for index_name, table_ref in EXPECTED.items():
        _, table = table_ref.split('.', 1)
        try:
            idxs = insp.get_indexes(table, schema='public')
        except Exception as exc:
            print(f"ERRO ao inspecionar {table_ref}: {exc}")
            continue
        names = {idx.get('name') for idx in idxs if idx.get('name')}
        if index_name in names:
            found.add(index_name)

    missing = [name for name in EXPECTED if name not in found]

    print("Índices encontrados:")
    for name in EXPECTED:
        if name in found:
            print(f"  OK   - {name} ({EXPECTED[name]})")

    if missing:
        print("
Índices ausentes:")
        for name in missing:
            print(f"  FALT - {name} ({EXPECTED[name]})")
        return 1

    print("
Tudo certo: todos os índices da Fase 3 foram encontrados.")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
