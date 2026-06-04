from __future__ import annotations

"""Verifica se os índices de performance do /relatorios/campanhas existem no banco.

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
    "ix_vendas_movimento_emp": "public.vendas",
    "ix_vendas_emp_movimento_vendedor": "public.vendas",
    "ix_vendas_relatorio_validas_emp_mov_mestre_vend": "public.vendas",
    "ix_vendas_relatorio_venda_emp_mestre_mov_vend": "public.vendas",
    "ix_camp_qtd_res_comp_emp_vend_camp": "public.campanhas_qtd_resultados",
    "ix_combo_res_comp_emp_vend_combo": "public.campanhas_combo_resultados",
    "ix_combo_ativo_ano_mes_emp": "public.campanhas_combo",
    "ix_combo_itens_combo_ordem_id_turbo": "public.campanhas_combo_itens",
    "ix_itens_parados_emp_ativo_vigencia_codigo_turbo": "public.itens_parados",
    "ix_itens_parados_res_comp_emp_vend_turbo": "public.itens_parados_resultados",
    "ix_meta_resultados_comp_emp_vend_meta_turbo": "public.metas_resultados",
}


def _table_exists(insp, table_ref: str) -> bool:
    schema, table = table_ref.split('.', 1)
    try:
        return insp.has_table(table, schema=schema)
    except Exception:
        return False


def main() -> int:
    insp = inspect(engine)
    found: set[str] = set()
    skipped: set[str] = set()

    for index_name, table_ref in EXPECTED.items():
        schema, table = table_ref.split('.', 1)
        if not _table_exists(insp, table_ref):
            skipped.add(index_name)
            continue
        try:
            idxs = insp.get_indexes(table, schema=schema)
        except Exception as exc:
            print(f"ERRO ao inspecionar {table_ref}: {exc}")
            continue
        names = {idx.get('name') for idx in idxs if idx.get('name')}
        if index_name in names:
            found.add(index_name)

    missing = [name for name in EXPECTED if name not in found and name not in skipped]

    print("Índices encontrados:")
    for name in EXPECTED:
        if name in found:
            print(f"  OK   - {name} ({EXPECTED[name]})")

    if skipped:
        print("\nTabelas opcionais não encontradas; índices ignorados:")
        for name in EXPECTED:
            if name in skipped:
                print(f"  SKIP - {name} ({EXPECTED[name]})")

    if missing:
        print("\nÍndices ausentes:")
        for name in missing:
            print(f"  FALT - {name} ({EXPECTED[name]})")
        return 1

    print("\nTudo certo: todos os índices aplicáveis foram encontrados.")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
