-- Pós-check da Fase 3 — confirme se os índices existem e se o planner já os vê

SELECT schemaname, tablename, indexname
FROM pg_indexes
WHERE schemaname = 'public'
  AND indexname IN (
    'ix_vendas_relatorio_ativos_emp_vendedor_mov_mestre',
    'ix_vendas_relatorio_oa_emp_mestre_mov_vendedor',
    'ix_camp_qtd_res_periodo_emp_vendedor_campanha',
    'ix_combo_res_periodo_emp_vendedor_combo',
    'ix_combo_ativo_periodo_emp',
    'ix_combo_ativo_periodo_global',
    'ix_combo_itens_combo_ordem_id',
    'ix_itens_parados_emp_ativo_vigencia_codigo',
    'ix_meta_resultados_periodo_emp_vendedor_meta',
    'ix_camp_v2_result_periodo_emp_vendedor_campanha',
    'ix_fin_pag_periodo_origem_emp_vendedor_origemid'
  )
ORDER BY tablename, indexname;
