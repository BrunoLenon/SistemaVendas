-- Relatórios / Campanhas — Recálculo em background + índices de performance
-- Data: 2026-06-30
-- Execute no SQL Editor do Supabase, preferencialmente fora do pico.
-- Observação: os índices em vendas usam CONCURRENTLY para reduzir bloqueios.

-- 1) Vendas válidas do relatório: acelera recálculo QTD/COMBO/participação ativa
-- e a trava de faturamento mínimo da EMP.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_vendas_relcamp_validas_emp_mov_vend_mestre_marca
ON public.vendas (emp, movimento, vendedor, mestre, marca)
WHERE upper(coalesce(mov_tipo_movto, '')) IN ('OA', 'OV', 'SV', 'VA', 'VV')
  AND coalesce(qtdade_vendida, 0) > 0;

-- 2) Faturamento total da loja por período: usado pela trava de faturamento mínimo.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_vendas_relcamp_faturamento_emp_mov
ON public.vendas (emp, movimento)
WHERE upper(coalesce(mov_tipo_movto, '')) IN ('OA', 'OV', 'SV', 'VA', 'VV')
  AND coalesce(qtdade_vendida, 0) > 0;

-- 3) Busca por descrição em campanhas por descrição/combo.
-- Requer pg_trgm, normalmente disponível no Supabase.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_vendas_relcamp_desc_trgm_validas
ON public.vendas USING gin (lower(coalesce(descricao_norm, descricao, '')) gin_trgm_ops)
WHERE upper(coalesce(mov_tipo_movto, '')) IN ('OA', 'OV', 'SV', 'VA', 'VV')
  AND coalesce(qtdade_vendida, 0) > 0;

-- 4) Campanhas QTD/GERENTE ativas por EMP e período.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_campanhas_qtd_relcamp_ativo_emp_periodo_tipo
ON public.campanhas_qtd (emp, ativo, data_inicio, data_fim, campanha_tipo, vendedor);

-- 5) Snapshots mais lidos pelo relatório.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_camp_qtd_res_relcamp_comp_emp_vend_camp
ON public.campanhas_qtd_resultados (competencia_ano, competencia_mes, emp, vendedor, campanha_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_combo_res_relcamp_comp_emp_vend_combo
ON public.campanhas_combo_resultados (competencia_ano, competencia_mes, emp, vendedor, combo_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_itens_parados_res_relcamp_comp_emp_vend_item
ON public.itens_parados_resultados (competencia_ano, competencia_mes, emp, vendedor, item_parado_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_metas_resultados_relcamp_comp_emp_vend_meta
ON public.metas_resultados (ano, mes, emp, vendedor, meta_id);

-- Atualiza estatísticas do planner após criar índices/importações grandes.
ANALYZE public.vendas;
ANALYZE public.campanhas_qtd;
ANALYZE public.campanhas_qtd_resultados;
ANALYZE public.campanhas_combo_resultados;
ANALYZE public.itens_parados_resultados;
ANALYZE public.metas_resultados;
