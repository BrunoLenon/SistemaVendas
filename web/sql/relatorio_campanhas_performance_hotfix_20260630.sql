-- Hotfix de performance - Relatório de Campanhas / Recálculo
-- Execute no Supabase SQL Editor fora de uma transação explícita.
-- CREATE INDEX CONCURRENTLY evita bloquear escrita/leitura por muito tempo.

-- Vendas: filtros principais usados por competência, EMP, tipo de movimento e vendedor.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_vendas_emp_mov_tipo_vendedor
ON vendas (emp, movimento, mov_tipo_movto, vendedor);

-- Vendas: campanhas por código/mestre com prefixo. Ajuda buscas do tipo mestre LIKE 'ABC%'.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_vendas_emp_mov_mestre_upper_prefix
ON vendas (emp, movimento, (upper(btrim((mestre)::text))) text_pattern_ops);

-- Vendas: campanhas por descrição normalizada com prefixo. Ajuda buscas do tipo descricao_norm LIKE 'abc%'.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_vendas_emp_mov_descricao_norm_prefix
ON vendas (emp, movimento, (lower(btrim(coalesce(descricao_norm, ''::text)))) text_pattern_ops);

-- Vendas: filtro por marca dentro do período/EMP.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_vendas_emp_mov_marca_upper
ON vendas (emp, movimento, (upper(btrim((marca)::text))));

-- Vendas: consolida leitura por vendedor incluindo métricas usadas no relatório.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_vendas_emp_mov_vendedor_metricas
ON vendas (emp, movimento, vendedor)
INCLUDE (valor_total, qtdade_vendida, mov_tipo_movto, mestre, marca);

-- Snapshots do relatório unificado.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_camp_qtd_res_comp_emp_vendedor
ON campanhas_qtd_resultados (competencia_ano, competencia_mes, emp, vendedor);

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_camp_qtd_res_comp_emp_campanha_vendedor
ON campanhas_qtd_resultados (competencia_ano, competencia_mes, emp, campanha_id, vendedor);

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_combo_res_comp_emp_vendedor
ON campanhas_combo_resultados (competencia_ano, competencia_mes, emp, vendedor);

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_itens_parados_res_comp_emp_vendedor
ON itens_parados_resultados (competencia_ano, competencia_mes, emp, vendedor);

CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_metas_resultados_comp_emp_vendedor
ON metas_resultados (ano, mes, emp, vendedor);

-- Estatísticas atualizadas para o planejador escolher os novos índices.
ANALYZE vendas;
ANALYZE campanhas_qtd_resultados;
ANALYZE campanhas_combo_resultados;
ANALYZE itens_parados_resultados;
ANALYZE metas_resultados;
