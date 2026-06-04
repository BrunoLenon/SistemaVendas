-- Relatório de Campanhas — Índices Turbo
-- Execute no SQL Editor do Supabase.
-- Objetivo: acelerar abertura de /relatorios/campanhas, filtros de EMP/vendedor
-- e leitura de snapshots sem alterar regras de cálculo.

-- Distinct de EMPs por período: usado para montar escopo do Admin.
CREATE INDEX IF NOT EXISTS ix_vendas_movimento_emp
ON public.vendas (movimento, emp);

-- Distinct de vendedores por EMP/período e leitura agrupada por EMP.
CREATE INDEX IF NOT EXISTS ix_vendas_emp_movimento_vendedor
ON public.vendas (emp, movimento, vendedor);

-- Leitura mensal de vendas válidas para Combo/QTD/Itens Parados.
CREATE INDEX IF NOT EXISTS ix_vendas_relatorio_validas_emp_mov_mestre_vend
ON public.vendas (emp, movimento, mestre, vendedor)
WHERE mov_tipo_movto <> 'DS' AND mov_tipo_movto <> 'CA';

-- Leitura específica do motor novo de Itens Parados, que usa OA/VV/SV.
CREATE INDEX IF NOT EXISTS ix_vendas_relatorio_venda_emp_mestre_mov_vend
ON public.vendas (emp, mestre, movimento, vendedor)
WHERE upper(coalesce(mov_tipo_movto, '')) IN ('OA', 'VV', 'SV');

-- Snapshot mensal QTD/GERENTE.
CREATE INDEX IF NOT EXISTS ix_camp_qtd_res_comp_emp_vend_camp
ON public.campanhas_qtd_resultados (competencia_ano, competencia_mes, emp, vendedor, campanha_id);

-- Snapshot mensal Combo.
CREATE INDEX IF NOT EXISTS ix_combo_res_comp_emp_vend_combo
ON public.campanhas_combo_resultados (competencia_ano, competencia_mes, emp, vendedor, combo_id);

-- Combo ativo por competência/EMP.
CREATE INDEX IF NOT EXISTS ix_combo_ativo_ano_mes_emp
ON public.campanhas_combo (ano, mes, emp)
WHERE ativo IS TRUE;

-- Itens do combo.
CREATE INDEX IF NOT EXISTS ix_combo_itens_combo_ordem_id_turbo
ON public.campanhas_combo_itens (combo_id, ordem, id);

-- Itens parados ativos por EMP/vigência/código.
CREATE INDEX IF NOT EXISTS ix_itens_parados_emp_ativo_vigencia_codigo_turbo
ON public.itens_parados (emp, data_inicio, data_fim, codigo)
WHERE ativo IS TRUE;

-- Snapshot de itens parados, quando a tabela existir.
DO $$
BEGIN
  IF to_regclass('public.itens_parados_resultados') IS NOT NULL THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS ix_itens_parados_res_comp_emp_vend_turbo ON public.itens_parados_resultados (competencia_ano, competencia_mes, emp, vendedor)';
  END IF;
END $$;

-- Metas integradas ao relatório, quando a tabela existir.
DO $$
BEGIN
  IF to_regclass('public.metas_resultados') IS NOT NULL THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS ix_meta_resultados_comp_emp_vend_meta_turbo ON public.metas_resultados (ano, mes, emp, vendedor, meta_id)';
  END IF;
END $$;

-- Ajuda o planner a escolher plano atualizado depois de índices/importações grandes.
ANALYZE public.vendas;
ANALYZE public.campanhas_qtd_resultados;
ANALYZE public.campanhas_combo_resultados;
ANALYZE public.campanhas_combo;
ANALYZE public.campanhas_combo_itens;
ANALYZE public.itens_parados;
DO $$
BEGIN
  IF to_regclass('public.itens_parados_resultados') IS NOT NULL THEN
    EXECUTE 'ANALYZE public.itens_parados_resultados';
  END IF;
  IF to_regclass('public.metas_resultados') IS NOT NULL THEN
    EXECUTE 'ANALYZE public.metas_resultados';
  END IF;
END $$;
