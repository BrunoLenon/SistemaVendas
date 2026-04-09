-- Fase 3 — banco e índices para /relatorios/campanhas
--
-- Objetivo:
-- 1) reduzir tempo de leitura dos snapshots mensais
-- 2) acelerar consultas em vendas usadas por Combo/QTD/Itens Parados
-- 3) preparar a base para Metas / V2 / Financeiro sem recalcular tudo em memória
--
-- Como aplicar:
-- - Execute este arquivo no SQL Editor do Supabase.
-- - Se a tabela public.vendas for muito grande, rode em horário de menor uso.
-- - Depois execute o arquivo relatorio_campanhas_fase3_poscheck.sql para conferir.

BEGIN;

CREATE INDEX IF NOT EXISTS ix_vendas_relatorio_ativos_emp_vendedor_mov_mestre
ON public.vendas (emp, vendedor, movimento, mestre)
WHERE mov_tipo_movto <> 'DS' AND mov_tipo_movto <> 'CA';

CREATE INDEX IF NOT EXISTS ix_vendas_relatorio_oa_emp_mestre_mov_vendedor
ON public.vendas (emp, mestre, movimento, vendedor)
WHERE mov_tipo_movto = 'OA';

CREATE INDEX IF NOT EXISTS ix_camp_qtd_res_periodo_emp_vendedor_campanha
ON public.campanhas_qtd_resultados (competencia_ano, competencia_mes, emp, vendedor, campanha_id);

CREATE INDEX IF NOT EXISTS ix_combo_res_periodo_emp_vendedor_combo
ON public.campanhas_combo_resultados (competencia_ano, competencia_mes, emp, vendedor, combo_id);

CREATE INDEX IF NOT EXISTS ix_combo_ativo_periodo_emp
ON public.campanhas_combo (ano, mes, emp)
WHERE ativo IS TRUE;

CREATE INDEX IF NOT EXISTS ix_combo_ativo_periodo_global
ON public.campanhas_combo (ano, mes)
WHERE ativo IS TRUE AND (emp IS NULL OR emp = '');

CREATE INDEX IF NOT EXISTS ix_combo_itens_combo_ordem_id
ON public.campanhas_combo_itens (combo_id, ordem, id);

CREATE INDEX IF NOT EXISTS ix_itens_parados_emp_ativo_vigencia_codigo
ON public.itens_parados (emp, data_inicio, data_fim, codigo)
WHERE ativo IS TRUE;

CREATE INDEX IF NOT EXISTS ix_meta_resultados_periodo_emp_vendedor_meta
ON public.metas_resultados (ano, mes, emp, vendedor, meta_id);

CREATE INDEX IF NOT EXISTS ix_camp_v2_result_periodo_emp_vendedor_campanha
ON public.campanhas_v2_resultados (ano, mes, emp, vendedor, campanha_id);

CREATE INDEX IF NOT EXISTS ix_fin_pag_periodo_origem_emp_vendedor_origemid
ON public.financeiro_pagamentos (ano, mes, origem_tipo, emp, vendedor, origem_id);

COMMIT;

ANALYZE public.vendas;
ANALYZE public.campanhas_qtd_resultados;
ANALYZE public.campanhas_combo_resultados;
ANALYZE public.campanhas_combo;
ANALYZE public.campanhas_combo_itens;
ANALYZE public.itens_parados;
ANALYZE public.metas_resultados;
ANALYZE public.campanhas_v2_resultados;
ANALYZE public.financeiro_pagamentos;
