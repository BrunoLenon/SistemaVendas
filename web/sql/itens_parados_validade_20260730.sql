-- SistemaVendas - Validade dos produtos da ação de Itens Parados
-- Execute no Supabase antes do deploy.
--
-- A validade é inclusiva:
--   DATA_INICIO <= data da venda <= DATA_FIM
-- Produtos sem as duas datas não geram pontos até que a validade seja definida.

ALTER TABLE IF EXISTS public.itens_parados
    ADD COLUMN IF NOT EXISTS data_inicio DATE,
    ADD COLUMN IF NOT EXISTS data_fim DATE;

CREATE INDEX IF NOT EXISTS ix_itens_parados_emp_codigo_validade
    ON public.itens_parados (emp, codigo, ativo, data_inicio, data_fim);

COMMENT ON COLUMN public.itens_parados.data_inicio IS
    'Primeiro dia, inclusive, em que as vendas do produto geram pontos na EMP.';
COMMENT ON COLUMN public.itens_parados.data_fim IS
    'Último dia, inclusive, em que as vendas do produto geram pontos na EMP.';
