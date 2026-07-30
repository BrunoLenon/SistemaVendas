-- SistemaVendas - Itens Parados por pontos inteiros
-- Execute no Supabase antes do deploy.
--
-- Regra:
--   pontos = FLOOR(valor_liquido_elegivel / base_reais)
--   bonus  = pontos * valor_por_ponto
--
-- O faturamento elegível e o bônus ficam separados. Registros históricos já
-- importados não são convertidos automaticamente; reimporte a competência para
-- gerar os pontos e o bônus com a nova regra.

CREATE TABLE IF NOT EXISTS public.itens_parados_pontos_config (
    id BIGSERIAL PRIMARY KEY,
    emp VARCHAR(30),
    base_reais NUMERIC(18,4) NOT NULL DEFAULT 100,
    valor_por_ponto NUMERIC(18,4) NOT NULL DEFAULT 10,
    ativo BOOLEAN NOT NULL DEFAULT TRUE,
    criado_em TIMESTAMP NOT NULL DEFAULT NOW(),
    atualizado_em TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_cfg_emp
    ON public.itens_parados_pontos_config (emp);

INSERT INTO public.itens_parados_pontos_config
    (emp, base_reais, valor_por_ponto, ativo)
SELECT NULL, 100, 10, TRUE
WHERE NOT EXISTS (
    SELECT 1
    FROM public.itens_parados_pontos_config
    WHERE emp IS NULL
      AND ativo IS TRUE
);

ALTER TABLE IF EXISTS public.itens_parados_vendas_importacoes
    ADD COLUMN IF NOT EXISTS pontos_total INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS bonus_total NUMERIC(18,4) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS linhas_nao_elegiveis INTEGER NOT NULL DEFAULT 0;

ALTER TABLE IF EXISTS public.itens_parados_vendas_usuarios
    ADD COLUMN IF NOT EXISTS pontos INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS base_reais NUMERIC(18,4) NOT NULL DEFAULT 100,
    ADD COLUMN IF NOT EXISTS valor_por_ponto NUMERIC(18,4) NOT NULL DEFAULT 10,
    ADD COLUMN IF NOT EXISTS bonus_total NUMERIC(18,4) NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS ix_itens_parados_vendas_bonus_periodo
    ON public.itens_parados_vendas_usuarios (ano, mes, emp, bonus_total);

ALTER TABLE public.itens_parados_pontos_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.itens_parados_vendas_importacoes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.itens_parados_vendas_usuarios ENABLE ROW LEVEL SECURITY;

COMMENT ON COLUMN public.itens_parados_vendas_usuarios.valor_total IS
    'Valor liquido vendido somente dos produtos ativos da acao na mesma EMP.';
COMMENT ON COLUMN public.itens_parados_vendas_usuarios.pontos IS
    'Quantidade inteira de pontos: FLOOR(valor_total / base_reais).';
COMMENT ON COLUMN public.itens_parados_vendas_usuarios.bonus_total IS
    'Valor financeiro liberado por itens parados: pontos * valor_por_ponto.';
