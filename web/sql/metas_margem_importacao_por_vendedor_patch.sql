-- Patch: importação de margem por vendedor (sem EMP)
-- Seguro para rodar mais de uma vez no Supabase.

-- A coluna emp é mantida por compatibilidade com a tabela atual.
-- Novas importações gravam emp='GERAL' e o cálculo busca por ANO + MES + VENDEDOR.

CREATE INDEX IF NOT EXISTS ix_meta_margem_periodo_vendedor
  ON public.metas_margens_vendedores (ano, mes, vendedor);

CREATE INDEX IF NOT EXISTS ix_meta_margem_importado_em
  ON public.metas_margens_vendedores (importado_em DESC);
