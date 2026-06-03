-- Patch: Margem mínima individual por vendedor na Meta Crescimento
-- Seguro para rodar mais de uma vez no Supabase.

-- A margem atual importada continua em metas_margens_vendedores.
-- A margem mínima exigida por exceção individual fica em metas_bases_manuais.margem_percentual.
-- Se este campo estiver NULL/0, o sistema usa metas_programas.margem_minima como margem padrão da meta.

ALTER TABLE public.metas_programas
  ADD COLUMN IF NOT EXISTS margem_minima double precision;

ALTER TABLE public.metas_bases_manuais
  ADD COLUMN IF NOT EXISTS margem_percentual double precision;

ALTER TABLE public.metas_resultados
  ADD COLUMN IF NOT EXISTS margem_percentual double precision;

ALTER TABLE public.metas_resultados
  ADD COLUMN IF NOT EXISTS margem_minima double precision;

ALTER TABLE public.metas_resultados
  ADD COLUMN IF NOT EXISTS margem_atingida boolean;

ALTER TABLE public.metas_resultados
  ADD COLUMN IF NOT EXISTS bloqueado_margem boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS ix_metas_bases_meta_emp_vendedor
  ON public.metas_bases_manuais (meta_id, emp, vendedor);
