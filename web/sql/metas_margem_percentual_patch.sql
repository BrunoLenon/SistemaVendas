-- Patch: Margem percentual para Meta Crescimento
-- Seguro para rodar mais de uma vez no Supabase.

ALTER TABLE public.metas_programas
  ADD COLUMN IF NOT EXISTS margem_minima double precision;

CREATE TABLE IF NOT EXISTS public.metas_margens_vendedores (
    id SERIAL PRIMARY KEY,
    ano INTEGER NOT NULL,
    mes INTEGER NOT NULL,
    emp VARCHAR(30) NOT NULL,
    vendedor VARCHAR(80) NOT NULL,
    margem_percentual DOUBLE PRECISION NOT NULL DEFAULT 0,
    observacao VARCHAR(240),
    arquivo_origem VARCHAR(255),
    importado_por VARCHAR(80),
    importado_em TIMESTAMP NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_meta_margem_vendedor_periodo UNIQUE (ano, mes, emp, vendedor)
);

CREATE INDEX IF NOT EXISTS ix_meta_margem_emp_periodo
  ON public.metas_margens_vendedores (emp, ano, mes);

CREATE INDEX IF NOT EXISTS ix_meta_margem_vendedor_periodo
  ON public.metas_margens_vendedores (vendedor, ano, mes);

ALTER TABLE public.metas_resultados
  ADD COLUMN IF NOT EXISTS margem_percentual double precision;

ALTER TABLE public.metas_resultados
  ADD COLUMN IF NOT EXISTS margem_minima double precision;

ALTER TABLE public.metas_resultados
  ADD COLUMN IF NOT EXISTS margem_atingida boolean;

ALTER TABLE public.metas_resultados
  ADD COLUMN IF NOT EXISTS bloqueado_margem boolean NOT NULL DEFAULT false;
