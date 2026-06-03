-- Hotfix compatibilidade: campanha GERENTE + margens por vendedor + trava faturamento EMP

ALTER TABLE public.campanhas_qtd
  ADD COLUMN IF NOT EXISTS campanha_tipo varchar(20) NOT NULL DEFAULT 'VENDEDOR',
  ADD COLUMN IF NOT EXISTS faturamento_minimo_emp double precision;

ALTER TABLE public.campanhas_qtd_resultados
  ADD COLUMN IF NOT EXISTS campanha_tipo varchar(20) NOT NULL DEFAULT 'VENDEDOR',
  ADD COLUMN IF NOT EXISTS premio_potencial double precision,
  ADD COLUMN IF NOT EXISTS faturamento_minimo_emp double precision,
  ADD COLUMN IF NOT EXISTS faturamento_emp double precision,
  ADD COLUMN IF NOT EXISTS faltante_faturamento_emp double precision,
  ADD COLUMN IF NOT EXISTS bloqueado_faturamento_emp integer NOT NULL DEFAULT 0;

UPDATE public.campanhas_qtd
SET campanha_tipo = 'VENDEDOR'
WHERE campanha_tipo IS NULL OR campanha_tipo = '';

UPDATE public.campanhas_qtd_resultados
SET campanha_tipo = 'VENDEDOR'
WHERE campanha_tipo IS NULL OR campanha_tipo = '';

CREATE INDEX IF NOT EXISTS ix_campanhas_qtd_tipo
  ON public.campanhas_qtd (campanha_tipo);

CREATE INDEX IF NOT EXISTS ix_campanhas_qtd_resultados_tipo
  ON public.campanhas_qtd_resultados (campanha_tipo);

CREATE INDEX IF NOT EXISTS ix_campanhas_qtd_resultados_bloq_emp
  ON public.campanhas_qtd_resultados (competencia_ano, competencia_mes, emp, bloqueado_faturamento_emp);

ALTER TABLE public.metas_programas
  ADD COLUMN IF NOT EXISTS margem_minima double precision;

ALTER TABLE public.metas_bases_manuais
  ADD COLUMN IF NOT EXISTS margem_percentual double precision,
  ADD COLUMN IF NOT EXISTS bonus_extra_percentual double precision,
  ADD COLUMN IF NOT EXISTS observacao varchar(200);

CREATE TABLE IF NOT EXISTS public.metas_margens_vendedores (
  id SERIAL PRIMARY KEY,
  ano integer NOT NULL,
  mes integer NOT NULL,
  emp varchar(30) NOT NULL DEFAULT 'GERAL',
  vendedor varchar(80) NOT NULL,
  margem_percentual double precision NOT NULL DEFAULT 0,
  observacao varchar(240),
  arquivo_origem varchar(255),
  importado_por varchar(80),
  importado_em timestamp NOT NULL DEFAULT now(),
  CONSTRAINT uq_meta_margem_vendedor_periodo UNIQUE (ano, mes, emp, vendedor)
);

CREATE INDEX IF NOT EXISTS ix_meta_margem_emp_periodo
  ON public.metas_margens_vendedores (emp, ano, mes);

CREATE INDEX IF NOT EXISTS ix_meta_margem_vendedor_periodo
  ON public.metas_margens_vendedores (vendedor, ano, mes);

CREATE INDEX IF NOT EXISTS ix_meta_margem_periodo_vendedor
  ON public.metas_margens_vendedores (ano, mes, vendedor);

ALTER TABLE public.metas_resultados
  ADD COLUMN IF NOT EXISTS margem_percentual double precision,
  ADD COLUMN IF NOT EXISTS margem_minima double precision,
  ADD COLUMN IF NOT EXISTS margem_atingida boolean,
  ADD COLUMN IF NOT EXISTS bloqueado_margem boolean NOT NULL DEFAULT false;
