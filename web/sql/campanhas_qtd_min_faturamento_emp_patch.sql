-- HOTFIX: Campanhas QTD - faturamento mínimo por EMP
-- Rode uma vez no Supabase SQL Editor.
-- Seguro para rodar mais de uma vez por usar IF NOT EXISTS.

ALTER TABLE public.campanhas_qtd
  ADD COLUMN IF NOT EXISTS faturamento_minimo_emp double precision;

ALTER TABLE public.campanhas_qtd_resultados
  ADD COLUMN IF NOT EXISTS premio_potencial double precision;

ALTER TABLE public.campanhas_qtd_resultados
  ADD COLUMN IF NOT EXISTS faturamento_minimo_emp double precision;

ALTER TABLE public.campanhas_qtd_resultados
  ADD COLUMN IF NOT EXISTS faturamento_emp double precision;

ALTER TABLE public.campanhas_qtd_resultados
  ADD COLUMN IF NOT EXISTS faltante_faturamento_emp double precision;

ALTER TABLE public.campanhas_qtd_resultados
  ADD COLUMN IF NOT EXISTS bloqueado_faturamento_emp integer NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS ix_campanhas_qtd_resultados_bloq_emp
  ON public.campanhas_qtd_resultados (competencia_ano, competencia_mes, emp, bloqueado_faturamento_emp);
