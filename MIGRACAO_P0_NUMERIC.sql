-- MIGRACAO P0: tipos NUMERIC para valores (evita distorções de float)
-- Execute no Supabase (SQL Editor) ANTES de subir o novo código no Render.

BEGIN;

-- 1) VENDAS (valores e quantidades)
ALTER TABLE IF EXISTS vendas
  ALTER COLUMN unit TYPE numeric(18,4) USING unit::numeric,
  ALTER COLUMN des TYPE numeric(18,4) USING des::numeric,
  ALTER COLUMN qtdade_vendida TYPE numeric(18,3) USING qtdade_vendida::numeric,
  ALTER COLUMN valor_total TYPE numeric(18,2) USING valor_total::numeric;

-- 2) DASHBOARD CACHE (valores)
ALTER TABLE IF EXISTS dashboard_cache
  ALTER COLUMN valor_bruto TYPE numeric(18,2) USING valor_bruto::numeric,
  ALTER COLUMN valor_liquido TYPE numeric(18,2) USING valor_liquido::numeric,
  ALTER COLUMN devolucoes TYPE numeric(18,2) USING devolucoes::numeric,
  ALTER COLUMN cancelamentos TYPE numeric(18,2) USING cancelamentos::numeric,
  ALTER COLUMN total_liquido_periodo TYPE numeric(18,2) USING total_liquido_periodo::numeric;

-- 3) CAMPANHAS
ALTER TABLE IF EXISTS campanhas_qtd
  ALTER COLUMN recompensa_unit TYPE numeric(18,2) USING recompensa_unit::numeric,
  ALTER COLUMN valor_minimo TYPE numeric(18,2) USING valor_minimo::numeric;

ALTER TABLE IF EXISTS campanhas_qtd_resultados
  ALTER COLUMN recompensa_unit TYPE numeric(18,2) USING recompensa_unit::numeric,
  ALTER COLUMN valor_vendido TYPE numeric(18,2) USING valor_vendido::numeric,
  ALTER COLUMN valor_recompensa TYPE numeric(18,2) USING valor_recompensa::numeric;

-- 4) METAS
ALTER TABLE IF EXISTS metas_bases_manuais
  ALTER COLUMN base_valor TYPE numeric(18,2) USING base_valor::numeric;

ALTER TABLE IF EXISTS metas_resultados
  ALTER COLUMN valor_mes TYPE numeric(18,2) USING valor_mes::numeric,
  ALTER COLUMN base_valor TYPE numeric(18,2) USING base_valor::numeric,
  ALTER COLUMN valor_marcas TYPE numeric(18,2) USING valor_marcas::numeric,
  ALTER COLUMN premio TYPE numeric(18,2) USING premio::numeric;

-- 5) RESUMO PERIODO (ano passado)
ALTER TABLE IF EXISTS vendas_resumo_periodo
  ALTER COLUMN valor_venda TYPE numeric(18,2) USING valor_venda::numeric;

-- Defaults seguros
ALTER TABLE IF EXISTS dashboard_cache
  ALTER COLUMN valor_bruto SET DEFAULT 0,
  ALTER COLUMN valor_liquido SET DEFAULT 0,
  ALTER COLUMN devolucoes SET DEFAULT 0,
  ALTER COLUMN cancelamentos SET DEFAULT 0,
  ALTER COLUMN total_liquido_periodo SET DEFAULT 0;

ALTER TABLE IF EXISTS campanhas_qtd
  ALTER COLUMN recompensa_unit SET DEFAULT 0;

ALTER TABLE IF EXISTS campanhas_qtd_resultados
  ALTER COLUMN recompensa_unit SET DEFAULT 0,
  ALTER COLUMN valor_vendido SET DEFAULT 0,
  ALTER COLUMN valor_recompensa SET DEFAULT 0;

ALTER TABLE IF EXISTS metas_bases_manuais
  ALTER COLUMN base_valor SET DEFAULT 0;

ALTER TABLE IF EXISTS metas_resultados
  ALTER COLUMN valor_mes SET DEFAULT 0,
  ALTER COLUMN bonus_percentual SET DEFAULT 0,
  ALTER COLUMN premio SET DEFAULT 0;

ALTER TABLE IF EXISTS vendas_resumo_periodo
  ALTER COLUMN valor_venda SET DEFAULT 0;

COMMIT;
