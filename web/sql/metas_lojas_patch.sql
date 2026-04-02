-- Patch opcional para banco já existente.
-- O sistema também tenta aplicar isso automaticamente em criar_tabelas().

ALTER TABLE IF EXISTS metas_programas ADD COLUMN IF NOT EXISTS escopo varchar(20) NOT NULL DEFAULT 'VENDEDOR';
ALTER TABLE IF EXISTS metas_programas ADD COLUMN IF NOT EXISTS faturamento_minimo double precision;
ALTER TABLE IF EXISTS metas_programas ADD COLUMN IF NOT EXISTS margem_minima double precision;
ALTER TABLE IF EXISTS metas_programas ADD COLUMN IF NOT EXISTS teto_faturamento double precision;
ALTER TABLE IF EXISTS metas_programas ADD COLUMN IF NOT EXISTS teto_bonus_percentual double precision;

ALTER TABLE IF EXISTS metas_bases_manuais ADD COLUMN IF NOT EXISTS margem_percentual double precision;
ALTER TABLE IF EXISTS metas_bases_manuais ADD COLUMN IF NOT EXISTS bonus_extra_percentual double precision;
