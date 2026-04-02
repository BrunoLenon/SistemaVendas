ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS escopo varchar(20) NOT NULL DEFAULT 'VENDEDOR';
ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS faturamento_minimo double precision;
ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS margem_minima double precision;
ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS teto_faturamento double precision;
ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS teto_bonus_percentual double precision;

ALTER TABLE metas_bases_manuais ADD COLUMN IF NOT EXISTS margem_percentual double precision;
ALTER TABLE metas_bases_manuais ADD COLUMN IF NOT EXISTS bonus_extra_percentual double precision;
