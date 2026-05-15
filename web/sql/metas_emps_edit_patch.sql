-- Patch: edição de EMPs em metas ativas + faturamento mínimo padrão
-- Seguro para rodar mais de uma vez no Supabase.

ALTER TABLE metas_programas
  ADD COLUMN IF NOT EXISTS faturamento_minimo DOUBLE PRECISION;

ALTER TABLE metas_programas
  ALTER COLUMN faturamento_minimo SET DEFAULT 70000;

UPDATE metas_programas
   SET faturamento_minimo = 70000
 WHERE faturamento_minimo IS NULL;

ALTER TABLE metas_programas_emps
  ADD COLUMN IF NOT EXISTS ativo BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE metas_programas_emps
  ADD COLUMN IF NOT EXISTS criado_em TIMESTAMP NOT NULL DEFAULT NOW();

ALTER TABLE metas_programas_emps
  ADD COLUMN IF NOT EXISTS atualizado_em TIMESTAMP;

ALTER TABLE metas_programas_emps
  ADD COLUMN IF NOT EXISTS removido_em TIMESTAMP;

UPDATE metas_programas_emps
   SET ativo = TRUE
 WHERE ativo IS NULL;

CREATE INDEX IF NOT EXISTS ix_metas_programas_emps_ativo
    ON metas_programas_emps (meta_id, ativo, emp);
