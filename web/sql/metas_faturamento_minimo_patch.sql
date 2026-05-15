-- Patch de segurança para Metas: faturamento mínimo obrigatório.
-- Pode rodar no Supabase sem apagar dados.

ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS faturamento_minimo double precision;
ALTER TABLE metas_programas ALTER COLUMN faturamento_minimo SET DEFAULT 70000;
UPDATE metas_programas
   SET faturamento_minimo = 70000
 WHERE faturamento_minimo IS NULL;
