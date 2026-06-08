-- Patch: importação assistida de itens parados
-- Adiciona campo opcional de código interno para conferência da planilha.

ALTER TABLE IF EXISTS itens_parados
  ADD COLUMN IF NOT EXISTS interno varchar(120) NULL;

CREATE INDEX IF NOT EXISTS ix_itens_parados_interno
  ON itens_parados(interno);
