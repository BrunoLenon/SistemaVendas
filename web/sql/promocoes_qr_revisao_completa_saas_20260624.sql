-- ============================================================
-- Promoções QR - revisão SaaS / segurança operacional
-- Execute no Supabase somente se quiser garantir o default seguro no banco.
-- A aplicação também executa esse ajuste automaticamente ao abrir o módulo.
-- ============================================================

ALTER TABLE IF EXISTS promocoes_qr_campanhas
    ALTER COLUMN ativo SET DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS ix_promocoes_qr_campanhas_criado
    ON promocoes_qr_campanhas (criado_em DESC, id DESC);

CREATE INDEX IF NOT EXISTS ix_promocoes_qr_codigos_campanha_ativos_lote
    ON promocoes_qr_codigos (campanha_id, lote)
    WHERE excluido_em IS NULL;

CREATE INDEX IF NOT EXISTS ix_promocoes_qr_codigos_campanha_criado
    ON promocoes_qr_codigos (campanha_id, criado_em DESC, id DESC)
    WHERE excluido_em IS NULL;
