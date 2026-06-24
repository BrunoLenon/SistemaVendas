-- ============================================================
-- Promoções QR - Exclusão em massa segura/auditável
-- Execute no SQL Editor do Supabase antes ou depois do deploy.
-- O código também executa essas migrações automaticamente, mas este
-- script antecipa os campos/índices e evita lentidão na primeira abertura.
-- ============================================================

ALTER TABLE IF EXISTS promocoes_qr_codigos
  ADD COLUMN IF NOT EXISTS excluido_em TIMESTAMP;

ALTER TABLE IF EXISTS promocoes_qr_codigos
  ADD COLUMN IF NOT EXISTS excluido_motivo TEXT;

CREATE INDEX IF NOT EXISTS ix_promocoes_qr_codigos_lote
  ON promocoes_qr_codigos(campanha_id, lote);

CREATE INDEX IF NOT EXISTS ix_promocoes_qr_codigos_ativos
  ON promocoes_qr_codigos(campanha_id, usado, premiado)
  WHERE excluido_em IS NULL;

-- Conferência rápida por campanha
SELECT
    campanha_id,
    COUNT(*) FILTER (WHERE excluido_em IS NULL) AS codigos_ativos,
    COUNT(*) FILTER (WHERE excluido_em IS NULL AND usado = FALSE) AS codigos_disponiveis,
    COUNT(*) FILTER (WHERE excluido_em IS NULL AND usado = TRUE) AS codigos_lidos,
    COUNT(*) FILTER (WHERE excluido_em IS NULL AND premiado = TRUE) AS codigos_premiados,
    COUNT(*) FILTER (WHERE excluido_em IS NOT NULL) AS codigos_excluidos
FROM promocoes_qr_codigos
GROUP BY campanha_id
ORDER BY campanha_id;
