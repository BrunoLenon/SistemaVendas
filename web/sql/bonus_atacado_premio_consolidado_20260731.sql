-- SistemaVendas — Bônus Atacado: prêmio consolidado
-- Execute no SQL Editor do Supabase antes de publicar os arquivos deste ajuste.
-- Seguro para executar mais de uma vez.

BEGIN;

ALTER TABLE public.bonus_atacado_usuarios
    ADD COLUMN IF NOT EXISTS premio_consolidado NUMERIC(18,4);

COMMENT ON COLUMN public.bonus_atacado_usuarios.premio_consolidado IS
    'Prêmio final consolidado importado da aba PremiacaoFinal. A coluna total_produtos permanece como provisão.';

COMMIT;

-- Conferência opcional:
SELECT
    column_name,
    data_type,
    numeric_precision,
    numeric_scale
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'bonus_atacado_usuarios'
  AND column_name IN ('total_produtos', 'premio_consolidado')
ORDER BY ordinal_position;
