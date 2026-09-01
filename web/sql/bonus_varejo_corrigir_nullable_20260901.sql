-- SistemaVendas - Bônus Varejo
-- Corrige compatibilidade do schema antigo com o importador atual.
-- Seguro para executar mais de uma vez.

BEGIN;

ALTER TABLE public.bonus_usuarios_importados
    ALTER COLUMN percentual_importado DROP NOT NULL,
    ALTER COLUMN crescimento_loja DROP NOT NULL;

COMMIT;

-- Conferência: as duas colunas devem retornar is_nullable = YES
SELECT
    column_name,
    data_type,
    is_nullable,
    numeric_precision,
    numeric_scale
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'bonus_usuarios_importados'
  AND column_name IN ('percentual_importado', 'crescimento_loja')
ORDER BY column_name;
