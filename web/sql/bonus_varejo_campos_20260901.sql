-- Bônus Varejo: campos adicionais da aba Final Bonus
-- Seguro para executar mais de uma vez.

ALTER TABLE public.bonus_usuarios_importados
    ADD COLUMN IF NOT EXISTS crescimento_loja NUMERIC(12,6),
    ADD COLUMN IF NOT EXISTS percentual_importado NUMERIC(12,6);

COMMENT ON COLUMN public.bonus_usuarios_importados.crescimento_loja
    IS 'Percentual importado do cabeçalho Crescimento Loja, usado pelo mecânico.';

COMMENT ON COLUMN public.bonus_usuarios_importados.percentual_importado
    IS 'Percentual importado do cabeçalho % Importado, usado pelo vendedor.';

-- Conferência opcional
SELECT column_name, data_type, numeric_precision, numeric_scale
FROM information_schema.columns
WHERE table_schema = 'public'
  AND table_name = 'bonus_usuarios_importados'
  AND column_name IN ('crescimento_loja', 'percentual_importado')
ORDER BY column_name;
