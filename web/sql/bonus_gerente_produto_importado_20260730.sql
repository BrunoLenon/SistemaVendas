-- SistemaVendas - Bônus Varejo: colunas adicionais do gerente
-- M = Produto Gerente | R = Bônus Importado
-- Seguro para execução repetida.

BEGIN;

ALTER TABLE public.bonus_usuarios_importados
    ADD COLUMN IF NOT EXISTS produto_gerente NUMERIC(18,4) NOT NULL DEFAULT 0;

COMMENT ON COLUMN public.bonus_usuarios_importados.produto_gerente IS
'Coluna M da aba BONUS FINAL: bônus de produtos agregado do gerente/loja.';

COMMENT ON COLUMN public.bonus_usuarios_importados.bonus_importado IS
'Coluna R da aba BONUS FINAL: bônus de importado do vendedor ou do gerente, conforme a função do registro.';

COMMIT;
