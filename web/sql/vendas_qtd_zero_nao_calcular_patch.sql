-- Patch: vendas com QTDADE_VENDIDA zerada não devem participar de cálculos.
-- Uso recomendado no Supabase após subir o código, para normalizar registros antigos já importados.
--
-- O código novo já ignora qtdade_vendida = 0 nos cálculos e, em novas importações,
-- grava valor_total = 0 para essas linhas. Este SQL apenas corrige a base histórica.

-- 1) Diagnóstico antes da correção
SELECT
    COUNT(*) AS linhas_qtd_zero_com_valor,
    COALESCE(SUM(valor_total), 0)::numeric(14,2) AS valor_total_indevido
FROM vendas
WHERE COALESCE(qtdade_vendida, 0) = 0
  AND COALESCE(valor_total, 0) <> 0;

-- 2) Correção da base histórica
UPDATE vendas
SET valor_total = 0
WHERE COALESCE(qtdade_vendida, 0) = 0
  AND COALESCE(valor_total, 0) <> 0;

-- 3) Conferência após a correção
SELECT
    COUNT(*) AS linhas_qtd_zero_com_valor_restantes,
    COALESCE(SUM(valor_total), 0)::numeric(14,2) AS valor_total_restante
FROM vendas
WHERE COALESCE(qtdade_vendida, 0) = 0
  AND COALESCE(valor_total, 0) <> 0;
