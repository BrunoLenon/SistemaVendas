-- =====================================================================
-- SistemaVendas - Integridade / exatidão de vendas e recompensas
-- Data: 2026-07-02
-- Objetivo:
--   1) Evitar duplicidade silenciosa na chave de importação de vendas.
--   2) Travar duplicidade em snapshots de combos.
--   3) Criar visão de conferência mensal por EMP/vendedor.
--
-- IMPORTANTE:
--   Rode primeiro em Supabase SQL Editor. Se o bloco levantar exceção de
--   duplicidade, execute a consulta de diagnóstico no final e envie o retorno
--   antes de normalizar/aplicar travas.
-- =====================================================================

-- 1) Diagnóstico preventivo: se houver duas ou mais linhas com a mesma chave
--    usando COALESCE nos campos que podem vir vazios, paramos para não apagar
--    nem mascarar vendas legítimas.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM (
            SELECT
                mestre,
                COALESCE(marca, '') AS marca_key,
                vendedor,
                movimento,
                mov_tipo_movto,
                COALESCE(nota, '') AS nota_key,
                COALESCE(emp, '') AS emp_key,
                COUNT(*) AS qtd
            FROM vendas
            GROUP BY
                mestre,
                COALESCE(marca, ''),
                vendedor,
                movimento,
                mov_tipo_movto,
                COALESCE(nota, ''),
                COALESCE(emp, '')
            HAVING COUNT(*) > 1
            LIMIT 1
        ) d
    ) THEN
        RAISE EXCEPTION 'Existem duplicidades na chave de importação de vendas. Rode a consulta DIAGNOSTICO_DUPLICIDADES no final deste arquivo e revise antes de continuar.';
    END IF;
END $$;

-- 2) Normaliza NULLs nos campos da chave de importação. O importador novo já
--    grava string vazia nesses campos, mas esta etapa protege dados antigos.
UPDATE vendas SET marca = '' WHERE marca IS NULL;
UPDATE vendas SET nota = '' WHERE nota IS NULL;
UPDATE vendas SET emp = '' WHERE emp IS NULL;

ALTER TABLE vendas ALTER COLUMN marca SET DEFAULT '';
ALTER TABLE vendas ALTER COLUMN nota SET DEFAULT '';
ALTER TABLE vendas ALTER COLUMN emp SET DEFAULT '';

-- 3) Trava contra duplicidade de snapshot de combo.
CREATE UNIQUE INDEX IF NOT EXISTS uq_combo_resultado_comp_emp_vendedor
ON campanhas_combo_resultados (combo_id, emp, vendedor, competencia_ano, competencia_mes);

-- 4) Trava contra duplicidade no resumo mensal manual/importado.
CREATE UNIQUE INDEX IF NOT EXISTS uq_vendas_resumo_periodo_emp_vendedor_comp
ON vendas_resumo_periodo (emp, vendedor, ano, mes);

-- 5) Visão de conferência: base oficial para auditar vendas importadas por
--    competência, EMP e vendedor, separando venda/cancelamento/devolução.
CREATE OR REPLACE VIEW vw_conferencia_vendas_competencia AS
SELECT
    EXTRACT(YEAR FROM movimento)::int AS ano,
    EXTRACT(MONTH FROM movimento)::int AS mes,
    COALESCE(emp, '') AS emp,
    UPPER(TRIM(vendedor)) AS vendedor,
    COUNT(*) AS linhas_total,
    COUNT(*) FILTER (WHERE COALESCE(qtdade_vendida, 0) = 0) AS linhas_qtd_zero,
    SUM(CASE WHEN UPPER(COALESCE(mov_tipo_movto, '')) IN ('OA','OV','SV','VA','VV')
             AND COALESCE(qtdade_vendida, 0) > 0
             THEN COALESCE(valor_total, 0) ELSE 0 END) AS total_vendas,
    SUM(CASE WHEN UPPER(COALESCE(mov_tipo_movto, '')) = 'CA'
             AND COALESCE(qtdade_vendida, 0) > 0
             THEN ABS(COALESCE(valor_total, 0)) ELSE 0 END) AS total_cancelamentos,
    SUM(CASE WHEN UPPER(COALESCE(mov_tipo_movto, '')) = 'DS'
             AND COALESCE(qtdade_vendida, 0) > 0
             THEN ABS(COALESCE(valor_total, 0)) ELSE 0 END) AS total_devolucoes,
    (
      SUM(CASE WHEN UPPER(COALESCE(mov_tipo_movto, '')) IN ('OA','OV','SV','VA','VV')
               AND COALESCE(qtdade_vendida, 0) > 0
               THEN COALESCE(valor_total, 0) ELSE 0 END)
      - SUM(CASE WHEN UPPER(COALESCE(mov_tipo_movto, '')) IN ('CA','DS')
                 AND COALESCE(qtdade_vendida, 0) > 0
                 THEN ABS(COALESCE(valor_total, 0)) ELSE 0 END)
    ) AS total_liquido
FROM vendas
GROUP BY
    EXTRACT(YEAR FROM movimento)::int,
    EXTRACT(MONTH FROM movimento)::int,
    COALESCE(emp, ''),
    UPPER(TRIM(vendedor));

-- =====================================================================
-- DIAGNOSTICO_DUPLICIDADES
-- Rode esta consulta separadamente caso o bloco acima acuse duplicidade.
-- Ela mostra as chaves repetidas e o impacto em valor/qtd.
-- =====================================================================
-- SELECT
--     mestre,
--     COALESCE(marca, '') AS marca_key,
--     vendedor,
--     movimento,
--     mov_tipo_movto,
--     COALESCE(nota, '') AS nota_key,
--     COALESCE(emp, '') AS emp_key,
--     COUNT(*) AS qtd_linhas,
--     SUM(COALESCE(qtdade_vendida, 0)) AS qtd_total,
--     SUM(COALESCE(valor_total, 0)) AS valor_total
-- FROM vendas
-- GROUP BY
--     mestre,
--     COALESCE(marca, ''),
--     vendedor,
--     movimento,
--     mov_tipo_movto,
--     COALESCE(nota, ''),
--     COALESCE(emp, '')
-- HAVING COUNT(*) > 1
-- ORDER BY movimento DESC, COALESCE(emp, ''), vendedor, mestre
-- LIMIT 200;
