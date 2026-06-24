-- ============================================================
-- DIAGNÓSTICO / CONFERÊNCIA DO DASHBOARD POR DIA E POR LOJA
-- SistemaVendas / Veipeças
-- Competência padrão: Junho/2026
-- ============================================================

-- Índices auxiliares para acelerar Dashboard/conferência.
-- Rode uma vez no Supabase SQL Editor.
CREATE INDEX IF NOT EXISTS ix_vendas_dashboard_movimento_emp
ON vendas (movimento, emp);

CREATE INDEX IF NOT EXISTS ix_vendas_dashboard_movimento_emp_vendedor
ON vendas (movimento, emp, vendedor);

CREATE INDEX IF NOT EXISTS ix_vendas_dashboard_movimento_tipo
ON vendas (movimento, mov_tipo_movto);

-- ============================================================
-- 1) Conferência geral por dia, igual ao card Importado do Dashboard
-- ============================================================
WITH parametros AS (
    SELECT
        2026::int AS ano_filtro,
        6::int AS mes_filtro
), base AS (
    SELECT v.*
    FROM vendas v
    CROSS JOIN parametros p
    WHERE v.movimento IS NOT NULL
      AND EXTRACT(YEAR FROM v.movimento::date) = p.ano_filtro
      AND EXTRACT(MONTH FROM v.movimento::date) = p.mes_filtro
)
SELECT
    b.movimento::date AS data_movimento,
    TO_CHAR(b.movimento::date, 'DD/MM/YYYY') AS data_formatada,
    COUNT(*) AS total_linhas_importadas,
    COUNT(DISTINCT b.emp) AS total_emps,
    COUNT(DISTINCT NULLIF(b.vendedor, '')) AS total_vendedores,
    SUM(COALESCE(b.valor_total, 0)) AS valor_importado,
    SUM(
        CASE
            WHEN COALESCE(b.qtdade_vendida, 0) > 0
             AND UPPER(COALESCE(b.mov_tipo_movto, '')) IN ('OA','OV','SV','VA','VV')
            THEN COALESCE(b.valor_total, 0)
            ELSE 0
        END
    ) AS valor_bruto,
    SUM(
        CASE
            WHEN COALESCE(b.qtdade_vendida, 0) > 0
             AND UPPER(COALESCE(b.mov_tipo_movto, '')) IN ('DS','CA')
            THEN COALESCE(b.valor_total, 0)
            ELSE 0
        END
    ) AS valor_devolvido,
    SUM(
        CASE
            WHEN COALESCE(b.qtdade_vendida, 0) > 0
             AND UPPER(COALESCE(b.mov_tipo_movto, '')) IN ('OA','OV','SV','VA','VV')
            THEN COALESCE(b.valor_total, 0)
            WHEN COALESCE(b.qtdade_vendida, 0) > 0
             AND UPPER(COALESCE(b.mov_tipo_movto, '')) IN ('DS','CA')
            THEN -COALESCE(b.valor_total, 0)
            ELSE 0
        END
    ) AS valor_liquido
FROM base b
GROUP BY b.movimento::date
ORDER BY b.movimento::date;

-- ============================================================
-- 2) Conferência por dia e por EMP/loja
-- Altere o valor da CTE parametros.emp_filtro para conferir uma loja específica.
-- Use NULL para todas as lojas.
-- ============================================================
WITH parametros AS (
    SELECT
        2026::int AS ano_filtro,
        6::int AS mes_filtro,
        NULL::text AS emp_filtro
        -- Exemplo para uma loja específica:
        -- '1001'::text AS emp_filtro
), base AS (
    SELECT v.*
    FROM vendas v
    CROSS JOIN parametros p
    WHERE v.movimento IS NOT NULL
      AND EXTRACT(YEAR FROM v.movimento::date) = p.ano_filtro
      AND EXTRACT(MONTH FROM v.movimento::date) = p.mes_filtro
      AND (p.emp_filtro IS NULL OR v.emp = p.emp_filtro)
)
SELECT
    b.movimento::date AS data_movimento,
    TO_CHAR(b.movimento::date, 'DD/MM/YYYY') AS data_formatada,
    b.emp,
    COUNT(*) AS total_linhas_importadas,
    COUNT(DISTINCT NULLIF(b.vendedor, '')) AS total_vendedores,
    SUM(COALESCE(b.valor_total, 0)) AS valor_importado,
    SUM(
        CASE
            WHEN COALESCE(b.qtdade_vendida, 0) > 0
             AND UPPER(COALESCE(b.mov_tipo_movto, '')) IN ('OA','OV','SV','VA','VV')
            THEN COALESCE(b.valor_total, 0)
            ELSE 0
        END
    ) AS valor_bruto,
    SUM(
        CASE
            WHEN COALESCE(b.qtdade_vendida, 0) > 0
             AND UPPER(COALESCE(b.mov_tipo_movto, '')) IN ('DS','CA')
            THEN COALESCE(b.valor_total, 0)
            ELSE 0
        END
    ) AS valor_devolvido,
    SUM(
        CASE
            WHEN COALESCE(b.qtdade_vendida, 0) > 0
             AND UPPER(COALESCE(b.mov_tipo_movto, '')) IN ('OA','OV','SV','VA','VV')
            THEN COALESCE(b.valor_total, 0)
            WHEN COALESCE(b.qtdade_vendida, 0) > 0
             AND UPPER(COALESCE(b.mov_tipo_movto, '')) IN ('DS','CA')
            THEN -COALESCE(b.valor_total, 0)
            ELSE 0
        END
    ) AS valor_liquido
FROM base b
GROUP BY b.movimento::date, b.emp
ORDER BY b.movimento::date, b.emp;
