-- ============================================================
-- DIAGNÓSTICO / CONFERÊNCIA DO DASHBOARD
-- Competência: altere ano/mes se precisar
-- Objetivo:
--   1) Mostrar o valor importado bruto do banco
--   2) Separar venda positiva, DS/CA e líquido oficial
--   3) Comparar vendas ao vivo x dashboard_cache
-- ============================================================

WITH params AS (
    SELECT 2026::int AS ano, 6::int AS mes
), periodo AS (
    SELECT
        make_date(ano, mes, 1) AS dt_ini,
        (make_date(ano, mes, 1) + interval '1 month')::date AS dt_fim,
        ano,
        mes
    FROM params
), vendas_base AS (
    SELECT
        v.emp,
        upper(coalesce(v.vendedor, '')) AS vendedor,
        upper(coalesce(v.mov_tipo_movto, '')) AS mov_tipo_movto,
        coalesce(v.qtdade_vendida, 0) AS qtdade_vendida,
        coalesce(v.valor_total, 0) AS valor_total
    FROM vendas v
    JOIN periodo p ON v.movimento >= p.dt_ini AND v.movimento < p.dt_fim
    WHERE v.movimento IS NOT NULL
), vendas_calc AS (
    SELECT
        emp,
        vendedor,
        CASE
            WHEN qtdade_vendida > 0 AND mov_tipo_movto IN ('OA','OV','SV','VA','VV') THEN valor_total
            ELSE 0
        END AS bruto_vendas,
        CASE
            WHEN qtdade_vendida > 0 AND mov_tipo_movto IN ('DS','CA') THEN valor_total
            ELSE 0
        END AS devolvido_ds_ca,
        CASE
            WHEN qtdade_vendida > 0 AND mov_tipo_movto IN ('OA','OV','SV','VA','VV') THEN valor_total
            WHEN qtdade_vendida > 0 AND mov_tipo_movto IN ('DS','CA') THEN -valor_total
            ELSE 0
        END AS liquido_oficial,
        CASE
            WHEN qtdade_vendida > 0 AND mov_tipo_movto IN ('OA','OV','SV','VA','VV','DS','CA') THEN valor_total
            ELSE 0
        END AS importado_banco
    FROM vendas_base
)
SELECT
    'TOTAL AO VIVO - TABELA VENDAS' AS origem,
    ROUND(SUM(importado_banco)::numeric, 2) AS total_importado_banco,
    ROUND(SUM(bruto_vendas)::numeric, 2) AS bruto_somente_vendas_positivas,
    ROUND(SUM(devolvido_ds_ca)::numeric, 2) AS devolvido_ds_ca,
    ROUND(SUM(liquido_oficial)::numeric, 2) AS liquido_oficial_dashboard,
    COUNT(*) AS linhas_consideradas
FROM vendas_calc;

-- Comparação contra o dashboard_cache atual
WITH params AS (
    SELECT 2026::int AS ano, 6::int AS mes
), periodo AS (
    SELECT
        make_date(ano, mes, 1) AS dt_ini,
        (make_date(ano, mes, 1) + interval '1 month')::date AS dt_fim,
        ano,
        mes
    FROM params
), live AS (
    SELECT
        v.emp,
        ROUND(SUM(CASE WHEN coalesce(v.qtdade_vendida,0) > 0 AND upper(coalesce(v.mov_tipo_movto,'')) IN ('OA','OV','SV','VA','VV') THEN coalesce(v.valor_total,0) ELSE 0 END)::numeric, 2) AS bruto_live,
        ROUND(SUM(CASE WHEN coalesce(v.qtdade_vendida,0) > 0 AND upper(coalesce(v.mov_tipo_movto,'')) IN ('DS','CA') THEN coalesce(v.valor_total,0) ELSE 0 END)::numeric, 2) AS devol_live,
        ROUND(SUM(CASE WHEN coalesce(v.qtdade_vendida,0) > 0 AND upper(coalesce(v.mov_tipo_movto,'')) IN ('OA','OV','SV','VA','VV') THEN coalesce(v.valor_total,0)
                       WHEN coalesce(v.qtdade_vendida,0) > 0 AND upper(coalesce(v.mov_tipo_movto,'')) IN ('DS','CA') THEN -coalesce(v.valor_total,0)
                       ELSE 0 END)::numeric, 2) AS liquido_live
    FROM vendas v
    JOIN periodo p ON v.movimento >= p.dt_ini AND v.movimento < p.dt_fim
    GROUP BY v.emp
), cache AS (
    SELECT
        dc.emp,
        ROUND(SUM(coalesce(dc.valor_bruto,0))::numeric, 2) AS bruto_cache,
        ROUND(SUM(coalesce(dc.devolucoes,0) + coalesce(dc.cancelamentos,0))::numeric, 2) AS devol_cache,
        ROUND(SUM(coalesce(dc.valor_liquido,0))::numeric, 2) AS liquido_cache
    FROM dashboard_cache dc
    JOIN periodo p ON dc.ano = p.ano AND dc.mes = p.mes
    GROUP BY dc.emp
)
SELECT
    coalesce(l.emp, c.emp) AS emp,
    l.bruto_live,
    c.bruto_cache,
    ROUND((coalesce(l.bruto_live,0) - coalesce(c.bruto_cache,0))::numeric, 2) AS dif_bruto,
    l.devol_live,
    c.devol_cache,
    ROUND((coalesce(l.devol_live,0) - coalesce(c.devol_cache,0))::numeric, 2) AS dif_devolvido,
    l.liquido_live,
    c.liquido_cache,
    ROUND((coalesce(l.liquido_live,0) - coalesce(c.liquido_cache,0))::numeric, 2) AS dif_liquido
FROM live l
FULL JOIN cache c ON c.emp = l.emp
WHERE ABS(coalesce(l.liquido_live,0) - coalesce(c.liquido_cache,0)) > 0.01
   OR ABS(coalesce(l.bruto_live,0) - coalesce(c.bruto_cache,0)) > 0.01
   OR ABS(coalesce(l.devol_live,0) - coalesce(c.devol_cache,0)) > 0.01
ORDER BY ABS(coalesce(l.liquido_live,0) - coalesce(c.liquido_cache,0)) DESC;

-- Índices recomendados para manter o dashboard ao vivo rápido
CREATE INDEX IF NOT EXISTS ix_vendas_dashboard_live_mes_emp_vend_mov
ON vendas (movimento, emp, vendedor, mov_tipo_movto);

CREATE INDEX IF NOT EXISTS ix_vendas_dashboard_live_emp_mes
ON vendas (emp, movimento);
