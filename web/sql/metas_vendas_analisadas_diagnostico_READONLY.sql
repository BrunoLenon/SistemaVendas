-- =====================================================================
-- SistemaVendas - Diagnóstico READONLY da página Metas
-- Data: 2026-07-14
-- Objetivo: conferir exatamente a origem de "Venda importada analisada".
--
-- Regra oficial:
--   OA, OV, SV, VA, VV = vendas positivas
--   CA, DS             = abatimentos
--   quantidade zero    = ignorada no cálculo
--   quantidade negativa em CA/DS é aceita; o movimento define o sinal
-- =====================================================================

WITH params AS (
    SELECT
        '101'::text AS emp,
        2026::int AS ano,
        7::int AS mes,
        NULL::text AS vendedor -- informe o login em maiúsculo ou deixe NULL
), base AS (
    SELECT
        v.*,
        CASE
            WHEN trim(coalesce(v.emp, '')) ~ '^[+-]?[0-9]+[.]0+$'
                THEN split_part(trim(v.emp), '.', 1)
            ELSE trim(coalesce(v.emp, ''))
        END AS emp_normalizada,
        upper(trim(coalesce(v.vendedor, ''))) AS vendedor_normalizado,
        upper(trim(coalesce(v.mov_tipo_movto, ''))) AS movimento_normalizado
    FROM vendas v
    CROSS JOIN params p
    WHERE v.movimento >= make_date(p.ano, p.mes, 1)
      AND v.movimento < (make_date(p.ano, p.mes, 1) + interval '1 month')
), filtrada AS (
    SELECT b.*
    FROM base b
    CROSS JOIN params p
    WHERE b.emp_normalizada = p.emp
      AND (p.vendedor IS NULL OR b.vendedor_normalizado = upper(trim(p.vendedor)))
)
SELECT
    count(*) AS linhas_importadas,
    count(*) FILTER (WHERE abs(coalesce(qtdade_vendida, 0)) = 0) AS linhas_qtd_zero,
    count(*) FILTER (
        WHERE abs(coalesce(qtdade_vendida, 0)) > 0
          AND movimento_normalizado NOT IN ('OA','OV','SV','VA','VV','CA','DS')
    ) AS movimentos_fora_regra,
    coalesce(sum(CASE
        WHEN abs(coalesce(qtdade_vendida, 0)) > 0
         AND movimento_normalizado IN ('OA','OV','SV','VA','VV')
        THEN coalesce(valor_total, 0) ELSE 0 END), 0) AS vendas_brutas,
    coalesce(sum(CASE
        WHEN abs(coalesce(qtdade_vendida, 0)) > 0
         AND movimento_normalizado = 'CA'
        THEN abs(coalesce(valor_total, 0)) ELSE 0 END), 0) AS cancelamentos,
    coalesce(sum(CASE
        WHEN abs(coalesce(qtdade_vendida, 0)) > 0
         AND movimento_normalizado = 'DS'
        THEN abs(coalesce(valor_total, 0)) ELSE 0 END), 0) AS devolucoes,
    coalesce(sum(CASE
        WHEN abs(coalesce(qtdade_vendida, 0)) > 0
         AND movimento_normalizado IN ('OA','OV','SV','VA','VV')
        THEN coalesce(valor_total, 0)
        WHEN abs(coalesce(qtdade_vendida, 0)) > 0
         AND movimento_normalizado IN ('CA','DS')
        THEN -abs(coalesce(valor_total, 0))
        ELSE 0 END), 0) AS venda_importada_analisada
FROM filtrada;

-- Mostra se a mesma EMP está gravada com formatos diferentes, como 101 e 101.0.
WITH params AS (
    SELECT '101'::text AS emp, 2026::int AS ano, 7::int AS mes
)
SELECT
    trim(coalesce(v.emp, '')) AS emp_gravada,
    count(*) AS linhas,
    coalesce(sum(v.valor_total), 0) AS soma_valor_sem_regra
FROM vendas v
CROSS JOIN params p
WHERE v.movimento >= make_date(p.ano, p.mes, 1)
  AND v.movimento < (make_date(p.ano, p.mes, 1) + interval '1 month')
  AND (
      trim(coalesce(v.emp, '')) = p.emp
      OR trim(coalesce(v.emp, '')) = p.emp || '.0'
  )
GROUP BY trim(coalesce(v.emp, ''))
ORDER BY emp_gravada;
