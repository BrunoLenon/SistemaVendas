-- Patch opcional para atualizar o MIX já gravado em dashboard_cache.
-- Regra oficial do MIX:
--   OA/OV/SV/VA/VV somam QTDADE_VENDIDA
--   CA/DS subtraem QTDADE_VENDIDA
--   somente MESTRE com quantidade líquida > 0 conta 1 no mix_produtos
--
-- Pode ser executado no Supabase depois do deploy para corrigir caches antigos.

WITH por_produto AS (
    SELECT
        emp::text AS emp,
        upper(trim(vendedor)) AS vendedor,
        ano::int AS ano,
        mes::int AS mes,
        trim(mestre::text) AS mestre,
        SUM(
            CASE
                WHEN COALESCE(qtdade_vendida, 0) <= 0 THEN 0
                WHEN upper(COALESCE(mov_tipo_movto, '')) IN ('CA', 'DS') THEN -COALESCE(qtdade_vendida, 0)
                WHEN upper(COALESCE(mov_tipo_movto, '')) IN ('OA', 'OV', 'SV', 'VA', 'VV') THEN COALESCE(qtdade_vendida, 0)
                ELSE 0
            END
        ) AS qtd_liquida
    FROM vendas
    WHERE mestre IS NOT NULL
      AND trim(mestre::text) <> ''
      AND vendedor IS NOT NULL
      AND trim(vendedor) <> ''
      AND emp IS NOT NULL
      AND trim(emp::text) <> ''
      AND ano IS NOT NULL
      AND mes IS NOT NULL
    GROUP BY emp::text, upper(trim(vendedor)), ano::int, mes::int, trim(mestre::text)
), mix_calc AS (
    SELECT
        emp,
        vendedor,
        ano,
        mes,
        COUNT(*)::int AS mix_produtos
    FROM por_produto
    WHERE qtd_liquida > 0
    GROUP BY emp, vendedor, ano, mes
)
UPDATE dashboard_cache dc
SET
    mix_produtos = COALESCE(mc.mix_produtos, 0),
    atualizado_em = now()
FROM mix_calc mc
WHERE dc.emp = mc.emp
  AND upper(trim(dc.vendedor)) = mc.vendedor
  AND dc.ano = mc.ano
  AND dc.mes = mc.mes;

-- Zera caches que não possuem nenhum item com saldo positivo no período.
WITH chaves_com_mix AS (
    SELECT DISTINCT emp, vendedor, ano, mes
    FROM (
        SELECT
            emp::text AS emp,
            upper(trim(vendedor)) AS vendedor,
            ano::int AS ano,
            mes::int AS mes,
            trim(mestre::text) AS mestre,
            SUM(
                CASE
                    WHEN COALESCE(qtdade_vendida, 0) <= 0 THEN 0
                    WHEN upper(COALESCE(mov_tipo_movto, '')) IN ('CA', 'DS') THEN -COALESCE(qtdade_vendida, 0)
                    WHEN upper(COALESCE(mov_tipo_movto, '')) IN ('OA', 'OV', 'SV', 'VA', 'VV') THEN COALESCE(qtdade_vendida, 0)
                    ELSE 0
                END
            ) AS qtd_liquida
        FROM vendas
        WHERE mestre IS NOT NULL
          AND trim(mestre::text) <> ''
          AND vendedor IS NOT NULL
          AND trim(vendedor) <> ''
          AND emp IS NOT NULL
          AND trim(emp::text) <> ''
          AND ano IS NOT NULL
          AND mes IS NOT NULL
        GROUP BY emp::text, upper(trim(vendedor)), ano::int, mes::int, trim(mestre::text)
    ) x
    WHERE qtd_liquida > 0
)
UPDATE dashboard_cache dc
SET
    mix_produtos = 0,
    atualizado_em = now()
WHERE NOT EXISTS (
    SELECT 1
    FROM chaves_com_mix cm
    WHERE cm.emp = dc.emp
      AND cm.vendedor = upper(trim(dc.vendedor))
      AND cm.ano = dc.ano
      AND cm.mes = dc.mes
);

-- Diagnóstico rápido: veja alguns caches após a correção.
SELECT emp, vendedor, ano, mes, mix_produtos, atualizado_em
FROM dashboard_cache
ORDER BY ano DESC, mes DESC, emp, vendedor
LIMIT 100;
