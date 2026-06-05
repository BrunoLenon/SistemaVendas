-- Diagnóstico pós-hotfix para a campanha QTD 538 / competência 06-2026.
-- Somente leitura.
WITH cfg AS (
  SELECT 538::int AS campanha_id, 2026::int AS ano_ref, 6::int AS mes_ref
), c AS (
  SELECT c.*,
         make_date((SELECT ano_ref FROM cfg), (SELECT mes_ref FROM cfg), 1) AS mes_ini,
         ((make_date((SELECT ano_ref FROM cfg), (SELECT mes_ref FROM cfg), 1) + interval '1 month - 1 day')::date) AS mes_fim
  FROM public.campanhas_qtd c
  WHERE c.id = (SELECT campanha_id FROM cfg)
), periodo AS (
  SELECT *, GREATEST(data_inicio, mes_ini) AS dt_ini, LEAST(data_fim, mes_fim) AS dt_fim
  FROM c
), venda_match AS (
  SELECT v.*
  FROM public.vendas v
  JOIN periodo c ON true
  WHERE v.emp::text = c.emp::text
    AND v.movimento::date BETWEEN c.dt_ini AND c.dt_fim
    AND COALESCE(v.mov_tipo_movto,'') NOT IN ('DS','CA')
    AND upper(trim(v.marca::text)) = upper(trim(c.marca::text))
    AND (
      (COALESCE(c.campo_match,'codigo') <> 'descricao' AND upper(trim(v.mestre::text)) LIKE upper(trim(c.produto_prefixo::text)) || '%')
      OR
      (COALESCE(c.campo_match,'codigo') = 'descricao' AND lower(trim(COALESCE(v.descricao_norm, v.descricao, ''))) LIKE lower(trim(COALESCE(NULLIF(c.descricao_prefixo,''), c.produto_prefixo, ''))) || '%')
    )
), res AS (
  SELECT *
  FROM public.campanhas_qtd_resultados r
  WHERE r.campanha_id = (SELECT campanha_id FROM cfg)
    AND r.competencia_ano = (SELECT ano_ref FROM cfg)
    AND r.competencia_mes = (SELECT mes_ref FROM cfg)
)
SELECT '01_campanha' AS etapa,
       COUNT(*)::text AS qtd,
       NULL::text AS detalhes
FROM c
UNION ALL
SELECT '02_vendas_match_bruto', COUNT(*)::text,
       'qtd=' || COALESCE(SUM(qtdade_vendida),0)::text || ' valor=' || COALESCE(SUM(valor_total),0)::text
FROM venda_match
UNION ALL
SELECT '03_vendas_match_por_vendedor', COUNT(*)::text,
       COALESCE(string_agg(vendedor || ': qtd=' || qtd::text || ' valor=' || valor::text, ' | ' ORDER BY vendedor), 'sem vendas')
FROM (
  SELECT upper(trim(vendedor::text)) AS vendedor,
         SUM(qtdade_vendida) AS qtd,
         SUM(valor_total) AS valor
  FROM venda_match
  GROUP BY upper(trim(vendedor::text))
) x
UNION ALL
SELECT '04_snapshot_gerado', COUNT(*)::text,
       COALESCE(string_agg(vendedor || ': premio=' || valor_recompensa::text || ' qtd=' || qtd_vendida::text, ' | ' ORDER BY vendedor), 'sem snapshot')
FROM res;
