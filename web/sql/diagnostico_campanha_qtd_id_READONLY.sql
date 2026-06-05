-- Diagnóstico seguro (somente leitura) para uma campanha QTD que não calcula.
-- Ajuste estes parâmetros antes de rodar no Supabase:
--   campanha_id: ID da campanha em public.campanhas_qtd
--   ano_ref/mes_ref: competência que você está conferindo no relatório

WITH params AS (
    SELECT
        536::int AS campanha_id,
        2026::int AS ano_ref,
        6::int AS mes_ref
), c AS (
    SELECT cq.*
    FROM public.campanhas_qtd cq
    JOIN params p ON p.campanha_id = cq.id
), periodo AS (
    SELECT
        c.*,
        GREATEST(c.data_inicio, make_date(p.ano_ref, p.mes_ref, 1))::date AS periodo_ini,
        LEAST(
            c.data_fim,
            (date_trunc('month', make_date(p.ano_ref, p.mes_ref, 1)) + interval '1 month - 1 day')::date
        )::date AS periodo_fim,
        p.ano_ref,
        p.mes_ref
    FROM c
    CROSS JOIN params p
), base_vendas AS (
    SELECT v.*, p.id AS campanha_id, p.periodo_ini, p.periodo_fim,
           upper(trim(coalesce(v.vendedor,''))) AS vendedor_norm,
           upper(trim(coalesce(v.marca,''))) AS marca_norm,
           upper(trim(coalesce(v.mestre::text,''))) AS mestre_norm,
           lower(trim(coalesce(v.descricao_norm, v.descricao, ''))) AS descricao_norm_calc,
           upper(trim(coalesce(p.vendedor,''))) AS campanha_vendedor_norm,
           upper(trim(coalesce(p.marca,''))) AS campanha_marca_norm,
           upper(trim(coalesce(p.produto_prefixo,''))) AS campanha_codigo_norm,
           lower(trim(coalesce(nullif(p.descricao_prefixo,''), p.produto_prefixo, ''))) AS campanha_descricao_norm,
           lower(trim(coalesce(p.campo_match,'codigo'))) AS campanha_campo_match,
           upper(trim(coalesce(p.campanha_tipo,'VENDEDOR'))) AS campanha_tipo_norm
    FROM public.vendas v
    CROSS JOIN periodo p
    WHERE v.emp::text = p.emp::text
      AND v.movimento >= p.periodo_ini
      AND v.movimento <= p.periodo_fim
      AND coalesce(v.mov_tipo_movto,'') NOT IN ('DS','CA')
), checks AS (
    SELECT
        '01_campanha_public' AS etapa,
        COUNT(*)::numeric AS qtd_registros,
        NULL::numeric AS qtd_vendida,
        NULL::numeric AS valor_vendido,
        NULL::text AS vendedores_encontrados,
        CASE WHEN COUNT(*) = 0 THEN 'FALHA: campanha_id não existe em public.campanhas_qtd' ELSE 'OK' END AS observacao
    FROM c

    UNION ALL
    SELECT
        '02_resultados_snapshot_existentes' AS etapa,
        COUNT(*)::numeric AS qtd_registros,
        COALESCE(SUM(r.qtd_vendida),0)::numeric AS qtd_vendida,
        COALESCE(SUM(r.valor_vendido),0)::numeric AS valor_vendido,
        string_agg(DISTINCT r.vendedor, ', ' ORDER BY r.vendedor) AS vendedores_encontrados,
        'Registros já gravados em public.campanhas_qtd_resultados para esta competência' AS observacao
    FROM public.campanhas_qtd_resultados r
    JOIN params p ON r.campanha_id = p.campanha_id
                 AND r.competencia_ano = p.ano_ref
                 AND r.competencia_mes = p.mes_ref

    UNION ALL
    SELECT
        '03_vendas_emp_periodo_validas' AS etapa,
        COUNT(*)::numeric AS qtd_registros,
        COALESCE(SUM(qtdade_vendida),0)::numeric AS qtd_vendida,
        COALESCE(SUM(valor_total),0)::numeric AS valor_vendido,
        string_agg(DISTINCT vendedor_norm, ', ' ORDER BY vendedor_norm) AS vendedores_encontrados,
        'Vendas válidas da EMP no período da campanha' AS observacao
    FROM base_vendas

    UNION ALL
    SELECT
        '04_match_codigo_ou_descricao_marca_sem_vendedor' AS etapa,
        COUNT(*)::numeric AS qtd_registros,
        COALESCE(SUM(qtdade_vendida),0)::numeric AS qtd_vendida,
        COALESCE(SUM(valor_total),0)::numeric AS valor_vendido,
        string_agg(DISTINCT vendedor_norm, ', ' ORDER BY vendedor_norm) AS vendedores_encontrados,
        'Produto/descrição + marca batendo, ignorando vendedor' AS observacao
    FROM base_vendas
    WHERE marca_norm = campanha_marca_norm
      AND (
            (campanha_campo_match = 'descricao' AND descricao_norm_calc LIKE campanha_descricao_norm || '%')
         OR (campanha_campo_match <> 'descricao' AND mestre_norm LIKE campanha_codigo_norm || '%')
      )

    UNION ALL
    SELECT
        '05_match_final_regra_campanha' AS etapa,
        COUNT(*)::numeric AS qtd_registros,
        COALESCE(SUM(qtdade_vendida),0)::numeric AS qtd_vendida,
        COALESCE(SUM(valor_total),0)::numeric AS valor_vendido,
        string_agg(DISTINCT vendedor_norm, ', ' ORDER BY vendedor_norm) AS vendedores_encontrados,
        'Essa é a regra final usada para calcular vendedor/gerente' AS observacao
    FROM base_vendas
    WHERE marca_norm = campanha_marca_norm
      AND (
            (campanha_campo_match = 'descricao' AND descricao_norm_calc LIKE campanha_descricao_norm || '%')
         OR (campanha_campo_match <> 'descricao' AND mestre_norm LIKE campanha_codigo_norm || '%')
      )
      AND (
            campanha_tipo_norm = 'GERENTE'
         OR campanha_vendedor_norm = ''
         OR vendedor_norm = campanha_vendedor_norm
      )

    UNION ALL
    SELECT
        '06_vendas_mes_por_vendedor_da_campanha' AS etapa,
        COUNT(*)::numeric AS qtd_registros,
        COALESCE(SUM(v.qtdade_vendida),0)::numeric AS qtd_vendida,
        COALESCE(SUM(v.valor_total),0)::numeric AS valor_vendido,
        string_agg(DISTINCT upper(trim(v.vendedor)), ', ' ORDER BY upper(trim(v.vendedor))) AS vendedores_encontrados,
        'Se zerar aqui, o vendedor da campanha não tem venda válida nessa EMP/período' AS observacao
    FROM public.vendas v
    CROSS JOIN periodo p
    WHERE v.emp::text = p.emp::text
      AND v.movimento >= p.periodo_ini
      AND v.movimento <= p.periodo_fim
      AND coalesce(v.mov_tipo_movto,'') NOT IN ('DS','CA')
      AND upper(trim(coalesce(v.vendedor,''))) = upper(trim(coalesce(p.vendedor,'')))
)
SELECT *
FROM checks
ORDER BY etapa;

-- Detalhe das vendas que deveriam entrar no cálculo, se existirem.
WITH params AS (
    SELECT 536::int AS campanha_id, 2026::int AS ano_ref, 6::int AS mes_ref
), c AS (
    SELECT cq.* FROM public.campanhas_qtd cq JOIN params p ON p.campanha_id = cq.id
), periodo AS (
    SELECT c.*, GREATEST(c.data_inicio, make_date(p.ano_ref, p.mes_ref, 1))::date AS periodo_ini,
           LEAST(c.data_fim, (date_trunc('month', make_date(p.ano_ref, p.mes_ref, 1)) + interval '1 month - 1 day')::date)::date AS periodo_fim
    FROM c CROSS JOIN params p
)
SELECT
    v.movimento,
    v.emp,
    v.vendedor,
    v.mestre,
    v.descricao,
    v.marca,
    v.mov_tipo_movto,
    v.qtdade_vendida,
    v.valor_total
FROM public.vendas v
CROSS JOIN periodo p
WHERE v.emp::text = p.emp::text
  AND v.movimento >= p.periodo_ini
  AND v.movimento <= p.periodo_fim
  AND coalesce(v.mov_tipo_movto,'') NOT IN ('DS','CA')
  AND upper(trim(coalesce(v.marca,''))) = upper(trim(coalesce(p.marca,'')))
  AND (
        (lower(trim(coalesce(p.campo_match,'codigo'))) = 'descricao'
         AND lower(trim(coalesce(v.descricao_norm, v.descricao, ''))) LIKE lower(trim(coalesce(nullif(p.descricao_prefixo,''), p.produto_prefixo, ''))) || '%')
     OR (lower(trim(coalesce(p.campo_match,'codigo'))) <> 'descricao'
         AND upper(trim(coalesce(v.mestre::text,''))) LIKE upper(trim(coalesce(p.produto_prefixo,''))) || '%')
  )
  AND (
        upper(trim(coalesce(p.campanha_tipo,'VENDEDOR'))) = 'GERENTE'
     OR upper(trim(coalesce(p.vendedor,''))) = ''
     OR upper(trim(coalesce(v.vendedor,''))) = upper(trim(coalesce(p.vendedor,'')))
  )
ORDER BY v.movimento, v.vendedor, v.mestre
LIMIT 100;
