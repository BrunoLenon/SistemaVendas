-- Diagnóstico somente leitura: trava de faturamento mínimo da EMP em campanhas QTD.
-- Ajuste os parâmetros em params conforme necessário.
WITH params AS (
    SELECT
        2026::int AS ano_ref,
        6::int AS mes_ref,
        NULL::int AS campanha_id_ref  -- informe o ID da campanha ou deixe NULL para listar todas da competência
), periodo AS (
    SELECT
        make_date(ano_ref, mes_ref, 1) AS inicio_mes,
        (make_date(ano_ref, mes_ref, 1) + interval '1 month - 1 day')::date AS fim_mes,
        ano_ref,
        mes_ref,
        campanha_id_ref
    FROM params
), campanhas AS (
    SELECT c.*
    FROM public.campanhas_qtd c
    CROSS JOIN periodo p
    WHERE c.ativo = 1
      AND c.data_inicio <= p.fim_mes
      AND c.data_fim >= p.inicio_mes
      AND (p.campanha_id_ref IS NULL OR c.id = p.campanha_id_ref)
), fat_emp AS (
    SELECT
        c.id AS campanha_id,
        c.emp,
        COALESCE(SUM(v.valor_total), 0)::numeric AS faturamento_emp
    FROM campanhas c
    CROSS JOIN periodo p
    LEFT JOIN public.vendas v
      ON v.emp::text = c.emp::text
     AND v.movimento >= GREATEST(c.data_inicio, p.inicio_mes)
     AND v.movimento <= LEAST(c.data_fim, p.fim_mes)
     AND COALESCE(v.mov_tipo_movto, '') NOT IN ('DS', 'CA')
    GROUP BY c.id, c.emp
), snap AS (
    SELECT
        r.campanha_id,
        r.emp,
        COUNT(*) AS linhas_snapshot,
        SUM(COALESCE(r.premio_potencial, r.valor_recompensa, 0)) AS potencial_snapshot,
        SUM(COALESCE(r.valor_recompensa, 0)) AS liberado_snapshot,
        MAX(COALESCE(r.faturamento_minimo_emp, 0)) AS minimo_snapshot,
        MAX(COALESCE(r.faturamento_emp, 0)) AS faturamento_snapshot,
        MAX(COALESCE(r.faltante_faturamento_emp, 0)) AS faltante_snapshot,
        MAX(COALESCE(r.bloqueado_faturamento_emp, 0)) AS bloqueado_snapshot
    FROM public.campanhas_qtd_resultados r
    CROSS JOIN periodo p
    WHERE r.competencia_ano = p.ano_ref
      AND r.competencia_mes = p.mes_ref
      AND (p.campanha_id_ref IS NULL OR r.campanha_id = p.campanha_id_ref)
    GROUP BY r.campanha_id, r.emp
)
SELECT
    c.id AS campanha_id,
    c.emp,
    c.titulo,
    c.produto_prefixo,
    NULLIF(c.marca, '') AS marca,
    c.faturamento_minimo_emp AS minimo_cadastrado,
    f.faturamento_emp AS faturamento_real_periodo,
    CASE
        WHEN COALESCE(c.faturamento_minimo_emp, 0) <= 0 THEN 'SEM_TRAVA'
        WHEN f.faturamento_emp >= c.faturamento_minimo_emp THEN 'LIBERADA'
        ELSE 'BLOQUEAR'
    END AS decisao_esperada,
    GREATEST(COALESCE(c.faturamento_minimo_emp, 0) - COALESCE(f.faturamento_emp, 0), 0) AS faltante_esperado,
    COALESCE(s.linhas_snapshot, 0) AS linhas_snapshot,
    COALESCE(s.potencial_snapshot, 0) AS potencial_snapshot,
    COALESCE(s.liberado_snapshot, 0) AS liberado_snapshot,
    COALESCE(s.minimo_snapshot, 0) AS minimo_snapshot,
    COALESCE(s.faturamento_snapshot, 0) AS faturamento_snapshot,
    COALESCE(s.faltante_snapshot, 0) AS faltante_snapshot,
    COALESCE(s.bloqueado_snapshot, 0) AS bloqueado_snapshot
FROM campanhas c
LEFT JOIN fat_emp f ON f.campanha_id = c.id AND f.emp::text = c.emp::text
LEFT JOIN snap s ON s.campanha_id = c.id AND s.emp::text = c.emp::text
ORDER BY c.emp, c.id;
