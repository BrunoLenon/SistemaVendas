-- Diagnóstico somente leitura: identifica possíveis campanhas QTD duplicadas.
-- Critério: mesma EMP, tipo, beneficiário, marca, base de apuração, regra de produto/descrição
-- e vigência sobreposta. Não altera dados.

WITH base AS (
    SELECT
        id,
        emp,
        COALESCE(NULLIF(UPPER(TRIM(campanha_tipo)), ''), 'VENDEDOR') AS campanha_tipo,
        COALESCE(NULLIF(UPPER(TRIM(vendedor)), ''), 'TODOS') AS beneficiario,
        COALESCE(NULLIF(LOWER(TRIM(campo_match)), ''), 'codigo') AS campo_match,
        CASE
            WHEN COALESCE(NULLIF(LOWER(TRIM(campo_match)), ''), 'codigo') = 'descricao'
                THEN COALESCE(NULLIF(UPPER(TRIM(descricao_prefixo)), ''), '')
            ELSE COALESCE(NULLIF(UPPER(TRIM(produto_prefixo)), ''), '')
        END AS regra,
        COALESCE(NULLIF(UPPER(TRIM(marca)), ''), '') AS marca,
        titulo,
        ativo,
        data_inicio,
        data_fim
    FROM public.campanhas_qtd
)
SELECT
    a.emp,
    a.campanha_tipo,
    a.beneficiario,
    a.campo_match,
    a.regra,
    a.marca,
    a.id AS campanha_id_1,
    a.titulo AS titulo_1,
    a.ativo AS ativo_1,
    a.data_inicio AS inicio_1,
    a.data_fim AS fim_1,
    b.id AS campanha_id_2,
    b.titulo AS titulo_2,
    b.ativo AS ativo_2,
    b.data_inicio AS inicio_2,
    b.data_fim AS fim_2
FROM base a
JOIN base b
  ON b.id > a.id
 AND b.emp = a.emp
 AND b.campanha_tipo = a.campanha_tipo
 AND b.beneficiario = a.beneficiario
 AND b.campo_match = a.campo_match
 AND b.regra = a.regra
 AND b.marca = a.marca
 AND b.data_inicio <= a.data_fim
 AND b.data_fim >= a.data_inicio
ORDER BY a.emp, a.marca, a.regra, a.data_inicio, a.id;
