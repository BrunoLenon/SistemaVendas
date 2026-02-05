-- ============================================================
-- PRE-CHECKS (execute before adding constraints / changing types)
-- Supabase / PostgreSQL 15+
-- Safe to run multiple times (read-only).
-- ============================================================

-- 1) Orphans: campanhas_combo_itens -> campanhas_combo
SELECT count(*) AS orfaos_combo_itens
FROM campanhas_combo_itens i
LEFT JOIN campanhas_combo c ON c.id = i.combo_id
WHERE c.id IS NULL;

-- 2) Orphans: campanhas_combo_resultados -> campanhas_combo
SELECT count(*) AS orfaos_combo_resultados
FROM campanhas_combo_resultados r
LEFT JOIN campanhas_combo c ON c.id = r.combo_id
WHERE c.id IS NULL;

-- 3) Orphans: campanhas_qtd_resultados -> campanhas_qtd
SELECT count(*) AS orfaos_campanha_qtd_resultados
FROM campanhas_qtd_resultados r
LEFT JOIN campanhas_qtd c ON c.id = r.campanha_id
WHERE c.id IS NULL;

-- 4) Orphans: usuario_emps.emp -> emps.codigo
SELECT count(*) AS orfaos_usuario_emps_emp
FROM usuario_emps ue
LEFT JOIN emps e ON e.codigo = ue.emp
WHERE e.codigo IS NULL;

-- 5) Orphans: usuario_emps.usuario_id -> usuarios.id
SELECT count(*) AS orfaos_usuario_emps_usuario
FROM usuario_emps ue
LEFT JOIN usuarios u ON u.id = ue.usuario_id
WHERE u.id IS NULL;

-- 6) Orphans: mensagem_empresas.emp -> emps.codigo
SELECT count(*) AS orfaos_mensagem_empresas_emp
FROM mensagem_empresas me
LEFT JOIN emps e ON e.codigo = me.emp
WHERE e.codigo IS NULL;

-- 7) Orphans: mensagem_empresas.mensagem_id -> mensagens.id
SELECT count(*) AS orfaos_mensagem_empresas_mensagem
FROM mensagem_empresas me
LEFT JOIN mensagens m ON m.id = me.mensagem_id
WHERE m.id IS NULL;

-- 8) Orphans: mensagem_usuarios.usuario_id / mensagem_id
SELECT 
  (SELECT count(*) FROM mensagem_usuarios mu LEFT JOIN usuarios u ON u.id = mu.usuario_id WHERE u.id IS NULL) AS orfaos_mensagem_usuarios_usuario,
  (SELECT count(*) FROM mensagem_usuarios mu LEFT JOIN mensagens m ON m.id = mu.mensagem_id WHERE m.id IS NULL) AS orfaos_mensagem_usuarios_mensagem;

-- 9) Duplicates that will break UNIQUE (should be zero if constraints already exist)
SELECT mensagem_id, emp, count(*) AS repetidos
FROM mensagem_empresas
GROUP BY mensagem_id, emp
HAVING count(*) > 1;

SELECT mensagem_id, usuario_id, data, count(*) AS repetidos
FROM mensagem_lidas_diarias
GROUP BY mensagem_id, usuario_id, data
HAVING count(*) > 1;

-- 10) Type readiness checks (money stored as float -> numeric)
-- Rows with NaN/Infinity in float columns will break CAST to numeric.
-- If any row appears here, fix it BEFORE running the type migration.
SELECT id, unit, des, qtdade_vendida, valor_total
FROM vendas
WHERE unit::text IN ('NaN','Infinity','-Infinity')
   OR des::text IN ('NaN','Infinity','-Infinity')
   OR qtdade_vendida::text IN ('NaN','Infinity','-Infinity')
   OR valor_total::text IN ('NaN','Infinity','-Infinity');

SELECT id, minimo_qtd, valor_unitario
FROM campanhas_combo_itens
WHERE minimo_qtd::text IN ('NaN','Infinity','-Infinity')
   OR (valor_unitario IS NOT NULL AND valor_unitario::text IN ('NaN','Infinity','-Infinity'));

SELECT id, valor_recompensa
FROM campanhas_combo_resultados
WHERE valor_recompensa::text IN ('NaN','Infinity','-Infinity');
