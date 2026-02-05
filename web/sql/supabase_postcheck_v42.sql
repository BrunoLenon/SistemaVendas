-- supabase_postcheck_v42.sql
-- Quick sanity checks after hardening

-- List public FKs + validation status
SELECT
  rel.relname AS tabela,
  con.conname AS constraint_name,
  con.convalidated AS validada,
  pg_get_constraintdef(con.oid) AS definicao
FROM pg_constraint con
JOIN pg_class rel ON rel.oid = con.conrelid
JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
WHERE con.contype = 'f'
  AND nsp.nspname = 'public'
ORDER BY con.convalidated, rel.relname, con.conname;

-- Confirm no orphans remain for key relations
SELECT COUNT(*) AS orfaos_combo_itens
FROM public.campanhas_combo_itens i
LEFT JOIN public.campanhas_combo c ON c.id = i.combo_id
WHERE c.id IS NULL;

SELECT COUNT(*) AS orfaos_combo_resultados
FROM public.campanhas_combo_resultados r
LEFT JOIN public.campanhas_combo c ON c.id = r.combo_id
WHERE c.id IS NULL;

SELECT COUNT(*) AS orfaos_campanha_qtd_resultados
FROM public.campanhas_qtd_resultados r
LEFT JOIN public.campanhas_qtd c ON c.id = r.campanha_id
WHERE c.id IS NULL;
