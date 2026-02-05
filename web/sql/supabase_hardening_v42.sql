-- supabase_hardening_v42.sql
-- Safe FK creation + cleanup + validation (public schema)
-- Run in Supabase SQL Editor as postgres

-- 1) Create missing FKs (NOT VALID) only if tables/constraints exist
DO $$
BEGIN
  -- campanhas_combo_itens(combo_id) -> campanhas_combo(id)
  IF to_regclass('public.campanhas_combo_itens') IS NOT NULL
     AND to_regclass('public.campanhas_combo') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_combo_itens_combo_id') THEN
    ALTER TABLE public.campanhas_combo_itens
      ADD CONSTRAINT fk_combo_itens_combo_id
      FOREIGN KEY (combo_id) REFERENCES public.campanhas_combo(id)
      ON UPDATE CASCADE ON DELETE CASCADE NOT VALID;
  END IF;

  -- campanhas_combo_resultados(combo_id) -> campanhas_combo(id)
  IF to_regclass('public.campanhas_combo_resultados') IS NOT NULL
     AND to_regclass('public.campanhas_combo') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_combo_resultados_combo_id') THEN
    ALTER TABLE public.campanhas_combo_resultados
      ADD CONSTRAINT fk_combo_resultados_combo_id
      FOREIGN KEY (combo_id) REFERENCES public.campanhas_combo(id)
      ON UPDATE CASCADE ON DELETE CASCADE NOT VALID;
  END IF;

  -- campanhas_qtd_resultados(campanha_id) -> campanhas_qtd(id)
  IF to_regclass('public.campanhas_qtd_resultados') IS NOT NULL
     AND to_regclass('public.campanhas_qtd') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_campanha_qtd_resultados_campanha_id') THEN
    ALTER TABLE public.campanhas_qtd_resultados
      ADD CONSTRAINT fk_campanha_qtd_resultados_campanha_id
      FOREIGN KEY (campanha_id) REFERENCES public.campanhas_qtd(id)
      ON UPDATE CASCADE ON DELETE CASCADE NOT VALID;
  END IF;

  -- usuario_emps(usuario_id) -> usuarios(id)
  IF to_regclass('public.usuario_emps') IS NOT NULL
     AND to_regclass('public.usuarios') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_usuario_emps_usuario_id') THEN
    ALTER TABLE public.usuario_emps
      ADD CONSTRAINT fk_usuario_emps_usuario_id
      FOREIGN KEY (usuario_id) REFERENCES public.usuarios(id)
      ON UPDATE CASCADE ON DELETE CASCADE NOT VALID;
  END IF;

  -- usuario_emps(emp) -> emps(codigo)
  IF to_regclass('public.usuario_emps') IS NOT NULL
     AND to_regclass('public.emps') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_usuario_emps_emp') THEN
    ALTER TABLE public.usuario_emps
      ADD CONSTRAINT fk_usuario_emps_emp
      FOREIGN KEY (emp) REFERENCES public.emps(codigo)
      ON UPDATE CASCADE ON DELETE RESTRICT NOT VALID;
  END IF;

  -- mensagem_empresas(mensagem_id) -> mensagens(id)
  IF to_regclass('public.mensagem_empresas') IS NOT NULL
     AND to_regclass('public.mensagens') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_mensagem_empresas_mensagem_id') THEN
    ALTER TABLE public.mensagem_empresas
      ADD CONSTRAINT fk_mensagem_empresas_mensagem_id
      FOREIGN KEY (mensagem_id) REFERENCES public.mensagens(id)
      ON UPDATE CASCADE ON DELETE CASCADE NOT VALID;
  END IF;

  -- mensagem_empresas(emp) -> emps(codigo)
  IF to_regclass('public.mensagem_empresas') IS NOT NULL
     AND to_regclass('public.emps') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_mensagem_empresas_emp') THEN
    ALTER TABLE public.mensagem_empresas
      ADD CONSTRAINT fk_mensagem_empresas_emp
      FOREIGN KEY (emp) REFERENCES public.emps(codigo)
      ON UPDATE CASCADE ON DELETE RESTRICT NOT VALID;
  END IF;

  -- mensagem_usuarios(mensagem_id) -> mensagens(id)
  IF to_regclass('public.mensagem_usuarios') IS NOT NULL
     AND to_regclass('public.mensagens') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_mensagem_usuarios_mensagem_id') THEN
    ALTER TABLE public.mensagem_usuarios
      ADD CONSTRAINT fk_mensagem_usuarios_mensagem_id
      FOREIGN KEY (mensagem_id) REFERENCES public.mensagens(id)
      ON UPDATE CASCADE ON DELETE CASCADE NOT VALID;
  END IF;

  -- mensagem_usuarios(usuario_id) -> usuarios(id)
  IF to_regclass('public.mensagem_usuarios') IS NOT NULL
     AND to_regclass('public.usuarios') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_mensagem_usuarios_usuario_id') THEN
    ALTER TABLE public.mensagem_usuarios
      ADD CONSTRAINT fk_mensagem_usuarios_usuario_id
      FOREIGN KEY (usuario_id) REFERENCES public.usuarios(id)
      ON UPDATE CASCADE ON DELETE CASCADE NOT VALID;
  END IF;

  -- mensagem_lidas_diarias(mensagem_id) -> mensagens(id)
  IF to_regclass('public.mensagem_lidas_diarias') IS NOT NULL
     AND to_regclass('public.mensagens') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_mensagem_lidas_diarias_mensagem_id') THEN
    ALTER TABLE public.mensagem_lidas_diarias
      ADD CONSTRAINT fk_mensagem_lidas_diarias_mensagem_id
      FOREIGN KEY (mensagem_id) REFERENCES public.mensagens(id)
      ON UPDATE CASCADE ON DELETE CASCADE NOT VALID;
  END IF;

  -- mensagem_lidas_diarias(usuario_id) -> usuarios(id)
  IF to_regclass('public.mensagem_lidas_diarias') IS NOT NULL
     AND to_regclass('public.usuarios') IS NOT NULL
     AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_mensagem_lidas_diarias_usuario_id') THEN
    ALTER TABLE public.mensagem_lidas_diarias
      ADD CONSTRAINT fk_mensagem_lidas_diarias_usuario_id
      FOREIGN KEY (usuario_id) REFERENCES public.usuarios(id)
      ON UPDATE CASCADE ON DELETE CASCADE NOT VALID;
  END IF;

END $$;

-- 2) Cleanup orphans (safe deletes for link/snapshot tables)
-- campaigns
DELETE FROM public.campanhas_combo_itens i
WHERE to_regclass('public.campanhas_combo') IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM public.campanhas_combo c WHERE c.id = i.combo_id);

DELETE FROM public.campanhas_combo_resultados r
WHERE to_regclass('public.campanhas_combo') IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM public.campanhas_combo c WHERE c.id = r.combo_id);

DELETE FROM public.campanhas_qtd_resultados r
WHERE to_regclass('public.campanhas_qtd') IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM public.campanhas_qtd c WHERE c.id = r.campanha_id);

-- mensagens
DELETE FROM public.mensagem_empresas me
WHERE to_regclass('public.mensagens') IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM public.mensagens m WHERE m.id = me.mensagem_id);

DELETE FROM public.mensagem_usuarios mu
WHERE to_regclass('public.mensagens') IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM public.mensagens m WHERE m.id = mu.mensagem_id);

DELETE FROM public.mensagem_usuarios mu
WHERE to_regclass('public.usuarios') IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM public.usuarios u WHERE u.id = mu.usuario_id);

DELETE FROM public.mensagem_lidas_diarias ml
WHERE to_regclass('public.mensagens') IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM public.mensagens m WHERE m.id = ml.mensagem_id);

DELETE FROM public.mensagem_lidas_diarias ml
WHERE to_regclass('public.usuarios') IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM public.usuarios u WHERE u.id = ml.usuario_id);

-- usuario_emps
DELETE FROM public.usuario_emps ue
WHERE to_regclass('public.usuarios') IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM public.usuarios u WHERE u.id = ue.usuario_id);

DELETE FROM public.usuario_emps ue
WHERE to_regclass('public.emps') IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM public.emps e WHERE e.codigo = ue.emp);

-- 3) Validate all NOT VALID FKs in public
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT nsp.nspname AS schema, rel.relname AS tabela, con.conname AS fk_nome
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
    WHERE con.contype = 'f'
      AND nsp.nspname = 'public'
      AND con.convalidated = false
  LOOP
    EXECUTE format('ALTER TABLE %I.%I VALIDATE CONSTRAINT %I;', r.schema, r.tabela, r.fk_nome);
  END LOOP;
END $$;

-- 4) Optional (large table): vendas(emp) -> emps(codigo) as NOT VALID only
-- Uncomment when ready (may be heavy to validate on large vendas)
-- ALTER TABLE public.vendas
--   ADD CONSTRAINT fk_vendas_emp
--   FOREIGN KEY (emp) REFERENCES public.emps(codigo)
--   ON UPDATE CASCADE ON DELETE SET NULL NOT VALID;
