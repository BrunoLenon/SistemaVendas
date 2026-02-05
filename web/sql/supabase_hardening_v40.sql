-- ============================================================
-- SUPABASE HARDENING & PERFORMANCE (v40)
-- PostgreSQL 15+ (Supabase)
--
-- IMPORTANT:
-- - Run the PRE-CHECKS first (supabase_prechecks_v40.sql).
-- - This script is designed to be SAFE and RE-RUNNABLE.
-- - It adds constraints as NOT VALID first (to avoid long locks),
--   then validates them in a second step.
-- - Some index operations (DROP/CREATE CONCURRENTLY) cannot run
--   inside a transaction. Supabase SQL editor runs each statement
--   sequentially; do NOT wrap the whole file in BEGIN/COMMIT.
-- ============================================================

-- =========================
-- 0) Recommended session settings (optional)
-- =========================
SET lock_timeout = '5s';
SET statement_timeout = '15min';

-- =========================
-- 1) Audit columns (lightweight, non-breaking)
-- =========================
-- Use these where you need traceability. They are NULLable to avoid breaking inserts.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='campanhas_combo' AND column_name='created_at'
  ) THEN
    ALTER TABLE campanhas_combo
      ADD COLUMN created_at timestamptz NULL DEFAULT now(),
      ADD COLUMN updated_at timestamptz NULL DEFAULT now(),
      ADD COLUMN created_by text NULL,
      ADD COLUMN updated_by text NULL;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='campanhas_qtd' AND column_name='created_at'
  ) THEN
    ALTER TABLE campanhas_qtd
      ADD COLUMN created_at timestamptz NULL DEFAULT now(),
      ADD COLUMN updated_at timestamptz NULL DEFAULT now(),
      ADD COLUMN created_by text NULL,
      ADD COLUMN updated_by text NULL;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='fechamento_mensal' AND column_name='created_at'
  ) THEN
    ALTER TABLE fechamento_mensal
      ADD COLUMN created_at timestamptz NULL DEFAULT now(),
      ADD COLUMN updated_at timestamptz NULL DEFAULT now(),
      ADD COLUMN created_by text NULL,
      ADD COLUMN updated_by text NULL;
  END IF;
END $$;

-- =========================
-- 2) Standardize timestamps (rename criado_em -> created_at)
-- =========================
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='campanhas_combo_itens' AND column_name='criado_em'
  )
  AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='campanhas_combo_itens' AND column_name='created_at'
  )
  THEN
    ALTER TABLE campanhas_combo_itens RENAME COLUMN criado_em TO created_at;
  END IF;

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='itens_parados' AND column_name='criado_em'
  )
  AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='itens_parados' AND column_name='created_at'
  )
  THEN
    ALTER TABLE itens_parados RENAME COLUMN criado_em TO created_at;
  END IF;
END $$;

-- =========================
-- 3) Data types: float -> numeric (money/qty)
-- =========================
-- NOTE: casting float->numeric will ROUND.
-- Choose precision consciously. Here:
-- - money: numeric(14,2)
-- - qty:   numeric(14,3)
DO $$
BEGIN
  -- vendas
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='vendas' AND column_name='valor_total')
  AND (SELECT data_type FROM information_schema.columns WHERE table_name='vendas' AND column_name='valor_total') IN ('double precision','real')
  THEN
    ALTER TABLE vendas
      ALTER COLUMN unit TYPE numeric(14,2) USING round(unit::numeric, 2),
      ALTER COLUMN des TYPE numeric(14,2) USING round(des::numeric, 2),
      ALTER COLUMN qtdade_vendida TYPE numeric(14,3) USING round(qtdade_vendida::numeric, 3),
      ALTER COLUMN valor_total TYPE numeric(14,2) USING round(valor_total::numeric, 2);
  END IF;

  -- campanhas_combo_itens
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='campanhas_combo_itens' AND column_name='minimo_qtd')
  AND (SELECT data_type FROM information_schema.columns WHERE table_name='campanhas_combo_itens' AND column_name='minimo_qtd') IN ('double precision','real')
  THEN
    ALTER TABLE campanhas_combo_itens
      ALTER COLUMN minimo_qtd TYPE numeric(14,3) USING round(minimo_qtd::numeric, 3),
      ALTER COLUMN valor_unitario TYPE numeric(14,2) USING (CASE WHEN valor_unitario IS NULL THEN NULL ELSE round(valor_unitario::numeric, 2) END);
  END IF;

  -- campanhas_combo_resultados
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='campanhas_combo_resultados' AND column_name='valor_recompensa')
  AND (SELECT data_type FROM information_schema.columns WHERE table_name='campanhas_combo_resultados' AND column_name='valor_recompensa') IN ('double precision','real')
  THEN
    ALTER TABLE campanhas_combo_resultados
      ALTER COLUMN valor_recompensa TYPE numeric(14,2) USING round(valor_recompensa::numeric, 2);
  END IF;
END $$;

-- =========================
-- 4) Missing Foreign Keys (added as NOT VALID first)
-- =========================
-- Why NOT VALID? Adds constraint with minimal lock.
-- Then VALIDATE separately.
DO $$
BEGIN
  -- campanhas_combo_itens.combo_id -> campanhas_combo.id
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fk_combo_itens_combo_id') THEN
    ALTER TABLE campanhas_combo_itens
      ADD CONSTRAINT fk_combo_itens_combo_id
      FOREIGN KEY (combo_id) REFERENCES campanhas_combo(id)
      ON UPDATE CASCADE ON DELETE CASCADE
      NOT VALID;
  END IF;

  -- campanhas_combo_resultados.combo_id -> campanhas_combo.id
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fk_combo_resultados_combo_id') THEN
    ALTER TABLE campanhas_combo_resultados
      ADD CONSTRAINT fk_combo_resultados_combo_id
      FOREIGN KEY (combo_id) REFERENCES campanhas_combo(id)
      ON UPDATE CASCADE ON DELETE CASCADE
      NOT VALID;
  END IF;

  -- campanhas_qtd_resultados.campanha_id -> campanhas_qtd.id
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fk_campanha_qtd_resultados_campanha_id') THEN
    ALTER TABLE campanhas_qtd_resultados
      ADD CONSTRAINT fk_campanha_qtd_resultados_campanha_id
      FOREIGN KEY (campanha_id) REFERENCES campanhas_qtd(id)
      ON UPDATE CASCADE ON DELETE CASCADE
      NOT VALID;
  END IF;

  -- usuario_emps.usuario_id -> usuarios.id
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fk_usuario_emps_usuario_id') THEN
    ALTER TABLE usuario_emps
      ADD CONSTRAINT fk_usuario_emps_usuario_id
      FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
      ON UPDATE CASCADE ON DELETE CASCADE
      NOT VALID;
  END IF;

  -- usuario_emps.emp -> emps.codigo
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fk_usuario_emps_emp') THEN
    ALTER TABLE usuario_emps
      ADD CONSTRAINT fk_usuario_emps_emp
      FOREIGN KEY (emp) REFERENCES emps(codigo)
      ON UPDATE CASCADE ON DELETE RESTRICT
      NOT VALID;
  END IF;

  -- mensagem_empresas.mensagem_id -> mensagens.id
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fk_mensagem_empresas_mensagem_id') THEN
    ALTER TABLE mensagem_empresas
      ADD CONSTRAINT fk_mensagem_empresas_mensagem_id
      FOREIGN KEY (mensagem_id) REFERENCES mensagens(id)
      ON UPDATE CASCADE ON DELETE CASCADE
      NOT VALID;
  END IF;

  -- mensagem_empresas.emp -> emps.codigo
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fk_mensagem_empresas_emp') THEN
    ALTER TABLE mensagem_empresas
      ADD CONSTRAINT fk_mensagem_empresas_emp
      FOREIGN KEY (emp) REFERENCES emps(codigo)
      ON UPDATE CASCADE ON DELETE RESTRICT
      NOT VALID;
  END IF;

  -- mensagem_usuarios.mensagem_id -> mensagens.id
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fk_mensagem_usuarios_mensagem_id') THEN
    ALTER TABLE mensagem_usuarios
      ADD CONSTRAINT fk_mensagem_usuarios_mensagem_id
      FOREIGN KEY (mensagem_id) REFERENCES mensagens(id)
      ON UPDATE CASCADE ON DELETE CASCADE
      NOT VALID;
  END IF;

  -- mensagem_usuarios.usuario_id -> usuarios.id
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fk_mensagem_usuarios_usuario_id') THEN
    ALTER TABLE mensagem_usuarios
      ADD CONSTRAINT fk_mensagem_usuarios_usuario_id
      FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
      ON UPDATE CASCADE ON DELETE CASCADE
      NOT VALID;
  END IF;

  -- mensagem_lidas_diarias.mensagem_id -> mensagens.id
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fk_mensagem_lidas_diarias_mensagem_id') THEN
    ALTER TABLE mensagem_lidas_diarias
      ADD CONSTRAINT fk_mensagem_lidas_diarias_mensagem_id
      FOREIGN KEY (mensagem_id) REFERENCES mensagens(id)
      ON UPDATE CASCADE ON DELETE CASCADE
      NOT VALID;
  END IF;

  -- mensagem_lidas_diarias.usuario_id -> usuarios.id
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fk_mensagem_lidas_diarias_usuario_id') THEN
    ALTER TABLE mensagem_lidas_diarias
      ADD CONSTRAINT fk_mensagem_lidas_diarias_usuario_id
      FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
      ON UPDATE CASCADE ON DELETE CASCADE
      NOT VALID;
  END IF;

  -- vendas.emp -> emps.codigo (nullable, so this is safe)
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='vendas' AND column_name='emp')
  AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='fk_vendas_emp')
  THEN
    ALTER TABLE vendas
      ADD CONSTRAINT fk_vendas_emp
      FOREIGN KEY (emp) REFERENCES emps(codigo)
      ON UPDATE CASCADE ON DELETE SET NULL
      NOT VALID;
  END IF;
END $$;

-- =========================
-- 5) Validate constraints (run AFTER orphans fixed)
-- =========================
-- If validation fails, you still keep the constraint NOT VALID and can fix data then re-run VALIDATE.
ALTER TABLE campanhas_combo_itens VALIDATE CONSTRAINT fk_combo_itens_combo_id;
ALTER TABLE campanhas_combo_resultados VALIDATE CONSTRAINT fk_combo_resultados_combo_id;
ALTER TABLE campanhas_qtd_resultados VALIDATE CONSTRAINT fk_campanha_qtd_resultados_campanha_id;
ALTER TABLE usuario_emps VALIDATE CONSTRAINT fk_usuario_emps_usuario_id;
ALTER TABLE usuario_emps VALIDATE CONSTRAINT fk_usuario_emps_emp;
ALTER TABLE mensagem_empresas VALIDATE CONSTRAINT fk_mensagem_empresas_mensagem_id;
ALTER TABLE mensagem_empresas VALIDATE CONSTRAINT fk_mensagem_empresas_emp;
ALTER TABLE mensagem_usuarios VALIDATE CONSTRAINT fk_mensagem_usuarios_mensagem_id;
ALTER TABLE mensagem_usuarios VALIDATE CONSTRAINT fk_mensagem_usuarios_usuario_id;
ALTER TABLE mensagem_lidas_diarias VALIDATE CONSTRAINT fk_mensagem_lidas_diarias_mensagem_id;
ALTER TABLE mensagem_lidas_diarias VALIDATE CONSTRAINT fk_mensagem_lidas_diarias_usuario_id;
-- vendas.emp validation can be heavy if vendas is huge
-- ALTER TABLE vendas VALIDATE CONSTRAINT fk_vendas_emp;

-- =========================
-- 6) Index hygiene (remove duplicates / add missing)
-- =========================
-- 6.1) Remove redundant indexes (KEEP the most useful composite ones)
-- NOTE: DROP INDEX CONCURRENTLY cannot run inside a transaction.

-- mensagem_lidas_diarias: if both exist, drop the redundant single-column index on data
DROP INDEX CONCURRENTLY IF EXISTS ix_mensagem_lidas_diarias_data;
DROP INDEX CONCURRENTLY IF EXISTS ix_msg_lidas_data;

-- mensagem_empresas: unique constraint already covers (mensagem_id, emp)
-- if you have an extra index duplicating this, drop it:
DROP INDEX CONCURRENTLY IF EXISTS ix_mensagem_empresas_mensagem_id_emp;
DROP INDEX CONCURRENTLY IF EXISTS ix_msg_empresas_mensagem_emp;

-- 6.2) Missing indexes for frequent filters (create concurrently)
-- vendas.movimento is heavily filtered by month/period
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_vendas_movimento ON vendas (movimento);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_vendas_emp_movimento ON vendas (emp, movimento);
CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_vendas_vendedor_movimento ON vendas (vendedor, movimento);

-- =========================
-- 7) Security hardening (safe default)
-- =========================
-- 7.1) backup_usuarios contains senha_hash -> make it service-role only using RLS.
-- This will not break your Flask app if it connects using the DB password (service role equivalent),
-- but WILL block anon/authenticated API access.
ALTER TABLE IF EXISTS backup_usuarios ENABLE ROW LEVEL SECURITY;
-- No policies => blocked for anon/authenticated; service_role bypasses RLS in Supabase.

-- 7.2) OPTIONAL RLS templates (ONLY if you use Supabase Auth and want to enforce per-user access)
-- These are provided as a starting point and are commented out to avoid breaking your current app.
-- Uncomment ONLY after you confirm your app uses JWT / auth.uid().
--
-- -- usuarios: user can read own row
-- -- ALTER TABLE usuarios ENABLE ROW LEVEL SECURITY;
-- -- CREATE POLICY usuarios_select_own
-- --   ON usuarios FOR SELECT
-- --   USING (auth.uid()::text = usuario_uuid);
--
-- -- vendas: example - allow read for members of same EMP via a join table
-- -- ALTER TABLE vendas ENABLE ROW LEVEL SECURITY;
-- -- CREATE POLICY vendas_select_emp
-- --   ON vendas FOR SELECT
-- --   USING (
-- --     EXISTS (
-- --       SELECT 1
-- --       FROM usuario_emps ue
-- --       JOIN usuarios u ON u.id = ue.usuario_id
-- --       WHERE ue.emp = vendas.emp
-- --         AND u.usuario_uuid = auth.uid()::text
-- --     )
-- --   );

-- =========================
-- 8) Post-run sanity checks
-- =========================
-- Constraints status
SELECT conname, convalidated
FROM pg_constraint
WHERE conname IN (
  'fk_combo_itens_combo_id',
  'fk_combo_resultados_combo_id',
  'fk_campanha_qtd_resultados_campanha_id',
  'fk_usuario_emps_usuario_id',
  'fk_usuario_emps_emp',
  'fk_mensagem_empresas_mensagem_id',
  'fk_mensagem_empresas_emp',
  'fk_mensagem_usuarios_mensagem_id',
  'fk_mensagem_usuarios_usuario_id',
  'fk_mensagem_lidas_diarias_mensagem_id',
  'fk_mensagem_lidas_diarias_usuario_id',
  'fk_vendas_emp'
)
ORDER BY conname;
