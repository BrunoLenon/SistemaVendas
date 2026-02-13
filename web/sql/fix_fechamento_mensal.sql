-- Fix schema/defaults for fechamento_mensal
-- Allows ABERTO periods to have fechado_em = NULL and default fechado = false.

ALTER TABLE fechamento_mensal
  ALTER COLUMN fechado SET DEFAULT false;

ALTER TABLE fechamento_mensal
  ALTER COLUMN fechado_em DROP NOT NULL;

ALTER TABLE fechamento_mensal
  ALTER COLUMN fechado_em DROP DEFAULT;

-- Normalize existing data
UPDATE fechamento_mensal
   SET fechado_em = NULL
 WHERE COALESCE(status,'aberto')='aberto' OR fechado = false;

-- Optional: keep fechado flag consistent with status
UPDATE fechamento_mensal
   SET fechado = true
 WHERE COALESCE(status,'aberto') IN ('a_pagar','pago');

UPDATE fechamento_mensal
   SET fechado = false
 WHERE COALESCE(status,'aberto')='aberto';
