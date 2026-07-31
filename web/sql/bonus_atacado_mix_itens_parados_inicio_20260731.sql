-- SistemaVendas — Bônus Atacado: coluna MIX
-- Aplicação segura e idempotente no Supabase/PostgreSQL.

BEGIN;

ALTER TABLE public.bonus_atacado_usuarios
    ADD COLUMN IF NOT EXISTS mix INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN public.bonus_atacado_usuarios.mix IS
    'Quantidade de produtos diferentes vendidos, importada da coluna N (MIX) da aba PremiacaoFinal.';

COMMIT;
