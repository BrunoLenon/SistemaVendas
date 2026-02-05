-- Campanhas Combo: suporte ao Modelo de pagamento (TODOS_ITENS vs POR_DESCRICAO)
-- Seguro para rodar no Supabase (PostgreSQL 15+)

BEGIN;

ALTER TABLE IF EXISTS public.campanhas_combo
  ADD COLUMN IF NOT EXISTS modelo_pagamento varchar(20) NOT NULL DEFAULT 'TODOS_ITENS',
  ADD COLUMN IF NOT EXISTS filtro_marca varchar(120),
  ADD COLUMN IF NOT EXISTS filtro_descricao_prefixo varchar(200),
  ADD COLUMN IF NOT EXISTS valor_unitario_modelo2 double precision;

-- Índices para filtros
CREATE INDEX IF NOT EXISTS ix_campanhas_combo_modelo_pagamento ON public.campanhas_combo (modelo_pagamento);
CREATE INDEX IF NOT EXISTS ix_campanhas_combo_filtro_marca ON public.campanhas_combo (filtro_marca);

COMMIT;
