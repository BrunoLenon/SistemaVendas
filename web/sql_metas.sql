-- Metas (Crescimento / MIX / Share de Marcas)
-- Execute no Supabase (schema public). Seguro rodar mais de uma vez (usa IF NOT EXISTS onde aplicável).

CREATE TABLE IF NOT EXISTS public.metas_programas (
  id bigserial PRIMARY KEY,
  nome varchar(180) NOT NULL,
  tipo varchar(30) NOT NULL,
  ano int NOT NULL,
  mes int NOT NULL,
  ativo boolean NOT NULL DEFAULT true,
  created_by_user_id int NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_metas_programas_tipo_periodo ON public.metas_programas (tipo, ano, mes);
CREATE INDEX IF NOT EXISTS ix_metas_programas_periodo ON public.metas_programas (ano, mes);

CREATE TABLE IF NOT EXISTS public.metas_programas_emps (
  id bigserial PRIMARY KEY,
  meta_id bigint NOT NULL REFERENCES public.metas_programas(id) ON DELETE CASCADE,
  emp varchar(30) NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_meta_emp ON public.metas_programas_emps (meta_id, emp);
CREATE INDEX IF NOT EXISTS ix_meta_emp_emp ON public.metas_programas_emps (emp);

CREATE TABLE IF NOT EXISTS public.metas_escalas (
  id bigserial PRIMARY KEY,
  meta_id bigint NOT NULL REFERENCES public.metas_programas(id) ON DELETE CASCADE,
  ordem int NOT NULL DEFAULT 0,
  limite_min double precision NOT NULL,
  bonus_percentual double precision NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_meta_escala_ordem ON public.metas_escalas (meta_id, ordem);
CREATE INDEX IF NOT EXISTS ix_meta_escala_meta ON public.metas_escalas (meta_id);

CREATE TABLE IF NOT EXISTS public.metas_marcas (
  id bigserial PRIMARY KEY,
  meta_id bigint NOT NULL REFERENCES public.metas_programas(id) ON DELETE CASCADE,
  marca varchar(120) NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_meta_marca ON public.metas_marcas (meta_id, marca);
CREATE INDEX IF NOT EXISTS ix_meta_marca_marca ON public.metas_marcas (marca);

CREATE TABLE IF NOT EXISTS public.metas_bases_manuais (
  id bigserial PRIMARY KEY,
  meta_id bigint NOT NULL REFERENCES public.metas_programas(id) ON DELETE CASCADE,
  emp varchar(30) NOT NULL,
  vendedor varchar(80) NOT NULL,
  base_valor double precision NOT NULL DEFAULT 0,
  observacao varchar(200) NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_meta_base_manual ON public.metas_bases_manuais (meta_id, emp, vendedor);
CREATE INDEX IF NOT EXISTS ix_meta_base_manual_emp_vend ON public.metas_bases_manuais (emp, vendedor);

CREATE TABLE IF NOT EXISTS public.metas_resultados (
  id bigserial PRIMARY KEY,
  meta_id bigint NOT NULL REFERENCES public.metas_programas(id) ON DELETE CASCADE,
  emp varchar(30) NOT NULL,
  vendedor varchar(80) NOT NULL,
  ano int NOT NULL,
  mes int NOT NULL,
  valor_mes double precision NOT NULL DEFAULT 0,
  base_valor double precision NULL,
  crescimento_pct double precision NULL,
  mix_itens_unicos double precision NULL,
  share_pct double precision NULL,
  valor_marcas double precision NULL,
  bonus_percentual double precision NOT NULL DEFAULT 0,
  premio double precision NOT NULL DEFAULT 0,
  calculado_em timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_meta_resultado ON public.metas_resultados (meta_id, emp, vendedor, ano, mes);
CREATE INDEX IF NOT EXISTS ix_meta_resultados_emp_periodo ON public.metas_resultados (emp, ano, mes);
CREATE INDEX IF NOT EXISTS ix_meta_resultados_meta_periodo ON public.metas_resultados (meta_id, ano, mes);
