-- Metas V2 (Vendedores) - Programa + Critérios (Crescimento/Mix) + Resultados (snapshot)
-- Execute no Supabase (SQL Editor). Seguro para rodar 1x.
-- Observação: usa JSONB e ON CONFLICT.

create table if not exists metas_v2_programas (
  id bigserial primary key,
  nome text not null,
  ano int not null,
  mes int not null,
  ativo boolean not null default true,

  baseline_tipo text not null default 'ano_passado', -- 'ano_passado' | 'media_meses'
  baseline_janela_meses int not null default 3,

  gate_itens_parados_enabled boolean not null default false,
  gate_itens_parados_min_valor numeric not null default 0,

  criado_em timestamptz not null default now(),
  atualizado_em timestamptz not null default now()
);

create index if not exists idx_metas_v2_programas_periodo on metas_v2_programas (ano, mes);

create table if not exists metas_v2_programa_emps (
  programa_id bigint not null references metas_v2_programas(id) on delete cascade,
  emp text not null,
  primary key (programa_id, emp)
);

create table if not exists metas_v2_criterios (
  id bigserial primary key,
  programa_id bigint not null references metas_v2_programas(id) on delete cascade,
  tipo text not null, -- 'crescimento' | 'mix' | futuros
  ativo boolean not null default true,
  params jsonb not null default '{}'::jsonb
);

create unique index if not exists uq_metas_v2_criterios on metas_v2_criterios (programa_id, tipo);

create table if not exists metas_v2_faixas (
  id bigserial primary key,
  criterio_id bigint not null references metas_v2_criterios(id) on delete cascade,
  limite numeric not null,          -- crescimento_pct ou mix_itens
  recompensa_pct numeric not null,  -- percent (ex.: 0.10 => 0,10%)
  ordem int not null default 0
);

create index if not exists idx_metas_v2_faixas_criterio on metas_v2_faixas (criterio_id, ordem, limite);

create table if not exists metas_v2_resultados (
  id bigserial primary key,
  programa_id bigint not null references metas_v2_programas(id) on delete cascade,
  emp text not null,
  vendedor text not null,
  ano int not null,
  mes int not null,

  valor_liquido numeric not null default 0,
  itens_parados_valor numeric not null default 0,

  crescimento_base numeric null,
  crescimento_atual_ref numeric null,
  crescimento_pct numeric null,

  mix_produtos int not null default 0,

  pct_total numeric not null default 0,
  valor_premio numeric not null default 0,

  breakdown jsonb not null default '{}'::jsonb,
  criado_em timestamptz not null default now()
);

create unique index if not exists uq_metas_v2_resultados on metas_v2_resultados (programa_id, emp, vendedor, ano, mes);
create index if not exists idx_metas_v2_resultados_lookup on metas_v2_resultados (ano, mes, emp, vendedor);
