-- ==========================================================
-- SistemaVendas - Campaign Engine V2 (Enterprise)
-- Tabelas universais para campanhas avançadas (sem Margem)
-- ==========================================================

create table if not exists campanhas_master_v2 (
  id bigserial primary key,
  titulo varchar(180) not null,
  tipo varchar(40) not null,
  escopo varchar(20) not null default 'EMP',
  emps_json text null,
  marca_alvo varchar(120) null,
  data_inicio date null,
  data_fim date null,
  regras_json text null,
  premiacao_json text null,
  ativo boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists ix_camp_master_v2_tipo on campanhas_master_v2(tipo);
create index if not exists ix_camp_master_v2_escopo on campanhas_master_v2(escopo);
create index if not exists ix_camp_master_v2_ativo on campanhas_master_v2(ativo);
create index if not exists ix_camp_master_v2_marca on campanhas_master_v2(marca_alvo);

create table if not exists campanhas_resultados_v2 (
  id bigserial primary key,
  campanha_id bigint not null,
  tipo varchar(40) not null,
  competencia_ano int not null,
  competencia_mes int not null,
  emp varchar(30) not null,
  vendedor varchar(80) not null,
  base_num double precision not null default 0,
  base_ref double precision null,
  pct_real double precision null,
  pct_meta double precision null,
  atingiu boolean not null default false,
  valor_recompensa double precision not null default 0,
  detalhes_json text null,
  vigencia_ini date null,
  vigencia_fim date null,
  status_pagamento varchar(20) not null default 'PENDENTE',
  pago_em timestamptz null,
  atualizado_em timestamptz not null default now(),
  constraint uq_camp_res_v2 unique (campanha_id, emp, vendedor, competencia_ano, competencia_mes)
);

create index if not exists ix_camp_res_v2_comp on campanhas_resultados_v2(competencia_ano, competencia_mes);
create index if not exists ix_camp_res_v2_emp_vend on campanhas_resultados_v2(emp, vendedor);
create index if not exists ix_camp_res_v2_status on campanhas_resultados_v2(status_pagamento);

create table if not exists campanhas_audit_v2 (
  id bigserial primary key,
  campanha_id bigint null,
  competencia_ano int null,
  competencia_mes int null,
  emp varchar(30) null,
  vendedor varchar(80) null,
  acao varchar(40) not null,
  de_status varchar(20) null,
  para_status varchar(20) null,
  usuario varchar(80) null,
  payload_json text null,
  created_at timestamptz not null default now()
);

create index if not exists ix_camp_audit_v2_comp on campanhas_audit_v2(competencia_ano, competencia_mes);
create index if not exists ix_camp_audit_v2_emp on campanhas_audit_v2(emp);
create index if not exists ix_camp_audit_v2_usuario on campanhas_audit_v2(usuario);

-- ----------------------------------------------------------
-- Seeds opcionais (padrões). Execute apenas se desejar.
-- Ranking Top 1/2/3 (geral). Meta % 10%. Meta abs 100k. Mix 10. Acum 3m.
-- ----------------------------------------------------------
-- insert into campanhas_master_v2 (titulo, tipo, escopo, regras_json, premiacao_json, ativo)
-- values
-- ('Ranking por valor (Top 1/2/3) - Geral', 'RANKING_VALOR', 'EMP', '{"mov_tipo":"OA"}', '{"top":[{"pos":1,"valor":300},{"pos":2,"valor":200},{"pos":3,"valor":100}]}', true),
-- ('Meta % vs Mês Anterior (10%)', 'META_PCT_MOM', 'EMP', '{"pct_meta":10}', '{"premio":0}', true),
-- ('Meta % vs Ano Passado (10%)', 'META_PCT_YOY', 'EMP', '{"pct_meta":10}', '{"premio":0}', true),
-- ('Meta Absoluta (R$ 100.000)', 'META_ABS', 'EMP', '{"meta_valor":100000}', '{"premio":0}', true),
-- ('Mix (10 produtos distintos)', 'MIX_MESTRE', 'EMP', '{"minimo":10}', '{"premio":0}', true),
-- ('Acumulativa (3 meses)', 'ACUM_3M', 'EMP', '{"meses":3,"meta_valor":0}', '{"premio":0}', true);
