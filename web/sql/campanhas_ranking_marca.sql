-- Campanha Ranking por Marca (Top N)
-- Seguro para rodar no Supabase: cria tabelas/índices se não existirem.

CREATE TABLE IF NOT EXISTS campanhas_ranking_marca (
  id SERIAL PRIMARY KEY,
  titulo VARCHAR(200) NOT NULL,
  marca VARCHAR(120) NOT NULL,
  data_inicio DATE NOT NULL,
  data_fim DATE NOT NULL,
  competencia_ano INTEGER,
  competencia_mes INTEGER,
  escopo_tipo VARCHAR(20) NOT NULL DEFAULT 'GLOBAL',
  ativo BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_rank_marca_marca ON campanhas_ranking_marca (marca);
CREATE INDEX IF NOT EXISTS ix_rank_marca_periodo ON campanhas_ranking_marca (data_inicio, data_fim);
CREATE INDEX IF NOT EXISTS ix_rank_marca_comp ON campanhas_ranking_marca (competencia_ano, competencia_mes);
CREATE INDEX IF NOT EXISTS ix_rank_marca_escopo ON campanhas_ranking_marca (escopo_tipo);

CREATE TABLE IF NOT EXISTS campanhas_ranking_marca_emps (
  id SERIAL PRIMARY KEY,
  campanha_id INTEGER NOT NULL,
  emp VARCHAR(30) NOT NULL,
  CONSTRAINT uq_rank_marca_emp UNIQUE (campanha_id, emp)
);
CREATE INDEX IF NOT EXISTS ix_rank_marca_emps_campanha ON campanhas_ranking_marca_emps (campanha_id);
CREATE INDEX IF NOT EXISTS ix_rank_marca_emps_emp ON campanhas_ranking_marca_emps (emp);

CREATE TABLE IF NOT EXISTS campanhas_ranking_marca_premios (
  id SERIAL PRIMARY KEY,
  campanha_id INTEGER NOT NULL,
  posicao INTEGER NOT NULL,
  valor_premio DOUBLE PRECISION NOT NULL DEFAULT 0,
  CONSTRAINT uq_rank_marca_premio UNIQUE (campanha_id, posicao)
);
CREATE INDEX IF NOT EXISTS ix_rank_marca_premios_campanha ON campanhas_ranking_marca_premios (campanha_id);

CREATE TABLE IF NOT EXISTS campanhas_ranking_marca_resultados (
  id SERIAL PRIMARY KEY,
  campanha_id INTEGER NOT NULL,
  competencia_ano INTEGER NOT NULL,
  competencia_mes INTEGER NOT NULL,
  emp VARCHAR(30),
  vendedor VARCHAR(80) NOT NULL,
  valor_vendido DOUBLE PRECISION NOT NULL DEFAULT 0,
  posicao INTEGER,
  valor_premio DOUBLE PRECISION NOT NULL DEFAULT 0,
  status_pagamento VARCHAR(20) NOT NULL DEFAULT 'PENDENTE',
  pago_em TIMESTAMP,
  atualizado_em TIMESTAMP NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_rank_marca_resultado UNIQUE (campanha_id, competencia_ano, competencia_mes, emp, vendedor)
);

CREATE INDEX IF NOT EXISTS ix_rank_marca_res_emp_comp ON campanhas_ranking_marca_resultados (emp, competencia_ano, competencia_mes);
CREATE INDEX IF NOT EXISTS ix_rank_marca_res_vendedor_comp ON campanhas_ranking_marca_resultados (vendedor, competencia_ano, competencia_mes);
CREATE INDEX IF NOT EXISTS ix_rank_marca_res_status ON campanhas_ranking_marca_resultados (status_pagamento);
