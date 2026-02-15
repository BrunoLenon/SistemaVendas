-- Campaign Engine V2 (Enterprise) - SEM MARGEM
-- Rode este arquivo 1x no Supabase SQL Editor.

CREATE TABLE IF NOT EXISTS campanhas_master_v2 (
  id BIGSERIAL PRIMARY KEY,
  titulo VARCHAR(160) NOT NULL,
  tipo VARCHAR(40) NOT NULL,
  escopo VARCHAR(20) NOT NULL DEFAULT 'EMP',
  emps_json TEXT,
  vigencia_ini DATE NOT NULL,
  vigencia_fim DATE NOT NULL,
  ativo BOOLEAN NOT NULL DEFAULT TRUE,
  regras_json TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_camp_v2_tipo_ativo ON campanhas_master_v2(tipo, ativo);
CREATE INDEX IF NOT EXISTS ix_camp_v2_escopo ON campanhas_master_v2(escopo);

CREATE TABLE IF NOT EXISTS campanhas_resultados_v2 (
  id BIGSERIAL PRIMARY KEY,
  campanha_id BIGINT NOT NULL,
  competencia_ano INT NOT NULL,
  competencia_mes INT NOT NULL,
  emp INT NOT NULL,
  vendedor VARCHAR(80) NOT NULL,
  tipo VARCHAR(40) NOT NULL,
  base_num DOUBLE PRECISION NOT NULL DEFAULT 0,
  atingiu BOOLEAN NOT NULL DEFAULT FALSE,
  valor_recompensa DOUBLE PRECISION NOT NULL DEFAULT 0,
  detalhes_json TEXT,
  vigencia_ini DATE,
  vigencia_fim DATE,
  status_pagamento VARCHAR(20) NOT NULL DEFAULT 'PENDENTE',
  pago_em TIMESTAMPTZ,
  atualizado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_camp_v2_res UNIQUE (campanha_id, competencia_ano, competencia_mes, emp, vendedor)
);

CREATE INDEX IF NOT EXISTS ix_camp_v2_res_comp_emp ON campanhas_resultados_v2(competencia_ano, competencia_mes, emp);
CREATE INDEX IF NOT EXISTS ix_camp_v2_res_vendedor ON campanhas_resultados_v2(vendedor);
CREATE INDEX IF NOT EXISTS ix_camp_v2_res_status ON campanhas_resultados_v2(status_pagamento);

CREATE TABLE IF NOT EXISTS campanhas_audit_v2 (
  id BIGSERIAL PRIMARY KEY,
  campanha_id BIGINT,
  competencia_ano INT,
  competencia_mes INT,
  emp INT,
  vendedor VARCHAR(80),
  acao VARCHAR(60) NOT NULL,
  de_status VARCHAR(20),
  para_status VARCHAR(20),
  actor VARCHAR(60),
  payload_json TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_camp_v2_audit_comp ON campanhas_audit_v2(competencia_ano, competencia_mes);
CREATE INDEX IF NOT EXISTS ix_camp_v2_audit_emp ON campanhas_audit_v2(emp);
