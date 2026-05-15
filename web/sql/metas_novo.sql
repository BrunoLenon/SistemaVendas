-- Novo módulo oficial de Metas
-- Idempotente: pode rodar no Supabase sem apagar dados existentes.

CREATE TABLE IF NOT EXISTS metas_programas (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(180) NOT NULL,
    tipo VARCHAR(30) NOT NULL,
    ano INTEGER NOT NULL,
    mes INTEGER NOT NULL,
    ativo BOOLEAN NOT NULL DEFAULT TRUE,
    escopo VARCHAR(20) NOT NULL DEFAULT 'VENDEDOR',
    faturamento_minimo DOUBLE PRECISION DEFAULT 70000,
    margem_minima DOUBLE PRECISION,
    teto_faturamento DOUBLE PRECISION,
    teto_bonus_percentual DOUBLE PRECISION,
    created_by_user_id INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS metas_programas_emps (
    id SERIAL PRIMARY KEY,
    meta_id INTEGER NOT NULL,
    emp VARCHAR(30) NOT NULL
);

CREATE TABLE IF NOT EXISTS metas_escalas (
    id SERIAL PRIMARY KEY,
    meta_id INTEGER NOT NULL,
    ordem INTEGER NOT NULL DEFAULT 0,
    limite_min DOUBLE PRECISION NOT NULL,
    bonus_percentual DOUBLE PRECISION NOT NULL
);

CREATE TABLE IF NOT EXISTS metas_marcas (
    id SERIAL PRIMARY KEY,
    meta_id INTEGER NOT NULL,
    marca VARCHAR(120) NOT NULL
);

CREATE TABLE IF NOT EXISTS metas_bases_manuais (
    id SERIAL PRIMARY KEY,
    meta_id INTEGER NOT NULL,
    emp VARCHAR(30) NOT NULL,
    vendedor VARCHAR(80) NOT NULL,
    base_valor DOUBLE PRECISION NOT NULL DEFAULT 0,
    margem_percentual DOUBLE PRECISION,
    bonus_extra_percentual DOUBLE PRECISION DEFAULT 0,
    observacao VARCHAR(200),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS metas_resultados (
    id SERIAL PRIMARY KEY,
    meta_id INTEGER NOT NULL,
    emp VARCHAR(30) NOT NULL,
    vendedor VARCHAR(80) NOT NULL,
    ano INTEGER NOT NULL,
    mes INTEGER NOT NULL,
    valor_mes DOUBLE PRECISION NOT NULL DEFAULT 0,
    base_valor DOUBLE PRECISION,
    crescimento_pct DOUBLE PRECISION,
    mix_itens_unicos DOUBLE PRECISION,
    share_pct DOUBLE PRECISION,
    valor_marcas DOUBLE PRECISION,
    bonus_percentual DOUBLE PRECISION NOT NULL DEFAULT 0,
    premio DOUBLE PRECISION NOT NULL DEFAULT 0,
    calculado_em TIMESTAMP NOT NULL DEFAULT NOW()
);

ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS escopo varchar(20) NOT NULL DEFAULT 'VENDEDOR';
ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS faturamento_minimo double precision;
ALTER TABLE metas_programas ALTER COLUMN faturamento_minimo SET DEFAULT 70000;
UPDATE metas_programas SET faturamento_minimo = 70000 WHERE faturamento_minimo IS NULL;
ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS margem_minima double precision;
ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS teto_faturamento double precision;
ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS teto_bonus_percentual double precision;
ALTER TABLE metas_bases_manuais ADD COLUMN IF NOT EXISTS margem_percentual double precision;
ALTER TABLE metas_bases_manuais ADD COLUMN IF NOT EXISTS bonus_extra_percentual double precision;
ALTER TABLE metas_bases_manuais ADD COLUMN IF NOT EXISTS observacao varchar(200);

CREATE INDEX IF NOT EXISTS ix_metas_programas_periodo ON metas_programas (ano, mes);
CREATE INDEX IF NOT EXISTS ix_metas_programas_tipo_periodo ON metas_programas (tipo, ano, mes);
CREATE INDEX IF NOT EXISTS ix_metas_programas_emps_meta ON metas_programas_emps (meta_id);
CREATE INDEX IF NOT EXISTS ix_metas_programas_emps_emp ON metas_programas_emps (emp);
CREATE INDEX IF NOT EXISTS ix_metas_escalas_meta ON metas_escalas (meta_id);
CREATE INDEX IF NOT EXISTS ix_metas_marcas_meta ON metas_marcas (meta_id);
CREATE INDEX IF NOT EXISTS ix_metas_marcas_marca ON metas_marcas (marca);
CREATE INDEX IF NOT EXISTS ix_metas_bases_meta_emp_vendedor ON metas_bases_manuais (meta_id, emp, vendedor);
CREATE INDEX IF NOT EXISTS ix_metas_resultados_emp_periodo ON metas_resultados (emp, ano, mes);
CREATE INDEX IF NOT EXISTS ix_metas_resultados_meta_periodo ON metas_resultados (meta_id, ano, mes);

-- Índices úteis para cálculo mensal por EMP/vendedor/marca/mestre.
CREATE INDEX IF NOT EXISTS ix_vendas_metas_periodo_emp_vendedor ON vendas (ano, mes, emp, vendedor);
CREATE INDEX IF NOT EXISTS ix_vendas_metas_movimento_emp_vendedor ON vendas (movimento, emp, vendedor);
CREATE INDEX IF NOT EXISTS ix_vendas_metas_marca ON vendas (emp, vendedor, marca);
CREATE INDEX IF NOT EXISTS ix_vendas_metas_mestre ON vendas (emp, vendedor, mestre);
