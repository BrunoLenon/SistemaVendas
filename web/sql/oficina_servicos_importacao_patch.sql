-- Patch: importação de mão de obra/oficina para compor faturamento de metas e campanhas
-- Data: 2026-06-26
-- Seguro/idempotente para Supabase/Postgres.

CREATE TABLE IF NOT EXISTS oficina_servicos (
    id SERIAL PRIMARY KEY,
    ano INTEGER NOT NULL,
    mes INTEGER NOT NULL,
    emp VARCHAR(30) NOT NULL,
    usuario VARCHAR(80) NOT NULL,
    valor_servico DOUBLE PRECISION NOT NULL DEFAULT 0,
    observacao VARCHAR(240),
    arquivo_origem VARCHAR(255),
    importado_por VARCHAR(80),
    importado_em TIMESTAMP NOT NULL DEFAULT NOW(),
    ativo BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT uq_oficina_servico_periodo_usuario UNIQUE (ano, mes, emp, usuario)
);

ALTER TABLE oficina_servicos ADD COLUMN IF NOT EXISTS observacao VARCHAR(240);
ALTER TABLE oficina_servicos ADD COLUMN IF NOT EXISTS arquivo_origem VARCHAR(255);
ALTER TABLE oficina_servicos ADD COLUMN IF NOT EXISTS importado_por VARCHAR(80);
ALTER TABLE oficina_servicos ADD COLUMN IF NOT EXISTS importado_em TIMESTAMP NOT NULL DEFAULT NOW();
ALTER TABLE oficina_servicos ADD COLUMN IF NOT EXISTS ativo BOOLEAN NOT NULL DEFAULT TRUE;

CREATE UNIQUE INDEX IF NOT EXISTS ux_oficina_servicos_periodo_usuario
    ON oficina_servicos (ano, mes, emp, usuario);

CREATE INDEX IF NOT EXISTS ix_oficina_servicos_emp_periodo
    ON oficina_servicos (emp, ano, mes);

CREATE INDEX IF NOT EXISTS ix_oficina_servicos_usuario_periodo
    ON oficina_servicos (usuario, ano, mes);

CREATE INDEX IF NOT EXISTS ix_oficina_servicos_periodo
    ON oficina_servicos (ano, mes);
