-- Financeiro de Bônus — fechamento imutável por competência e EMP
-- Execute no Supabase antes de publicar os arquivos do módulo.

BEGIN;

CREATE TABLE IF NOT EXISTS public.financeiro_bonus_fechamentos (
    id BIGSERIAL PRIMARY KEY,
    ano INTEGER NOT NULL,
    mes INTEGER NOT NULL,
    emp VARCHAR(30) NOT NULL,
    status VARCHAR(12) NOT NULL DEFAULT 'ABERTO',
    pago BOOLEAN NOT NULL DEFAULT FALSE,
    versao INTEGER NOT NULL DEFAULT 0,

    total_varejo NUMERIC(18,4) NOT NULL DEFAULT 0,
    total_atacado NUMERIC(18,4) NOT NULL DEFAULT 0,
    total_itens_parados NUMERIC(18,4) NOT NULL DEFAULT 0,
    total_outros_varejo NUMERIC(18,4) NOT NULL DEFAULT 0,
    total_outros_atacado NUMERIC(18,4) NOT NULL DEFAULT 0,
    total_geral NUMERIC(18,4) NOT NULL DEFAULT 0,

    fechado_por_user_id INTEGER,
    fechado_por VARCHAR(100),
    fechado_em TIMESTAMP,
    reaberto_por_user_id INTEGER,
    reaberto_por VARCHAR(100),
    reaberto_em TIMESTAMP,
    pago_por_user_id INTEGER,
    pago_por VARCHAR(100),
    pago_em TIMESTAMP,
    atualizado_em TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_financeiro_bonus_fechamento_periodo_emp
        UNIQUE (ano, mes, emp),
    CONSTRAINT ck_financeiro_bonus_status
        CHECK (status IN ('ABERTO', 'FECHADO')),
    CONSTRAINT ck_financeiro_bonus_mes
        CHECK (mes BETWEEN 1 AND 12)
);

CREATE TABLE IF NOT EXISTS public.financeiro_bonus_fechamento_itens (
    id BIGSERIAL PRIMARY KEY,
    fechamento_id BIGINT NOT NULL
        REFERENCES public.financeiro_bonus_fechamentos(id) ON DELETE CASCADE,
    usuario_id INTEGER,
    usuario_nome VARCHAR(100) NOT NULL,
    funcao VARCHAR(30),
    emp VARCHAR(30) NOT NULL,

    bonus_varejo NUMERIC(18,4) NOT NULL DEFAULT 0,
    bonus_atacado NUMERIC(18,4) NOT NULL DEFAULT 0,
    itens_parados NUMERIC(18,4) NOT NULL DEFAULT 0,
    outros_varejo NUMERIC(18,4) NOT NULL DEFAULT 0,
    outros_atacado NUMERIC(18,4) NOT NULL DEFAULT 0,
    total_geral NUMERIC(18,4) NOT NULL DEFAULT 0,
    outros_detalhes_json TEXT,
    criado_em TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_financeiro_bonus_item_fechamento_usuario
        UNIQUE (fechamento_id, emp, usuario_nome)
);

CREATE TABLE IF NOT EXISTS public.financeiro_bonus_eventos (
    id BIGSERIAL PRIMARY KEY,
    fechamento_id BIGINT NOT NULL
        REFERENCES public.financeiro_bonus_fechamentos(id) ON DELETE CASCADE,
    acao VARCHAR(20) NOT NULL,
    status_anterior VARCHAR(12),
    status_novo VARCHAR(12),
    pago_anterior BOOLEAN,
    pago_novo BOOLEAN,
    total_geral NUMERIC(18,4) NOT NULL DEFAULT 0,
    usuario_id INTEGER,
    usuario_nome VARCHAR(100),
    detalhes TEXT,
    criado_em TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_financeiro_bonus_periodo_emp
    ON public.financeiro_bonus_fechamentos (ano, mes, emp);
CREATE INDEX IF NOT EXISTS ix_financeiro_bonus_status_periodo
    ON public.financeiro_bonus_fechamentos (ano, mes, status, pago);
CREATE INDEX IF NOT EXISTS ix_financeiro_bonus_item_fechamento
    ON public.financeiro_bonus_fechamento_itens (fechamento_id);
CREATE INDEX IF NOT EXISTS ix_financeiro_bonus_item_emp_usuario
    ON public.financeiro_bonus_fechamento_itens (emp, usuario_nome);
CREATE INDEX IF NOT EXISTS ix_financeiro_bonus_evento_fechamento
    ON public.financeiro_bonus_eventos (fechamento_id, criado_em);

ALTER TABLE public.financeiro_bonus_fechamentos ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.financeiro_bonus_fechamento_itens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.financeiro_bonus_eventos ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE public.financeiro_bonus_fechamentos IS
    'Estado do fechamento por competência e EMP. FECHADO congela os valores até reabertura.';
COMMENT ON TABLE public.financeiro_bonus_fechamento_itens IS
    'Snapshot por funcionário gravado no instante do fechamento.';
COMMENT ON TABLE public.financeiro_bonus_eventos IS
    'Auditoria de fechamento, reabertura, pagamento e retirada de pagamento.';

COMMIT;
