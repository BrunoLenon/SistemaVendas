-- Lançamentos manuais de Outros Valores nos módulos Bônus Varejo e Atacado.
-- Seguro para executar mais de uma vez no Supabase.

CREATE TABLE IF NOT EXISTS public.bonus_outros_valores (
    id BIGSERIAL PRIMARY KEY,
    origem VARCHAR(10) NOT NULL,
    ano INTEGER NOT NULL,
    mes INTEGER NOT NULL,
    usuario_id BIGINT NOT NULL,
    usuario_nome VARCHAR(100) NOT NULL,
    emp VARCHAR(30) NOT NULL,
    descricao VARCHAR(255) NOT NULL,
    valor NUMERIC(18,4) NOT NULL,
    criado_por_user_id BIGINT NULL,
    criado_por VARCHAR(100) NULL,
    criado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_bonus_outros_origem
        CHECK (origem IN ('VAREJO', 'ATACADO')),
    CONSTRAINT ck_bonus_outros_valor_positivo
        CHECK (valor > 0)
);

CREATE INDEX IF NOT EXISTS ix_bonus_outros_origem_periodo
    ON public.bonus_outros_valores (origem, ano, mes);
CREATE INDEX IF NOT EXISTS ix_bonus_outros_usuario_periodo
    ON public.bonus_outros_valores (usuario_id, ano, mes);
CREATE INDEX IF NOT EXISTS ix_bonus_outros_emp_periodo
    ON public.bonus_outros_valores (emp, ano, mes);
CREATE INDEX IF NOT EXISTS ix_bonus_outros_usuario_nome
    ON public.bonus_outros_valores (usuario_nome);
CREATE INDEX IF NOT EXISTS ix_bonus_outros_criado_por_user_id
    ON public.bonus_outros_valores (criado_por_user_id);

ALTER TABLE public.bonus_outros_valores ENABLE ROW LEVEL SECURITY;
