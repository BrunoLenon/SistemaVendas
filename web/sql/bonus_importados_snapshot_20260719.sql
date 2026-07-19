-- SistemaVendas - Snapshot mensal da aba "Final Bonus"
-- Objetivo: armazenar somente os valores já calculados na planilha.
-- Seguro para execução repetida no Supabase.

BEGIN;

CREATE TABLE IF NOT EXISTS public.bonus_importacoes_lotes (
    id SERIAL PRIMARY KEY,
    ano INTEGER NOT NULL,
    mes INTEGER NOT NULL CHECK (mes BETWEEN 1 AND 12),
    arquivo_origem VARCHAR(255) NOT NULL,
    importado_por_user_id INTEGER,
    importado_por VARCHAR(80),
    importado_em TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    linhas_lidas INTEGER NOT NULL DEFAULT 0,
    linhas_importadas INTEGER NOT NULL DEFAULT 0,
    linhas_ignoradas INTEGER NOT NULL DEFAULT 0,
    avisos_json TEXT
);

CREATE TABLE IF NOT EXISTS public.bonus_usuarios_importados (
    id SERIAL PRIMARY KEY,
    lote_id INTEGER NOT NULL,
    ano INTEGER NOT NULL,
    mes INTEGER NOT NULL CHECK (mes BETWEEN 1 AND 12),
    linha_origem INTEGER,

    usuario_id INTEGER,
    usuario_nome VARCHAR(80) NOT NULL,
    funcao VARCHAR(30) NOT NULL,
    emp VARCHAR(30) NOT NULL,

    importado NUMERIC(18,4) NOT NULL DEFAULT 0,
    faturamento_individual_anterior NUMERIC(18,4) NOT NULL DEFAULT 0,
    faturamento_individual_atual NUMERIC(18,4) NOT NULL DEFAULT 0,
    final_vendedor NUMERIC(18,4) NOT NULL DEFAULT 0,
    final_gerente NUMERIC(18,4) NOT NULL DEFAULT 0,

    percentual_faturamento NUMERIC(12,6) NOT NULL DEFAULT 0,
    percentual_meta NUMERIC(12,6) NOT NULL DEFAULT 0,
    valor_meta NUMERIC(18,4) NOT NULL DEFAULT 0,
    bonus_gerente_total NUMERIC(18,4) NOT NULL DEFAULT 0,

    percentual_importado NUMERIC(12,6) NOT NULL DEFAULT 0,
    percentual_bonus_importado_vendedor NUMERIC(12,6) NOT NULL DEFAULT 0,
    bonus_importado_vendedor NUMERIC(18,4) NOT NULL DEFAULT 0,

    importado_loja NUMERIC(18,4) NOT NULL DEFAULT 0,
    percentual_importado_gerente NUMERIC(12,6) NOT NULL DEFAULT 0,
    percentual_bonus_importado_loja NUMERIC(12,6) NOT NULL DEFAULT 0,
    bonus_importado_loja NUMERIC(18,4) NOT NULL DEFAULT 0,

    meta_loja NUMERIC(18,4) NOT NULL DEFAULT 0,
    venda_loja_atual NUMERIC(18,4) NOT NULL DEFAULT 0,
    crescimento_loja NUMERIC(12,6) NOT NULL DEFAULT 0,
    percentual_crescimento NUMERIC(12,6) NOT NULL DEFAULT 0,
    bonus_gerente NUMERIC(18,4) NOT NULL DEFAULT 0,

    bonus_final NUMERIC(18,4) NOT NULL DEFAULT 0,
    importado_em TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_bonus_usuario_periodo_emp
        UNIQUE (ano, mes, emp, usuario_nome)
);

CREATE INDEX IF NOT EXISTS ix_bonus_lotes_periodo_importado
    ON public.bonus_importacoes_lotes (ano, mes, importado_em DESC);

CREATE INDEX IF NOT EXISTS ix_bonus_lotes_importado_em
    ON public.bonus_importacoes_lotes (importado_em DESC);

CREATE INDEX IF NOT EXISTS ix_bonus_lotes_importado_por_user_id
    ON public.bonus_importacoes_lotes (importado_por_user_id);

CREATE INDEX IF NOT EXISTS ix_bonus_usuario_periodo
    ON public.bonus_usuarios_importados (usuario_nome, ano, mes);

CREATE INDEX IF NOT EXISTS ix_bonus_emp_periodo
    ON public.bonus_usuarios_importados (emp, ano, mes);

CREATE INDEX IF NOT EXISTS ix_bonus_funcao_periodo
    ON public.bonus_usuarios_importados (funcao, ano, mes);

CREATE INDEX IF NOT EXISTS ix_bonus_usuarios_lote_id
    ON public.bonus_usuarios_importados (lote_id);

CREATE INDEX IF NOT EXISTS ix_bonus_usuarios_usuario_id
    ON public.bonus_usuarios_importados (usuario_id);

COMMENT ON TABLE public.bonus_usuarios_importados IS
'Valores mensais já calculados externamente na aba Final Bonus. O SistemaVendas não recalcula estas métricas.';

COMMENT ON COLUMN public.bonus_usuarios_importados.bonus_importado_loja IS
'Bônus de produtos importados da empresa destinado ao gerente.';

COMMENT ON COLUMN public.bonus_usuarios_importados.bonus_gerente IS
'Bônus do gerente referente ao desempenho agregado da empresa.';

COMMIT;
