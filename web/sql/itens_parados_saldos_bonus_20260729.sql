-- Saldo mensal importado de vendas de Itens Parados
-- Seguro para executar mais de uma vez no Supabase.

CREATE TABLE IF NOT EXISTS public.itens_parados_vendas_importacoes (
    id BIGSERIAL PRIMARY KEY,
    ano INTEGER NOT NULL,
    mes INTEGER NOT NULL,
    arquivo_origem VARCHAR(255) NOT NULL,
    importado_por_user_id BIGINT NULL,
    importado_por VARCHAR(80) NULL,
    importado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data_inicio DATE NULL,
    data_fim DATE NULL,
    linhas_lidas INTEGER NOT NULL DEFAULT 0,
    linhas_importadas INTEGER NOT NULL DEFAULT 0,
    linhas_ignoradas INTEGER NOT NULL DEFAULT 0,
    registros_usuarios INTEGER NOT NULL DEFAULT 0,
    valor_total NUMERIC(18,4) NOT NULL DEFAULT 0,
    avisos_json TEXT NULL
);

CREATE TABLE IF NOT EXISTS public.itens_parados_vendas_usuarios (
    id BIGSERIAL PRIMARY KEY,
    lote_id BIGINT NOT NULL,
    ano INTEGER NOT NULL,
    mes INTEGER NOT NULL,
    usuario_id BIGINT NULL,
    usuario_nome VARCHAR(100) NOT NULL,
    emp VARCHAR(30) NOT NULL,
    valor_total NUMERIC(18,4) NOT NULL DEFAULT 0,
    qtd_linhas INTEGER NOT NULL DEFAULT 0,
    qtd_itens INTEGER NOT NULL DEFAULT 0,
    importado_em TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_itens_parados_vendas_usuario_periodo_emp
        UNIQUE (ano, mes, emp, usuario_nome)
);

CREATE INDEX IF NOT EXISTS ix_itens_parados_vendas_lote_periodo
    ON public.itens_parados_vendas_importacoes (ano, mes, importado_em DESC);
CREATE INDEX IF NOT EXISTS ix_itens_parados_vendas_lote_usuario
    ON public.itens_parados_vendas_importacoes (importado_por_user_id);
CREATE INDEX IF NOT EXISTS ix_itens_parados_vendas_usuario_periodo
    ON public.itens_parados_vendas_usuarios (usuario_nome, ano, mes);
CREATE INDEX IF NOT EXISTS ix_itens_parados_vendas_emp_periodo
    ON public.itens_parados_vendas_usuarios (emp, ano, mes);
CREATE INDEX IF NOT EXISTS ix_itens_parados_vendas_usuario_id
    ON public.itens_parados_vendas_usuarios (usuario_id);
CREATE INDEX IF NOT EXISTS ix_itens_parados_vendas_lote_id
    ON public.itens_parados_vendas_usuarios (lote_id);

ALTER TABLE public.itens_parados_vendas_importacoes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.itens_parados_vendas_usuarios ENABLE ROW LEVEL SECURITY;
