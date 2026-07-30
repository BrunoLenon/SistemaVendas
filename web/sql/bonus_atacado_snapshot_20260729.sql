-- Bônus Atacado - snapshot mensal da aba PremiacaoFinal
-- Execute no SQL Editor do Supabase antes de publicar os arquivos do módulo.

BEGIN;

CREATE TABLE IF NOT EXISTS public.bonus_atacado_importacoes_lotes (
    id BIGSERIAL PRIMARY KEY,
    ano INTEGER NOT NULL CHECK (ano BETWEEN 2000 AND 2100),
    mes INTEGER NOT NULL CHECK (mes BETWEEN 1 AND 12),
    arquivo_origem VARCHAR(255) NOT NULL,
    aba_origem VARCHAR(120) NOT NULL DEFAULT 'PremiacaoFinal',
    importado_por_user_id INTEGER,
    importado_por VARCHAR(80),
    importado_em TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    linhas_lidas INTEGER NOT NULL DEFAULT 0,
    linhas_importadas INTEGER NOT NULL DEFAULT 0,
    linhas_ignoradas INTEGER NOT NULL DEFAULT 0,
    avisos_json TEXT
);

CREATE TABLE IF NOT EXISTS public.bonus_atacado_usuarios (
    id BIGSERIAL PRIMARY KEY,
    lote_id BIGINT NOT NULL,
    ano INTEGER NOT NULL CHECK (ano BETWEEN 2000 AND 2100),
    mes INTEGER NOT NULL CHECK (mes BETWEEN 1 AND 12),
    linha_origem INTEGER,
    usuario_id INTEGER,
    usuario_nome VARCHAR(100) NOT NULL,
    funcao_planilha VARCHAR(30),
    emp VARCHAR(30) NOT NULL,
    total_produtos NUMERIC(18,4),
    venda_anterior NUMERIC(18,4),
    venda_atual NUMERIC(18,4),
    importado NUMERIC(18,4),
    percentual_importado NUMERIC(12,6),
    loja_anterior NUMERIC(18,4),
    loja_atual NUMERIC(18,4),
    falta_valor_vendedor NUMERIC(18,4),
    importado_em TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_bonus_atacado_usuario_periodo_emp
        UNIQUE (ano, mes, emp, usuario_nome)
);

CREATE INDEX IF NOT EXISTS ix_bonus_atacado_lotes_periodo_importado
    ON public.bonus_atacado_importacoes_lotes (ano, mes, importado_em DESC);

CREATE INDEX IF NOT EXISTS ix_bonus_atacado_lotes_importado_por_user_id
    ON public.bonus_atacado_importacoes_lotes (importado_por_user_id);

CREATE INDEX IF NOT EXISTS ix_bonus_atacado_usuario_periodo
    ON public.bonus_atacado_usuarios (usuario_nome, ano, mes);

CREATE INDEX IF NOT EXISTS ix_bonus_atacado_emp_periodo
    ON public.bonus_atacado_usuarios (emp, ano, mes);

CREATE INDEX IF NOT EXISTS ix_bonus_atacado_usuario_id
    ON public.bonus_atacado_usuarios (usuario_id);

CREATE INDEX IF NOT EXISTS ix_bonus_atacado_lote_id
    ON public.bonus_atacado_usuarios (lote_id);

-- As tabelas ficam fechadas para a API pública do Supabase. O backend Flask
-- acessa os dados pela conexão PostgreSQL configurada no servidor.
ALTER TABLE public.bonus_atacado_importacoes_lotes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bonus_atacado_usuarios ENABLE ROW LEVEL SECURITY;

COMMIT;

-- Conferência opcional:
SELECT tablename, rowsecurity
FROM pg_tables
WHERE schemaname = 'public'
  AND tablename IN (
      'bonus_atacado_importacoes_lotes',
      'bonus_atacado_usuarios'
  )
ORDER BY tablename;
