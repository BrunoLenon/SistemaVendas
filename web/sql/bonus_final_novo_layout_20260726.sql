-- SistemaVendas - atualização do módulo Bônus para a nova aba "BONUS FINAL"
-- Execute uma vez no SQL Editor do Supabase antes do deploy dos arquivos.
-- Seguro para execução repetida.

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
    bonus_final NUMERIC(18,4) NOT NULL DEFAULT 0,
    importado_em TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_bonus_usuario_periodo_emp UNIQUE (ano, mes, emp, usuario_nome)
);

ALTER TABLE public.bonus_usuarios_importados
    ADD COLUMN IF NOT EXISTS produto_vendedor NUMERIC(18,4) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS mecanico_faturado NUMERIC(18,4) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS venda_anterior NUMERIC(18,4) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS venda_atual NUMERIC(18,4) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS crescimento NUMERIC(12,6),
    ADD COLUMN IF NOT EXISTS loja_anterior NUMERIC(18,4) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS loja_atual NUMERIC(18,4) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS importado_vendedor NUMERIC(18,4) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS importado_loja NUMERIC(18,4) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS bonus_importado NUMERIC(18,4) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS valor_meta NUMERIC(18,4) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS valor_parcial NUMERIC(18,4) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS bonus_final NUMERIC(18,4) NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS ix_bonus_lotes_periodo_importado
    ON public.bonus_importacoes_lotes (ano, mes, importado_em DESC);
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
'Valores prontos importados da aba BONUS FINAL. O SistemaVendas não recalcula as métricas.';
COMMENT ON COLUMN public.bonus_usuarios_importados.produto_vendedor IS
'Coluna E: bônus de produtos do vendedor.';
COMMENT ON COLUMN public.bonus_usuarios_importados.mecanico_faturado IS
'Coluna F: valor faturado pelo mecânico.';
COMMENT ON COLUMN public.bonus_usuarios_importados.venda_anterior IS
'Coluna G: venda do vendedor no mesmo período do ano anterior.';
COMMENT ON COLUMN public.bonus_usuarios_importados.venda_atual IS
'Coluna H: venda atual do vendedor.';
COMMENT ON COLUMN public.bonus_usuarios_importados.crescimento IS
'Coluna I: percentual de crescimento do vendedor. Pode ser nulo quando a planilha não consegue calcular.';
COMMENT ON COLUMN public.bonus_usuarios_importados.loja_anterior IS
'Coluna J: venda da loja no mesmo período do ano anterior.';
COMMENT ON COLUMN public.bonus_usuarios_importados.loja_atual IS
'Coluna K: venda atual da loja totalizada com serviço.';
COMMENT ON COLUMN public.bonus_usuarios_importados.importado_vendedor IS
'Coluna N: valor de produtos importados vendido pelo vendedor.';
COMMENT ON COLUMN public.bonus_usuarios_importados.importado_loja IS
'Coluna O: valor total de produtos importados vendido na loja.';
COMMENT ON COLUMN public.bonus_usuarios_importados.bonus_importado IS
'Coluna R: bônus de importado do vendedor.';
COMMENT ON COLUMN public.bonus_usuarios_importados.valor_meta IS
'Coluna T: valor de bônus de meta calculado externamente.';
COMMENT ON COLUMN public.bonus_usuarios_importados.valor_parcial IS
'Coluna U: provisão de bônus calculada externamente.';
COMMENT ON COLUMN public.bonus_usuarios_importados.bonus_final IS
'Coluna V: valor final liberado após todos os requisitos calculados externamente.';

ALTER TABLE public.bonus_importacoes_lotes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bonus_usuarios_importados ENABLE ROW LEVEL SECURITY;

COMMIT;
