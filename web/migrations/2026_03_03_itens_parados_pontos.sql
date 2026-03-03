-- Veipeças / SistemaVendas - Itens Parados (PONTOS)
-- Data: 2026-03-03
-- Observação: execute no Supabase (SQL editor) antes do deploy.

-- 1) Alterar tabela existente de itens parados para suportar modo PONTOS e janela/multiplicador
ALTER TABLE IF EXISTS itens_parados
  ADD COLUMN IF NOT EXISTS modo varchar(20) NOT NULL DEFAULT 'PONTOS',
  ADD COLUMN IF NOT EXISTS data_inicio date NULL,
  ADD COLUMN IF NOT EXISTS data_fim date NULL,
  ADD COLUMN IF NOT EXISTS multiplicador_pontos double precision NOT NULL DEFAULT 1.0;

-- 2) Configuração de pontos (global ou por EMP)
CREATE TABLE IF NOT EXISTS itens_parados_pontos_config (
  id bigserial PRIMARY KEY,
  emp varchar(30) NULL,
  base_reais integer NOT NULL DEFAULT 100,
  valor_por_ponto double precision NOT NULL DEFAULT 10.0,
  ativo boolean NOT NULL DEFAULT true,
  criado_em timestamptz NOT NULL DEFAULT now(),
  atualizado_em timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_cfg_emp ON itens_parados_pontos_config(emp);

-- 3) Faixas de bônus extra
CREATE TABLE IF NOT EXISTS itens_parados_pontos_bonus (
  id bigserial PRIMARY KEY,
  emp varchar(30) NULL,
  min_pontos integer NOT NULL DEFAULT 10,
  bonus_valor double precision NOT NULL DEFAULT 50.0,
  ativo boolean NOT NULL DEFAULT true,
  criado_em timestamptz NOT NULL DEFAULT now(),
  atualizado_em timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_bonus_emp ON itens_parados_pontos_bonus(emp);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_bonus_min ON itens_parados_pontos_bonus(min_pontos);

-- 4) Fechamentos manuais (intervalo)
CREATE TABLE IF NOT EXISTS itens_parados_pontos_fechamentos (
  id bigserial PRIMARY KEY,
  emp varchar(30) NULL,
  data_inicio date NOT NULL,
  data_fim date NOT NULL,
  criado_por varchar(80) NULL,
  criado_em timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_fech_emp ON itens_parados_pontos_fechamentos(emp);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_fech_ini ON itens_parados_pontos_fechamentos(data_inicio);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_fech_fim ON itens_parados_pontos_fechamentos(data_fim);

-- 5) Resultados do fechamento (snapshot)
CREATE TABLE IF NOT EXISTS itens_parados_pontos_resultados (
  id bigserial PRIMARY KEY,
  fechamento_id bigint NOT NULL,
  emp varchar(30) NOT NULL,
  vendedor varchar(80) NOT NULL,
  valor_vendido double precision NOT NULL DEFAULT 0.0,
  pontos integer NOT NULL DEFAULT 0,
  base_reais integer NOT NULL DEFAULT 100,
  valor_por_ponto double precision NOT NULL DEFAULT 10.0,
  bonus_extra double precision NOT NULL DEFAULT 0.0,
  total double precision NOT NULL DEFAULT 0.0,
  status_pagamento varchar(20) NOT NULL DEFAULT 'PENDENTE',
  pago_em timestamptz NULL,
  criado_em timestamptz NOT NULL DEFAULT now(),
  atualizado_em timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_res_emp ON itens_parados_pontos_resultados(emp);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_res_vend ON itens_parados_pontos_resultados(vendedor);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_res_fech ON itens_parados_pontos_resultados(fechamento_id);

-- 6) Seeds (opcional): regra global padrão e faixas padrão
INSERT INTO itens_parados_pontos_config(emp, base_reais, valor_por_ponto, ativo)
SELECT NULL, 100, 10.0, true
WHERE NOT EXISTS (SELECT 1 FROM itens_parados_pontos_config WHERE emp IS NULL AND ativo = true);

-- Faixas sugeridas (ajuste no Admin depois)
INSERT INTO itens_parados_pontos_bonus(emp, min_pontos, bonus_valor, ativo)
SELECT NULL, v.min_pontos, v.bonus_valor, true
FROM (VALUES (10, 50.0), (20, 150.0), (30, 300.0)) AS v(min_pontos, bonus_valor)
WHERE NOT EXISTS (SELECT 1 FROM itens_parados_pontos_bonus WHERE emp IS NULL AND min_pontos = v.min_pontos);
