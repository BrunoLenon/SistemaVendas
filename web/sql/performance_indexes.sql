-- Índices recomendados (Postgres/Supabase)
-- Execute no SQL Editor do Supabase.
-- Observação: 'IF NOT EXISTS' evita erro se o índice já existir.

-- Acelera filtros por EMP + vendedor + período
CREATE INDEX IF NOT EXISTS ix_vendas_emp_vendedor_data
ON public.vendas (emp, vendedor, movimento);

-- Acelera drill-down por cliente (razao_norm) + período (por EMP)
CREATE INDEX IF NOT EXISTS ix_vendas_emp_cliente_data
ON public.vendas (emp, razao_norm, movimento);

-- Acelera consulta de itens do cliente (mestre) + período (por EMP)
CREATE INDEX IF NOT EXISTS ix_vendas_emp_mestre_data
ON public.vendas (emp, mestre, movimento);

-- Opcional: se você usa muito 'marca' nos filtros de relatório
CREATE INDEX IF NOT EXISTS ix_vendas_emp_marca_data
ON public.vendas (emp, marca, movimento);
