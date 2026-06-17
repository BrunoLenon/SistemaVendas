-- Patch de performance para evitar 502 por healthcheck no Render
-- Execute no SQL Editor do Supabase, fora do horário de pico se a base for grande.

CREATE INDEX IF NOT EXISTS ix_dashboard_cache_ano_mes_emp
ON public.dashboard_cache (ano, mes, emp);

CREATE INDEX IF NOT EXISTS ix_dashboard_cache_ano_mes_vendedor
ON public.dashboard_cache (ano, mes, vendedor);

CREATE INDEX IF NOT EXISTS ix_dashboard_cache_ano_mes_valor
ON public.dashboard_cache (ano, mes, valor_liquido DESC);

-- Ajuda consultas restantes por período/EMP quando o usuário abre análise detalhada.
CREATE INDEX IF NOT EXISTS ix_vendas_periodo_emp_vendedor
ON public.vendas (movimento, emp, vendedor);

CREATE INDEX IF NOT EXISTS ix_vendas_periodo_emp_mestre
ON public.vendas (movimento, emp, mestre);

CREATE INDEX IF NOT EXISTS ix_vendas_periodo_emp_marca
ON public.vendas (movimento, emp, marca);

ANALYZE public.dashboard_cache;
ANALYZE public.vendas;
