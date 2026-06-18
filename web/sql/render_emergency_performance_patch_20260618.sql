-- ============================================================
-- VEIPEÇAS / SISTEMA VENDAS
-- Patch emergencial de performance para Render 502 / SLOW_REQUEST
-- Data: 2026-06-18
-- Execute no SQL Editor do Supabase.
-- ============================================================

-- 1) Dashboard cache: a nova tela /dashboard usa esta tabela como fonte leve.
CREATE INDEX IF NOT EXISTS ix_dashboard_cache_ano_mes_emp
ON public.dashboard_cache (ano, mes, emp);

CREATE INDEX IF NOT EXISTS ix_dashboard_cache_ano_mes_vendedor
ON public.dashboard_cache (ano, mes, vendedor);

CREATE INDEX IF NOT EXISTS ix_dashboard_cache_emp_ano_mes_vendedor
ON public.dashboard_cache (emp, ano, mes, vendedor);

-- 2) Usuários/vínculos: evita SELECT DISTINCT pesado na tabela vendas para dropdown.
CREATE INDEX IF NOT EXISTS ix_usuarios_role_username_lower
ON public.usuarios ((lower(role)), username);

CREATE INDEX IF NOT EXISTS ix_usuario_emps_usuario_ativo_emp
ON public.usuario_emps (usuario_id, ativo, emp);

CREATE INDEX IF NOT EXISTS ix_usuario_emps_emp_ativo_usuario
ON public.usuario_emps (emp, ativo, usuario_id);

-- 3) Importação/reprocessamento: acelera DELETE por EMP + data e filtros por competência.
CREATE INDEX IF NOT EXISTS ix_vendas_emp_movimento
ON public.vendas (emp, movimento);

CREATE INDEX IF NOT EXISTS ix_vendas_movimento_emp_movtipo
ON public.vendas (movimento, emp, mov_tipo_movto);

-- 4) Dashboard/vendedor/relatórios: acelera filtros principais sem varrer a tabela inteira.
CREATE INDEX IF NOT EXISTS ix_vendas_vendedor_movimento_emp
ON public.vendas (vendedor, movimento, emp);

CREATE INDEX IF NOT EXISTS ix_vendas_emp_movimento_vendedor
ON public.vendas (emp, movimento, vendedor);

CREATE INDEX IF NOT EXISTS ix_vendas_emp_movimento_mestre
ON public.vendas (emp, movimento, mestre);

CREATE INDEX IF NOT EXISTS ix_vendas_emp_movimento_marca
ON public.vendas (emp, movimento, marca);

-- 5) Admin Itens Parados: acelera validação por MESTRE importado.
CREATE INDEX IF NOT EXISTS ix_vendas_upper_trim_mestre
ON public.vendas ((upper(trim(mestre))));

-- 6) Atualiza estatísticas para o planner escolher os índices novos.
ANALYZE public.dashboard_cache;
ANALYZE public.usuarios;
ANALYZE public.usuario_emps;
ANALYZE public.vendas;
