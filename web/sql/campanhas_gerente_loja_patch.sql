-- Campanhas por Gerente de Loja
-- Seguro para rodar mais de uma vez no Supabase.

ALTER TABLE public.campanhas_qtd
  ADD COLUMN IF NOT EXISTS campanha_tipo varchar(20) NOT NULL DEFAULT 'VENDEDOR';

ALTER TABLE public.campanhas_qtd_resultados
  ADD COLUMN IF NOT EXISTS campanha_tipo varchar(20) NOT NULL DEFAULT 'VENDEDOR';

UPDATE public.campanhas_qtd
   SET campanha_tipo = 'VENDEDOR'
 WHERE campanha_tipo IS NULL OR trim(campanha_tipo) = '';

UPDATE public.campanhas_qtd_resultados
   SET campanha_tipo = 'VENDEDOR'
 WHERE campanha_tipo IS NULL OR trim(campanha_tipo) = '';

CREATE INDEX IF NOT EXISTS ix_campanhas_qtd_tipo
  ON public.campanhas_qtd (campanha_tipo);

CREATE INDEX IF NOT EXISTS ix_campanhas_qtd_resultados_tipo
  ON public.campanhas_qtd_resultados (campanha_tipo);

CREATE INDEX IF NOT EXISTS ix_usuarios_role
  ON public.usuarios (role);

CREATE INDEX IF NOT EXISTS ix_usuario_emps_usuario_ativo_emp
  ON public.usuario_emps (usuario_id, ativo, emp);
