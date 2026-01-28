-- Cria a tabela de vínculo usuário x EMP (permissões)
create table if not exists public.usuario_emps (
  id bigserial primary key,
  usuario_id integer not null,
  emp text not null,
  created_at timestamptz not null default now(),
  unique (usuario_id, emp)
);

create index if not exists idx_usuario_emps_usuario on public.usuario_emps (usuario_id);
create index if not exists idx_usuario_emps_emp on public.usuario_emps (emp);
