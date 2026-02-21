PATCH: /admin/campanhas (admin_campanhas_qtd) - listar SOMENTE campanhas_qtd

O que mudou:
- Removeu qualquer leitura de 'CampanhaQtdResultado' e variáveis relacionadas para evitar dependência de tabela de resultados.
- Mantém CRUD e as validações já existentes (ex.: bloqueio por fechamento mensal se existir no sistema).

SQL úteis (Supabase/PSQL):
1) visão geral:
select
  count(*) as total,
  sum(case when ativo = 1 then 1 else 0 end) as ativas,
  sum(case when ativo = 0 then 1 else 0 end) as inativas,
  min(data_inicio) as menor_inicio,
  max(data_fim) as maior_fim
from campanhas_qtd;

2) por EMP:
select
  emp,
  count(*) as total,
  sum(case when ativo = 1 then 1 else 0 end) as ativas,
  sum(case when ativo = 0 then 1 else 0 end) as inativas
from campanhas_qtd
group by emp
order by emp;

3) amostra (mais recentes):
select *
from campanhas_qtd
order by id desc
limit 50;

4) campanhas ativas hoje:
select *
from campanhas_qtd
where ativo = 1
  and current_date between data_inicio and data_fim
order by emp, titulo;

5) checar campos que estão vazios (prefixos):
select id, emp, titulo, produto_prefixo, descricao_prefixo, campo_match
from campanhas_qtd
where (coalesce(produto_prefixo,'') = '' and coalesce(descricao_prefixo,'') = '')
order by id desc;
