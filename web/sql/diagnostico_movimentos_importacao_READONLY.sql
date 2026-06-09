-- Diagnóstico READONLY: conferir valores importados por tipo de movimento.
-- Ajuste EMP/ANO/MES no bloco params antes de executar.

with params as (
    select
        '101'::text as emp,
        2026::int as ano,
        6::int as mes
), base as (
    select
        upper(trim(coalesce(v.mov_tipo_movto, ''))) as movimento,
        count(*) as linhas,
        coalesce(sum(case when coalesce(v.qtdade_vendida, 0) > 0 then v.qtdade_vendida else 0 end), 0) as qtd_considerada,
        coalesce(sum(case when coalesce(v.qtdade_vendida, 0) > 0 then v.valor_total else 0 end), 0) as valor_considerado
    from vendas v
    join params p on p.emp = v.emp
    where v.movimento >= make_date(p.ano, p.mes, 1)
      and v.movimento < (make_date(p.ano, p.mes, 1) + interval '1 month')
    group by upper(trim(coalesce(v.mov_tipo_movto, '')))
), classificado as (
    select
        movimento,
        linhas,
        qtd_considerada,
        valor_considerado,
        case
            when movimento in ('OA', 'OV', 'SV', 'VA', 'VV') then 'VENDA'
            when movimento = 'CA' then 'CANCELAMENTO'
            when movimento = 'DS' then 'DEVOLUCAO'
            else 'IGNORADO_NO_CALCULO'
        end as regra
    from base
)
select *
from classificado
order by regra, movimento;

-- Resumo financeiro pela regra oficial:
with params as (
    select
        '101'::text as emp,
        2026::int as ano,
        6::int as mes
), base as (
    select
        upper(trim(coalesce(v.mov_tipo_movto, ''))) as movimento,
        coalesce(v.qtdade_vendida, 0) as qtd,
        coalesce(v.valor_total, 0) as valor
    from vendas v
    join params p on p.emp = v.emp
    where v.movimento >= make_date(p.ano, p.mes, 1)
      and v.movimento < (make_date(p.ano, p.mes, 1) + interval '1 month')
)
select
    coalesce(sum(case when qtd > 0 and movimento in ('OA', 'OV', 'SV', 'VA', 'VV') then valor else 0 end), 0) as total_vendas,
    coalesce(sum(case when qtd > 0 and movimento = 'CA' then abs(valor) else 0 end), 0) as total_cancelamentos,
    coalesce(sum(case when qtd > 0 and movimento = 'DS' then abs(valor) else 0 end), 0) as total_devolucoes,
    coalesce(sum(case
        when qtd > 0 and movimento in ('OA', 'OV', 'SV', 'VA', 'VV') then valor
        when qtd > 0 and movimento in ('CA', 'DS') then -abs(valor)
        else 0
    end), 0) as total_liquido_oficial,
    coalesce(sum(case when qtd <= 0 then 1 else 0 end), 0) as linhas_qtd_zero
from base;
