# SistemaVendas — versão enxuta

Esta versão mantém somente os módulos essenciais:

- Dashboard leve;
- Bônus Varejo;
- Bônus Atacado (estrutura inicial, sem importador nesta etapa);
- Itens Parados;
- Itens Parados (Admin);
- Usuários;
- Configurações;
- Promoções QR;
- Trocar senha.

## O que foi desativado

As rotas antigas de campanhas, metas, ranking, relatórios, mensagens, fechamento,
importações gerais, vendas por produto, cidades/clientes, combos e financeiro não
são importadas nem registradas no Flask. Portanto, não executam consultas durante
a navegação do sistema.

O banco de dados não é apagado por este pacote. As tabelas antigas permanecem
preservadas para auditoria e eventual recuperação, mas ficam sem uso pelo app.

## Dashboard

O dashboard foi substituído por uma central de acesso sem consultas às tabelas de
vendas. Os novos indicadores poderão ser implantados depois, sobre uma estrutura
mais simples.

## Bônus

- `/bonus-varejo`: módulo atual baseado na aba `BONUS FINAL`;
- `/bonus-atacado`: página inicial reservada ao futuro importador do atacado;
- `/bonus`: redireciona para `/bonus-varejo` para preservar favoritos antigos.

## Banco de dados

Nenhum SQL novo é necessário para esta redução. As tabelas já existentes de Bônus
Varejo, Itens Parados, usuários, configurações e Promoções QR continuam sendo usadas.
