# Campanhas — Esboço de Cálculo

Este documento descreve o **modelo mental** e o **cálculo esperado** para campanhas de Quantidade e Combo.

## 1) Conceitos

- **Campanha** = regra/configuração (o que vale, quando vale, para quem vale)
- **Apuração** = processo que lê as vendas no período e gera um *snapshot*
- **Resultado** = fotografia por (EMP, vendedor, campanha, competência mês/ano)

Campos recomendados em resultados:
- `competencia_ano`, `competencia_mes`
- `emp`, `vendedor`
- `campanha_id` (ou `combo_id`)
- `atingiu`/`atingiu_gate`
- `qtd_base` (quantidade relevante)
- `qtd_unidades_premiadas` / `qtd_combos`
- `valor_recompensa`
- `status_pagamento` (PENDENTE / A_PAGAR / PAGO)
- `apurado_em`, `apurado_por`

## 2) Campanha de Quantidade (campanhas_qtd)

### Regra (exemplo)
- Produto prefixo = `ABC`
- Marca = `X`
- Mínimo = 10 unidades
- Recompensa unitária = R$ 2,50 por unidade (ou por bloco)

### Apuração (SQL base)
1) Filtrar vendas no período e escopo (EMP(s) e/ou vendedor)
2) Filtrar pelo produto/marca
3) Agrupar por (emp, vendedor)
4) Calcular `qtd_total`

### Cálculo (Python/pseudocódigo)
- Se `qtd_total < minimo_qtd` → `atingiu = false`, `valor = 0`
- Se `qtd_total >= minimo_qtd`:
  - **Modo A (por unidade, após gate)**: `valor = qtd_total * valor_unitario`
  - **Modo B (por blocos)**: `blocos = floor(qtd_total / minimo_qtd)` e `valor = blocos * valor_recompensa_bloco`

> O seu sistema hoje já segue majoritariamente o **Modo A** (gate + valor por unidade).

## 3) Campanha de Combo (campanhas_combo + campanhas_combo_itens)

### Regra (exemplo)
- Itens do combo:
  - Item 1: produto prefixo `PNEU` mínimo 2
  - Item 2: produto prefixo `OLEO` mínimo 1
- Recompensa:
  - **Global**: `combo.valor_unitario_global` (por unidade vendida, após gate) **ou**
  - **Por item**: `it.valor_unitario` (por unidade vendida daquele item, após gate)

### Apuração
1) Buscar combos ativos no mês (overlap entre datas do combo e o mês)
2) Para cada combo, listar itens
3) Para cada item, somar a quantidade vendida por (emp, vendedor) no período do combo
4) Regra de gate: o vendedor precisa atingir **o mínimo de TODOS os itens**

### Cálculo recomendado (2 opções)
**Opção 1 — Gate + comissão por unidade (modelo atual)**
- Se não bateu mínimo em algum item → 0
- Se bateu → somar `qtd_item * valor_unitario_item` (ou global)

**Opção 2 — Por número de combos completos (mais “padrão combo”)**
- `qtd_combos = min( floor(qtd_item / minimo_item) para todos os itens )`
- `valor = qtd_combos * valor_premio_por_combo`

## 4) Regras de prioridade (quando houver campanhas sobrepostas)
- Campanha específica do vendedor deve substituir a geral (mesma chave de regra)
- Em empate: preferir a campanha com maior `prioridade` ou mais recente

## 5) Boas práticas
- Armazenar valores monetários como `numeric(12,2)` no Postgres
- Garantir FKs (combo_id, campanha_id) para evitar órfãos
- Apurar via job/cron (evitar travar request web)
