# Varredura enterprise — SistemaVendas (snapshot do /web enviado)

Este relatório **não altera nada** no seu repositório; ele apenas documenta inconsistências encontradas e o que o patch anexado corrige.

## 1) Problema principal (Ranking por Marca)

**Sintomas relatados**
- Página /admin/campanhas/ranking-marca instável (500 por `url_for('campanhas')`).
- Formulário vinha com valores pré-preenchidos e acabava salvando 3º prêmio mesmo quando você não queria.
- Recalcular/Ver ranking retornando vazio.

**Causas prováveis identificadas**
- Template `admin_campanhas_ranking_marca.html` chamava `url_for('campanhas')`, mas no sistema o endpoint real é `campanhas_qtd`.
- Inputs vinham com `value="10000/300/200/100"` (isso **é enviado no POST** mesmo que você não digite nada).
- Cálculo filtrava marca com igualdade exata (`UPPER(marca) == 'MAGNETRON'`) sem `TRIM` e sem tolerar variações; se a marca estiver como `MAGNETRON `, `MAGNETRON - ...`, etc, zera o resultado.


**O patch entregue corrige**
- Troca o link de volta para `url_for('campanhas_qtd')`.
- Remove `value=` dos campos e deixa só `placeholder=`.
- Ajusta o backend para não “inventar” prêmio padrão (defaults agora são **0**).
- Ajusta o filtro de marca para `TRIM + UPPER` e permite match `EXATO ou CONTÉM` (mais tolerante).
- Adiciona botão **Excluir** (POST action=remover) na listagem.

## 2) Endpoints usados em templates vs endpoints existentes

### 2.1 Endpoints *não encontrados* (potenciais 500 quando esses templates forem acessados)

- `campanhas` → usado em: `templates/admin_campanhas_ranking_marca.html`
- `admin_campanhas_v2_recalcular_uma` → usado em: `templates/admin_campanhas_v2.html`
- `admin_campanhas_v2_toggle` → usado em: `templates/admin_campanhas_v2.html`
- `admin_campanhas_v2_duplicar` → usado em: `templates/admin_campanhas_v2.html`
- `admin_campanhas_v2_delete` → usado em: `templates/admin_campanhas_v2.html`
- `admin_fechamento_detalhes` → usado em: `templates/admin_fechamento_detalhes.html`
- `financeiro_campanhas_v2_export` → usado em: `templates/financeiro_campanhas_v2.html`

### 2.2 Observação importante sobre blueprints
- Seu projeto possui `auth` como Blueprint (`web/auth.py`). Quando templates usam `url_for('auth.logout')`, isso só funciona se o blueprint estiver registrado com name `auth` (o que parece ser o caso).


## 3) Rotas duplicadas/colidindo
- No `web/app.py` não encontrei rotas duplicadas com o mesmo path+method. O principal problema detectado foi **template chamando endpoint inexistente**.


## 4) Serviços V1 vs V2 (campanhas_service.py vs campanhas_v2_service.py)

- `services/campanhas_service.py` → **V1**: lógica mais antiga de campanhas/combos e relatórios (tende a fazer mais cálculo direto).
- `services/campanhas_v2_engine.py` + `services/campanhas_v2_service.py` → **V2**: motor/snapshot (separação de config x execução e gravação em tabelas de resultado), alinhado com sua meta de performance.

**O que é seguro manter agora**
- Mantenha os dois enquanto existirem páginas usando V1.
- Evite “misturar” chamadas: páginas novas (como ranking por marca) devem ficar na V2 (snapshot).

**Como aposentar com segurança (recomendado)**
1. Mapear quais rotas importam `campanhas_service.py` vs `campanhas_v2_service.py`.
2. Migrar página por página para V2.
3. Só então remover V1.


## 5) Recomendações de estabilidade (curtas)
- Centralizar nomes de endpoints (ou criar aliases) para evitar que templates quebrem quando você renomeia funções.
- Para filtros de texto (marca, vendedor), normalize sempre (`TRIM`, `UPPER`) e considere fallback `LIKE` quando não houver match exato.
- Logar no recalcular (info) a janela usada e quantos vendedores retornaram; isso acelera diagnóstico no Render.


## Evolução (v56 -> v57) — Relatório Unificado / Segurança / Performance

### Implementado no código
- **Relatório unificado** em `/relatorios/campanhas` (QTD + COMBO + ITENS PARADOS) com:
  - tabela consolidada, filtros (mês/ano, EMP, vendedor), KPIs e gráficos (Chart.js);
  - paginação server-side simples (`page`/`per_page`);
  - **recalculo on-demand** via `?recalc=1` (evita recálculo automático a cada acesso);
  - exportação **CSV** em `/relatorios/campanhas/export.csv`.
- **Novo snapshot** (proposto e modelado): `itens_parados_resultados` (`ItemParadoResultado`) para acelerar relatórios e permitir `status_pagamento`/`pago_em` nos itens parados.

### Recomendações (próximos passos)
- Autenticação:
  - Migrar 100% para **Flask-Login** (sessão server-side) e/ou JWT apenas para APIs.
  - Ativar cookies com `Secure` + `SameSite=Lax` já está feito; considerar `SameSite=Strict` em rotas sem integrações.
- Rate limiting:
  - Trocar rate-limit em memória por Redis (ex.: Flask-Limiter) para múltiplos workers.
- Auditoria:
  - Persistir logs críticos em tabela (audit trail) com quem/quando/o quê (ex.: alterações de status de pagamento, exclusões).
- Banco/SQL:
  - Índices sugeridos (se ainda não existirem):
    - `campanhas_qtd_resultados (emp, competencia_ano, competencia_mes)`
    - `campanhas_combo_resultados (emp, competencia_ano, competencia_mes)`
    - `itens_parados_resultados (emp, competencia_ano, competencia_mes)`
    - `vendas (emp, movimento, vendedor)` (muito usado em relatórios)
- Performance:
  - Cache de relatório (Redis / Flask-Caching) por competência+escopo.
  - Job assíncrono para snapshots (Celery/APS/cron) + botão “recalcular” apenas dispara job.
- Segurança Web:
  - CSP mais restritiva (whitelist do bootstrap cdn + chart.js), e hardening de headers.
  - Sanitização de campos exibidos em HTML (Jinja já escapa por padrão; evitar `|safe`).

