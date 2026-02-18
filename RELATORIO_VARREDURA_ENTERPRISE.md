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
