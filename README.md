# SistemaVendas

Sistema web de gestão comercial/vendas (Flask + Supabase/PostgreSQL).

## Estrutura
- `web/` -> aplicação Flask (rotas, templates, assets)
- `sincronizador/` -> rotinas de sincronização/importação
- `processador.py` -> processamento auxiliar
- `usuarios.json` -> dados auxiliares (se aplicável)

## Requisitos
Python 3.11+ (Render pode usar 3.11/3.12; use a mesma versão localmente).

As dependências estão em `requirements.txt` (na raiz).

## Rodar localmente (Windows)
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# crie um .env na raiz (ou em web/) com as variáveis do Supabase/Postgres
# exemplo:
# DATABASE_URL=postgresql+psycopg2://USER:PASSWORD@HOST:5432/DBNAME

python -m web.app
```

## Deploy no Render
Configure no serviço:
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `gunicorn web.app:app`

Se você optar por manter o requirements em `web/requirements.txt`, então o Build Command deve ser:
`pip install -r web/requirements.txt`

## Variáveis de ambiente (Render / Supabase)
- `DATABASE_URL` (ou as variáveis usadas no seu `db.py`/config)
- `FLASK_SECRET_KEY` (se aplicável)
- outras variáveis que você já usa no projeto

## Observações
- Se o repositório estiver público, este README evita o “404” e documenta instalação/deploy.
