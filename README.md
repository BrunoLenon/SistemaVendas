# SistemaVendas

Sistema web de **gestão comercial/vendas** com **campanhas (quantidade e combo)**, metas, relatórios e fechamento mensal.

## Stack
- Backend: Python + Flask
- Banco: Supabase (PostgreSQL)
- Deploy: Render (Gunicorn)

## Rodar localmente
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/Mac: source .venv/bin/activate
pip install -r requirements.txt
set FLASK_ENV=development
python web/app.py
```

> Configure suas variáveis em `.env` (use `.env.example` como base).

## Deploy (Render)
Use um **Procfile** na raiz:
`web: gunicorn --chdir web app:app`

## Campanhas: como funciona (resumo)
Veja `docs/campanhas.md`.
