"""WSGI entrypoint (Render/Gunicorn).

Mantém compatibilidade com o comando atual: `wsgi:app`
"""
from web import create_app

app = create_app()
