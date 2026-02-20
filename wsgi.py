"""WSGI entrypoint para Render.
Mantém o boot simples e previsível.
"""
import os
import sys

BASE_DIR = os.path.dirname(__file__)
WEB_DIR = os.path.join(BASE_DIR, "web")

# 1) permite `import web` (pacote) a partir do diretório raiz
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# 2) mantém compatibilidade com imports antigos (ex.: `from db import ...`)
if WEB_DIR not in sys.path:
    sys.path.insert(0, WEB_DIR)

from web import create_app  # noqa: E402

app = create_app()
