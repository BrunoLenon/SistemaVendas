"""WSGI entrypoint para Render.
Mantém o boot simples e previsível.
"""
import os, sys

BASE_DIR = os.path.dirname(__file__)
WEB_DIR = os.path.join(BASE_DIR, "web")

# garante imports do web/
if WEB_DIR not in sys.path:
    sys.path.insert(0, WEB_DIR)

from app import app  # noqa: E402,F401
