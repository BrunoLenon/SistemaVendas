"""WSGI entrypoint (Render/Gunicorn).

Mantém o import do app bem previsível e resolve problemas de path quando o
Gunicorn é iniciado na raiz do projeto.

Start command recomendado no Render:
  gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 2 --timeout 180 \
    --access-logfile - --error-logfile - --log-level info --capture-output wsgi:app
"""

from __future__ import annotations

import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")

# Garante que os imports do app encontrem os módulos dentro de web/
if WEB_DIR not in sys.path:
    sys.path.insert(0, WEB_DIR)

# Importa o Flask app real
from app import app  # noqa: E402
