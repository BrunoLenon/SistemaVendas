"""WSGI entrypoint para Render.
Mantém o boot simples e previsível.
"""

import os
import sys
import warnings
from requests.exceptions import RequestsDependencyWarning

# Suprime o warning de dependência do requests (urllib3/charset-normalizer)
warnings.filterwarnings("ignore", category=RequestsDependencyWarning)

BASE_DIR = os.path.dirname(__file__)
WEB_DIR = os.path.join(BASE_DIR, "web")

# Garante que o diretório 'web' esteja no path para imports
if WEB_DIR not in sys.path:
    sys.path.insert(0, WEB_DIR)

# Importa a aplicação Flask
from app import app  # noqa: E402