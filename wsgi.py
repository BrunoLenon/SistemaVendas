"""WSGI entrypoint for Render/Gunicorn.

Why this exists:
- Keeps a stable import path (wsgi:app) regardless of Render "Start Command".
- Avoids relying on implicit namespace packages (web.app) or --chdir.
- Ensures the /web folder is on sys.path so legacy imports like `from db import ...` work.
"""

from __future__ import annotations

import os
import sys


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")

# Guarantee that imports like `import app` (from WEB_DIR) and `from db import ...` work.
if WEB_DIR not in sys.path:
    sys.path.insert(0, WEB_DIR)

# Import the Flask app defined in web/app.py
from app import app  # noqa: E402


# Optional alias used by some platforms
application = app
