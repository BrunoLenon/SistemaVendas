# Thin wrapper to keep Render/Gunicorn entrypoint stable.
# The full Flask application lives in app_main.py to keep this file small.
from app_main import app  # noqa: F401
