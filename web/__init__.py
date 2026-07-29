from __future__ import annotations

"""Application factory do SistemaVendas enxuto."""

import os
import sys
from flask import Flask


def _ensure_web_on_path() -> None:
    web_dir = os.path.dirname(__file__)
    base_dir = os.path.dirname(web_dir)
    if web_dir not in sys.path:
        sys.path.insert(0, web_dir)
    if base_dir not in sys.path:
        sys.path.insert(0, base_dir)


def create_app() -> Flask:
    _ensure_web_on_path()
    from web.app import app
    return app
