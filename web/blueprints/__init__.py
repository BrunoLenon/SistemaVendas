"""Blueprints do SistemaVendas.

Este pacote organiza rotas em módulos separados para reduzir o tamanho do app.py
e diminuir regressões (padrão SaaS).
"""

from .auth import bp as auth_bp
from .admin import bp as admin_bp
from .mensagens import bp as mensagens_bp

__all__ = ["auth_bp", "admin_bp", "mensagens_bp"]
