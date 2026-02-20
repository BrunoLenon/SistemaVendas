"""Pacote web (SaaS-ready).

Mantém compatibilidade com o padrão atual do projeto (imports estilo 'from db import ...')
e introduz App Factory para boot previsível (Render/Gunicorn).
"""

from __future__ import annotations

from typing import Any

def create_app(**kwargs: Any):
    """Cria e retorna a instância Flask do sistema.

    Neste passo (migração segura), reutilizamos o app existente em web/app.py.
    Próximos passos moverão rotas para blueprints e reduzirão o tamanho do app.py.
    """
    # Import tardio para evitar efeitos colaterais no import do pacote.
    from .app import app as _app  # noqa: WPS433

    return _app
