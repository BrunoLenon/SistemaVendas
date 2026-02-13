"""
Service para montar o contexto do /relatorios/campanhas.
Patch: compatibilidade com itens_parados.ativo como BOOLEAN (Supabase/Postgres).
- Evita comparar boolean com integer (ativo = 1).
- Usa ItemParado.ativo.is_(True) quando a coluna é boolean.
- Mantém fallback para bases legadas onde ativo ainda seja integer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from sqlalchemy import and_
from sqlalchemy.orm import Session

# Os models são importados do db.py
from db import ItemParado  # type: ignore


def _is_boolean_column(model, col_name: str) -> bool:
    """
    Detecta se a coluna é BOOLEAN no SQLAlchemy/Postgres.
    Funciona mesmo com reflected types.
    """
    try:
        col = getattr(model, col_name).property.columns[0]
        # SQLAlchemy Boolean type usually has python_type == bool
        return getattr(col.type, "python_type", None) is bool
    except Exception:
        return False


def _filter_ativo_true(query, model):
    """
    Aplica filtro 'ativo' compatível com boolean/integer.
    - boolean: ativo IS TRUE
    - integer: ativo = 1
    """
    if _is_boolean_column(model, "ativo"):
        return query.filter(getattr(model, "ativo").is_(True))
    # fallback legado (0/1)
    return query.filter(getattr(model, "ativo") == 1)


def carregar_itens_parados_por_emp(db: Session, emp: str):
    """
    Carrega itens_parados ativos de uma EMP, ordenados por descrição/código.
    Retorna lista de ItemParado.
    """
    q = db.query(ItemParado).filter(ItemParado.emp == str(emp))
    q = _filter_ativo_true(q, ItemParado)
    q = q.order_by(ItemParado.descricao.asc(), ItemParado.codigo.asc())
    return q.all()


# -------------------------
# A partir daqui, o restante do service depende do seu projeto.
# Este patch contém apenas a função usada pelo relatório para evitar 500.
# Caso seu service possua outra função que consulta ItemParado, aplique o mesmo padrão.
# -------------------------
