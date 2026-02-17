from __future__ import annotations

import os
import threading
import time
from sqlalchemy import text

from db import engine


# ==============================
# Cache leve em memória (pandas)
# ==============================
# Objetivo: evitar recarregar TODAS as vendas do banco a cada request.
# Em produção (Render), isso reduz bastante o tempo de abertura do dashboard.
#
# Observação: é um cache por processo (cada worker tem o seu). Mesmo assim,
# já ajuda muito.

_DF_CACHE_LOCK = threading.Lock()
_DF_CACHE: dict[str, object] = {"df": None, "ts": 0.0}


def carregar_df(force: bool = False):
    """Carrega dataframe de vendas do banco.

    Usa cache em memória com TTL (segundos). Configure com:
      DF_CACHE_SECONDS=60

    Use force=True para ignorar o cache (ex.: após importação ou limpeza).
    """
    import pandas as pd

    ttl = int(os.getenv("DF_CACHE_SECONDS", "60") or 60)
    now = time.time()

    if not force and ttl > 0:
        with _DF_CACHE_LOCK:
            cached_df = _DF_CACHE.get("df")
            ts = float(_DF_CACHE.get("ts") or 0.0)
            if cached_df is not None and (now - ts) < ttl:
                # Retorna cópia para evitar efeitos colaterais se o código
                # adicionar colunas/alterar tipos.
                return cached_df.copy(deep=False)

    sql = text(
        """
        SELECT
            mestre AS "MESTRE",
            marca AS "MARCA",
            movimento AS "MOVIMENTO",
            mov_tipo_movto AS "MOV_TIPO_MOVTO",
            vendedor AS "VENDEDOR",
            emp AS "EMP",
            qtdade_vendida AS "QTDADE_VENDIDA",
            valor_total AS "VALOR_TOTAL"
        FROM vendas
        """
    )

    with engine.connect() as conn:
        df = pd.read_sql(sql, conn)

    if ttl > 0:
        with _DF_CACHE_LOCK:
            _DF_CACHE["df"] = df
            _DF_CACHE["ts"] = now

    return df


def limpar_cache_df() -> None:
    """Força limpeza do cache de dataframe."""
    with _DF_CACHE_LOCK:
        _DF_CACHE["df"] = None
        _DF_CACHE["ts"] = 0.0
