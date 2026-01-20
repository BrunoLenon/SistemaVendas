import pandas as pd
from sqlalchemy import text
from db import engine

def carregar_df():
    sql = text("""
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
    """)
    with engine.connect() as conn:
        df = pd.read_sql(sql, conn)
    return df
