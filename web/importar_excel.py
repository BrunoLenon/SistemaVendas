import pandas as pd
from sqlalchemy import text
from db import engine, SessionLocal, Venda

EXCEL_PATH = r"C:\Users\lenon\Documents\SistemaVendas\planilha\vendas.xlsx"

# Colunas da sua planilha (confirmadas por você)
COL_MESTRE = "MESTRE"
COL_MARCA = "MARCA"
COL_DATA = "MOVIMENTO"
COL_TIPO = "MOV_TIPO_MOVTO"
COL_VENDEDOR = "VENDEDOR"
COL_QTDE = "QTDADE_VENDIDA"
COL_VALOR = "VALOR_TOTAL"


def main():
    df = pd.read_excel(EXCEL_PATH)

    # Normalizar tipos
    df[COL_DATA] = pd.to_datetime(df[COL_DATA], errors="coerce").dt.date

    # Se tiver linhas com data inválida, remove
    df = df.dropna(subset=[COL_DATA])

    # Limpa a tabela vendas antes de importar (evita duplicar)
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE TABLE vendas RESTART IDENTITY;"))

    # Monta objetos para inserir
    session = SessionLocal()
    try:
        objs = []
        for _, row in df.iterrows():
            objs.append(
                Venda(
                    mestre=str(row[COL_MESTRE]).strip() if pd.notna(row[COL_MESTRE]) else None,
                    marca=str(row[COL_MARCA]).strip() if pd.notna(row[COL_MARCA]) else None,
                    vendedor=str(row[COL_VENDEDOR]).strip(),
                    data=row[COL_DATA],
                    mov_tipo_movto=str(row[COL_TIPO]).strip(),
                    qtda_vendida=float(row[COL_QTDE]) if pd.notna(row[COL_QTDE]) else None,
                    valor_total=float(row[COL_VALOR]) if pd.notna(row[COL_VALOR]) else 0.0,
                )
            )

        # Inserção rápida em lote
        session.bulk_save_objects(objs)
        session.commit()

        print(f"✅ Importação concluída! Linhas importadas: {len(objs)}")

    finally:
        session.close()


if __name__ == "__main__":
    main()
