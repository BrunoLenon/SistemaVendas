from sqlalchemy import create_engine, text

DB_URL = "postgresql+psycopg2://postgres:%40Veipecas101@localhost:5437/sistemavendas"

engine = create_engine(DB_URL)

with engine.connect() as conn:
    result = conn.execute(text("SELECT 1"))
    print("Conexão OK:", result.scalar())
