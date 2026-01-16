import os

from dotenv import load_dotenv
from sqlalchemy import Column, Date, Float, Index, Integer, String, create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import declarative_base, sessionmaker

# Carrega .env local (dev). Em producao (Render), configure variaveis no painel Environment.
load_dotenv()

DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "postgres")

# Monta a URL de forma segura (senha com @, :, etc) e força SSL (necessario no Supabase).
_db_url = URL.create(
    "postgresql+psycopg2",
    username=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=int(DB_PORT) if DB_PORT else None,
    database=DB_NAME,
    query={"sslmode": "require"},
)

# ===============================
# SQLALCHEMY
# ===============================
engine = create_engine(
    _db_url,
    pool_pre_ping=True,
    pool_recycle=1800,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ===============================
# TABELA USUARIOS
# ===============================
class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    senha_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="vendedor")


# ===============================
# TABELA VENDAS
# ===============================
class Venda(Base):
    __tablename__ = "vendas"

    id = Column(Integer, primary_key=True)

    mestre = Column(String(120), index=True)
    marca = Column(String(120), index=True)

    vendedor = Column(String(80), index=True, nullable=False)
    data = Column(Date, index=True, nullable=False)

    mov_tipo_movto = Column(String(5), nullable=False)
    qtda_vendida = Column(Float)
    valor_total = Column(Float, nullable=False)

    __table_args__ = (Index("ix_vendas_vendedor_data", "vendedor", "data"),)


def criar_tabelas():
    Base.metadata.create_all(engine)
