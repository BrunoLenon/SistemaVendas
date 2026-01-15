import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Float, Date, Index
from sqlalchemy.orm import declarative_base, sessionmaker
from urllib.parse import quote_plus

# ===============================
# CARREGA VARIÁVEIS DO .env
# ===============================
load_dotenv()

DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "sistemavendas")

# Escapa caracteres especiais da senha (ex: @)
senha_ok = quote_plus(DB_PASSWORD)

DB_URL = f"postgresql+psycopg2://{DB_USER}:{senha_ok}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# ===============================
# SQLALCHEMY
# ===============================
engine = create_engine(DB_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ===============================
# TABELA USUÁRIOS
# ===============================
class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    senha_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="vendedor")  # vendedor/admin

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

    __table_args__ = (
        Index("ix_vendas_vendedor_data", "vendedor", "data"),
    )

def criar_tabelas():
    Base.metadata.create_all(engine)
