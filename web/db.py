import os
from urllib.parse import quote_plus

from sqlalchemy import create_engine, Column, Integer, String, Float, Date, Index, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker

# =====================
# Config via ENV (Render)
# =====================
# Expected on Render:
# DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
# Optional:
# DB_SSLMODE (default: require)

DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD_RAW = os.getenv("DB_PASSWORD", "")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "postgres")
DB_SSLMODE = os.getenv("DB_SSLMODE", "require")

if DB_PASSWORD_RAW:
    DB_PASSWORD = quote_plus(DB_PASSWORD_RAW)
else:
    DB_PASSWORD = ""

# Build URL
if DB_PASSWORD:
    DB_URL = f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?sslmode={DB_SSLMODE}"
else:
    # Allow passwordless local dev if user wants
    DB_URL = f"postgresql+psycopg2://{DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}?sslmode={DB_SSLMODE}"

engine = create_engine(
    DB_URL,
    pool_pre_ping=True,
    pool_recycle=1800,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    senha_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="vendedor")


class Venda(Base):
    __tablename__ = "vendas"

    id = Column(Integer, primary_key=True)

    mestre = Column(String(120), nullable=False, index=True)
    marca = Column(String(120), index=True)

    vendedor = Column(String(80), nullable=False, index=True)
    data = Column(Date, nullable=False, index=True)  # MOVIMENTO

    mov_tipo_movto = Column(String(10), nullable=False)

    nota = Column(String(60), nullable=True)  # NOTA
    emp = Column(String(30), nullable=True)   # EMP

    unit = Column(Float, nullable=True)
    des = Column(Float, nullable=True)
    qtda_vendida = Column(Float, nullable=True)
    valor_total = Column(Float, nullable=False)

    __table_args__ = (
        # Performance
        Index("ix_vendas_vendedor_data", "vendedor", "data"),
        # Anti-duplicidade (o critério mais completo)
        UniqueConstraint("mestre", "vendedor", "nota", "emp", name="uq_vendas_mestre_vendedor_nota_emp"),
    )


def criar_tabelas():
    Base.metadata.create_all(engine)
