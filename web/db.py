import os
from urllib.parse import quote_plus

from sqlalchemy import create_engine, Column, Integer, String, Float, Date, Index, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker

# =====================
# Config via ENV (Render)
# =====================
# No Render, o mais comum é existir DATABASE_URL.
# Alternativamente você pode usar DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD.
# Opcional: DB_SSLMODE (default: require)

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

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
if DATABASE_URL:
    # Render às vezes fornece "postgres://" (antigo). SQLAlchemy prefere "postgresql://".
    DB_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    if "sslmode=" not in DB_URL and DB_SSLMODE:
        joiner = "&" if "?" in DB_URL else "?"
        DB_URL = f"{DB_URL}{joiner}sslmode={DB_SSLMODE}"
    # Garante driver
    if DB_URL.startswith("postgresql://"):
        DB_URL = DB_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
else:
    if DB_PASSWORD:
        DB_URL = (
            f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
            f"?sslmode={DB_SSLMODE}"
        )
    else:
        # Dev local sem senha
        DB_URL = (
            f"postgresql+psycopg2://{DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
            f"?sslmode={DB_SSLMODE}"
        )

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
    # Para o perfil "supervisor", define a loja/filial (EMP) que ele pode visualizar.
    # Para "admin" e "vendedor", pode ficar NULL.
    emp = Column(Integer, nullable=True)


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
    qtdade_vendida = Column(Float, nullable=True)
    valor_total = Column(Float, nullable=False)

    __table_args__ = (
        # Performance
        Index("ix_vendas_vendedor_data", "vendedor", "data"),
        # Anti-duplicidade (critério mais completo, inclui tipo de movimento)
        # Deve bater com o índice/unique do Supabase.
        UniqueConstraint(
            "mestre",
            "data",
            "vendedor",
            "nota",
            "mov_tipo_movto",
            "emp",
            name="uq_vendas_mestre_data_vendedor_nota_tipo_emp",
        ),
    )


def criar_tabelas():
    Base.metadata.create_all(engine)
