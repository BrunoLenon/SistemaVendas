import os
from datetime import datetime
from urllib.parse import quote_plus

from sqlalchemy import create_engine, Column, Integer, String, Float, Date, DateTime, Text, Boolean, Index, UniqueConstraint, text
from sqlalchemy.orm import declarative_base, sessionmaker, synonym

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
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    # Importante: por padrão o SQLAlchemy "expira" os objetos após commit.
    # Como o app usa a sessão em um context manager e fecha logo depois,
    # acessar atributos no template pode disparar refresh e gerar
    # DetachedInstanceError. Mantendo os valores carregados após commit,
    # o template consegue renderizar sem precisar da sessão.
    expire_on_commit=False,
)
Base = declarative_base()


class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    senha_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="vendedor")
    # Para o perfil "supervisor", define a loja/filial (EMP) que ele pode visualizar.
    # Para "admin" e "vendedor", pode ficar NULL.
    #
    # Importante: já existiram versões do banco onde EMP foi criada como texto.
    # Para manter compatibilidade (e evitar que o supervisor fique "sem EMP"),
    # armazenamos como string.
    emp = Column(String(30), nullable=True)



class UsuarioEmp(Base):
    __tablename__ = "usuario_emps"

    id = Column(Integer, primary_key=True)
    usuario_id = Column(Integer, nullable=False, index=True)
    emp = Column(String(30), nullable=False, index=True)
    ativo = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("usuario_id", "emp", name="uq_usuario_emps_usuario_emp"),
    )


class Emp(Base):
    """Cadastro de EMP (loja/filial).

    `codigo` é o identificador que também aparece nas vendas e nos vínculos de usuário.
    """

    __tablename__ = "emps"

    id = Column(Integer, primary_key=True)
    codigo = Column(String(30), nullable=False, unique=True, index=True)
    nome = Column(String(120), nullable=False)
    cidade = Column(String(120), nullable=True)
    uf = Column(String(2), nullable=True)
    ativo = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_emps_uf", "uf"),
        Index("ix_emps_cidade", "cidade"),
    )

class Venda(Base):
    __tablename__ = "vendas"

    id = Column(Integer, primary_key=True)

    mestre = Column(String(120), nullable=False, index=True)
    marca = Column(String(120), index=True)

    vendedor = Column(String(80), nullable=False, index=True)

    # No banco a coluna se chama 'movimento' (planilha: MOVIMENTO)
    movimento = Column(Date, nullable=False, index=True)
    # Alias para manter compatibilidade com código legado que usa Venda.data
    data = synonym("movimento")

    mov_tipo_movto = Column(String(10), nullable=False)

    nota = Column(String(60), nullable=True)  # NOTA
    emp = Column(String(30), nullable=True)   # EMP

    unit = Column(Float, nullable=True)
    des = Column(Float, nullable=True)
    qtdade_vendida = Column(Float, nullable=True)
    valor_total = Column(Float, nullable=False)

    # === Novos campos para relatórios e campanhas por descrição (opcionais) ===
    descricao = Column(Text, nullable=True)        # DESCRICAO
    razao = Column(Text, nullable=True)            # RAZAO
    cidade = Column(String(120), nullable=True)    # CIDADE
    cnpj_cpf = Column(String(40), nullable=True)   # CNPJ_CPF

    # Normalizados (para busca eficiente e contagens)
    descricao_norm = Column(Text, nullable=True, index=True)
    razao_norm = Column(Text, nullable=True, index=True)
    cidade_norm = Column(String(120), nullable=True, index=True)
    cliente_id_norm = Column(String(64), nullable=True, index=True)

    __table_args__ = (
        # Performance
        Index("ix_vendas_vendedor_data", "vendedor", "movimento"),
        Index("ix_vendas_emp_data", "emp", "movimento"),
        Index("ix_vendas_cidade_data", "cidade_norm", "movimento"),
        Index("ix_vendas_cliente_data", "cliente_id_norm", "movimento"),
        # Anti-duplicidade (idempotente) - deve bater com o banco (Supabase)
        # Chave completa: (mestre, marca, vendedor, movimento, mov_tipo_movto, nota, emp)
        UniqueConstraint(
            "mestre",
            "marca",
            "vendedor",
            "movimento",
            "mov_tipo_movto",
            "nota",
            "emp",
            name="vendas_unique_import",
        ),
    )

class DashboardCache(Base):
    __tablename__ = 'dashboard_cache'

    # No Supabase, esta tabela foi criada com chave composta (emp, vendedor, ano, mes)
    # para evitar duplicidade e facilitar consultas rápidas.
    # NÃO usamos uma coluna `id` aqui, porque a tabela já tem PRIMARY KEY composta.
    emp = Column(String(30), primary_key=True, nullable=False, index=True)
    vendedor = Column(String(80), primary_key=True, nullable=False, index=True)
    ano = Column(Integer, primary_key=True, nullable=False, index=True)
    mes = Column(Integer, primary_key=True, nullable=False, index=True)

    valor_bruto = Column(Float, nullable=False, default=0.0)
    valor_liquido = Column(Float, nullable=False, default=0.0)
    devolucoes = Column(Float, nullable=False, default=0.0)
    cancelamentos = Column(Float, nullable=False, default=0.0)
    pct_devolucao = Column(Float, nullable=False, default=0.0)

    mix_produtos = Column(Integer, nullable=False, default=0)
    mix_marcas = Column(Integer, nullable=False, default=0)

    # Rankings (JSON serializado em texto para simplicidade)
    ranking_json = Column(Text, nullable=False, default='[]')
    ranking_top15_json = Column(Text, nullable=False, default='[]')
    total_liquido_periodo = Column(Float, nullable=False, default=0.0)

    atualizado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    # Compatibilidade: algumas rotas usam o nome "updated_at".
    # Usamos synonym para funcionar em filtros e order_by.
    updated_at = synonym("atualizado_em")

    __table_args__ = (
        # Índices para acelerar consultas do dashboard
        Index('ix_dashboard_cache_emp_ano_mes', 'emp', 'ano', 'mes'),
        Index('ix_dashboard_cache_vendedor_ano_mes', 'vendedor', 'ano', 'mes'),
    )

class ItemParado(Base):
    __tablename__ = "itens_parados"

    id = Column(Integer, primary_key=True)

    # Empresa/loja (EMP) a que o relatório pertence
    emp = Column(String(30), nullable=False, index=True)

    # Código do produto (vamos comparar com Venda.mestre)
    codigo = Column(String(120), nullable=False, index=True)

    descricao = Column(String(255), nullable=True)
    quantidade = Column(Integer, nullable=True)

    # Percentual de recompensa (ex: 10 para 10%)
    recompensa_pct = Column(Float, nullable=False, default=0.0)

    ativo = Column(Integer, nullable=False, default=1)  # 1=ativo, 0=inativo

    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow)
    atualizado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index('ix_itens_parados_emp_codigo', 'emp', 'codigo'),
    )


class CampanhaQtd(Base):
    """Campanhas de recompensa por quantidade (por EMP e opcionalmente por vendedor).

    - produto_prefixo: texto que deve estar no início do campo do item (prefix match)
    - marca: marca do item
    - recompensa_unit: valor pago por unidade vendida
    - qtd_minima: se preenchido, só paga se vender >= qtd_minima
    - data_inicio/data_fim: período da campanha (inclusive)
    """

    __tablename__ = "campanhas_qtd"

    id = Column(Integer, primary_key=True)

    emp = Column(String(30), nullable=False, index=True)
    vendedor = Column(String(80), nullable=True, index=True)  # NULL = todos

    titulo = Column(String(120), nullable=True)
    produto_prefixo = Column(String(200), nullable=False)
    marca = Column(String(120), nullable=False)

    # Novo: campanhas por descrição (prefixo no início). Se campo_match='descricao', usa Venda.descricao_norm.
    campo_match = Column(String(20), nullable=False, default='codigo')  # 'codigo' ou 'descricao'
    descricao_prefixo = Column(String(200), nullable=True)

    recompensa_unit = Column(Float, nullable=False, default=0.0)
    qtd_minima = Column(Float, nullable=True)
    valor_minimo = Column(Float, nullable=True)

    data_inicio = Column(Date, nullable=False, index=True)
    data_fim = Column(Date, nullable=False, index=True)

    ativo = Column(Integer, nullable=False, default=1)

    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow)
    atualizado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_campanhas_qtd_emp_periodo", "emp", "data_inicio", "data_fim"),
    )


class CampanhaQtdResultado(Base):
    """Snapshot mensal por vendedor/campanha.

    Guardamos os resultados para que continuem visíveis mesmo após o fim da campanha.
    """

    __tablename__ = "campanhas_qtd_resultados"

    id = Column(Integer, primary_key=True)
    campanha_id = Column(Integer, nullable=False, index=True)

    # Competência (para relatórios por mês)
    competencia_ano = Column(Integer, nullable=False, index=True)
    competencia_mes = Column(Integer, nullable=False, index=True)

    emp = Column(String(30), nullable=False, index=True)
    vendedor = Column(String(80), nullable=False, index=True)

    # Duplicamos campos da campanha para auditoria
    titulo = Column(String(120), nullable=True)
    produto_prefixo = Column(String(200), nullable=False)
    marca = Column(String(120), nullable=False)
    recompensa_unit = Column(Float, nullable=False, default=0.0)
    qtd_minima = Column(Float, nullable=True)
    data_inicio = Column(Date, nullable=False)
    data_fim = Column(Date, nullable=False)

    qtd_vendida = Column(Float, nullable=False, default=0.0)
    valor_vendido = Column(Float, nullable=False, default=0.0)
    atingiu_minimo = Column(Integer, nullable=False, default=0)
    valor_recompensa = Column(Float, nullable=False, default=0.0)

    status_pagamento = Column(String(20), nullable=False, default="PENDENTE")
    pago_em = Column(DateTime, nullable=True)

    atualizado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint(
            "campanha_id",
            "emp",
            "vendedor",
            "competencia_ano",
            "competencia_mes",
            name="uq_campanha_qtd_resultado",
        ),
        Index(
            "ix_campanha_qtd_resultados_emp_comp",
            "emp",
            "competencia_ano",
            "competencia_mes",
        ),
    )


class VendasResumoPeriodo(Base):
    """Resumo mensal manual/importado (ex.: ano passado) por vendedor e EMP.

    Usado para exibir comparativos (ex.: "Ano passado") sem precisar manter
    toda a base de vendas antiga no banco.
    """

    __tablename__ = "vendas_resumo_periodo"

    id = Column(Integer, primary_key=True)
    emp = Column(String(30), nullable=False, default="", index=True)
    vendedor = Column(String(80), nullable=False, index=True)
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)

    valor_venda = Column(Float, nullable=False, default=0.0)
    mix_produtos = Column(Integer, nullable=False, default=0)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        # O Supabase não permite UNIQUE com expressão diretamente em constraint,
        # então a deduplicação é feita por UNIQUE INDEX via migration/SQL.
        Index("ix_resumo_emp_ano_mes", "emp", "ano", "mes"),
    )


class FechamentoMensal(Base):
    """Controle de fechamento (trava edição) por EMP e competência."""

    __tablename__ = "fechamento_mensal"

    id = Column(Integer, primary_key=True)
    emp = Column(String(30), nullable=False, default="", index=True)
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)

    fechado = Column(Boolean, nullable=False, default=True)
    fechado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("emp", "ano", "mes", name="uq_fechamento_mensal_raw"),
    )




class AppSetting(Base):
    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True)
    key = Column(String(120), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class BrandingTheme(Base):
    __tablename__ = "branding_themes"

    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    start_date = Column(Date, nullable=False)
    end_date = Column(Date, nullable=False)
    logo_url = Column(Text, nullable=True)
    favicon_url = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("ix_branding_themes_active_dates", "is_active", "start_date", "end_date"),
    )


def criar_tabelas():
    """Cria tabelas e aplica ajustes leves de schema (compatibilidade).

    Observação: isso NÃO substitui migrations (Alembic), mas ajuda a evitar
    que versões antigas do banco que não tinham colunas (ex.: usuarios.emp)
    quebrem o sistema ao atualizar o código.
    """
    # Cria tabelas que não existirem
    Base.metadata.create_all(engine)

    # Ajustes compatíveis (IF NOT EXISTS) — seguros para rodar em produção
    try:
        with engine.begin() as conn:
            # Cadastro de EMPs (lojas/filiais)
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS emps (
                    id SERIAL PRIMARY KEY,
                    codigo VARCHAR(30) NOT NULL UNIQUE,
                    nome VARCHAR(120) NOT NULL,
                    cidade VARCHAR(120),
                    uf VARCHAR(2),
                    ativo BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
                );
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_emps_codigo ON emps (codigo);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_emps_uf ON emps (uf);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_emps_cidade ON emps (cidade);"))

            # Usuários: role/emp
            conn.execute(text("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS role varchar(20);"))
            conn.execute(text("ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS emp varchar(30);"))
            # Tabela de vínculo multi-EMP por usuário (vendedor/supervisor)
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS usuario_emps (
                    id SERIAL PRIMARY KEY,
                    usuario_id INTEGER NOT NULL,
                    emp VARCHAR(30) NOT NULL,
                    ativo BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    CONSTRAINT uq_usuario_emps_usuario_emp UNIQUE (usuario_id, emp)
                );
            """))
            # Garantir colunas/índices (compatibilidade com bancos antigos)
            conn.execute(text("ALTER TABLE usuario_emps ADD COLUMN IF NOT EXISTS ativo BOOLEAN NOT NULL DEFAULT TRUE;"))
            conn.execute(text("ALTER TABLE usuario_emps ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT NOW();"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_usuario_emps_usuario_id ON usuario_emps (usuario_id);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_usuario_emps_emp ON usuario_emps (emp);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_usuario_emps_ativo ON usuario_emps (ativo);"))
            # Compatibilidade: se existir tabela antiga usuario_emp, copia vínculos (não derruba se falhar)
            conn.execute(text("""
                DO $$
                BEGIN
                    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='usuario_emp') THEN
                        INSERT INTO usuario_emps (usuario_id, emp, ativo, created_at)
                        SELECT usuario_id, emp, COALESCE(ativo, TRUE), NOW()
                        FROM usuario_emp
                        ON CONFLICT (usuario_id, emp) DO UPDATE SET ativo = EXCLUDED.ativo;
                    END IF;
                EXCEPTION WHEN others THEN
                    -- ignora erros de permissão/DDL
                    NULL;
                END $$;
            """))
            conn.execute(text("UPDATE usuarios SET role='vendedor' WHERE role IS NULL OR role='' ;"))
            conn.execute(text("UPDATE usuarios SET role=lower(role) WHERE role IS NOT NULL;"))
            # Vendas: novos campos para relatórios (IF NOT EXISTS)
            conn.execute(text("ALTER TABLE vendas ADD COLUMN IF NOT EXISTS descricao text;"))
            conn.execute(text("ALTER TABLE vendas ADD COLUMN IF NOT EXISTS razao text;"))
            conn.execute(text("ALTER TABLE vendas ADD COLUMN IF NOT EXISTS cidade varchar(120);"))
            conn.execute(text("ALTER TABLE vendas ADD COLUMN IF NOT EXISTS cnpj_cpf varchar(40);"))
            conn.execute(text("ALTER TABLE vendas ADD COLUMN IF NOT EXISTS descricao_norm text;"))
            conn.execute(text("ALTER TABLE vendas ADD COLUMN IF NOT EXISTS razao_norm text;"))
            conn.execute(text("ALTER TABLE vendas ADD COLUMN IF NOT EXISTS cidade_norm varchar(120);"))
            conn.execute(text("ALTER TABLE vendas ADD COLUMN IF NOT EXISTS cliente_id_norm varchar(64);"))

            # Índices (seguros)
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vendas_emp_data ON vendas (emp, movimento);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vendas_cidade_data ON vendas (cidade_norm, movimento);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vendas_cliente_data ON vendas (cliente_id_norm, movimento);"))

            # Campanhas: suporte a match por descrição
            conn.execute(text("ALTER TABLE campanhas_qtd ADD COLUMN IF NOT EXISTS campo_match varchar(20) DEFAULT 'codigo';"))
            conn.execute(text("ALTER TABLE campanhas_qtd ADD COLUMN IF NOT EXISTS descricao_prefixo varchar(200);"))
            conn.execute(text("ALTER TABLE campanhas_qtd ADD COLUMN IF NOT EXISTS valor_minimo double precision;"))
            conn.execute(text("UPDATE campanhas_qtd SET campo_match='codigo' WHERE campo_match IS NULL OR campo_match='';"))


    except Exception:
        # Se não tiver permissão ou der algum erro, não derruba o app.
        pass