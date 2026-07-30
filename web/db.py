import os
from datetime import datetime
from urllib.parse import quote_plus

from sqlalchemy import create_engine, Column, Integer, String, Float, Numeric, Date, DateTime, Text, Boolean, Index, UniqueConstraint, text, func
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

# Evita executar dezenas de DDLs idempotentes em toda abertura do Admin > Metas.
# A migração continua sendo garantida na primeira chamada de cada processo.
_METAS_LOJAS_SCHEMA_READY = False
_BONUS_IMPORTADOS_SCHEMA_READY = False
_BONUS_ATACADO_SCHEMA_READY = False
_ITENS_PARADOS_SNAPSHOT_SCHEMA_READY = False
_BONUS_OUTROS_VALORES_SCHEMA_READY = False
_FINANCEIRO_BONUS_SCHEMA_READY = False



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


class BonusImportacaoLote(Base):
    """Auditoria das importações da aba ``Final Bonus``.

    Os cálculos permanecem na planilha de origem. O sistema apenas valida,
    persiste e apresenta o snapshot importado para a competência escolhida.
    """

    __tablename__ = "bonus_importacoes_lotes"

    id = Column(Integer, primary_key=True)
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)
    arquivo_origem = Column(String(255), nullable=False)
    importado_por_user_id = Column(Integer, nullable=True, index=True)
    importado_por = Column(String(80), nullable=True)
    importado_em = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    linhas_lidas = Column(Integer, nullable=False, default=0)
    linhas_importadas = Column(Integer, nullable=False, default=0)
    linhas_ignoradas = Column(Integer, nullable=False, default=0)
    avisos_json = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_bonus_lotes_periodo_importado", "ano", "mes", "importado_em"),
    )


class BonusUsuarioImportado(Base):
    """Snapshot mensal dos valores prontos da aba ``BONUS FINAL``."""

    __tablename__ = "bonus_usuarios_importados"

    id = Column(Integer, primary_key=True)
    lote_id = Column(Integer, nullable=False, index=True)
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)
    linha_origem = Column(Integer, nullable=True)

    usuario_id = Column(Integer, nullable=True, index=True)
    usuario_nome = Column(String(80), nullable=False, index=True)
    funcao = Column(String(30), nullable=False, index=True)
    emp = Column(String(30), nullable=False, index=True)

    # Colunas autorizadas do layout atual da aba BONUS FINAL.
    produto_vendedor = Column(Numeric(18, 4), nullable=False, default=0)  # E
    mecanico_faturado = Column(Numeric(18, 4), nullable=False, default=0)  # F
    venda_anterior = Column(Numeric(18, 4), nullable=False, default=0)  # G
    venda_atual = Column(Numeric(18, 4), nullable=False, default=0)  # H
    crescimento = Column(Numeric(12, 6), nullable=True)  # I
    loja_anterior = Column(Numeric(18, 4), nullable=False, default=0)  # J
    loja_atual = Column(Numeric(18, 4), nullable=False, default=0)  # K
    produto_gerente = Column(Numeric(18, 4), nullable=False, default=0)  # M
    importado_vendedor = Column(Numeric(18, 4), nullable=False, default=0)  # N
    importado_loja = Column(Numeric(18, 4), nullable=False, default=0)  # O
    bonus_importado = Column(Numeric(18, 4), nullable=False, default=0)  # R
    valor_meta = Column(Numeric(18, 4), nullable=False, default=0)  # T
    valor_parcial = Column(Numeric(18, 4), nullable=False, default=0)  # U
    bonus_final = Column(Numeric(18, 4), nullable=False, default=0)  # V

    importado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint(
            "ano",
            "mes",
            "emp",
            "usuario_nome",
            name="uq_bonus_usuario_periodo_emp",
        ),
        Index("ix_bonus_usuario_periodo", "usuario_nome", "ano", "mes"),
        Index("ix_bonus_emp_periodo", "emp", "ano", "mes"),
        Index("ix_bonus_funcao_periodo", "funcao", "ano", "mes"),
    )


class BonusAtacadoImportacaoLote(Base):
    """Auditoria das importações mensais da aba ``PremiacaoFinal`` do atacado."""

    __tablename__ = "bonus_atacado_importacoes_lotes"

    id = Column(Integer, primary_key=True)
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)
    arquivo_origem = Column(String(255), nullable=False)
    aba_origem = Column(String(120), nullable=False, default="PremiacaoFinal")
    importado_por_user_id = Column(Integer, nullable=True, index=True)
    importado_por = Column(String(80), nullable=True)
    importado_em = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    linhas_lidas = Column(Integer, nullable=False, default=0)
    linhas_importadas = Column(Integer, nullable=False, default=0)
    linhas_ignoradas = Column(Integer, nullable=False, default=0)
    avisos_json = Column(Text, nullable=True)

    __table_args__ = (
        Index(
            "ix_bonus_atacado_lotes_periodo_importado",
            "ano",
            "mes",
            "importado_em",
        ),
    )


class BonusAtacadoUsuario(Base):
    """Snapshot mensal dos valores já calculados da premiação do atacado."""

    __tablename__ = "bonus_atacado_usuarios"

    id = Column(Integer, primary_key=True)
    lote_id = Column(Integer, nullable=False, index=True)
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)
    linha_origem = Column(Integer, nullable=True)

    usuario_id = Column(Integer, nullable=True, index=True)
    usuario_nome = Column(String(100), nullable=False, index=True)
    funcao_planilha = Column(String(30), nullable=True)
    emp = Column(String(30), nullable=False, index=True)

    total_produtos = Column(Numeric(18, 4), nullable=True)
    venda_anterior = Column(Numeric(18, 4), nullable=True)
    venda_atual = Column(Numeric(18, 4), nullable=True)
    importado = Column(Numeric(18, 4), nullable=True)
    percentual_importado = Column(Numeric(12, 6), nullable=True)
    loja_anterior = Column(Numeric(18, 4), nullable=True)
    loja_atual = Column(Numeric(18, 4), nullable=True)
    falta_valor_vendedor = Column(Numeric(18, 4), nullable=True)

    importado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint(
            "ano",
            "mes",
            "emp",
            "usuario_nome",
            name="uq_bonus_atacado_usuario_periodo_emp",
        ),
        Index(
            "ix_bonus_atacado_usuario_periodo",
            "usuario_nome",
            "ano",
            "mes",
        ),
        Index("ix_bonus_atacado_emp_periodo", "emp", "ano", "mes"),
    )


class BonusOutroValor(Base):
    """Lançamento manual adicional vinculado ao bônus de um usuário e EMP."""

    __tablename__ = "bonus_outros_valores"

    id = Column(Integer, primary_key=True)
    origem = Column(String(10), nullable=False, index=True)  # VAREJO | ATACADO
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)

    usuario_id = Column(Integer, nullable=False, index=True)
    usuario_nome = Column(String(100), nullable=False, index=True)
    emp = Column(String(30), nullable=False, index=True)

    descricao = Column(String(255), nullable=False)
    valor = Column(Numeric(18, 4), nullable=False)

    criado_por_user_id = Column(Integer, nullable=True, index=True)
    criado_por = Column(String(100), nullable=True)
    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index(
            "ix_bonus_outros_origem_periodo",
            "origem",
            "ano",
            "mes",
        ),
        Index(
            "ix_bonus_outros_usuario_periodo",
            "usuario_id",
            "ano",
            "mes",
        ),
        Index(
            "ix_bonus_outros_emp_periodo",
            "emp",
            "ano",
            "mes",
        ),
    )


class FinanceiroBonusFechamento(Base):
    """Fechamento financeiro congelado por competência e EMP."""

    __tablename__ = "financeiro_bonus_fechamentos"

    id = Column(Integer, primary_key=True)
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)
    emp = Column(String(30), nullable=False, index=True)
    status = Column(String(12), nullable=False, default="ABERTO", index=True)
    pago = Column(Boolean, nullable=False, default=False, index=True)
    versao = Column(Integer, nullable=False, default=0)

    total_varejo = Column(Numeric(18, 4), nullable=False, default=0)
    total_atacado = Column(Numeric(18, 4), nullable=False, default=0)
    total_itens_parados = Column(Numeric(18, 4), nullable=False, default=0)
    total_outros_varejo = Column(Numeric(18, 4), nullable=False, default=0)
    total_outros_atacado = Column(Numeric(18, 4), nullable=False, default=0)
    total_geral = Column(Numeric(18, 4), nullable=False, default=0)

    fechado_por_user_id = Column(Integer, nullable=True, index=True)
    fechado_por = Column(String(100), nullable=True)
    fechado_em = Column(DateTime, nullable=True, index=True)
    reaberto_por_user_id = Column(Integer, nullable=True, index=True)
    reaberto_por = Column(String(100), nullable=True)
    reaberto_em = Column(DateTime, nullable=True)
    pago_por_user_id = Column(Integer, nullable=True, index=True)
    pago_por = Column(String(100), nullable=True)
    pago_em = Column(DateTime, nullable=True, index=True)
    atualizado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint(
            "ano", "mes", "emp", name="uq_financeiro_bonus_fechamento_periodo_emp"
        ),
        Index("ix_financeiro_bonus_status_periodo", "ano", "mes", "status", "pago"),
    )


class FinanceiroBonusFechamentoItem(Base):
    """Valores por funcionário preservados no instante do fechamento."""

    __tablename__ = "financeiro_bonus_fechamento_itens"

    id = Column(Integer, primary_key=True)
    fechamento_id = Column(Integer, nullable=False, index=True)
    usuario_id = Column(Integer, nullable=True, index=True)
    usuario_nome = Column(String(100), nullable=False, index=True)
    funcao = Column(String(30), nullable=True)
    emp = Column(String(30), nullable=False, index=True)

    bonus_varejo = Column(Numeric(18, 4), nullable=False, default=0)
    bonus_atacado = Column(Numeric(18, 4), nullable=False, default=0)
    itens_parados = Column(Numeric(18, 4), nullable=False, default=0)
    outros_varejo = Column(Numeric(18, 4), nullable=False, default=0)
    outros_atacado = Column(Numeric(18, 4), nullable=False, default=0)
    total_geral = Column(Numeric(18, 4), nullable=False, default=0)
    outros_detalhes_json = Column(Text, nullable=True)
    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint(
            "fechamento_id",
            "emp",
            "usuario_nome",
            name="uq_financeiro_bonus_item_fechamento_usuario",
        ),
        Index("ix_financeiro_bonus_item_emp_usuario", "emp", "usuario_nome"),
    )


class FinanceiroBonusEvento(Base):
    """Auditoria dos fechamentos, reaberturas e alterações de pagamento."""

    __tablename__ = "financeiro_bonus_eventos"

    id = Column(Integer, primary_key=True)
    fechamento_id = Column(Integer, nullable=False, index=True)
    acao = Column(String(20), nullable=False, index=True)
    status_anterior = Column(String(12), nullable=True)
    status_novo = Column(String(12), nullable=True)
    pago_anterior = Column(Boolean, nullable=True)
    pago_novo = Column(Boolean, nullable=True)
    total_geral = Column(Numeric(18, 4), nullable=False, default=0)
    usuario_id = Column(Integer, nullable=True, index=True)
    usuario_nome = Column(String(100), nullable=True)
    detalhes = Column(Text, nullable=True)
    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)


class ItensParadosVendaImportacaoLote(Base):
    """Auditoria das importações mensais das vendas de itens parados."""

    __tablename__ = "itens_parados_vendas_importacoes"

    id = Column(Integer, primary_key=True)
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)
    arquivo_origem = Column(String(255), nullable=False)
    importado_por_user_id = Column(Integer, nullable=True, index=True)
    importado_por = Column(String(80), nullable=True)
    importado_em = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    data_inicio = Column(Date, nullable=True)
    data_fim = Column(Date, nullable=True)
    linhas_lidas = Column(Integer, nullable=False, default=0)
    linhas_importadas = Column(Integer, nullable=False, default=0)
    linhas_ignoradas = Column(Integer, nullable=False, default=0)
    registros_usuarios = Column(Integer, nullable=False, default=0)
    valor_total = Column(Numeric(18, 4), nullable=False, default=0)
    avisos_json = Column(Text, nullable=True)

    __table_args__ = (
        Index(
            "ix_itens_parados_vendas_lote_periodo",
            "ano",
            "mes",
            "importado_em",
        ),
    )


class ItensParadosVendaUsuario(Base):
    """Saldo mensal importado por usuário e EMP para itens parados."""

    __tablename__ = "itens_parados_vendas_usuarios"

    id = Column(Integer, primary_key=True)
    lote_id = Column(Integer, nullable=False, index=True)
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)
    usuario_id = Column(Integer, nullable=True, index=True)
    usuario_nome = Column(String(100), nullable=False, index=True)
    emp = Column(String(30), nullable=False, index=True)
    valor_total = Column(Numeric(18, 4), nullable=False, default=0)
    qtd_linhas = Column(Integer, nullable=False, default=0)
    qtd_itens = Column(Integer, nullable=False, default=0)
    importado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint(
            "ano",
            "mes",
            "emp",
            "usuario_nome",
            name="uq_itens_parados_vendas_usuario_periodo_emp",
        ),
        Index(
            "ix_itens_parados_vendas_usuario_periodo",
            "usuario_nome",
            "ano",
            "mes",
        ),
        Index(
            "ix_itens_parados_vendas_emp_periodo",
            "emp",
            "ano",
            "mes",
        ),
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

# =====================
# Mensagens (comunicados)
# =====================

class Mensagem(Base):
    __tablename__ = "mensagens"

    id = Column(Integer, primary_key=True)
    titulo = Column(String(180), nullable=False)
    conteudo = Column(Text, nullable=False)
    bloqueante = Column(Boolean, nullable=False, default=False)
    ativo = Column(Boolean, nullable=False, default=True)
    inicio_em = Column(Date, nullable=True)
    fim_em = Column(Date, nullable=True)

    created_by_user_id = Column(Integer, nullable=True, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_mensagens_ativo_bloqueante", "ativo", "bloqueante"),
        Index("ix_mensagens_periodo", "inicio_em", "fim_em"),
    )


class MensagemEmpresa(Base):
    __tablename__ = "mensagem_empresas"

    id = Column(Integer, primary_key=True)
    mensagem_id = Column(Integer, nullable=False, index=True)
    emp = Column(String(30), nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("mensagem_id", "emp", name="uq_msg_empresa"),
    )


class MensagemUsuario(Base):
    __tablename__ = "mensagem_usuarios"

    id = Column(Integer, primary_key=True)
    mensagem_id = Column(Integer, nullable=False, index=True)
    usuario_id = Column(Integer, nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("mensagem_id", "usuario_id", name="uq_msg_usuario"),
    )


class MensagemLidaDiaria(Base):
    __tablename__ = "mensagem_lidas_diarias"

    id = Column(Integer, primary_key=True)
    mensagem_id = Column(Integer, nullable=False, index=True)
    usuario_id = Column(Integer, nullable=False, index=True)
    data = Column(Date, nullable=False, index=True)
    lida_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("mensagem_id", "usuario_id", "data", name="uq_msg_lida_dia"),
        Index("ix_msg_lidas_usuario_data", "usuario_id", "data"),
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

    # Empresa/loja (EMP) a que o item/campanha pertence
    emp = Column(String(30), nullable=False, index=True)

    # Código do produto (cruza com Venda.mestre)
    codigo = Column(String(120), nullable=False, index=True)

    # Código interno opcional do produto. Usado para conferência em importações em lote.
    interno = Column(String(120), nullable=True, index=True)

    descricao = Column(String(255), nullable=True)
    quantidade = Column(Integer, nullable=True)

    # Campo legado (modo percentual). Mantido por compatibilidade.
    recompensa_pct = Column(Float, nullable=False, default=0.0)

    # Novo modo oficial: campanha por pontos.
    modo = Column(String(20), nullable=False, default="PONTOS")
    multiplicador_pontos = Column(Float, nullable=False, default=1.0)
    data_inicio = Column(Date, nullable=True)
    data_fim = Column(Date, nullable=True)

    ativo = Column(Boolean, nullable=False, default=True)

    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow)
    atualizado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index('ix_itens_parados_emp_codigo', 'emp', 'codigo'),
    )


class ItensParadosPontosConfig(Base):
    __tablename__ = "itens_parados_pontos_config"

    id = Column(Integer, primary_key=True)
    emp = Column(String(30), nullable=True, index=True)  # NULL = global
    base_reais = Column(Float, nullable=False, default=100.0)
    valor_por_ponto = Column(Float, nullable=False, default=10.0)
    ativo = Column(Boolean, nullable=False, default=True)
    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow)
    atualizado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_itens_parados_pontos_cfg_emp", "emp"),
    )


class ItensParadosPontosBonus(Base):
    __tablename__ = "itens_parados_pontos_bonus"

    id = Column(Integer, primary_key=True)
    emp = Column(String(30), nullable=True, index=True)  # NULL = global
    min_pontos = Column(Float, nullable=False, default=10.0)
    bonus_valor = Column(Float, nullable=False, default=50.0)
    ativo = Column(Boolean, nullable=False, default=True)
    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow)
    atualizado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_itens_parados_pontos_bonus_emp", "emp"),
        Index("ix_itens_parados_pontos_bonus_min", "min_pontos"),
    )


class ItensParadosPontosFechamento(Base):
    __tablename__ = "itens_parados_pontos_fechamentos"

    id = Column(Integer, primary_key=True)
    emp = Column(String(30), nullable=True, index=True)  # NULL = fechamento multi-EMP
    data_inicio = Column(Date, nullable=False)
    data_fim = Column(Date, nullable=False)
    criado_por = Column(String(80), nullable=True)
    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_itens_parados_pontos_fech_emp", "emp"),
        Index("ix_itens_parados_pontos_fech_ini", "data_inicio"),
        Index("ix_itens_parados_pontos_fech_fim", "data_fim"),
    )


class ItensParadosPontosResultado(Base):
    __tablename__ = "itens_parados_pontos_resultados"

    id = Column(Integer, primary_key=True)
    fechamento_id = Column(Integer, nullable=False, index=True)
    emp = Column(String(30), nullable=False, index=True)
    vendedor = Column(String(80), nullable=False, index=True)
    valor_vendido = Column(Float, nullable=False, default=0.0)
    pontos = Column(Float, nullable=False, default=0.0)
    base_reais = Column(Float, nullable=False, default=100.0)
    valor_por_ponto = Column(Float, nullable=False, default=10.0)
    bonus_extra = Column(Float, nullable=False, default=0.0)
    total = Column(Float, nullable=False, default=0.0)
    status_pagamento = Column(String(20), nullable=False, default="PENDENTE")
    pago_em = Column(DateTime, nullable=True)
    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow)
    atualizado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_itens_parados_pontos_res_emp", "emp"),
        Index("ix_itens_parados_pontos_res_vend", "vendedor"),
        Index("ix_itens_parados_pontos_res_fech", "fechamento_id"),
    )


class ItemParadoResultado(Base):
    """
    Snapshot mensal por vendedor/item parado (para relatórios e Financeiro).

    Motivo:
    - Itens Parados eram calculados "ao vivo" no relatório, o que pode ficar pesado em meses com muito volume.
    - Este snapshot permite:
        * relatório unificado mais rápido
        * status_pagamento / pago_em
        * export e auditoria consistente
    """
    __tablename__ = "itens_parados_resultados"

    id = Column(Integer, primary_key=True)
    item_parado_id = Column(Integer, nullable=False, index=True)

    competencia_ano = Column(Integer, nullable=False, index=True)
    competencia_mes = Column(Integer, nullable=False, index=True)

    emp = Column(String(30), nullable=False, index=True)
    vendedor = Column(String(80), nullable=False, index=True)

    titulo = Column(String(255), nullable=False, default="")

    base_valor_vendido = Column(Float, nullable=False, default=0.0)
    recompensa_pct = Column(Float, nullable=False, default=0.0)

    # Snapshot v2 do relatório unificado:
    # - qtd_base guarda a quantidade/pontos exibida na coluna “Qtd vendida”
    # - recompensa_unit guarda o valor unitário/ponto exibido em “Recomp. (R$/un)”
    # Mantemos recompensa_pct por compatibilidade com versões antigas.
    qtd_base = Column(Float, nullable=True)
    recompensa_unit = Column(Float, nullable=True)

    valor_recompensa = Column(Float, nullable=False, default=0.0)

    status_pagamento = Column(String(20), nullable=False, default="PENDENTE")
    pago_em = Column(DateTime, nullable=True)

    atualizado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint(
            "item_parado_id",
            "emp",
            "vendedor",
            "competencia_ano",
            "competencia_mes",
            name="uq_itens_parados_resultado",
        ),
        Index("ix_itens_parados_res_emp_comp", "emp", "competencia_ano", "competencia_mes"),
        Index("ix_itens_parados_res_vend", "vendedor"),
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
    # VENDEDOR = recompensa sobre a venda individual; GERENTE = recompensa sobre a venda total da EMP.
    campanha_tipo = Column(String(20), nullable=False, default="VENDEDOR", index=True)
    vendedor = Column(String(80), nullable=True, index=True)  # NULL = todos / não usado em campanha GERENTE

    titulo = Column(String(120), nullable=True)
    produto_prefixo = Column(String(200), nullable=False)
    marca = Column(String(120), nullable=False)

    # Novo: campanhas por descrição (prefixo no início). Se campo_match='descricao', usa Venda.descricao_norm.
    campo_match = Column(String(20), nullable=False, default='codigo')  # 'codigo' ou 'descricao'
    descricao_prefixo = Column(String(200), nullable=True)

    recompensa_unit = Column(Float, nullable=False, default=0.0)
    qtd_minima = Column(Float, nullable=True)
    valor_minimo = Column(Float, nullable=True)
    # Trava comercial por loja: só libera pagamento se o faturamento total da EMP
    # no período da campanha atingir este valor. NULL/0 mantém comportamento antigo.
    faturamento_minimo_emp = Column(Float, nullable=True)

    data_inicio = Column(Date, nullable=False, index=True)
    data_fim = Column(Date, nullable=False, index=True)

    ativo = Column(Integer, nullable=False, default=1)

    __table_args__ = (
        Index("ix_campanhas_qtd_emp_periodo", "emp", "data_inicio", "data_fim"),
    )


    # timestamps (na tabela antiga os nomes são criado_em/atualizado_em)
    created_at = Column('criado_em', DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column('atualizado_em', DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    campanha_tipo = Column(String(20), nullable=False, default="VENDEDOR", index=True)

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

    # Valor efetivamente liberado para pagamento.
    valor_recompensa = Column(Float, nullable=False, default=0.0)

    # Auditoria da trava de faturamento mínimo da EMP.
    premio_potencial = Column(Float, nullable=True)
    faturamento_minimo_emp = Column(Float, nullable=True)
    faturamento_emp = Column(Float, nullable=True)
    faltante_faturamento_emp = Column(Float, nullable=True)
    bloqueado_faturamento_emp = Column(Integer, nullable=False, default=0)

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


# =====================
# Metas (crescimento / mix / share de marcas)
# =====================

class MetaPrograma(Base):
    """Programa de meta mensal.

    tipos:
      - CRESCIMENTO: compara valor do mês vs base (manual ou ano passado)
      - MIX: itens únicos (por mestre) no mês
      - SHARE_MARCA: participação (%) de um conjunto de marcas no total do mês
    """

    __tablename__ = "metas_programas"

    id = Column(Integer, primary_key=True)

    nome = Column(String(180), nullable=False)
    tipo = Column(String(30), nullable=False, index=True)  # CRESCIMENTO | MIX | SHARE_MARCA

    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)

    ativo = Column(Boolean, nullable=False, default=True)

    # Escopo da meta:
    # - VENDEDOR: calcula por vendedor/EMP
    # - GERENTE: calcula pelo total da EMP (linha especial GERENTE)
    escopo = Column(String(20), nullable=False, default="VENDEDOR")

    # Gates / travas opcionais
    faturamento_minimo = Column(Float, nullable=True, default=0.0)
    margem_minima = Column(Float, nullable=True, default=0.0)

    # Teto opcional de % de premiação quando o faturamento atingir um valor específico.
    teto_faturamento = Column(Float, nullable=True)
    teto_bonus_percentual = Column(Float, nullable=True)

    created_by_user_id = Column(Integer, nullable=True, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_metas_programas_tipo_periodo", "tipo", "ano", "mes"),
        Index("ix_metas_programas_periodo", "ano", "mes"),
    )


class MetaProgramaEmp(Base):
    __tablename__ = "metas_programas_emps"

    id = Column(Integer, primary_key=True)
    meta_id = Column(Integer, nullable=False, index=True)
    emp = Column(String(30), nullable=False, index=True)

    # Permite remover uma EMP da meta sem perder histórico/base manual.
    # O vínculo antigo fica inativo e pode ser reativado depois.
    ativo = Column(Boolean, nullable=False, default=True)
    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow)
    atualizado_em = Column(DateTime, nullable=True)
    removido_em = Column(DateTime, nullable=True)

    __table_args__ = (
        UniqueConstraint("meta_id", "emp", name="uq_meta_emp"),
        Index("ix_meta_emp_emp", "emp"),
    )


class MetaEscala(Base):
    """Faixas (escada) de atingimento -> bônus.

    Para CRESCIMENTO e SHARE_MARCA: limite_min é % (ex.: 5, 10, 20) e bonus_percentual é % pago (ex.: 0.10, 0.20)
    Para MIX: limite_min é quantidade de itens únicos (ex.: 1500, 1700) e bonus_percentual é % pago.
    """

    __tablename__ = "metas_escalas"

    id = Column(Integer, primary_key=True)
    meta_id = Column(Integer, nullable=False, index=True)

    ordem = Column(Integer, nullable=False, default=0)
    limite_min = Column(Float, nullable=False)
    bonus_percentual = Column(Float, nullable=False)

    __table_args__ = (
        UniqueConstraint("meta_id", "ordem", name="uq_meta_escala_ordem"),
        Index("ix_meta_escala_meta", "meta_id"),
    )


class MetaMarca(Base):
    """Marcas incluídas no cálculo de SHARE_MARCA (podem ser várias)."""

    __tablename__ = "metas_marcas"

    id = Column(Integer, primary_key=True)
    meta_id = Column(Integer, nullable=False, index=True)
    marca = Column(String(120), nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("meta_id", "marca", name="uq_meta_marca"),
        Index("ix_meta_marca_marca", "marca"),
    )


class MetaBaseManual(Base):
    """Base manual (override) para CRESCIMENTO por vendedor/EMP (mensal)."""

    __tablename__ = "metas_bases_manuais"

    id = Column(Integer, primary_key=True)
    meta_id = Column(Integer, nullable=False, index=True)

    emp = Column(String(30), nullable=False, index=True)
    vendedor = Column(String(80), nullable=False, index=True)

    base_valor = Column(Float, nullable=False, default=0.0)
    margem_percentual = Column(Float, nullable=True)
    bonus_extra_percentual = Column(Float, nullable=True, default=0.0)
    observacao = Column(String(200), nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("meta_id", "emp", "vendedor", name="uq_meta_base_manual"),
        Index("ix_meta_base_manual_emp_vend", "emp", "vendedor"),
    )


class MetaMargemVendedor(Base):
    """Margem percentual importada por vendedor/competência.

    Regra atual: vale sempre a última margem importada para (ano, mes, vendedor).
    A coluna ``emp`` é mantida por compatibilidade com versões anteriores e recebe
    "GERAL" nas novas importações. A margem não soma, não faz média e não
    acumula por dia.
    """

    __tablename__ = "metas_margens_vendedores"

    id = Column(Integer, primary_key=True)
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)
    emp = Column(String(30), nullable=False, index=True)
    vendedor = Column(String(80), nullable=False, index=True)
    margem_percentual = Column(Float, nullable=False, default=0.0)
    observacao = Column(String(240), nullable=True)
    arquivo_origem = Column(String(255), nullable=True)
    importado_por = Column(String(80), nullable=True)
    importado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("ano", "mes", "emp", "vendedor", name="uq_meta_margem_vendedor_periodo"),
        Index("ix_meta_margem_emp_periodo", "emp", "ano", "mes"),
        Index("ix_meta_margem_vendedor_periodo", "vendedor", "ano", "mes"),
    )


class OficinaServico(Base):
    """Faturamento de mão de obra/oficina por competência, EMP e usuário.

    Mantemos separado de ``vendas`` porque serviço não tem produto/marca/mix, mas
    deve compor o faturamento usado por metas e travas de campanhas.
    """

    __tablename__ = "oficina_servicos"

    id = Column(Integer, primary_key=True)
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)
    emp = Column(String(30), nullable=False, index=True)
    usuario = Column(String(80), nullable=False, index=True)

    valor_servico = Column(Float, nullable=False, default=0.0)
    observacao = Column(String(240), nullable=True)
    arquivo_origem = Column(String(255), nullable=True)
    importado_por = Column(String(80), nullable=True)
    importado_em = Column(DateTime, nullable=False, default=datetime.utcnow)
    ativo = Column(Boolean, nullable=False, default=True)

    __table_args__ = (
        UniqueConstraint("ano", "mes", "emp", "usuario", name="uq_oficina_servico_periodo_usuario"),
        Index("ix_oficina_servicos_emp_periodo", "emp", "ano", "mes"),
        Index("ix_oficina_servicos_usuario_periodo", "usuario", "ano", "mes"),
        Index("ix_oficina_servicos_periodo", "ano", "mes"),
    )


class MetaResultado(Base):
    """Resultado calculado por meta/vendedor/EMP/mês.

    Armazenamos para abrir rápido e permitir auditoria.
    """

    __tablename__ = "metas_resultados"

    id = Column(Integer, primary_key=True)
    meta_id = Column(Integer, nullable=False, index=True)

    emp = Column(String(30), nullable=False, index=True)
    vendedor = Column(String(80), nullable=False, index=True)

    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)

    # métricas
    valor_mes = Column(Float, nullable=False, default=0.0)
    base_valor = Column(Float, nullable=True)
    crescimento_pct = Column(Float, nullable=True)
    mix_itens_unicos = Column(Float, nullable=True)
    share_pct = Column(Float, nullable=True)
    valor_marcas = Column(Float, nullable=True)
    margem_percentual = Column(Float, nullable=True)
    margem_minima = Column(Float, nullable=True)
    margem_atingida = Column(Boolean, nullable=True)
    bloqueado_margem = Column(Boolean, nullable=False, default=False)

    bonus_percentual = Column(Float, nullable=False, default=0.0)
    premio = Column(Float, nullable=False, default=0.0)

    calculado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("meta_id", "emp", "vendedor", "ano", "mes", name="uq_meta_resultado"),
        Index("ix_meta_resultados_emp_periodo", "emp", "ano", "mes"),
        Index("ix_meta_resultados_meta_periodo", "meta_id", "ano", "mes"),
    )


# =========================
# Campanhas Combo (Kit) — gate mínimo + pagamento por unidade (após bater todos os mínimos)
# =========================
class CampanhaCombo(Base):
    __tablename__ = "campanhas_combo"

    id = Column(Integer, primary_key=True)
    titulo = Column(String(160), nullable=False, default="")
    nome = Column(String(160), nullable=False, default="")
    emp = Column(String(30), nullable=True, index=True)  # null/'' => global
    marca = Column(String(120), nullable=False, default="", index=True)

    # Vigência
    data_inicio = Column(Date, nullable=False)
    data_fim = Column(Date, nullable=False)

    # Competência (para agrupar por mês/ano)
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)

    # Valor unitário global opcional (fallback quando item não tem valor_unitario)
    valor_unitario_global = Column(Float, nullable=True)

    # Modelo de pagamento:
    # - TODOS_ITENS: (modelo atual) após bater o mínimo em TODOS os itens, paga por unidade dos itens do gate (qtd * valor_unitario item/global)
    # - POR_DESCRICAO: após bater o mínimo em TODOS os itens do gate, paga por unidade nas vendas filtradas por descrição+marca (filtro_*), com valor_unitario_modelo2/global
    modelo_pagamento = Column(String(20), nullable=False, default="TODOS_ITENS", server_default="TODOS_ITENS", index=True)

    # Filtros do modelo POR_DESCRICAO (opcionais; quando vazios, não paga nada nesse modelo)
    filtro_marca = Column(String(120), nullable=True, index=True)  # ex: MAGNETRON
    filtro_descricao_prefixo = Column(String(200), nullable=True)  # ex: MOTOR DE PARTIDA

    # Valor unitário específico do modelo POR_DESCRICAO (fallback: valor_unitario_global)
    valor_unitario_modelo2 = Column(Float, nullable=True)

    ativo = Column(Boolean, nullable=False, default=True)

    __table_args__ = (
        Index("ix_combo_emp_marca", "emp", "marca"),
    )


    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow, server_default=func.now())

    @property
    def criado_em(self):
        return self.created_at

    @property
    def atualizado_em(self):
        return self.updated_at

class CampanhaComboItem(Base):
    __tablename__ = "campanhas_combo_itens"

    id = Column(Integer, primary_key=True)
    combo_id = Column(Integer, nullable=False, index=True)

    nome_item = Column(String(255), nullable=True)

    # Campo obrigatório no banco: define o texto-base do match (mestre_prefixo ou descricao_contains)
    match_mestre = Column(String(255), nullable=False)

    # Match: CODIGO (MESTRE) por prefixo e/ou DESCRIÇÃO por contains
    mestre_prefixo = Column(String(120), nullable=True)
    descricao_contains = Column(String(200), nullable=True)

    minimo_qtd = Column(Integer, nullable=False, default=0)
    valor_unitario = Column(Float, nullable=True)  # opcional; se vazio usa combo.valor_unitario_global

    ordem = Column(Integer, nullable=False, default=1)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, server_default=func.now())
    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow, server_default=func.now())
    atualizado_em = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow, server_default=func.now())

class CampanhaComboResultado(Base):
    __tablename__ = "campanhas_combo_resultados"

    id = Column(Integer, primary_key=True)
    combo_id = Column(Integer, nullable=False, index=True)

    competencia_ano = Column(Integer, nullable=False, index=True)
    competencia_mes = Column(Integer, nullable=False, index=True)

    emp = Column(String(30), nullable=False, index=True)
    vendedor = Column(String(80), nullable=False, index=True)

    titulo = Column(String(160), nullable=False, default="")
    marca = Column(String(120), nullable=False, default="")

    data_inicio = Column(Date, nullable=False)
    data_fim = Column(Date, nullable=False)

    atingiu_gate = Column(Integer, nullable=False, default=0)
    valor_recompensa = Column(Float, nullable=False, default=0.0)

    status_pagamento = Column(String(20), nullable=False, default="PENDENTE")
    pago_em = Column(DateTime, nullable=True)
    atualizado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint(
            "combo_id",
            "emp",
            "vendedor",
            "competencia_ano",
            "competencia_mes",
            name="uq_combo_resultado_comp_emp_vendedor",
        ),
        Index("ix_combo_res_emp_comp", "emp", "competencia_ano", "competencia_mes"),
        Index("ix_combo_res_vendedor", "vendedor"),
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

    fechado = Column(Boolean, nullable=False, default=False)
    fechado_em = Column(DateTime, nullable=True)
    # Status do período (controle financeiro): "aberto", "a_pagar", "pago"
    status = Column(String(20), nullable=False, default="aberto", index=True)

    __table_args__ = (
        UniqueConstraint("emp", "ano", "mes", name="uq_fechamento_mensal_raw"),
        {'extend_existing': True},
    )
class FechamentoMensalAudit(Base):
    """Auditoria de fechamento mensal (quem/quando/de->para)."""

    __tablename__ = "fechamento_mensal_audit"

    id = Column(Integer, primary_key=True)
    emp = Column(String(30), nullable=False, default="", index=True)
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)

    acao = Column(String(30), nullable=False, default="", index=True)  # gerar_fechamento, fechar_a_pagar, fechar_pago, reabrir
    fechado_de = Column(Boolean, nullable=True)
    fechado_para = Column(Boolean, nullable=True)
    status_de = Column(String(20), nullable=True)
    status_para = Column(String(20), nullable=True)

    actor = Column(String(120), nullable=True, default="")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        Index("ix_fech_audit_emp_ano_mes", "emp", "ano", "mes"),
        {'extend_existing': True},
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


# ==========================
# Campaign Engine V2 (Enterprise)
# ==========================


class CampanhaV2Master(Base):
    """Cadastro universal de campanhas V2 (enterprise).

    Nota: armazenamos regras/premiação em JSON (texto) para permitir evolução sem migrations.
    """

    __tablename__ = "campanhas_master_v2"

    id = Column(Integer, primary_key=True)
    titulo = Column(String(160), nullable=False)
    tipo = Column(String(40), nullable=False, index=True)  # RANKING_VALOR, META_PERCENTUAL, META_ABSOLUTA, MIX, ACUMULATIVA

    escopo = Column(String(20), nullable=False, default="EMP", index=True)  # EMP ou GLOBAL
    emps_json = Column(Text, nullable=True)  # ex: "[101,1001]" - usado quando escopo=EMP

    vigencia_ini = Column(Date, nullable=False)
    vigencia_fim = Column(Date, nullable=False)

    ativo = Column(Boolean, nullable=False, default=True, index=True)
    regras_json = Column(Text, nullable=True)  # JSON string

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index("ix_camp_v2_tipo_ativo", "tipo", "ativo"),
    )


class CampanhaV2Resultado(Base):
    __tablename__ = "campanhas_resultados_v2"

    id = Column(Integer, primary_key=True)
    campanha_id = Column(Integer, nullable=False, index=True)

    competencia_ano = Column(Integer, nullable=False, index=True)
    competencia_mes = Column(Integer, nullable=False, index=True)
    emp = Column(Integer, nullable=False, index=True)  # 0 = global
    vendedor = Column(String(80), nullable=False, index=True)

    tipo = Column(String(40), nullable=False, index=True)
    base_num = Column(Float, nullable=False, default=0.0)
    atingiu = Column(Boolean, nullable=False, default=False)
    valor_recompensa = Column(Float, nullable=False, default=0.0)

    detalhes_json = Column(Text, nullable=True)

    vigencia_ini = Column(Date, nullable=True)
    vigencia_fim = Column(Date, nullable=True)

    status_pagamento = Column(String(20), nullable=False, default="PENDENTE", index=True)
    pago_em = Column(DateTime, nullable=True)
    atualizado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint(
            "campanha_id",
            "competencia_ano",
            "competencia_mes",
            "emp",
            "vendedor",
            name="uq_camp_v2_res"
        ),
        Index("ix_camp_v2_res_comp_emp", "competencia_ano", "competencia_mes", "emp"),
    )


class CampanhaV2Audit(Base):
    __tablename__ = "campanhas_audit_v2"

    id = Column(Integer, primary_key=True)
    campanha_id = Column(Integer, nullable=True, index=True)
    competencia_ano = Column(Integer, nullable=True, index=True)
    competencia_mes = Column(Integer, nullable=True, index=True)
    emp = Column(Integer, nullable=True, index=True)
    vendedor = Column(String(80), nullable=True, index=True)

    acao = Column(String(60), nullable=False)  # ex: status_update
    de_status = Column(String(20), nullable=True)
    para_status = Column(String(20), nullable=True)
    actor = Column(String(60), nullable=True)
    payload_json = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


# --------------------------
# Backwards-compatible aliases (some patches referenced alternate names)
# --------------------------
# These aliases avoid ImportError if other modules expect the V2 models
# to be exposed with different identifiers.
CampanhaMasterV2 = CampanhaV2Master
CampanhaResultadoV2 = CampanhaV2Resultado
CampanhaAuditV2 = CampanhaV2Audit




# ==========================
# Campaign Engine V2 (NEW schema - 2026-02)
# These map to the new tables created via Supabase SQL:
#   campanhas_v2_master, campanhas_scope_emp_v2, campanhas_v2_resultados
# and are used by the Financeiro module (pagamentos) and the V2 engine going forward.
# They coexist with the older V2 tables (campanhas_master_v2 / campanhas_resultados_v2)
# to avoid breaking older deployments.
# ==========================

class CampanhaV2MasterNew(Base):
    __tablename__ = "campanhas_v2_master"

    id = Column(Integer, primary_key=True)
    nome = Column(Text, nullable=False)
    tipo = Column(String(40), nullable=False, index=True)

    ativo = Column(Boolean, nullable=False, default=True)

    vigencia_inicio = Column(Date, nullable=True)
    vigencia_fim = Column(Date, nullable=True)

    scope_mode = Column(String(20), nullable=False, default="GLOBAL")  # GLOBAL | POR_EMP

    marca_alvo = Column(Text, nullable=True)

    meta_valor = Column(Float, nullable=True)
    meta_percentual = Column(Float, nullable=True)

    mix_qtd_min = Column(Integer, nullable=True)

    janela_meses = Column(Integer, nullable=False, default=1)

    premio_tipo = Column(String(20), nullable=False, default="FIXO")  # FIXO | PERCENTUAL
    premio_top1 = Column(Float, nullable=True)
    premio_top2 = Column(Float, nullable=True)
    premio_top3 = Column(Float, nullable=True)
    premio_percentual = Column(Float, nullable=True)

    base_minima_valor = Column(Float, nullable=False, default=0.0)

    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow)
    atualizado_em = Column(DateTime, nullable=False, default=datetime.utcnow)


class CampanhaV2ScopeEMPNew(Base):
    __tablename__ = "campanhas_scope_emp_v2"

    id = Column(Integer, primary_key=True)
    campanha_id = Column(Integer, nullable=False, index=True)
    emp = Column(Integer, nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("campanha_id", "emp", name="uq_camp_v2_scope_emp"),
        Index("ix_camp_v2_scope_emp_emp", "emp"),
    )


class CampanhaV2ResultadoNew(Base):
    __tablename__ = "campanhas_v2_resultados"

    id = Column(Integer, primary_key=True)
    campanha_id = Column(Integer, nullable=False, index=True)

    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)

    emp = Column(Integer, nullable=True, index=True)  # null quando GLOBAL
    vendedor = Column(String(80), nullable=False, index=True)

    valor_base = Column(Float, nullable=True)
    valor_atual = Column(Float, nullable=True)
    pct = Column(Float, nullable=True)
    mix = Column(Integer, nullable=True)

    posicao = Column(Integer, nullable=True)
    atingiu = Column(Boolean, nullable=False, default=False)
    premio = Column(Float, nullable=False, default=0.0)

    detalhes_json = Column(Text, nullable=True)
    calculado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("campanha_id", "ano", "mes", "emp", "vendedor", name="uq_camp_v2_result_key"),
        Index("ix_camp_v2_result_competencia", "ano", "mes"),
        Index("ix_camp_v2_result_emp_competencia", "emp", "ano", "mes"),
        Index("ix_camp_v2_result_vendedor_competencia", "vendedor", "ano", "mes"),
    )



# ==========================
# Aliases de compatibilidade (IMPORTS do app.py)
# O app.py (legado) importa CampanhaV2Master / CampanhaV2ScopeEMP / CampanhaV2Resultado.
# Neste arquivo existem duas "V2":
#   - V2 antiga: campanhas_master_v2 / campanhas_resultados_v2  (classes CampanhaV2Master, CampanhaV2Resultado)
#   - V2 nova (2026-02): campanhas_v2_master / campanhas_scope_emp_v2 / campanhas_v2_resultados
#
# Para o Financeiro + Engine V2 nova, o app precisa encontrar CampanhaV2ScopeEMP.
# Portanto, expomos CampanhaV2ScopeEMP apontando para o model da V2 nova.
# Mantemos CampanhaV2Master e CampanhaV2Resultado como V2 antiga (para não quebrar rotas antigas),
# e também expomos aliases explícitos para a V2 nova quando necessário.
# ==========================

# V2 NOVA (2026-02) - nomes explícitos
CampanhaV2MasterNewSchema = CampanhaV2MasterNew
CampanhaV2ResultadoNewSchema = CampanhaV2ResultadoNew
CampanhaV2ScopeEMPNewSchema = CampanhaV2ScopeEMPNew

# Nome esperado pelo app.py / patches anteriores
CampanhaV2ScopeEMP = CampanhaV2ScopeEMPNew

# ==========================
# Financeiro (pagamentos + audit)
# Tables:
#   financeiro_pagamentos, financeiro_audit
# ==========================

class FinanceiroPagamento(Base):
    __tablename__ = "financeiro_pagamentos"

    __table_args__ = ({'extend_existing': True},)

    id = Column(Integer, primary_key=True)

    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)

    origem_tipo = Column(String(20), nullable=False, index=True)  # V1_QTD | V1_COMBO | V1_PARADOS | V2
    origem_id = Column(Integer, nullable=False, index=True)

    campanha_nome = Column(Text, nullable=True)

    emp = Column(Integer, nullable=True, index=True)
    vendedor = Column(String(80), nullable=False, index=True)

    valor_premio = Column(Float, nullable=False, default=0.0)
    status = Column(String(20), nullable=False, default="PENDENTE", index=True)

    atualizado_por = Column(Text, nullable=True)
    atualizado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("ano", "mes", "origem_tipo", "origem_id", "emp", "vendedor", name="uq_fin_pag_key"),
        Index("ix_fin_pag_competencia", "ano", "mes"),
        Index("ix_fin_pag_status", "status"),
        Index("ix_fin_pag_emp_competencia", "emp", "ano", "mes"),
        Index("ix_fin_pag_vendedor_competencia", "vendedor", "ano", "mes"),
        Index("ix_fin_pag_origem", "origem_tipo", "origem_id"),
    )




class ImportacaoLog(Base):
    __tablename__ = "importacoes_log"

    id = Column(Integer, primary_key=True)

    usuario = Column(String(80), nullable=True)
    arquivo_nome = Column(String(255), nullable=True)

    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    emps_json = Column(Text, nullable=True)
    periodos_json = Column(Text, nullable=True)
    resumo_json = Column(Text, nullable=True)

    total_linhas = Column(Integer, nullable=True)
    validas = Column(Integer, nullable=True)
    inseridas = Column(Integer, nullable=True)
    ignoradas = Column(Integer, nullable=True)
    erros_linha = Column(Integer, nullable=True)

    total_bruto = Column(Float, nullable=True)
    total_ca = Column(Float, nullable=True)
    total_liquido = Column(Float, nullable=True)
    ca_linhas = Column(Integer, nullable=True)
    duracao_s = Column(Float, nullable=True)

    __table_args__ = (
        Index("ix_importacoes_log_criado_em", "criado_em"),
    )

class FinanceiroAudit(Base):
    __tablename__ = "financeiro_audit"

    id = Column(Integer, primary_key=True)
    pagamento_id = Column(Integer, nullable=False, index=True)

    acao = Column(String(40), nullable=False)
    de_status = Column(String(20), nullable=True)
    para_status = Column(String(20), nullable=True)

    usuario = Column(Text, nullable=True)
    criado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    meta = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_fin_audit_pagamento", "pagamento_id"),
        Index("ix_fin_audit_criado_em", "criado_em"),
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
    # IMPORTANTE:
    # - Em Postgres, se uma alteração de schema falhar dentro de uma transação,
    #   a transação fica "aborted" e NENHUM comando seguinte é aplicado.
    # - Para evitar que 1 ajuste falho impeça todos os outros (e estoure
    #   UndefinedColumn depois), rodamos em AUTOCOMMIT.
    try:
        with engine.connect() as conn:
            conn = conn.execution_options(isolation_level="AUTOCOMMIT")
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

            # Metas - evolução compatível para metas de lojas / gerente
            conn.execute(text("ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS escopo varchar(20) NOT NULL DEFAULT 'VENDEDOR';"))
            conn.execute(text("ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS faturamento_minimo double precision;"))
            conn.execute(text("ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS margem_minima double precision;"))
            conn.execute(text("ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS teto_faturamento double precision;"))
            conn.execute(text("ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS teto_bonus_percentual double precision;"))
            conn.execute(text("ALTER TABLE metas_programas ALTER COLUMN faturamento_minimo SET DEFAULT 70000;"))
            conn.execute(text("UPDATE metas_programas SET faturamento_minimo = 70000 WHERE faturamento_minimo IS NULL;"))
            conn.execute(text("ALTER TABLE metas_programas_emps ADD COLUMN IF NOT EXISTS ativo boolean NOT NULL DEFAULT true;"))
            conn.execute(text("ALTER TABLE metas_programas_emps ADD COLUMN IF NOT EXISTS criado_em timestamp NOT NULL DEFAULT now();"))
            conn.execute(text("ALTER TABLE metas_programas_emps ADD COLUMN IF NOT EXISTS atualizado_em timestamp;"))
            conn.execute(text("ALTER TABLE metas_programas_emps ADD COLUMN IF NOT EXISTS removido_em timestamp;"))
            conn.execute(text("UPDATE metas_programas_emps SET ativo = true WHERE ativo IS NULL;"))
            conn.execute(text("ALTER TABLE metas_bases_manuais ADD COLUMN IF NOT EXISTS margem_percentual double precision;"))
            conn.execute(text("ALTER TABLE metas_bases_manuais ADD COLUMN IF NOT EXISTS bonus_extra_percentual double precision;"))
            conn.execute(text("ALTER TABLE metas_bases_manuais ADD COLUMN IF NOT EXISTS observacao varchar(200);"))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS metas_margens_vendedores (
                    id SERIAL PRIMARY KEY,
                    ano INTEGER NOT NULL,
                    mes INTEGER NOT NULL,
                    emp VARCHAR(30) NOT NULL DEFAULT 'GERAL',
                    vendedor VARCHAR(80) NOT NULL,
                    margem_percentual DOUBLE PRECISION NOT NULL DEFAULT 0,
                    observacao VARCHAR(240),
                    arquivo_origem VARCHAR(255),
                    importado_por VARCHAR(80),
                    importado_em TIMESTAMP NOT NULL DEFAULT NOW(),
                    CONSTRAINT uq_meta_margem_vendedor_periodo UNIQUE (ano, mes, emp, vendedor)
                );
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_meta_margem_emp_periodo ON metas_margens_vendedores (emp, ano, mes);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_meta_margem_vendedor_periodo ON metas_margens_vendedores (vendedor, ano, mes);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_meta_margem_periodo_vendedor ON metas_margens_vendedores (ano, mes, vendedor);"))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS oficina_servicos (
                    id SERIAL PRIMARY KEY,
                    ano INTEGER NOT NULL,
                    mes INTEGER NOT NULL,
                    emp VARCHAR(30) NOT NULL,
                    usuario VARCHAR(80) NOT NULL,
                    valor_servico DOUBLE PRECISION NOT NULL DEFAULT 0,
                    observacao VARCHAR(240),
                    arquivo_origem VARCHAR(255),
                    importado_por VARCHAR(80),
                    importado_em TIMESTAMP NOT NULL DEFAULT NOW(),
                    ativo BOOLEAN NOT NULL DEFAULT TRUE,
                    CONSTRAINT uq_oficina_servico_periodo_usuario UNIQUE (ano, mes, emp, usuario)
                );
            """))
            conn.execute(text("ALTER TABLE oficina_servicos ADD COLUMN IF NOT EXISTS observacao varchar(240);"))
            conn.execute(text("ALTER TABLE oficina_servicos ADD COLUMN IF NOT EXISTS arquivo_origem varchar(255);"))
            conn.execute(text("ALTER TABLE oficina_servicos ADD COLUMN IF NOT EXISTS importado_por varchar(80);"))
            conn.execute(text("ALTER TABLE oficina_servicos ADD COLUMN IF NOT EXISTS importado_em timestamp NOT NULL DEFAULT now();"))
            conn.execute(text("ALTER TABLE oficina_servicos ADD COLUMN IF NOT EXISTS ativo boolean NOT NULL DEFAULT true;"))
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_oficina_servicos_periodo_usuario ON oficina_servicos (ano, mes, emp, usuario);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_oficina_servicos_emp_periodo ON oficina_servicos (emp, ano, mes);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_oficina_servicos_usuario_periodo ON oficina_servicos (usuario, ano, mes);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_oficina_servicos_periodo ON oficina_servicos (ano, mes);"))
            conn.execute(text("ALTER TABLE metas_resultados ADD COLUMN IF NOT EXISTS margem_percentual double precision;"))
            conn.execute(text("ALTER TABLE metas_resultados ADD COLUMN IF NOT EXISTS margem_minima double precision;"))
            conn.execute(text("ALTER TABLE metas_resultados ADD COLUMN IF NOT EXISTS margem_atingida boolean;"))
            conn.execute(text("ALTER TABLE metas_resultados ADD COLUMN IF NOT EXISTS bloqueado_margem boolean NOT NULL DEFAULT false;"))
            # Campanhas QTD: tipo de beneficiário (vendedor individual ou gerente da loja)
            conn.execute(text("ALTER TABLE campanhas_qtd ADD COLUMN IF NOT EXISTS campanha_tipo varchar(20) NOT NULL DEFAULT 'VENDEDOR';"))
            conn.execute(text("ALTER TABLE campanhas_qtd_resultados ADD COLUMN IF NOT EXISTS campanha_tipo varchar(20) NOT NULL DEFAULT 'VENDEDOR';"))
            conn.execute(text("ALTER TABLE campanhas_qtd ADD COLUMN IF NOT EXISTS faturamento_minimo_emp double precision;"))
            conn.execute(text("ALTER TABLE campanhas_qtd_resultados ADD COLUMN IF NOT EXISTS premio_potencial double precision;"))
            conn.execute(text("ALTER TABLE campanhas_qtd_resultados ADD COLUMN IF NOT EXISTS faturamento_minimo_emp double precision;"))
            conn.execute(text("ALTER TABLE campanhas_qtd_resultados ADD COLUMN IF NOT EXISTS faturamento_emp double precision;"))
            conn.execute(text("ALTER TABLE campanhas_qtd_resultados ADD COLUMN IF NOT EXISTS faltante_faturamento_emp double precision;"))
            conn.execute(text("ALTER TABLE campanhas_qtd_resultados ADD COLUMN IF NOT EXISTS bloqueado_faturamento_emp integer NOT NULL DEFAULT 0;"))
            conn.execute(text("UPDATE campanhas_qtd SET campanha_tipo='VENDEDOR' WHERE campanha_tipo IS NULL OR campanha_tipo='';"))
            conn.execute(text("UPDATE campanhas_qtd_resultados SET campanha_tipo='VENDEDOR' WHERE campanha_tipo IS NULL OR campanha_tipo='';"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_campanhas_qtd_tipo ON campanhas_qtd (campanha_tipo);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_campanhas_qtd_resultados_tipo ON campanhas_qtd_resultados (campanha_tipo);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_campanhas_qtd_resultados_bloq_emp ON campanhas_qtd_resultados (competencia_ano, competencia_mes, emp, bloqueado_faturamento_emp);"))

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
            # Mensagens (comunicados) + destinos + leitura diária
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS mensagens (
                    id SERIAL PRIMARY KEY,
                    titulo VARCHAR(180) NOT NULL,
                    conteudo TEXT NOT NULL,
                    bloqueante BOOLEAN NOT NULL DEFAULT FALSE,
                    ativo BOOLEAN NOT NULL DEFAULT TRUE,
                    inicio_em DATE,
                    fim_em DATE,
                    created_by_user_id INTEGER,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW()
                );
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_mensagens_ativo_bloqueante ON mensagens (ativo, bloqueante);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_mensagens_periodo ON mensagens (inicio_em, fim_em);"))

            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS mensagem_empresas (
                    id SERIAL PRIMARY KEY,
                    mensagem_id INTEGER NOT NULL,
                    emp VARCHAR(30) NOT NULL,
                    CONSTRAINT uq_msg_empresa UNIQUE (mensagem_id, emp)
                );
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_msg_emp_mensagem_id ON mensagem_empresas (mensagem_id);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_msg_emp_emp ON mensagem_empresas (emp);"))

            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS mensagem_usuarios (
                    id SERIAL PRIMARY KEY,
                    mensagem_id INTEGER NOT NULL,
                    usuario_id INTEGER NOT NULL,
                    CONSTRAINT uq_msg_usuario UNIQUE (mensagem_id, usuario_id)
                );
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_msg_usr_mensagem_id ON mensagem_usuarios (mensagem_id);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_msg_usr_usuario_id ON mensagem_usuarios (usuario_id);"))

            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS mensagem_lidas_diarias (
                    id SERIAL PRIMARY KEY,
                    mensagem_id INTEGER NOT NULL,
                    usuario_id INTEGER NOT NULL,
                    data DATE NOT NULL,
                    lida_em TIMESTAMP NOT NULL DEFAULT NOW(),
                    CONSTRAINT uq_msg_lida_dia UNIQUE (mensagem_id, usuario_id, data)
                );
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_msg_lidas_usuario_data ON mensagem_lidas_diarias (usuario_id, data);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_msg_lidas_data ON mensagem_lidas_diarias (data);"))

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




            # Campanhas Combo (unificado): garantir colunas necessárias
            conn.execute(text("ALTER TABLE campanhas_combo ADD COLUMN IF NOT EXISTS titulo varchar(160);"))
            conn.execute(text("ALTER TABLE campanhas_combo ADD COLUMN IF NOT EXISTS data_inicio date;"))
            conn.execute(text("ALTER TABLE campanhas_combo ADD COLUMN IF NOT EXISTS data_fim date;"))

            # Campos de auditoria (o modelo usa criado_em/atualizado_em)
            conn.execute(text("ALTER TABLE campanhas_combo ADD COLUMN IF NOT EXISTS criado_em timestamptz DEFAULT now();"))
            conn.execute(text("ALTER TABLE campanhas_combo ADD COLUMN IF NOT EXISTS atualizado_em timestamptz;"))

            # Compat: versões antigas podem ter 'updated_at'
            conn.execute(text("ALTER TABLE campanhas_combo ADD COLUMN IF NOT EXISTS updated_at timestamptz;"))
            # Se existir coluna antiga "nome", copia para "titulo" quando estiver vazio
            conn.execute(text("""
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='campanhas_combo' AND column_name='nome')
     AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='campanhas_combo' AND column_name='titulo') THEN
    UPDATE campanhas_combo
       SET titulo = nome
     WHERE (titulo IS NULL OR titulo = '') AND nome IS NOT NULL;
  END IF;
END $$;
"""))

            # Fechamento mensal: status financeiro (aberto/a_pagar/pago)
            conn.execute(text("ALTER TABLE fechamento_mensal ADD COLUMN IF NOT EXISTS status varchar(20) DEFAULT 'aberto';"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_fechamento_mensal_status ON fechamento_mensal (status);"))

            # Itens Parados Resultado: colunas de snapshot v2 usadas pelo relatório unificado
            conn.execute(text("ALTER TABLE itens_parados_resultados ADD COLUMN IF NOT EXISTS qtd_base double precision;"))
            conn.execute(text("ALTER TABLE itens_parados_resultados ADD COLUMN IF NOT EXISTS recompensa_unit double precision;"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_itens_parados_res_comp_emp_vend ON itens_parados_resultados (competencia_ano, competencia_mes, emp, vendedor);"))

            # Fix default/nullable do fechamento (mes nasce aberto)
            try:
                conn.execute(text("ALTER TABLE fechamento_mensal ALTER COLUMN fechado SET DEFAULT FALSE;"))
            except Exception:
                pass
            try:
                conn.execute(text("ALTER TABLE fechamento_mensal ALTER COLUMN fechado_em DROP NOT NULL;"))
            except Exception:
                pass

            # Bancos mais antigos podem ter criado `status` como ENUM ou com restrições.
            # Neste caso, o valor 'a_pagar' pode não existir e a atualização falha silenciosamente.
            # Tentamos adicionar o valor ao ENUM, se for aplicável, sem derrubar a aplicação.
            try:
                row = conn.execute(text("""
                    SELECT data_type, udt_name
                    FROM information_schema.columns
                    WHERE table_schema = 'public'
                      AND table_name = 'fechamento_mensal'
                      AND column_name = 'status'
                    LIMIT 1
                """)).fetchone()

                if row and str(row[0]).upper() == 'USER-DEFINED':
                    enum_name = str(row[1] or '').strip()
                    # Segurança básica: só permite nomes simples (evita SQL injection em identifier)
                    if enum_name and all(ch.isalnum() or ch == '_' for ch in enum_name):
                        conn.execute(text(f"""
                            DO $$
                            BEGIN
                                IF NOT EXISTS (
                                    SELECT 1
                                    FROM pg_enum e
                                    JOIN pg_type t ON t.oid = e.enumtypid
                                    WHERE t.typname = '{enum_name}'
                                      AND e.enumlabel = 'a_pagar'
                                ) THEN
                                    ALTER TYPE {enum_name} ADD VALUE 'a_pagar';
                                END IF;
                            END$$;
                        """))
            except Exception:
                pass
    except Exception:
        # Se não tiver permissão ou der algum erro, não derruba o app.
        pass

# ==========================
# Financeiro Pagamentos Audit (idempotente)
# ==========================

class FinanceiroPagamentoAudit(Base):
    __tablename__ = "financeiro_pagamentos_audit"
    __table_args__ = ({'extend_existing': True},)

    id = Column(Integer, primary_key=True)

    pagamento_id = Column(Integer, nullable=False, index=True)
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)

    origem_tipo = Column(String(20), nullable=False, index=True)  # V1_QTD | V1_COMBO | V2 | etc
    origem_id = Column(Integer, nullable=False, index=True)

    emp = Column(String(30), nullable=True, index=True)
    vendedor = Column(String(80), nullable=True, index=True)

    status_de = Column(String(20), nullable=True)
    status_para = Column(String(20), nullable=False)

    alterado_por = Column(String(80), nullable=True)  # username
    alterado_em = Column(DateTime, nullable=False, default=datetime.utcnow)

    motivo = Column(Text, nullable=True)


def ensure_bonus_importados_schema(force: bool = False):
    """Garante as tabelas do snapshot mensal de bônus.

    A função é idempotente e roda somente na primeira utilização por processo,
    evitando depender de ``AUTO_MIGRATE`` no Render. O arquivo SQL equivalente
    também acompanha o projeto para aplicação manual no Supabase.
    """
    global _BONUS_IMPORTADOS_SCHEMA_READY
    if _BONUS_IMPORTADOS_SCHEMA_READY and not force:
        return

    with engine.connect() as conn:
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS bonus_importacoes_lotes (
                id SERIAL PRIMARY KEY,
                ano INTEGER NOT NULL,
                mes INTEGER NOT NULL,
                arquivo_origem VARCHAR(255) NOT NULL,
                importado_por_user_id INTEGER,
                importado_por VARCHAR(80),
                importado_em TIMESTAMP NOT NULL DEFAULT NOW(),
                linhas_lidas INTEGER NOT NULL DEFAULT 0,
                linhas_importadas INTEGER NOT NULL DEFAULT 0,
                linhas_ignoradas INTEGER NOT NULL DEFAULT 0,
                avisos_json TEXT
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS bonus_usuarios_importados (
                id SERIAL PRIMARY KEY,
                lote_id INTEGER NOT NULL,
                ano INTEGER NOT NULL,
                mes INTEGER NOT NULL,
                linha_origem INTEGER,
                usuario_id INTEGER,
                usuario_nome VARCHAR(80) NOT NULL,
                funcao VARCHAR(30) NOT NULL,
                emp VARCHAR(30) NOT NULL,
                produto_vendedor NUMERIC(18,4) NOT NULL DEFAULT 0,
                mecanico_faturado NUMERIC(18,4) NOT NULL DEFAULT 0,
                venda_anterior NUMERIC(18,4) NOT NULL DEFAULT 0,
                venda_atual NUMERIC(18,4) NOT NULL DEFAULT 0,
                crescimento NUMERIC(12,6),
                loja_anterior NUMERIC(18,4) NOT NULL DEFAULT 0,
                loja_atual NUMERIC(18,4) NOT NULL DEFAULT 0,
                produto_gerente NUMERIC(18,4) NOT NULL DEFAULT 0,
                importado_vendedor NUMERIC(18,4) NOT NULL DEFAULT 0,
                importado_loja NUMERIC(18,4) NOT NULL DEFAULT 0,
                bonus_importado NUMERIC(18,4) NOT NULL DEFAULT 0,
                valor_meta NUMERIC(18,4) NOT NULL DEFAULT 0,
                valor_parcial NUMERIC(18,4) NOT NULL DEFAULT 0,
                bonus_final NUMERIC(18,4) NOT NULL DEFAULT 0,
                importado_em TIMESTAMP NOT NULL DEFAULT NOW(),
                CONSTRAINT uq_bonus_usuario_periodo_emp UNIQUE (ano, mes, emp, usuario_nome)
            );
        """))
        # Atualiza instalações que já possuíam o layout anterior da tabela.
        conn.execute(text("ALTER TABLE bonus_usuarios_importados ADD COLUMN IF NOT EXISTS produto_vendedor NUMERIC(18,4) NOT NULL DEFAULT 0;"))
        conn.execute(text("ALTER TABLE bonus_usuarios_importados ADD COLUMN IF NOT EXISTS mecanico_faturado NUMERIC(18,4) NOT NULL DEFAULT 0;"))
        conn.execute(text("ALTER TABLE bonus_usuarios_importados ADD COLUMN IF NOT EXISTS venda_anterior NUMERIC(18,4) NOT NULL DEFAULT 0;"))
        conn.execute(text("ALTER TABLE bonus_usuarios_importados ADD COLUMN IF NOT EXISTS venda_atual NUMERIC(18,4) NOT NULL DEFAULT 0;"))
        conn.execute(text("ALTER TABLE bonus_usuarios_importados ADD COLUMN IF NOT EXISTS crescimento NUMERIC(12,6);"))
        conn.execute(text("ALTER TABLE bonus_usuarios_importados ADD COLUMN IF NOT EXISTS loja_anterior NUMERIC(18,4) NOT NULL DEFAULT 0;"))
        conn.execute(text("ALTER TABLE bonus_usuarios_importados ADD COLUMN IF NOT EXISTS loja_atual NUMERIC(18,4) NOT NULL DEFAULT 0;"))
        conn.execute(text("ALTER TABLE bonus_usuarios_importados ADD COLUMN IF NOT EXISTS produto_gerente NUMERIC(18,4) NOT NULL DEFAULT 0;"))
        conn.execute(text("ALTER TABLE bonus_usuarios_importados ADD COLUMN IF NOT EXISTS importado_vendedor NUMERIC(18,4) NOT NULL DEFAULT 0;"))
        conn.execute(text("ALTER TABLE bonus_usuarios_importados ADD COLUMN IF NOT EXISTS bonus_importado NUMERIC(18,4) NOT NULL DEFAULT 0;"))
        conn.execute(text("ALTER TABLE bonus_usuarios_importados ADD COLUMN IF NOT EXISTS valor_parcial NUMERIC(18,4) NOT NULL DEFAULT 0;"))
        conn.execute(text("ALTER TABLE bonus_usuarios_importados ADD COLUMN IF NOT EXISTS importado_loja NUMERIC(18,4) NOT NULL DEFAULT 0;"))
        conn.execute(text("ALTER TABLE bonus_usuarios_importados ADD COLUMN IF NOT EXISTS valor_meta NUMERIC(18,4) NOT NULL DEFAULT 0;"))
        conn.execute(text("ALTER TABLE bonus_usuarios_importados ADD COLUMN IF NOT EXISTS bonus_final NUMERIC(18,4) NOT NULL DEFAULT 0;"))

        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_lotes_periodo_importado ON bonus_importacoes_lotes (ano, mes, importado_em);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_lotes_importado_em ON bonus_importacoes_lotes (importado_em);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_lotes_importado_por_user_id ON bonus_importacoes_lotes (importado_por_user_id);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_usuario_periodo ON bonus_usuarios_importados (usuario_nome, ano, mes);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_emp_periodo ON bonus_usuarios_importados (emp, ano, mes);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_funcao_periodo ON bonus_usuarios_importados (funcao, ano, mes);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_usuarios_lote_id ON bonus_usuarios_importados (lote_id);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_usuarios_usuario_id ON bonus_usuarios_importados (usuario_id);"))

    _BONUS_IMPORTADOS_SCHEMA_READY = True



def ensure_bonus_atacado_schema(force: bool = False):
    """Garante a estrutura enxuta do módulo Bônus Atacado."""
    global _BONUS_ATACADO_SCHEMA_READY
    if _BONUS_ATACADO_SCHEMA_READY and not force:
        return

    with engine.connect() as conn:
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS bonus_atacado_importacoes_lotes (
                id SERIAL PRIMARY KEY,
                ano INTEGER NOT NULL,
                mes INTEGER NOT NULL,
                arquivo_origem VARCHAR(255) NOT NULL,
                aba_origem VARCHAR(120) NOT NULL DEFAULT 'PremiacaoFinal',
                importado_por_user_id INTEGER,
                importado_por VARCHAR(80),
                importado_em TIMESTAMP NOT NULL DEFAULT NOW(),
                linhas_lidas INTEGER NOT NULL DEFAULT 0,
                linhas_importadas INTEGER NOT NULL DEFAULT 0,
                linhas_ignoradas INTEGER NOT NULL DEFAULT 0,
                avisos_json TEXT
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS bonus_atacado_usuarios (
                id SERIAL PRIMARY KEY,
                lote_id INTEGER NOT NULL,
                ano INTEGER NOT NULL,
                mes INTEGER NOT NULL,
                linha_origem INTEGER,
                usuario_id INTEGER,
                usuario_nome VARCHAR(100) NOT NULL,
                funcao_planilha VARCHAR(30),
                emp VARCHAR(30) NOT NULL,
                total_produtos NUMERIC(18,4),
                venda_anterior NUMERIC(18,4),
                venda_atual NUMERIC(18,4),
                importado NUMERIC(18,4),
                percentual_importado NUMERIC(12,6),
                loja_anterior NUMERIC(18,4),
                loja_atual NUMERIC(18,4),
                falta_valor_vendedor NUMERIC(18,4),
                importado_em TIMESTAMP NOT NULL DEFAULT NOW(),
                CONSTRAINT uq_bonus_atacado_usuario_periodo_emp
                    UNIQUE (ano, mes, emp, usuario_nome)
            );
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_atacado_lotes_periodo_importado ON bonus_atacado_importacoes_lotes (ano, mes, importado_em);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_atacado_lotes_importado_por_user_id ON bonus_atacado_importacoes_lotes (importado_por_user_id);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_atacado_usuario_periodo ON bonus_atacado_usuarios (usuario_nome, ano, mes);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_atacado_emp_periodo ON bonus_atacado_usuarios (emp, ano, mes);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_atacado_usuario_id ON bonus_atacado_usuarios (usuario_id);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_atacado_lote_id ON bonus_atacado_usuarios (lote_id);"))
        conn.execute(text("ALTER TABLE bonus_atacado_importacoes_lotes ENABLE ROW LEVEL SECURITY;"))
        conn.execute(text("ALTER TABLE bonus_atacado_usuarios ENABLE ROW LEVEL SECURITY;"))

    _BONUS_ATACADO_SCHEMA_READY = True



def ensure_bonus_outros_valores_schema(force: bool = False):
    """Garante a tabela de lançamentos manuais de Outros Valores."""
    global _BONUS_OUTROS_VALORES_SCHEMA_READY
    if _BONUS_OUTROS_VALORES_SCHEMA_READY and not force:
        return

    with engine.connect() as conn:
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS bonus_outros_valores (
                id SERIAL PRIMARY KEY,
                origem VARCHAR(10) NOT NULL,
                ano INTEGER NOT NULL,
                mes INTEGER NOT NULL,
                usuario_id INTEGER NOT NULL,
                usuario_nome VARCHAR(100) NOT NULL,
                emp VARCHAR(30) NOT NULL,
                descricao VARCHAR(255) NOT NULL,
                valor NUMERIC(18,4) NOT NULL,
                criado_por_user_id INTEGER,
                criado_por VARCHAR(100),
                criado_em TIMESTAMP NOT NULL DEFAULT NOW(),
                CONSTRAINT ck_bonus_outros_origem
                    CHECK (origem IN ('VAREJO', 'ATACADO')),
                CONSTRAINT ck_bonus_outros_valor_positivo
                    CHECK (valor > 0)
            );
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_outros_origem_periodo ON bonus_outros_valores (origem, ano, mes);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_outros_usuario_periodo ON bonus_outros_valores (usuario_id, ano, mes);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_outros_emp_periodo ON bonus_outros_valores (emp, ano, mes);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_outros_usuario_nome ON bonus_outros_valores (usuario_nome);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_bonus_outros_criado_por_user_id ON bonus_outros_valores (criado_por_user_id);"))
        conn.execute(text("ALTER TABLE bonus_outros_valores ENABLE ROW LEVEL SECURITY;"))

    _BONUS_OUTROS_VALORES_SCHEMA_READY = True


def ensure_financeiro_bonus_schema(force: bool = False):
    """Garante o snapshot imutável dos fechamentos de bônus por EMP."""
    global _FINANCEIRO_BONUS_SCHEMA_READY
    if _FINANCEIRO_BONUS_SCHEMA_READY and not force:
        return

    with engine.connect() as conn:
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS financeiro_bonus_fechamentos (
                id SERIAL PRIMARY KEY,
                ano INTEGER NOT NULL,
                mes INTEGER NOT NULL,
                emp VARCHAR(30) NOT NULL,
                status VARCHAR(12) NOT NULL DEFAULT 'ABERTO',
                pago BOOLEAN NOT NULL DEFAULT FALSE,
                versao INTEGER NOT NULL DEFAULT 0,
                total_varejo NUMERIC(18,4) NOT NULL DEFAULT 0,
                total_atacado NUMERIC(18,4) NOT NULL DEFAULT 0,
                total_itens_parados NUMERIC(18,4) NOT NULL DEFAULT 0,
                total_outros_varejo NUMERIC(18,4) NOT NULL DEFAULT 0,
                total_outros_atacado NUMERIC(18,4) NOT NULL DEFAULT 0,
                total_geral NUMERIC(18,4) NOT NULL DEFAULT 0,
                fechado_por_user_id INTEGER,
                fechado_por VARCHAR(100),
                fechado_em TIMESTAMP,
                reaberto_por_user_id INTEGER,
                reaberto_por VARCHAR(100),
                reaberto_em TIMESTAMP,
                pago_por_user_id INTEGER,
                pago_por VARCHAR(100),
                pago_em TIMESTAMP,
                atualizado_em TIMESTAMP NOT NULL DEFAULT NOW(),
                CONSTRAINT uq_financeiro_bonus_fechamento_periodo_emp
                    UNIQUE (ano, mes, emp),
                CONSTRAINT ck_financeiro_bonus_status
                    CHECK (status IN ('ABERTO', 'FECHADO'))
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS financeiro_bonus_fechamento_itens (
                id SERIAL PRIMARY KEY,
                fechamento_id INTEGER NOT NULL,
                usuario_id INTEGER,
                usuario_nome VARCHAR(100) NOT NULL,
                funcao VARCHAR(30),
                emp VARCHAR(30) NOT NULL,
                bonus_varejo NUMERIC(18,4) NOT NULL DEFAULT 0,
                bonus_atacado NUMERIC(18,4) NOT NULL DEFAULT 0,
                itens_parados NUMERIC(18,4) NOT NULL DEFAULT 0,
                outros_varejo NUMERIC(18,4) NOT NULL DEFAULT 0,
                outros_atacado NUMERIC(18,4) NOT NULL DEFAULT 0,
                total_geral NUMERIC(18,4) NOT NULL DEFAULT 0,
                outros_detalhes_json TEXT,
                criado_em TIMESTAMP NOT NULL DEFAULT NOW(),
                CONSTRAINT uq_financeiro_bonus_item_fechamento_usuario
                    UNIQUE (fechamento_id, emp, usuario_nome),
                CONSTRAINT fk_financeiro_bonus_item_fechamento
                    FOREIGN KEY (fechamento_id)
                    REFERENCES financeiro_bonus_fechamentos(id)
                    ON DELETE CASCADE
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS financeiro_bonus_eventos (
                id SERIAL PRIMARY KEY,
                fechamento_id INTEGER NOT NULL,
                acao VARCHAR(20) NOT NULL,
                status_anterior VARCHAR(12),
                status_novo VARCHAR(12),
                pago_anterior BOOLEAN,
                pago_novo BOOLEAN,
                total_geral NUMERIC(18,4) NOT NULL DEFAULT 0,
                usuario_id INTEGER,
                usuario_nome VARCHAR(100),
                detalhes TEXT,
                criado_em TIMESTAMP NOT NULL DEFAULT NOW(),
                CONSTRAINT fk_financeiro_bonus_evento_fechamento
                    FOREIGN KEY (fechamento_id)
                    REFERENCES financeiro_bonus_fechamentos(id)
                    ON DELETE CASCADE
            );
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_financeiro_bonus_periodo_emp ON financeiro_bonus_fechamentos (ano, mes, emp);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_financeiro_bonus_status_periodo ON financeiro_bonus_fechamentos (ano, mes, status, pago);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_financeiro_bonus_item_fechamento ON financeiro_bonus_fechamento_itens (fechamento_id);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_financeiro_bonus_item_emp_usuario ON financeiro_bonus_fechamento_itens (emp, usuario_nome);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_financeiro_bonus_evento_fechamento ON financeiro_bonus_eventos (fechamento_id, criado_em);"))
        conn.execute(text("ALTER TABLE financeiro_bonus_fechamentos ENABLE ROW LEVEL SECURITY;"))
        conn.execute(text("ALTER TABLE financeiro_bonus_fechamento_itens ENABLE ROW LEVEL SECURITY;"))
        conn.execute(text("ALTER TABLE financeiro_bonus_eventos ENABLE ROW LEVEL SECURITY;"))

    _FINANCEIRO_BONUS_SCHEMA_READY = True


def ensure_itens_parados_snapshot_schema(force: bool = False):
    """Garante as tabelas enxutas do saldo importado de itens parados."""
    global _ITENS_PARADOS_SNAPSHOT_SCHEMA_READY
    if _ITENS_PARADOS_SNAPSHOT_SCHEMA_READY and not force:
        return

    with engine.connect() as conn:
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS itens_parados_vendas_importacoes (
                id SERIAL PRIMARY KEY,
                ano INTEGER NOT NULL,
                mes INTEGER NOT NULL,
                arquivo_origem VARCHAR(255) NOT NULL,
                importado_por_user_id INTEGER,
                importado_por VARCHAR(80),
                importado_em TIMESTAMP NOT NULL DEFAULT NOW(),
                data_inicio DATE,
                data_fim DATE,
                linhas_lidas INTEGER NOT NULL DEFAULT 0,
                linhas_importadas INTEGER NOT NULL DEFAULT 0,
                linhas_ignoradas INTEGER NOT NULL DEFAULT 0,
                registros_usuarios INTEGER NOT NULL DEFAULT 0,
                valor_total NUMERIC(18,4) NOT NULL DEFAULT 0,
                avisos_json TEXT
            );
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS itens_parados_vendas_usuarios (
                id SERIAL PRIMARY KEY,
                lote_id INTEGER NOT NULL,
                ano INTEGER NOT NULL,
                mes INTEGER NOT NULL,
                usuario_id INTEGER,
                usuario_nome VARCHAR(100) NOT NULL,
                emp VARCHAR(30) NOT NULL,
                valor_total NUMERIC(18,4) NOT NULL DEFAULT 0,
                qtd_linhas INTEGER NOT NULL DEFAULT 0,
                qtd_itens INTEGER NOT NULL DEFAULT 0,
                importado_em TIMESTAMP NOT NULL DEFAULT NOW(),
                CONSTRAINT uq_itens_parados_vendas_usuario_periodo_emp
                    UNIQUE (ano, mes, emp, usuario_nome)
            );
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_itens_parados_vendas_lote_periodo ON itens_parados_vendas_importacoes (ano, mes, importado_em);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_itens_parados_vendas_lote_usuario ON itens_parados_vendas_importacoes (importado_por_user_id);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_itens_parados_vendas_usuario_periodo ON itens_parados_vendas_usuarios (usuario_nome, ano, mes);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_itens_parados_vendas_emp_periodo ON itens_parados_vendas_usuarios (emp, ano, mes);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_itens_parados_vendas_usuario_id ON itens_parados_vendas_usuarios (usuario_id);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_itens_parados_vendas_lote_id ON itens_parados_vendas_usuarios (lote_id);"))
        conn.execute(text("ALTER TABLE itens_parados_vendas_importacoes ENABLE ROW LEVEL SECURITY;"))
        conn.execute(text("ALTER TABLE itens_parados_vendas_usuarios ENABLE ROW LEVEL SECURITY;"))

    _ITENS_PARADOS_SNAPSHOT_SCHEMA_READY = True


def ensure_metas_lojas_schema(force: bool = False):
    """Garante a estrutura do módulo novo de Metas.

    Mantido idempotente para não depender de AUTO_MIGRATE em produção.
    Para performance, as DDLs rodam somente na primeira chamada de cada processo
    Render, salvo quando ``force=True`` for usado explicitamente.
    """
    global _METAS_LOJAS_SCHEMA_READY
    if _METAS_LOJAS_SCHEMA_READY and not force:
        return
    try:
        with engine.connect() as conn:
            conn = conn.execution_options(isolation_level="AUTOCOMMIT")
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS metas_programas (
                    id SERIAL PRIMARY KEY,
                    nome VARCHAR(180) NOT NULL,
                    tipo VARCHAR(30) NOT NULL,
                    ano INTEGER NOT NULL,
                    mes INTEGER NOT NULL,
                    ativo BOOLEAN NOT NULL DEFAULT TRUE,
                    escopo VARCHAR(20) NOT NULL DEFAULT 'VENDEDOR',
                    faturamento_minimo DOUBLE PRECISION,
                    margem_minima DOUBLE PRECISION,
                    teto_faturamento DOUBLE PRECISION,
                    teto_bonus_percentual DOUBLE PRECISION,
                    created_by_user_id INTEGER,
                    created_at TIMESTAMP NOT NULL DEFAULT NOW()
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS metas_programas_emps (
                    id SERIAL PRIMARY KEY,
                    meta_id INTEGER NOT NULL,
                    emp VARCHAR(30) NOT NULL,
                    ativo BOOLEAN NOT NULL DEFAULT TRUE,
                    criado_em TIMESTAMP NOT NULL DEFAULT NOW(),
                    atualizado_em TIMESTAMP,
                    removido_em TIMESTAMP
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS metas_escalas (
                    id SERIAL PRIMARY KEY,
                    meta_id INTEGER NOT NULL,
                    ordem INTEGER NOT NULL DEFAULT 0,
                    limite_min DOUBLE PRECISION NOT NULL,
                    bonus_percentual DOUBLE PRECISION NOT NULL
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS metas_marcas (
                    id SERIAL PRIMARY KEY,
                    meta_id INTEGER NOT NULL,
                    marca VARCHAR(120) NOT NULL
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS metas_bases_manuais (
                    id SERIAL PRIMARY KEY,
                    meta_id INTEGER NOT NULL,
                    emp VARCHAR(30) NOT NULL,
                    vendedor VARCHAR(80) NOT NULL,
                    base_valor DOUBLE PRECISION NOT NULL DEFAULT 0,
                    margem_percentual DOUBLE PRECISION,
                    bonus_extra_percentual DOUBLE PRECISION DEFAULT 0,
                    observacao VARCHAR(200),
                    created_at TIMESTAMP NOT NULL DEFAULT NOW()
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS metas_margens_vendedores (
                    id SERIAL PRIMARY KEY,
                    ano INTEGER NOT NULL,
                    mes INTEGER NOT NULL,
                    emp VARCHAR(30) NOT NULL DEFAULT 'GERAL',
                    vendedor VARCHAR(80) NOT NULL,
                    margem_percentual DOUBLE PRECISION NOT NULL DEFAULT 0,
                    observacao VARCHAR(240),
                    arquivo_origem VARCHAR(255),
                    importado_por VARCHAR(80),
                    importado_em TIMESTAMP NOT NULL DEFAULT NOW(),
                    CONSTRAINT uq_meta_margem_vendedor_periodo UNIQUE (ano, mes, emp, vendedor)
                );
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS metas_resultados (
                    id SERIAL PRIMARY KEY,
                    meta_id INTEGER NOT NULL,
                    emp VARCHAR(30) NOT NULL,
                    vendedor VARCHAR(80) NOT NULL,
                    ano INTEGER NOT NULL,
                    mes INTEGER NOT NULL,
                    valor_mes DOUBLE PRECISION NOT NULL DEFAULT 0,
                    base_valor DOUBLE PRECISION,
                    crescimento_pct DOUBLE PRECISION,
                    mix_itens_unicos DOUBLE PRECISION,
                    share_pct DOUBLE PRECISION,
                    valor_marcas DOUBLE PRECISION,
                    margem_percentual DOUBLE PRECISION,
                    margem_minima DOUBLE PRECISION,
                    margem_atingida BOOLEAN,
                    bloqueado_margem BOOLEAN NOT NULL DEFAULT FALSE,
                    bonus_percentual DOUBLE PRECISION NOT NULL DEFAULT 0,
                    premio DOUBLE PRECISION NOT NULL DEFAULT 0,
                    calculado_em TIMESTAMP NOT NULL DEFAULT NOW()
                );
            """))

            conn.execute(text("ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS escopo varchar(20) NOT NULL DEFAULT 'VENDEDOR';"))
            conn.execute(text("ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS faturamento_minimo double precision;"))
            conn.execute(text("ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS margem_minima double precision;"))
            conn.execute(text("ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS teto_faturamento double precision;"))
            conn.execute(text("ALTER TABLE metas_programas ADD COLUMN IF NOT EXISTS teto_bonus_percentual double precision;"))
            conn.execute(text("ALTER TABLE metas_programas ALTER COLUMN faturamento_minimo SET DEFAULT 70000;"))
            conn.execute(text("UPDATE metas_programas SET faturamento_minimo = 70000 WHERE faturamento_minimo IS NULL;"))
            conn.execute(text("ALTER TABLE metas_programas_emps ADD COLUMN IF NOT EXISTS ativo boolean NOT NULL DEFAULT true;"))
            conn.execute(text("ALTER TABLE metas_programas_emps ADD COLUMN IF NOT EXISTS criado_em timestamp NOT NULL DEFAULT now();"))
            conn.execute(text("ALTER TABLE metas_programas_emps ADD COLUMN IF NOT EXISTS atualizado_em timestamp;"))
            conn.execute(text("ALTER TABLE metas_programas_emps ADD COLUMN IF NOT EXISTS removido_em timestamp;"))
            conn.execute(text("UPDATE metas_programas_emps SET ativo = true WHERE ativo IS NULL;"))
            conn.execute(text("ALTER TABLE metas_bases_manuais ADD COLUMN IF NOT EXISTS margem_percentual double precision;"))
            conn.execute(text("ALTER TABLE metas_bases_manuais ADD COLUMN IF NOT EXISTS bonus_extra_percentual double precision;"))
            conn.execute(text("ALTER TABLE metas_bases_manuais ADD COLUMN IF NOT EXISTS observacao varchar(200);"))
            conn.execute(text("ALTER TABLE metas_resultados ADD COLUMN IF NOT EXISTS margem_percentual double precision;"))
            conn.execute(text("ALTER TABLE metas_resultados ADD COLUMN IF NOT EXISTS margem_minima double precision;"))
            conn.execute(text("ALTER TABLE metas_resultados ADD COLUMN IF NOT EXISTS margem_atingida boolean;"))
            conn.execute(text("ALTER TABLE metas_resultados ADD COLUMN IF NOT EXISTS bloqueado_margem boolean NOT NULL DEFAULT false;"))

            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_metas_programas_periodo ON metas_programas (ano, mes);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_metas_programas_tipo_periodo ON metas_programas (tipo, ano, mes);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_metas_programas_emps_meta ON metas_programas_emps (meta_id);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_metas_programas_emps_emp ON metas_programas_emps (emp);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_metas_programas_emps_ativo ON metas_programas_emps (meta_id, ativo, emp);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_metas_escalas_meta ON metas_escalas (meta_id);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_metas_marcas_meta ON metas_marcas (meta_id);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_metas_marcas_marca ON metas_marcas (marca);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_metas_bases_meta_emp_vendedor ON metas_bases_manuais (meta_id, emp, vendedor);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_meta_margem_emp_periodo ON metas_margens_vendedores (emp, ano, mes);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_meta_margem_vendedor_periodo ON metas_margens_vendedores (vendedor, ano, mes);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_meta_margem_periodo_vendedor ON metas_margens_vendedores (ano, mes, vendedor);"))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS oficina_servicos (
                    id SERIAL PRIMARY KEY,
                    ano INTEGER NOT NULL,
                    mes INTEGER NOT NULL,
                    emp VARCHAR(30) NOT NULL,
                    usuario VARCHAR(80) NOT NULL,
                    valor_servico DOUBLE PRECISION NOT NULL DEFAULT 0,
                    observacao VARCHAR(240),
                    arquivo_origem VARCHAR(255),
                    importado_por VARCHAR(80),
                    importado_em TIMESTAMP NOT NULL DEFAULT NOW(),
                    ativo BOOLEAN NOT NULL DEFAULT TRUE,
                    CONSTRAINT uq_oficina_servico_periodo_usuario UNIQUE (ano, mes, emp, usuario)
                );
            """))
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_oficina_servicos_periodo_usuario ON oficina_servicos (ano, mes, emp, usuario);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_oficina_servicos_emp_periodo ON oficina_servicos (emp, ano, mes);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_oficina_servicos_usuario_periodo ON oficina_servicos (usuario, ano, mes);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_oficina_servicos_periodo ON oficina_servicos (ano, mes);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_metas_resultados_emp_periodo ON metas_resultados (emp, ano, mes);"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_metas_resultados_meta_periodo ON metas_resultados (meta_id, ano, mes);"))
        _METAS_LOJAS_SCHEMA_READY = True
    except Exception:
        pass
