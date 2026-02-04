import os
from datetime import datetime
from urllib.parse import quote_plus

from sqlalchemy import create_engine, Column, Integer, String, Float, Date, DateTime, Text, Boolean, Index, UniqueConstraint, text, func
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

    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow, server_default=func.now())

    # Compatibilidade: código legado às vezes usa `atualizado_em`.
    atualizado_em = synonym("updated_at")

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

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow, server_default=func.now())

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
    ano = Column(Integer, nullable=False, index=True)
    mes = Column(Integer, nullable=False, index=True)

    # Novo: campanhas por descrição (prefixo no início). Se campo_match='descricao', usa Venda.descricao_norm.
    campo_match = Column(String(20), nullable=False, default='codigo')  # 'codigo' ou 'descricao'
    descricao_prefixo = Column(String(200), nullable=True)

    recompensa_unit = Column(Float, nullable=False, default=0.0)
    qtd_minima = Column(Float, nullable=True)
    valor_minimo = Column(Float, nullable=True)

    data_inicio = Column(Date, nullable=False, index=True)
    data_fim = Column(Date, nullable=False, index=True)

    ativo = Column(Integer, nullable=False, default=1)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow, server_default=func.now())

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

    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow, server_default=func.now())

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
    observacao = Column(String(200), nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("meta_id", "emp", "vendedor", name="uq_meta_base_manual"),
        Index("ix_meta_base_manual_emp_vend", "emp", "vendedor"),
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
    nome = Column(String(160), nullable=False, server_default=text("''"))  # compat: coluna antiga/obrigatória
    emp = Column(String(30), nullable=True, index=True)  # null/'' => global
    marca = Column(String(120), nullable=False, default="", index=True)

    # Vigência
    data_inicio = Column(Date, nullable=False)
    data_fim = Column(Date, nullable=False)

    # Valor unitário global opcional (fallback quando item não tem valor_unitario)
    valor_unitario_global = Column(Float, nullable=True)

    ativo = Column(Boolean, nullable=False, default=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow, server_default=func.now())

    __table_args__ = (
        Index("ix_combo_emp_marca", "emp", "marca"),
        Index("ix_combo_ano_mes", "ano", "mes"),
    )


class CampanhaComboItem(Base):
    __tablename__ = "campanhas_combo_itens"

    id = Column(Integer, primary_key=True)
    combo_id = Column(Integer, nullable=False, index=True)

    # Match: CODIGO (MESTRE) por prefixo e/ou DESCRIÇÃO por contains
    mestre_prefixo = Column(String(120), nullable=True)
    descricao_contains = Column(String(200), nullable=True)

    minimo_qtd = Column(Float, nullable=False, default=0.0)
    valor_unitario = Column(Float, nullable=True)  # opcional; se vazio usa combo.valor_unitario_global

    ordem = Column(Integer, nullable=False, default=1)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, server_default=func.now())


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
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow, server_default=func.now())

    __table_args__ = (
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

    fechado = Column(Boolean, nullable=False, default=True)
    fechado_em = Column(DateTime, nullable=False, default=datetime.utcnow)
    # Status do período (controle financeiro): "aberto", "a_pagar", "pago"
    status = Column(String(20), nullable=False, default="aberto", index=True)

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