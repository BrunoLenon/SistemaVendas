"""
Utilitários extraídos de web/app.py.

Refatoração pura: mantém assinaturas e comportamento observável.
"""
from __future__ import annotations

import re
from datetime import date, datetime


# Regras oficiais de movimento para todos os cálculos comerciais.
# Positivos entram como venda/faturamento; negativos abatem o líquido;
# qualquer outro movimento deve ser importado para rastreabilidade, mas ignorado nos cálculos.
MOVIMENTOS_VENDA = ("OA", "OV", "SV", "VA", "VV")
MOVIMENTOS_CANCELAMENTO = ("CA",)
MOVIMENTOS_DEVOLUCAO = ("DS",)
MOVIMENTOS_NEGATIVOS = MOVIMENTOS_CANCELAMENTO + MOVIMENTOS_DEVOLUCAO
MOVIMENTOS_CALCULO = MOVIMENTOS_VENDA + MOVIMENTOS_NEGATIVOS


def normalizar_movimento(value: object) -> str:
    return str(value or "").strip().upper()


def classificar_movimento(value: object) -> str:
    mov = normalizar_movimento(value)
    if mov in MOVIMENTOS_VENDA:
        return "VENDA"
    if mov in MOVIMENTOS_CANCELAMENTO:
        return "CANCELAMENTO"
    if mov in MOVIMENTOS_DEVOLUCAO:
        return "DEVOLUCAO"
    return "IGNORADO"


def is_movimento_venda(value: object) -> bool:
    return normalizar_movimento(value) in MOVIMENTOS_VENDA


def is_movimento_negativo(value: object) -> bool:
    return normalizar_movimento(value) in MOVIMENTOS_NEGATIVOS


def _obj_get(obj, key, default=None):
    """Acesso seguro estilo dict: tenta dict, RowMapping, atributos e chaves."""
    if obj is None:
        return default
    try:
        # dict
        if isinstance(obj, dict):
            return obj.get(key, default)
        # SQLAlchemy Row: possui _mapping
        mapping = getattr(obj, "_mapping", None)
        if mapping is not None:
            return mapping.get(key, default)
        # dataclass/objeto: atributo
        if hasattr(obj, key):
            return getattr(obj, key)
        # tenta variações de caixa
        k = str(key)
        for kk in (k.lower(), k.upper()):
            if hasattr(obj, kk):
                return getattr(obj, kk)
        # fallback: __getitem__
        try:
            return obj[key]  # type: ignore[index]
        except Exception:
            return default
    except Exception:
        return default

def _obj_get_any(obj, keys, default=None):
    for k in keys:
        v = _obj_get(obj, k, None)
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        return v
    return default

def _normalize_cols(df):
    # Pandas é carregado apenas por fluxos legados que realmente tratam DataFrame.
    # Os módulos enxutos (Bônus/Itens Parados) não pagam esse custo no boot.
    import pandas as pd
    """Normaliza nomes/tipos de colunas vindas do banco.

    Regras do app:
    - VENDEDOR (str, UPPER) e EMP (str)
    - MOVIMENTO (datetime) é usado para filtrar mês/ano
    """
    if df is None or df.empty:
        return df

    rename: dict[str, str] = {}
    for col in df.columns:
        low = str(col).strip().lower()
        if low == "vendedor":
            rename[col] = "VENDEDOR"
        elif low == "marca":
            rename[col] = "MARCA"
        elif low in ("data", "movimento"):
            # O app usa MOVIMENTO para filtros de período
            rename[col] = "MOVIMENTO"
        elif low in ("mov_tipo_movto", "mov_tipo_movimento", "mov_tipo_movto "):
            rename[col] = "MOV_TIPO_MOVTO"
        elif low in ("valor_total", "valor", "total"):
            rename[col] = "VALOR_TOTAL"
        elif low == "mestre":
            rename[col] = "MESTRE"
        elif low in ("qtdade_vendida", "quantidade", "qtd", "qtde", "qtdade", "qtd_vendida"):
            rename[col] = "QTDADE_VENDIDA"
        elif low == "emp":
            rename[col] = "EMP"

    if rename:
        df = df.rename(columns=rename)

    # Tipos esperados
    if "MOVIMENTO" in df.columns:
        df["MOVIMENTO"] = pd.to_datetime(df["MOVIMENTO"], errors="coerce")
    if "VENDEDOR" in df.columns:
        df["VENDEDOR"] = df["VENDEDOR"].astype(str).str.strip().str.upper()
    if "EMP" in df.columns:
        df["EMP"] = df["EMP"].astype(str).str.strip()
    if "QTDADE_VENDIDA" in df.columns:
        df["QTDADE_VENDIDA"] = pd.to_numeric(df["QTDADE_VENDIDA"], errors="coerce").fillna(0.0)

    return df

def _mes_ano_from_request() -> tuple[int, int]:
    from flask import request
    mes = int(request.args.get("mes") or datetime.now().month)
    ano = int(request.args.get("ano") or datetime.now().year)
    mes = max(1, min(12, mes))
    ano = max(2000, min(2100, ano))
    return mes, ano

def _periodo_bounds(ano: int, mes: int):
    """Retorna (inicio, fim) do mês para filtro por intervalo (usa índice)."""
    mes = max(1, min(12, int(mes)))
    ano = int(ano)
    start = date(ano, mes, 1)
    if mes == 12:
        end = date(ano + 1, 1, 1)
    else:
        end = date(ano, mes + 1, 1)
    return start, end

def _parse_num_ptbr(val: str | None) -> float:
    """Parseia número em formatos comuns PT-BR:
    - '118589,72'
    - '118.589,72'
    - '118589.72'
    - 'R$ 118.589,72'
    """
    if val is None:
        return 0.0
    s = str(val).strip()
    if not s:
        return 0.0
    # remove moeda e espaços
    s = re.sub(r'[^0-9,\.-]', '', s)
    if not s:
        return 0.0

    # Se tiver vírgula e ponto, assume ponto milhar e vírgula decimal (PT-BR)
    if ',' in s and '.' in s:
        # remove separador de milhar
        s = s.replace('.', '')
        s = s.replace(',', '.')
    elif ',' in s:
        s = s.replace(',', '.')
    # senão: já está em formato com ponto decimal ou inteiro
    try:
        return float(s)
    except Exception:
        return 0.0


def emp_sort_key(emp: object) -> tuple[int, int, str]:
    """Chave de ordenação padrão para EMP.

    EMP é código numérico na operação. Ordenação alfabética coloca 1001 antes
    de 101; para filtros e relatórios a ordem correta é 101, 102, 807, 1001.
    Valores não numéricos ficam no final, em ordem textual.
    """
    s = str(emp or "").strip()
    if not s or s == "—":
        return (2, 0, s)
    try:
        return (0, int(s), s)
    except Exception:
        return (1, 0, s)


def sort_emp_codes(codigos: object) -> list[str]:
    """Normaliza, remove duplicados e ordena EMPs em ordem numérica crescente."""
    if not codigos:
        return []
    if isinstance(codigos, (str, bytes)):
        values = [codigos]
    else:
        try:
            values = list(codigos)  # aceita list/tuple/set e generators
        except Exception:
            values = [codigos]
    seen: set[str] = set()
    out: list[str] = []
    for c in values:
        s = str(c or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return sorted(out, key=emp_sort_key)

def _emp_norm(emp: str | None) -> str:
    """Normaliza EMP para armazenamento e comparação.

    Planilhas do Excel frequentemente entregam códigos inteiros como ``101.0``.
    Como EMP é um identificador textual inteiro no SistemaVendas, mantemos
    ``101`` e ``101.0`` como a mesma loja. Valores realmente alfanuméricos não
    são alterados.
    """
    s = str(emp or "").strip()
    if not s:
        return ""
    if re.fullmatch(r"[+-]?\d+\.0+", s):
        return s.split(".", 1)[0]
    return s

def _parse_multi_args(name: str) -> list[str]:
    from flask import request
    """Lê parâmetros repetidos via querystring (?emp=101&emp=102).
    Mantém compatibilidade com padrão antigo (?emp=101).
    """
    vals = []
    try:
        vals = request.args.getlist(name)
    except Exception:
        vals = []
    # Compat: alguns formulários antigos mandam apenas 1 valor em get()
    if not vals:
        v = (request.args.get(name) or "").strip()
        if v:
            vals = [v]
    # Aceita CSV (caso alguém copie/cole)
    out: list[str] = []
    for v in vals:
        for part in str(v).split(","):
            p = part.strip()
            if p:
                out.append(p)
    # unique mantendo ordem
    seen=set()
    res=[]
    for v in out:
        if v not in seen:
            seen.add(v); res.append(v)
    return res

def _parse_multi_args_from(args, name: str) -> list[str]:
    try:
        if hasattr(args, "getlist"):
            vals = args.getlist(name)
        else:
            vals = args.get(name)
            vals = vals if isinstance(vals, list) else ([vals] if vals else [])
        return [str(v).strip() for v in vals if str(v).strip()]
    except Exception:
        return []

def _emp_to_int_safe(emp: str) -> int | str:
    """Regra crítica: EMP é numérico na base de vendas.
    Sempre converte antes de comparar/filtrar para não zerar totais.
    """
    s = str(emp).strip()
    return int(s) if s.isdigit() else s
