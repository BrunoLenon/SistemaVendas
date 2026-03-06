"""
Utilitários extraídos de web/app.py.

Refatoração pura: mantém assinaturas e comportamento observável.
"""
from __future__ import annotations

import re
from datetime import date, datetime

import pandas as pd


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

def _normalize_cols(df: pd.DataFrame) -> pd.DataFrame:
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

def _emp_norm(emp: str | None) -> str:
    """Normaliza EMP para armazenamento ('' quando nulo)."""
    return (emp or "").strip()

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
