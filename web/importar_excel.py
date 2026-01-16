"""Importacao de vendas via planilha (.xlsx).

Uso no Flask:
    from importar_excel import importar_planilha
    resumo = importar_planilha(file_path, modo="ignorar_duplicados")

Retorna um dict com contagens e erros.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple

import pandas as pd
from sqlalchemy.dialects.postgresql import insert as pg_insert

from db import SessionLocal, Venda


REQUIRED_COLS = [
    "MESTRE",
    "MARCA",
    "MOVIMENTO",
    "MOV_TIPO_MOVTO",
    "VENDEDOR",
    "NOTA",
    "EMP",
    "UNIT",
    "DES",
    "QTDADE_VENDIDA",
    "VALOR_TOTAL",
]


def _to_date(value: Any) -> dt.date:
    if pd.isna(value):
        raise ValueError("MOVIMENTO vazio")
    if isinstance(value, dt.date) and not isinstance(value, dt.datetime):
        return value
    if isinstance(value, dt.datetime):
        return value.date()
    # pandas Timestamp
    try:
        return pd.to_datetime(value).date()
    except Exception as e:
        raise ValueError(f"MOVIMENTO invalido: {value}") from e


def _to_float(value: Any) -> Optional[float]:
    if pd.isna(value):
        return None
    try:
        return float(value)
    except Exception:
        return None


def _norm_str(value: Any) -> Optional[str]:
    if pd.isna(value):
        return None
    s = str(value).strip()
    return s if s else None


def importar_planilha(
    filepath: str,
    modo: str = "ignorar_duplicados",
    chave: str = "mestre_vendedor_nota_emp",
) -> Dict[str, Any]:
    """Importa vendas no banco.

    modo:
      - ignorar_duplicados (default): ON CONFLICT DO NOTHING
      - atualizar: ON CONFLICT DO UPDATE (atualiza campos financeiros e data)

    chave:
      - mestre_vendedor_nota_emp (default)
      - mestre_vendedor_nota

    OBS: para a opcao mestre_vendedor_nota, o EMP vira NULL na chave. (Nao recomendado no seu caso.)
    """

    df = pd.read_excel(filepath, engine="openpyxl")

    # Normaliza nomes de colunas
    df.columns = [str(c).strip().upper() for c in df.columns]

    missing = [c for c in REQUIRED_COLS if c not in df.columns]
    if missing:
        return {
            "ok": False,
            "msg": "Planilha com colunas faltando.",
            "faltando": missing,
            "lidas": list(df.columns),
            "inseridas": 0,
            "atualizadas": 0,
            "ignoradas": 0,
        }

    # Constrói registros
    records = []
    erros_linha = 0
    for _, row in df.iterrows():
        try:
            mestre = _norm_str(row.get("MESTRE"))
            vendedor = _norm_str(row.get("VENDEDOR"))
            if not mestre or not vendedor:
                erros_linha += 1
                continue

            nota = _norm_str(row.get("NOTA"))
            emp = _norm_str(row.get("EMP"))
            if chave == "mestre_vendedor_nota":
                emp = None

            rec = {
                "mestre": mestre,
                "marca": _norm_str(row.get("MARCA")),
                "data": _to_date(row.get("MOVIMENTO")),
                "mov_tipo_movto": _norm_str(row.get("MOV_TIPO_MOVTO")) or "",
                "vendedor": vendedor,
                "nota": nota,
                "emp": emp,
                "unit": _to_float(row.get("UNIT")),
                "des": _to_float(row.get("DES")),
                "qtda_vendida": _to_float(row.get("QTDADE_VENDIDA")),
                "valor_total": _to_float(row.get("VALOR_TOTAL")) or 0.0,
            }
            if not rec["mov_tipo_movto"]:
                erros_linha += 1
                continue
            records.append(rec)
        except Exception:
            erros_linha += 1

    if not records:
        return {
            "ok": False,
            "msg": "Nenhuma linha valida encontrada.",
            "inseridas": 0,
            "atualizadas": 0,
            "ignoradas": 0,
            "erros_linha": erros_linha,
        }

    conflict_cols = ["mestre", "vendedor", "nota"]
    if chave == "mestre_vendedor_nota_emp":
        conflict_cols.append("emp")

    inserted = 0
    updated = 0

    db = SessionLocal()
    try:
        stmt = pg_insert(Venda.__table__).values(records)

        if modo == "atualizar":
            update_cols = {
                "marca": stmt.excluded.marca,
                "data": stmt.excluded.data,
                "mov_tipo_movto": stmt.excluded.mov_tipo_movto,
                "unit": stmt.excluded.unit,
                "des": stmt.excluded.des,
                "qtda_vendida": stmt.excluded.qtda_vendida,
                "valor_total": stmt.excluded.valor_total,
                "emp": stmt.excluded.emp,
            }
            stmt = stmt.on_conflict_do_update(index_elements=conflict_cols, set_=update_cols)
        else:
            stmt = stmt.on_conflict_do_nothing(index_elements=conflict_cols)

        result = db.execute(stmt)
        db.commit()

        # rowcount no DO NOTHING pode ser -1 em alguns drivers; tentamos inferir
        if result.rowcount and result.rowcount > 0:
            inserted = int(result.rowcount)

        # Para atualizar: rowcount tende a ser total afetado
        if modo == "atualizar" and result.rowcount and result.rowcount > 0:
            updated = int(result.rowcount)

    finally:
        db.close()

    total = len(records)
    ignoradas = max(total - inserted, 0) if modo != "atualizar" else max(total - updated, 0)

    return {
        "ok": True,
        "msg": "Importacao finalizada.",
        "total_linhas": int(df.shape[0]),
        "validas": total,
        "inseridas": inserted,
        "atualizadas": updated,
        "ignoradas": ignoradas,
        "erros_linha": erros_linha,
        "modo": modo,
        "chave": chave,
    }
