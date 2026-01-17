"""Importacao de vendas via planilha (.xlsx) com baixo uso de memoria.

Esta versao evita carregar a planilha inteira com pandas e faz insercoes em lote
para nao estourar memoria/timeout no Render.

Uso no Flask:
    from importar_excel import importar_planilha
    resumo = importar_planilha(file_path, modo="ignorar_duplicados")

Retorna um dict com contagens e erros.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Dict, List, Optional

import pandas as pd
from openpyxl import load_workbook
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
    if value is None or (isinstance(value, float) and pd.isna(value)):
        raise ValueError("MOVIMENTO vazio")
    if isinstance(value, dt.date) and not isinstance(value, dt.datetime):
        return value
    if isinstance(value, dt.datetime):
        return value.date()
    # tenta converter strings / timestamps
    return pd.to_datetime(value).date()


def _to_float(value: Any) -> Optional[float]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    try:
        return float(value)
    except Exception:
        return None


def _norm_str(value: Any) -> Optional[str]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    s = str(value).strip()
    return s if s else None


def _build_stmt(records: List[dict], modo: str, conflict_cols: List[str]):
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

    # returning para contar de forma confiavel por lote
    return stmt.returning(Venda.id)


def importar_planilha(
    filepath: str,
    modo: str = "ignorar_duplicados",
    chave: str = "mestre_vendedor_nota_emp",
    batch_size: int = 500,
) -> Dict[str, Any]:
    """Importa vendas no banco com insercao em lotes.

    modo:
      - ignorar_duplicados (default): ON CONFLICT DO NOTHING
      - atualizar: ON CONFLICT DO UPDATE

    chave:
      - mestre_vendedor_nota_emp (default)
      - mestre_vendedor_nota
    """

    wb = None
    try:
        wb = load_workbook(filepath, read_only=True, data_only=True)
        ws = wb.active

        rows = ws.iter_rows(values_only=True)
        header = next(rows, None)
        if not header:
            return {"ok": False, "msg": "Planilha vazia.", "inseridas": 0, "atualizadas": 0, "ignoradas": 0, "erros_linha": 0}

        cols = [str(c).strip().upper() if c is not None else "" for c in header]
        col_index = {c: i for i, c in enumerate(cols)}

        missing = [c for c in REQUIRED_COLS if c not in col_index]
        if missing:
            return {
                "ok": False,
                "msg": "Planilha com colunas faltando.",
                "faltando": missing,
                "lidas": cols,
                "inseridas": 0,
                "atualizadas": 0,
                "ignoradas": 0,
            }

        conflict_cols = ["mestre", "vendedor", "nota"]
        if chave == "mestre_vendedor_nota_emp":
            conflict_cols.append("emp")

        total_linhas = 0
        validas = 0
        erros_linha = 0
        inseridas = 0
        atualizadas = 0

        batch: List[dict] = []

        db = SessionLocal()
        try:
            for r in rows:
                total_linhas += 1
                try:
                    def get(col: str):
                        return r[col_index[col]] if col in col_index else None

                    mestre = _norm_str(get("MESTRE"))
                    vendedor = _norm_str(get("VENDEDOR"))
                    if not mestre or not vendedor:
                        erros_linha += 1
                        continue

                    nota = _norm_str(get("NOTA"))
                    emp = _norm_str(get("EMP"))
                    if chave == "mestre_vendedor_nota":
                        emp = None

                    mov = _to_date(get("MOVIMENTO"))
                    mov_tipo = _norm_str(get("MOV_TIPO_MOVTO")) or ""
                    if not mov_tipo:
                        erros_linha += 1
                        continue

                    rec = {
                        "mestre": mestre,
                        "marca": _norm_str(get("MARCA")),
                        "data": mov,
                        "mov_tipo_movto": mov_tipo,
                        "vendedor": vendedor,
                        "nota": nota,
                        "emp": emp,
                        "unit": _to_float(get("UNIT")),
                        "des": _to_float(get("DES")),
                        "qtda_vendida": _to_float(get("QTDADE_VENDIDA")),
                        "valor_total": _to_float(get("VALOR_TOTAL")) or 0.0,
                    }

                    batch.append(rec)
                    validas += 1

                    if len(batch) >= batch_size:
                        stmt = _build_stmt(batch, modo, conflict_cols)
                        res = db.execute(stmt).fetchall()
                        db.commit()
                        if modo == "atualizar":
                            atualizadas += len(res)
                        else:
                            inseridas += len(res)
                        batch.clear()

                except Exception:
                    erros_linha += 1
                    continue

            # flush final
            if batch:
                stmt = _build_stmt(batch, modo, conflict_cols)
                res = db.execute(stmt).fetchall()
                db.commit()
                if modo == "atualizar":
                    atualizadas += len(res)
                else:
                    inseridas += len(res)
                batch.clear()

        finally:
            db.close()

        ignoradas = max(validas - (atualizadas if modo == "atualizar" else inseridas), 0)

        return {
            "ok": True,
            "msg": "Importacao finalizada.",
            "total_linhas": int(total_linhas),
            "validas": int(validas),
            "inseridas": int(inseridas),
            "atualizadas": int(atualizadas),
            "ignoradas": int(ignoradas),
            "erros_linha": int(erros_linha),
            "modo": modo,
            "chave": chave,
            "batch_size": int(batch_size),
        }

    finally:
        try:
            if wb is not None:
                wb.close()
        except Exception:
            pass
