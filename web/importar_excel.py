"""Importação de vendas (Render-friendly) com deduplicação configurável.

IMPORTANTE:
- Para o seu caso, o MOV_TIPO_MOVTO (ex: 'DS' / 'CA' / 'OA') DEVE fazer parte
  da chave de duplicidade, senão DS/CA "somem" do cálculo.
- Recomendado: criar um índice UNIQUE no Postgres com as colunas da chave,
  para o ON CONFLICT funcionar.

Suporta:
  - .csv (recomendado p/ arquivos grandes) -> streaming por chunks
  - .xlsx (arquivos menores)              -> read_only + batches

API:
  importar_planilha(filepath, modo="ignorar_duplicados", chave=..., ...)

chaves disponíveis:
  - mestre_vendedor_nota_emp           (antiga)
  - mestre_data_vendedor_nota_emp      (inclui MOVIMENTO/data)
  - mestre_data_vendedor_nota_tipo_emp (inclui MOVIMENTO + MOV_TIPO_MOVTO)  <-- RECOMENDADA
  - mestre_data_vendedor_nota_tipo     (sem EMP, se você não usa EMP na chave)
"""

from __future__ import annotations

import datetime as dt
import os
from typing import Any, Dict, List, Optional

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


def _norm_cols(cols: List[Any]) -> List[str]:
    return [str(c).strip().upper() if c is not None else "" for c in cols]


def _to_date(value: Any) -> dt.date:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        raise ValueError("MOVIMENTO vazio")
    if isinstance(value, dt.date) and not isinstance(value, dt.datetime):
        return value
    if isinstance(value, dt.datetime):
        return value.date()
    return pd.to_datetime(value).date()


def _to_float(value: Any) -> Optional[float]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    try:
        # troca vírgula por ponto se vier como string brasileira
        if isinstance(value, str):
            value = value.replace(".", "").replace(",", ".")
        return float(value)
    except Exception:
        return None


def _norm_str(value: Any) -> Optional[str]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    s = str(value).strip()
    return s if s else None


def _conflict_cols_from_key(chave: str) -> List[str]:
    """Mapeia o nome da chave para colunas do banco."""
    # nomes da tabela/ORM: mestre, data, vendedor, nota, emp, mov_tipo_movto
    if chave == "mestre_data_vendedor_nota_tipo_emp":
        return ["mestre", "data", "vendedor", "nota", "mov_tipo_movto", "emp"]
    if chave == "mestre_data_vendedor_nota_tipo":
        return ["mestre", "data", "vendedor", "nota", "mov_tipo_movto"]
    if chave == "mestre_data_vendedor_nota_emp":
        return ["mestre", "data", "vendedor", "nota", "emp"]
    # fallback antigo
    return ["mestre", "vendedor", "nota", "emp"]


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
            "nota": stmt.excluded.nota,
            "vendedor": stmt.excluded.vendedor,
            "mestre": stmt.excluded.mestre,
        }
        return stmt.on_conflict_do_update(index_elements=conflict_cols, set_=update_cols)
    return stmt.on_conflict_do_nothing(index_elements=conflict_cols)


def importar_planilha(
    filepath: str,
    modo: str = "ignorar_duplicados",
    chave: str = "mestre_data_vendedor_nota_tipo_emp",
    batch_size: int = 300,
    csv_chunksize: int = 3000,
    xlsx_max_mb: int = 12,
) -> Dict[str, Any]:
    """Importa vendas no banco com inserção em lotes."""
    ext = os.path.splitext(filepath)[1].lower()

    conflict_cols = _conflict_cols_from_key(chave)

    if ext == ".xlsx":
        try:
            mb = os.path.getsize(filepath) / (1024 * 1024)
            if mb > float(xlsx_max_mb):
                return {
                    "ok": False,
                    "msg": f"Arquivo XLSX grande ({mb:.1f}MB). Para evitar erro no Render, exporte para CSV e importe o CSV.",
                    "inseridas": 0,
                    "atualizadas": 0,
                    "ignoradas": 0,
                    "erros_linha": 0,
                }
        except Exception:
            pass

        from openpyxl import load_workbook

        wb = None
        db = SessionLocal()
        try:
            wb = load_workbook(filepath, read_only=True, data_only=True)
            ws = wb.active
            rows = ws.iter_rows(values_only=True)

            header = next(rows, None)
            if not header:
                return {"ok": False, "msg": "Planilha vazia.", "inseridas": 0, "atualizadas": 0, "ignoradas": 0, "erros_linha": 0}

            cols = _norm_cols(list(header))
            col_index = {c: i for i, c in enumerate(cols)}
            missing = [c for c in REQUIRED_COLS if c not in col_index]
            if missing:
                return {"ok": False, "msg": "Colunas faltando.", "faltando": missing, "lidas": cols}

            total_linhas = 0
            validas = 0
            erros_linha = 0
            inseridas = 0
            atualizadas = 0
            batch: List[dict] = []

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
                        res = db.execute(stmt)
                        db.commit()
                        if modo == "atualizar":
                            atualizadas += int(res.rowcount or 0)
                        else:
                            inseridas += int(res.rowcount or 0)
                        batch.clear()

                except Exception:
                    erros_linha += 1
                    continue

            if batch:
                stmt = _build_stmt(batch, modo, conflict_cols)
                res = db.execute(stmt)
                db.commit()
                if modo == "atualizar":
                    atualizadas += int(res.rowcount or 0)
                else:
                    inseridas += int(res.rowcount or 0)
                batch.clear()

            # rowcount = quantos foram inseridos/atualizados; o resto são ignorados (duplicados)
            efetivadas = atualizadas if modo == "atualizar" else inseridas
            ignoradas = max(validas - efetivadas, 0)

            return {
                "ok": True,
                "msg": "Importação finalizada.",
                "total_linhas": int(total_linhas),
                "validas": int(validas),
                "inseridas": int(inseridas),
                "atualizadas": int(atualizadas),
                "ignoradas": int(ignoradas),
                "erros_linha": int(erros_linha),
                "modo": modo,
                "chave": chave,
                "batch_size": int(batch_size),
                "conflict_cols": conflict_cols,
            }

        finally:
            try:
                db.close()
            except Exception:
                pass
            try:
                if wb is not None:
                    wb.close()
            except Exception:
                pass

    # CSV (recomendado)
    if ext != ".csv":
        return {"ok": False, "msg": "Formato não suportado. Use .csv (recomendado) ou .xlsx."}

    total_linhas = 0
    validas = 0
    erros_linha = 0
    inseridas = 0
    atualizadas = 0

    db = SessionLocal()
    try:
        for chunk in pd.read_csv(filepath, chunksize=csv_chunksize, dtype=str, encoding_errors="ignore"):
            chunk.columns = _norm_cols(list(chunk.columns))
            missing = [c for c in REQUIRED_COLS if c not in chunk.columns]
            if missing:
                return {"ok": False, "msg": "Colunas faltando.", "faltando": missing, "lidas": list(chunk.columns)}

            chunk["MOVIMENTO"] = pd.to_datetime(chunk["MOVIMENTO"], errors="coerce").dt.date

            records: List[dict] = []
            for _, row in chunk.iterrows():
                total_linhas += 1
                try:
                    mestre = _norm_str(row.get("MESTRE"))
                    vendedor = _norm_str(row.get("VENDEDOR"))
                    if not mestre or not vendedor:
                        erros_linha += 1
                        continue

                    nota = _norm_str(row.get("NOTA"))
                    emp = _norm_str(row.get("EMP"))
                    mov = row.get("MOVIMENTO")
                    if mov is None or pd.isna(mov):
                        erros_linha += 1
                        continue

                    mov_tipo = _norm_str(row.get("MOV_TIPO_MOVTO")) or ""
                    if not mov_tipo:
                        erros_linha += 1
                        continue

                    rec = {
                        "mestre": mestre,
                        "marca": _norm_str(row.get("MARCA")),
                        "data": mov,
                        "mov_tipo_movto": mov_tipo,
                        "vendedor": vendedor,
                        "nota": nota,
                        "emp": emp,
                        "unit": _to_float(row.get("UNIT")),
                        "des": _to_float(row.get("DES")),
                        "qtda_vendida": _to_float(row.get("QTDADE_VENDIDA")),
                        "valor_total": _to_float(row.get("VALOR_TOTAL")) or 0.0,
                    }
                    records.append(rec)
                    validas += 1

                    if len(records) >= batch_size:
                        stmt = _build_stmt(records, modo, conflict_cols)
                        res = db.execute(stmt)
                        db.commit()
                        if modo == "atualizar":
                            atualizadas += int(res.rowcount or 0)
                        else:
                            inseridas += int(res.rowcount or 0)
                        records.clear()

                except Exception:
                    erros_linha += 1
                    continue

            if records:
                stmt = _build_stmt(records, modo, conflict_cols)
                res = db.execute(stmt)
                db.commit()
                if modo == "atualizar":
                    atualizadas += int(res.rowcount or 0)
                else:
                    inseridas += int(res.rowcount or 0)
                records.clear()

    finally:
        db.close()

    efetivadas = atualizadas if modo == "atualizar" else inseridas
    ignoradas = max(validas - efetivadas, 0)

    return {
        "ok": True,
        "msg": "Importação finalizada.",
        "total_linhas": int(total_linhas),
        "validas": int(validas),
        "inseridas": int(inseridas),
        "atualizadas": int(atualizadas),
        "ignoradas": int(ignoradas),
        "erros_linha": int(erros_linha),
        "modo": modo,
        "chave": chave,
        "batch_size": int(batch_size),
        "csv_chunksize": int(csv_chunksize),
        "conflict_cols": conflict_cols,
    }
