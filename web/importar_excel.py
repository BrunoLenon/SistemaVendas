"""Importacao de vendas via planilha (.xlsx).

Este modulo foi pensado para rodar tanto local quanto no Render.

Uso tipico (no app.py):

    from importar_vendas import importar_vendas_xlsx
    res = importar_vendas_xlsx(file_stream, modo='ignorar_duplicados', chave='mestre_vendedor_nota_emp')

Retorna um dict com contagens e possiveis avisos.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from datetime import date
from typing import BinaryIO, Dict, Iterable, Optional, Tuple

import pandas as pd
from sqlalchemy import text

from db import SessionLocal, Venda


@dataclass
class ImportResult:
    lidas: int
    inseridas: int
    ignoradas: int
    erros: int
    aviso: Optional[str] = None

    def asdict(self) -> Dict[str, object]:
        return {
            "lidas": self.lidas,
            "inseridas": self.inseridas,
            "ignoradas": self.ignoradas,
            "erros": self.erros,
            "aviso": self.aviso,
        }


COLS_OBRIGATORIAS = {
    "MESTRE",
    "MARCA",
    "MOVIMENTO",
    "MOV_TIPO_MOVTO",
    "VENDEDOR",
    "UNIT",
    "DES",
    "QTDADE_VENDIDA",
    "VALOR_TOTAL",
}

COLS_OPCIONAIS = {"NOTA", "EMP"}


def _norm_col(c: str) -> str:
    return str(c).strip().upper()


def _to_date(v) -> Optional[date]:
    if pd.isna(v):
        return None
    # pandas pode vir com Timestamp
    try:
        ts = pd.to_datetime(v, errors="coerce")
        if pd.isna(ts):
            return None
        return ts.date()
    except Exception:
        return None


def importar_vendas_xlsx(
    fileobj: BinaryIO | bytes,
    *,
    modo: str = "ignorar_duplicados",
    chave: str = "mestre_vendedor_nota_emp",
    sheet: int | str = 0,
) -> Dict[str, object]:
    """Importa um XLSX e grava em `vendas`.

    - modo:
        - "ignorar_duplicados": tenta usar ON CONFLICT DO NOTHING (se existir unique index).
        - "atualizar": (por enquanto) comporta-se como ignorar_duplicados; pode ser evoluido.

    - chave:
        - "mestre_vendedor_nota_emp" (recomendado)
        - "mestre_vendedor_nota"

    Observacao: o banco atual (Venda) pode nao ter as colunas NOTA/EMP. Nesse caso,
    a importacao ainda insere mestre/marca/vendedor/data/mov_tipo/qtda/valor_total.
    """

    # Lê bytes
    if isinstance(fileobj, (bytes, bytearray)):
        bio = io.BytesIO(fileobj)
    else:
        bio = io.BytesIO(fileobj.read())

    # openpyxl é o engine mais seguro para .xlsx
    df = pd.read_excel(bio, sheet_name=sheet, engine="openpyxl")
    df.columns = [_norm_col(c) for c in df.columns]

    faltando = sorted(list(COLS_OBRIGATORIAS - set(df.columns)))
    if faltando:
        return ImportResult(
            lidas=0,
            inseridas=0,
            ignoradas=0,
            erros=1,
            aviso=(
                "Planilha invalida. Colunas obrigatorias faltando: " + ", ".join(faltando)
            ),
        ).asdict()

    # Normalizacoes
    df["VENDEDOR"] = df["VENDEDOR"].astype(str).str.strip().str.upper()
    df["MESTRE"] = df["MESTRE"].astype(str).str.strip()
    df["MARCA"] = df["MARCA"].astype(str).str.strip().str.upper()
    df["MOV_TIPO_MOVTO"] = df["MOV_TIPO_MOVTO"].astype(str).str.strip().str.upper()

    # Datas
    df["DATA"] = df["MOVIMENTO"].apply(_to_date)
    df = df.dropna(subset=["DATA", "VENDEDOR", "MOV_TIPO_MOVTO"]).copy()

    # Numericos (garante float)
    for col in ["QTDADE_VENDIDA", "UNIT", "DES", "VALOR_TOTAL"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Se VALOR_TOTAL veio vazio, tenta calcular (UNIT - DES) * QTDADE_VENDIDA
    mask_total = df["VALOR_TOTAL"].isna() & df["UNIT"].notna() & df["QTDADE_VENDIDA"].notna()
    if mask_total.any():
        df.loc[mask_total, "VALOR_TOTAL"] = (
            (df.loc[mask_total, "UNIT"].fillna(0) - df.loc[mask_total, "DES"].fillna(0))
            * df.loc[mask_total, "QTDADE_VENDIDA"].fillna(0)
        )

    df = df.dropna(subset=["VALOR_TOTAL"]).copy()

    lidas = int(len(df))
    if lidas == 0:
        return ImportResult(lidas=0, inseridas=0, ignoradas=0, erros=0, aviso="Nada para importar.").asdict()

    # Detecta se colunas NOTA/EMP existem na tabela (para poder usar a chave completa)
    venda_cols = set(Venda.__table__.columns.keys())
    tem_nota = "nota" in venda_cols
    tem_emp = "emp" in venda_cols

    # Monta linhas para insert
    rows = []
    for _, r in df.iterrows():
        row = {
            "mestre": str(r["MESTRE"]).strip(),
            "marca": str(r["MARCA"]).strip().upper(),
            "vendedor": str(r["VENDEDOR"]).strip().upper(),
            "data": r["DATA"],
            "mov_tipo_movto": str(r["MOV_TIPO_MOVTO"]).strip().upper(),
            "qtda_vendida": float(r["QTDADE_VENDIDA"]) if pd.notna(r["QTDADE_VENDIDA"]) else None,
            "valor_total": float(r["VALOR_TOTAL"]),
        }
        if tem_nota and "NOTA" in df.columns:
            row["nota"] = None if pd.isna(r.get("NOTA")) else str(r.get("NOTA")).strip()
        if tem_emp and "EMP" in df.columns:
            try:
                row["emp"] = None if pd.isna(r.get("EMP")) else int(r.get("EMP"))
            except Exception:
                row["emp"] = None
        rows.append(row)

    inseridas = 0
    ignoradas = 0
    erros = 0
    aviso = None

    # Tenta usar INSERT ... ON CONFLICT para performance e evitar duplicidade.
    # Para funcionar 100%, crie um UNIQUE INDEX no Supabase (veja SQL sugerido).
    conflict_clause = ""
    if chave == "mestre_vendedor_nota_emp" and tem_nota and tem_emp:
        conflict_clause = "ON CONFLICT (mestre, vendedor, nota, emp) DO NOTHING"
    elif chave == "mestre_vendedor_nota" and tem_nota:
        conflict_clause = "ON CONFLICT (mestre, vendedor, nota) DO NOTHING"
    else:
        # Sem colunas de chave no banco -> sem ON CONFLICT
        conflict_clause = ""
        aviso = "Aviso: sua tabela 'vendas' ainda nao tem NOTA/EMP; deduplicacao fica limitada."

    cols = list(rows[0].keys())
    col_sql = ",".join(cols)
    val_sql = ",".join([f":{c}" for c in cols])

    sql = f"INSERT INTO vendas ({col_sql}) VALUES ({val_sql}) {conflict_clause}"

    with SessionLocal() as sess:
        try:
            res = sess.execute(text(sql), rows)
            sess.commit()

            # Quando ON CONFLICT existe, rowcount costuma ser o numero inserido
            inseridas = int(getattr(res, "rowcount", 0) or 0)
            ignoradas = lidas - inseridas
        except Exception:
            sess.rollback()
            # Fallback: insere linha a linha
            inseridas = 0
            ignoradas = 0
            erros = 0
            for row in rows:
                try:
                    sess.add(Venda(**row))
                    sess.commit()
                    inseridas += 1
                except Exception:
                    sess.rollback()
                    erros += 1

    return ImportResult(lidas=lidas, inseridas=inseridas, ignoradas=ignoradas, erros=erros, aviso=aviso).asdict()
