"""Rotas: Admin Itens Parados (cadastro/configuração/fechamento)."""

from __future__ import annotations

from datetime import date, datetime
from io import BytesIO
import json
import os
import re
import tempfile
import threading
import time
import unicodedata
from uuid import uuid4
from decimal import Decimal, ROUND_FLOOR, ROUND_HALF_UP
from typing import Callable, Type

from flask import current_app, redirect, render_template, request, send_file, session, url_for
from sqlalchemy import func, inspect, or_, text
from sv_utils import MOVIMENTOS_VENDA, sort_emp_codes

from db import (
    engine,
    ItensParadosPontosBonus,
    ItensParadosPontosConfig,
    ItensParadosPontosFechamento,
    ItensParadosPontosResultado,
    Venda,
)

TWOPLACES = Decimal("0.01")
MIN_PONTOS_PAGAMENTO_ITENS_PARADOS = Decimal("10")
ITENS_PARADOS_MOV_TIPOS_VENDA = MOVIMENTOS_VENDA
_SCHEMA_LOCK = threading.Lock()
_SCHEMA_READY = False
_SCHEMA_READY_AT = 0.0
_SCHEMA_TTL_SECONDS = 1800
_AUX_CACHE_LOCK = threading.Lock()
_AUX_CACHE = {"payload": None, "ready_at": 0.0}
_AUX_CACHE_TTL_SECONDS = 60
_IMPORT_CACHE_PREFIX = "itens_parados_import_"
_IMPORT_CACHE_TTL_SECONDS = 60 * 60
_IMPORT_MAX_ROWS = 5000


SCHEMA_SQL = """
ALTER TABLE IF EXISTS itens_parados
  ADD COLUMN IF NOT EXISTS interno varchar(120) NULL,
  ADD COLUMN IF NOT EXISTS modo varchar(20) NOT NULL DEFAULT 'PONTOS',
  ADD COLUMN IF NOT EXISTS data_inicio date NULL,
  ADD COLUMN IF NOT EXISTS data_fim date NULL,
  ADD COLUMN IF NOT EXISTS multiplicador_pontos double precision NOT NULL DEFAULT 1.0;

CREATE TABLE IF NOT EXISTS itens_parados_pontos_config (
  id bigserial PRIMARY KEY,
  emp varchar(30) NULL,
  base_reais double precision NOT NULL DEFAULT 100.0,
  valor_por_ponto double precision NOT NULL DEFAULT 10.0,
  ativo boolean NOT NULL DEFAULT true,
  criado_em timestamptz NOT NULL DEFAULT now(),
  atualizado_em timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS itens_parados_pontos_bonus (
  id bigserial PRIMARY KEY,
  emp varchar(30) NULL,
  min_pontos double precision NOT NULL DEFAULT 10.0,
  bonus_valor double precision NOT NULL DEFAULT 50.0,
  ativo boolean NOT NULL DEFAULT true,
  criado_em timestamptz NOT NULL DEFAULT now(),
  atualizado_em timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS itens_parados_pontos_fechamentos (
  id bigserial PRIMARY KEY,
  emp varchar(30) NULL,
  data_inicio date NOT NULL,
  data_fim date NOT NULL,
  criado_por varchar(80) NULL,
  criado_em timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS itens_parados_pontos_resultados (
  id bigserial PRIMARY KEY,
  fechamento_id bigint NOT NULL,
  emp varchar(30) NOT NULL,
  vendedor varchar(80) NOT NULL,
  valor_vendido double precision NOT NULL DEFAULT 0.0,
  pontos double precision NOT NULL DEFAULT 0.0,
  base_reais double precision NOT NULL DEFAULT 100.0,
  valor_por_ponto double precision NOT NULL DEFAULT 10.0,
  bonus_extra double precision NOT NULL DEFAULT 0.0,
  total double precision NOT NULL DEFAULT 0.0,
  status_pagamento varchar(20) NOT NULL DEFAULT 'PENDENTE',
  pago_em timestamptz NULL,
  criado_em timestamptz NOT NULL DEFAULT now(),
  atualizado_em timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_itens_parados_emp_codigo ON itens_parados(emp, codigo);
CREATE INDEX IF NOT EXISTS ix_itens_parados_interno ON itens_parados(interno);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_cfg_emp ON itens_parados_pontos_config(emp);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_bonus_emp ON itens_parados_pontos_bonus(emp);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_bonus_min ON itens_parados_pontos_bonus(min_pontos);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_fech_emp ON itens_parados_pontos_fechamentos(emp);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_fech_ini ON itens_parados_pontos_fechamentos(data_inicio);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_fech_fim ON itens_parados_pontos_fechamentos(data_fim);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_res_emp ON itens_parados_pontos_resultados(emp);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_res_vend ON itens_parados_pontos_resultados(vendedor);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_res_fech ON itens_parados_pontos_resultados(fechamento_id);
"""


def _table_exists(table_name: str) -> bool:
    try:
        return inspect(engine).has_table(table_name)
    except Exception:
        return False


def _column_exists(table_name: str, column_name: str) -> bool:
    try:
        insp = inspect(engine)
        return any(col.get("name") == column_name for col in insp.get_columns(table_name))
    except Exception:
        return False


def _ensure_itens_parados_schema(force: bool = False) -> None:
    global _SCHEMA_READY, _SCHEMA_READY_AT
    now = time.time()
    if not force and _SCHEMA_READY and (now - _SCHEMA_READY_AT) < _SCHEMA_TTL_SECONDS:
        return

    with _SCHEMA_LOCK:
        now = time.time()
        if not force and _SCHEMA_READY and (now - _SCHEMA_READY_AT) < _SCHEMA_TTL_SECONDS:
            return

        with engine.begin() as conn:
            for stmt in [s.strip() for s in SCHEMA_SQL.split(';') if s.strip()]:
                conn.execute(text(stmt))

            if _table_exists('itens_parados_pontos_bonus') and _column_exists('itens_parados_pontos_bonus', 'min_pontos'):
                conn.execute(text("ALTER TABLE itens_parados_pontos_bonus ALTER COLUMN min_pontos TYPE double precision USING min_pontos::double precision"))
            if _table_exists('itens_parados_pontos_resultados'):
                if _column_exists('itens_parados_pontos_resultados', 'pontos'):
                    conn.execute(text("ALTER TABLE itens_parados_pontos_resultados ALTER COLUMN pontos TYPE double precision USING pontos::double precision"))
                if _column_exists('itens_parados_pontos_resultados', 'base_reais'):
                    conn.execute(text("ALTER TABLE itens_parados_pontos_resultados ALTER COLUMN base_reais TYPE double precision USING base_reais::double precision"))

            conn.execute(text("""
                INSERT INTO itens_parados_pontos_config(emp, base_reais, valor_por_ponto, ativo)
                SELECT NULL, 100, 10.0, true
                WHERE NOT EXISTS (SELECT 1 FROM itens_parados_pontos_config WHERE emp IS NULL AND ativo = true)
            """))
            conn.execute(text("""
                INSERT INTO itens_parados_pontos_bonus(emp, min_pontos, bonus_valor, ativo)
                SELECT NULL, v.min_pontos, v.bonus_valor, true
                FROM (VALUES (10.0, 50.0), (20.0, 120.0), (30.0, 200.0)) AS v(min_pontos, bonus_valor)
                WHERE NOT EXISTS (
                    SELECT 1 FROM itens_parados_pontos_bonus b
                    WHERE b.emp IS NULL AND b.min_pontos = v.min_pontos
                )
            """))

        _SCHEMA_READY = True
        _SCHEMA_READY_AT = time.time()



def _invalidate_admin_itens_parados_aux_cache() -> None:
    with _AUX_CACHE_LOCK:
        _AUX_CACHE["payload"] = None
        _AUX_CACHE["ready_at"] = 0.0


def _load_admin_itens_parados_aux(db, *, force: bool = False) -> dict:
    now = time.time()
    if not force:
        with _AUX_CACHE_LOCK:
            payload = _AUX_CACHE.get("payload")
            ready_at = float(_AUX_CACHE.get("ready_at") or 0.0)
            if payload is not None and (now - ready_at) < _AUX_CACHE_TTL_SECONDS:
                return payload

    payload = {
        "cfg_by_emp": (
            db.query(ItensParadosPontosConfig)
            .filter(ItensParadosPontosConfig.emp.isnot(None))
            .order_by(ItensParadosPontosConfig.emp.asc(), ItensParadosPontosConfig.id.desc())
            .all()
        ),
        "cfg_global": (
            db.query(ItensParadosPontosConfig)
            .filter(ItensParadosPontosConfig.emp.is_(None))
            .order_by(ItensParadosPontosConfig.id.desc())
            .limit(5)
            .all()
        ),
        "bonus_by_emp": (
            db.query(ItensParadosPontosBonus)
            .filter(ItensParadosPontosBonus.emp.isnot(None))
            .order_by(ItensParadosPontosBonus.emp.asc(), ItensParadosPontosBonus.min_pontos.asc())
            .all()
        ),
        "bonus_global": (
            db.query(ItensParadosPontosBonus)
            .filter(ItensParadosPontosBonus.emp.is_(None))
            .order_by(ItensParadosPontosBonus.min_pontos.asc())
            .all()
        ),
        "fechamentos": (
            db.query(ItensParadosPontosFechamento)
            .order_by(ItensParadosPontosFechamento.id.desc())
            .limit(20)
            .all()
        ),
    }

    with _AUX_CACHE_LOCK:
        _AUX_CACHE["payload"] = payload
        _AUX_CACHE["ready_at"] = time.time()
    return payload


def _d(value) -> Decimal:
    try:
        return Decimal(str(value or 0))
    except Exception:
        return Decimal("0")



def _round2(value: Decimal) -> Decimal:
    return value.quantize(TWOPLACES, rounding=ROUND_HALF_UP)


def _import_cache_dir() -> str:
    base = os.path.join(tempfile.gettempdir(), "sistemavendas_itens_parados_imports")
    os.makedirs(base, exist_ok=True)
    return base


def _cleanup_import_cache() -> None:
    base = _import_cache_dir()
    now = time.time()
    for name in os.listdir(base):
        if not name.startswith(_IMPORT_CACHE_PREFIX) or not name.endswith(".json"):
            continue
        path = os.path.join(base, name)
        try:
            if now - os.path.getmtime(path) > _IMPORT_CACHE_TTL_SECONDS:
                os.remove(path)
        except OSError:
            pass


def _save_import_payload(payload: dict) -> str:
    _cleanup_import_cache()
    token = uuid4().hex
    path = os.path.join(_import_cache_dir(), f"{_IMPORT_CACHE_PREFIX}{token}.json")
    payload = dict(payload or {})
    payload["created_at"] = time.time()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False)
    return token


def _load_import_payload(token: str) -> dict:
    token = re.sub(r"[^a-fA-F0-9]", "", str(token or ""))
    if not token:
        raise ValueError("Importação expirada ou inválida. Valide a planilha novamente.")
    path = os.path.join(_import_cache_dir(), f"{_IMPORT_CACHE_PREFIX}{token}.json")
    if not os.path.exists(path):
        raise ValueError("Importação expirada. Valide a planilha novamente.")
    if time.time() - os.path.getmtime(path) > _IMPORT_CACHE_TTL_SECONDS:
        try:
            os.remove(path)
        except OSError:
            pass
        raise ValueError("Importação expirada. Valide a planilha novamente.")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _discard_import_payload(token: str) -> None:
    token = re.sub(r"[^a-fA-F0-9]", "", str(token or ""))
    if not token:
        return
    path = os.path.join(_import_cache_dir(), f"{_IMPORT_CACHE_PREFIX}{token}.json")
    try:
        os.remove(path)
    except OSError:
        pass


def _norm_import_header(value) -> str:
    txt = unicodedata.normalize("NFKD", str(value or ""))
    txt = "".join(ch for ch in txt if not unicodedata.combining(ch))
    txt = re.sub(r"[^A-Za-z0-9]+", "", txt).upper()
    return txt


def _clean_import_text(value) -> str:
    if value is None:
        return ""
    txt = str(value).replace("\xa0", " ").strip()
    if txt.lower() in {"nan", "none", "null"}:
        return ""
    return re.sub(r"\s+", " ", txt)


def _clean_import_code(value) -> str:
    txt = _clean_import_text(value)
    if re.fullmatch(r"\d+\.0+", txt):
        txt = txt.split(".", 1)[0]
    return txt.strip()


def _read_itens_import_file(file_storage) -> tuple[list[dict], dict[str, str]]:
    filename = (getattr(file_storage, "filename", "") or "").lower().strip()
    if not filename:
        raise ValueError("Selecione uma planilha para validar.")
    if not filename.endswith((".xlsx", ".xls", ".csv")):
        raise ValueError("Formato inválido. Envie .xlsx, .xls ou .csv.")

    try:
        import pandas as pd
    except Exception as exc:
        raise ValueError("Pandas não está disponível no ambiente para ler a planilha.") from exc

    try:
        file_storage.stream.seek(0)
        if filename.endswith(".csv"):
            df = pd.read_csv(file_storage.stream, dtype=str, keep_default_na=False, sep=None, engine="python")
        else:
            df = pd.read_excel(file_storage.stream, dtype=str, keep_default_na=False)
    except Exception as exc:
        raise ValueError(f"Não foi possível ler a planilha: {exc}") from exc

    if df is None or df.empty:
        raise ValueError("A planilha está vazia.")
    if len(df.index) > _IMPORT_MAX_ROWS:
        raise ValueError(f"A planilha possui {len(df.index)} linhas. Limite atual: {_IMPORT_MAX_ROWS} linhas por importação.")

    aliases = {
        "mestre": {"MESTRE", "CODIGO", "CODIGOPRODUTO", "CODPRODUTO", "CODIGOMESTRE", "CODMESTRE", "PRODUTO"},
        "interno": {"INTERNO", "CODIGOINTERNO", "CODINTERNO", "PROCODGINTERNO", "PROCODINTERNO", "PRO_CODG_INTERNO"},
        "descricao": {"DESCRICAO", "DESCRICAOPRODUTO", "DESCRICAOCOMPLETA", "DESC", "NOME", "NOMEPRODUTO"},
    }
    col_map: dict[str, str] = {}
    for col in df.columns:
        norm = _norm_import_header(col)
        for target, names in aliases.items():
            if norm in names and target not in col_map:
                col_map[target] = col

    if "mestre" not in col_map:
        raise ValueError("A planilha precisa ter a coluna MESTRE. Baixe o modelo e tente novamente.")

    rows: list[dict] = []
    for idx, row in df.iterrows():
        mestre = _clean_import_code(row.get(col_map.get("mestre")))
        interno = _clean_import_code(row.get(col_map.get("interno"))) if col_map.get("interno") else ""
        descricao = _clean_import_text(row.get(col_map.get("descricao"))) if col_map.get("descricao") else ""
        if not mestre and not interno and not descricao:
            continue
        rows.append({
            "linha": int(idx) + 2,
            "mestre": mestre,
            "interno": interno,
            "descricao": descricao,
        })
    if not rows:
        raise ValueError("Nenhuma linha preenchida foi encontrada na planilha.")
    return rows, col_map


def _validar_importacao_itens_parados(db, file_storage) -> dict:
    rows, col_map = _read_itens_import_file(file_storage)

    validos: list[dict] = []
    invalidos: list[dict] = []
    seen: set[str] = set()
    for item in rows:
        mestre = _clean_import_code(item.get("mestre"))
        interno = _clean_import_code(item.get("interno"))
        descricao = _clean_import_text(item.get("descricao"))
        if not mestre:
            invalidos.append({**item, "motivo": "MESTRE vazio. O cálculo de itens parados cruza com vendas.mestre."})
            continue
        key = mestre.upper()
        if key in seen:
            invalidos.append({**item, "motivo": "MESTRE duplicado na planilha. Mantida apenas a primeira ocorrência."})
            continue
        seen.add(key)
        validos.append({
            "linha": int(item.get("linha") or 0),
            "mestre": mestre,
            "interno": interno,
            "descricao": descricao,
            "encontrado": False,
            "descricao_base": "",
            "marca_base": "",
            "vendas_base": 0,
            "alerta": "",
        })

    keys = [x["mestre"].upper() for x in validos]
    base_by_key: dict[str, dict] = {}
    if keys:
        rows_base = (
            db.query(
                func.upper(func.trim(Venda.mestre)).label("mestre_key"),
                func.max(Venda.descricao).label("descricao_base"),
                func.max(Venda.marca).label("marca_base"),
                func.count(Venda.id).label("qtd"),
            )
            .filter(func.upper(func.trim(Venda.mestre)).in_(keys))
            .group_by(func.upper(func.trim(Venda.mestre)))
            .all()
        )
        for mestre_key, descricao_base, marca_base, qtd in rows_base:
            base_by_key[str(mestre_key or "").upper()] = {
                "descricao_base": _clean_import_text(descricao_base),
                "marca_base": _clean_import_text(marca_base),
                "vendas_base": int(qtd or 0),
            }

    alertas = 0
    for item in validos:
        base = base_by_key.get(item["mestre"].upper())
        if base:
            item["encontrado"] = True
            item["descricao_base"] = base.get("descricao_base") or ""
            item["marca_base"] = base.get("marca_base") or ""
            item["vendas_base"] = int(base.get("vendas_base") or 0)
            if not item["descricao"] and item["descricao_base"]:
                item["descricao"] = item["descricao_base"]
        else:
            alertas += 1
            item["alerta"] = "MESTRE ainda não localizado na base de vendas. Será importado, mas só calculará quando houver venda futura com este MESTRE."

    return {
        "token": "",
        "validos": validos,
        "invalidos": invalidos,
        "total_linhas": len(rows),
        "total_validos": len(validos),
        "total_invalidos": len(invalidos),
        "total_alertas": alertas,
        "colunas_lidas": sorted(col_map.keys()),
    }


def _parse_emp_list(values: list[str], manual: str = "") -> list[str]:
    emps = []
    for value in list(values or []) + re.split(r"[,;\s]+", manual or ""):
        txt = str(value or "").strip()
        if txt:
            emps.append(txt)
    return sort_emp_codes(emps)


def _create_modelo_itens_parados_workbook() -> BytesIO:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill, Border, Side
        from openpyxl.worksheet.table import Table, TableStyleInfo
    except Exception as exc:
        raise RuntimeError("openpyxl não está disponível para gerar o modelo.") from exc

    wb = Workbook()
    ws = wb.active
    ws.title = "Itens Parados"
    ws.append(["MESTRE", "INTERNO", "DESCRICAO"])
    ws.append(["30015", "", "Descrição opcional para facilitar conferência"])
    ws.append(["PNEU", "", "Exemplo: use o código MESTRE que cruza com vendas.mestre"])

    header_fill = PatternFill("solid", fgColor="111827")
    header_font = Font(color="FFFFFF", bold=True)
    thin = Side(style="thin", color="D1D5DB")
    for row in ws.iter_rows(min_row=1, max_row=3, min_col=1, max_col=3):
        for cell in row:
            cell.alignment = Alignment(vertical="center", wrap_text=True)
            cell.border = Border(left=thin, right=thin, top=thin, bottom=thin)
            if cell.row == 1:
                cell.fill = header_fill
                cell.font = header_font
    ws.column_dimensions["A"].width = 18
    ws.column_dimensions["B"].width = 18
    ws.column_dimensions["C"].width = 52
    ws.freeze_panes = "A2"
    tab = Table(displayName="ModeloItensParados", ref="A1:C3")
    style = TableStyleInfo(name="TableStyleMedium2", showFirstColumn=False, showLastColumn=False, showRowStripes=True, showColumnStripes=False)
    tab.tableStyleInfo = style
    ws.add_table(tab)

    info = wb.create_sheet("Instrucoes")
    info.append(["Como preencher"])
    info.append(["MESTRE", "Obrigatório. É o código que será cruzado com vendas.mestre para cálculo."])
    info.append(["INTERNO", "Opcional. Campo de referência interna para conferência."])
    info.append(["DESCRICAO", "Opcional. Se ficar vazio, o sistema tenta sugerir pela base de vendas quando encontrar o MESTRE."])
    info.append(["Lojas e vigência", "Serão selecionadas depois da validação, dentro do sistema."])
    info.column_dimensions["A"].width = 24
    info.column_dimensions["B"].width = 90
    for row in info.iter_rows(min_row=1, max_row=5, min_col=1, max_col=2):
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)
            if cell.row == 1:
                cell.font = Font(bold=True, color="FFFFFF")
                cell.fill = header_fill
    bio = BytesIO()
    wb.save(bio)
    bio.seek(0)
    return bio


def _pontos_fechados_from_pontos(pontos: Decimal) -> Decimal:
    """Retorna apenas os pontos inteiros que geram pagamento."""
    pontos_validos = _d(pontos)
    if pontos_validos <= 0:
        return Decimal("0")
    pontos_fechados = pontos_validos.quantize(Decimal("1"), rounding=ROUND_FLOOR)
    return pontos_fechados if pontos_fechados > 0 else Decimal("0")


def _bonus_base_from_pontos(pontos: Decimal, valor_por_ponto: Decimal) -> Decimal:
    pontos_fechados = _pontos_fechados_from_pontos(pontos)
    if pontos_fechados <= 0:
        return Decimal("0")
    return pontos_fechados * _d(valor_por_ponto)


def _norm_emp(value) -> str | None:
    if value in (None, "", "NULL"):
        return None
    txt = str(value).strip()
    return txt or None


def _load_fechamento_rules(db):
    cfg_rows = (
        db.query(ItensParadosPontosConfig)
        .filter(ItensParadosPontosConfig.ativo.is_(True))
        .order_by(ItensParadosPontosConfig.id.desc())
        .all()
    )
    bonus_rows = (
        db.query(ItensParadosPontosBonus)
        .filter(ItensParadosPontosBonus.ativo.is_(True))
        .order_by(ItensParadosPontosBonus.emp.asc().nullsfirst(), ItensParadosPontosBonus.min_pontos.asc())
        .all()
    )

    cfg_global = {"base_reais": Decimal("100"), "valor_por_ponto": Decimal("10")}
    cfg_by_emp: dict[str, dict[str, Decimal]] = {}

    for cfg in cfg_rows:
        key = _norm_emp(getattr(cfg, "emp", None))
        base_reais = _d(getattr(cfg, "base_reais", None) or 100)
        valor_por_ponto = _d(getattr(cfg, "valor_por_ponto", None) or 10)
        if base_reais <= 0:
            base_reais = Decimal("100")
        data = {"base_reais": base_reais, "valor_por_ponto": valor_por_ponto}
        if key is None:
            cfg_global = data
        elif key not in cfg_by_emp:
            cfg_by_emp[key] = data

    bonus_global: list[tuple[Decimal, Decimal]] = []
    bonus_by_emp: dict[str, list[tuple[Decimal, Decimal]]] = {}
    for bonus in bonus_rows:
        item = (
            _d(getattr(bonus, "min_pontos", None) or 0),
            _d(getattr(bonus, "bonus_valor", None) or 0),
        )
        key = _norm_emp(getattr(bonus, "emp", None))
        if key is None:
            bonus_global.append(item)
        else:
            bonus_by_emp.setdefault(key, []).append(item)

    return cfg_global, cfg_by_emp, bonus_global, bonus_by_emp


def _build_itens_factor_index(itens_rows, cfg_global, cfg_by_emp):
    itens_idx: dict[tuple[str, str], list[tuple[date | None, date | None, Decimal]]] = {}
    for emp_v, codigo_v, data_inicio_v, data_fim_v, multiplicador_v in itens_rows:
        emp_key = _norm_emp(emp_v)
        codigo_key = (codigo_v or "").strip()
        if not emp_key or not codigo_key:
            continue
        cfg = cfg_by_emp.get(emp_key) or cfg_global
        base_reais = cfg.get("base_reais") or Decimal("100")
        if base_reais <= 0:
            base_reais = Decimal("100")
        mult = _d(multiplicador_v or 1.0)
        if mult <= 0:
            mult = Decimal("1")
        pontos_por_real = mult / base_reais
        itens_idx.setdefault((emp_key, codigo_key), []).append((data_inicio_v, data_fim_v, pontos_por_real))
    return itens_idx


def _iter_vendas_agrupadas(db, emps, di, df, codigos):
    query = (
        db.query(
            Venda.emp,
            Venda.vendedor,
            Venda.mestre,
            Venda.movimento,
            func.coalesce(func.sum(Venda.valor_total), 0.0),
        )
        .filter(Venda.emp.in_(emps))
        .filter(Venda.movimento >= di)
        .filter(Venda.movimento <= df)
        .filter(func.upper(func.coalesce(Venda.mov_tipo_movto, "")).in_(ITENS_PARADOS_MOV_TIPOS_VENDA))
        .filter(func.coalesce(Venda.qtdade_vendida, 0.0) > 0)
        .filter(Venda.mestre.in_(codigos))
        .group_by(Venda.emp, Venda.vendedor, Venda.mestre, Venda.movimento)
    )
    return query.yield_per(2000)


def _processar_fechamento_itens_parados(db, *, ItemParado, emps, di, df, usuario_logado_fn):
    cfg_global, cfg_by_emp, bonus_global, bonus_by_emp = _load_fechamento_rules(db)

    itens_rows = (
        db.query(
            ItemParado.emp,
            ItemParado.codigo,
            ItemParado.data_inicio,
            ItemParado.data_fim,
            ItemParado.multiplicador_pontos,
        )
        .filter(ItemParado.emp.in_(emps))
        .filter(ItemParado.ativo.is_(True))
        .filter(or_(ItemParado.data_inicio.is_(None), ItemParado.data_inicio <= df))
        .filter(or_(ItemParado.data_fim.is_(None), ItemParado.data_fim >= di))
        .all()
    )
    if not itens_rows:
        raise ValueError("Nenhum item ativo foi encontrado no período informado.")

    codigos = sorted({(codigo or "").strip() for _, codigo, _, _, _ in itens_rows if (codigo or "").strip()})
    if not codigos:
        raise ValueError("Nenhum código de item válido foi encontrado para o período informado.")

    itens_idx = _build_itens_factor_index(itens_rows, cfg_global, cfg_by_emp)

    fechamento = ItensParadosPontosFechamento(
        emp=emps[0] if len(emps) == 1 else None,
        data_inicio=di,
        data_fim=df,
        criado_por=str(usuario_logado_fn() or ""),
        criado_em=datetime.utcnow(),
    )
    db.add(fechamento)
    db.flush()

    acc: dict[tuple[str, str], dict[str, Decimal]] = {}
    for emp_v, vend, mestre, movimento, total in _iter_vendas_agrupadas(db, emps, di, df, codigos):
        emp_key = _norm_emp(emp_v) or ""
        vend_key = (vend or "").strip().upper()
        cod_key = (mestre or "").strip()
        if not emp_key or not vend_key or not cod_key:
            continue

        ranges = itens_idx.get((emp_key, cod_key), [])
        if not ranges:
            continue

        total_dec = _d(total)
        if total_dec <= 0:
            continue

        pontos_factor = Decimal("0")
        for data_inicio_v, data_fim_v, pontos_por_real in ranges:
            if data_inicio_v and movimento < data_inicio_v:
                continue
            if data_fim_v and movimento > data_fim_v:
                continue

            # Evita multiplicar a mesma venda quando o mesmo MESTRE estiver duplicado
            # ou com vigências sobrepostas. A venda conta uma vez; se houver
            # multiplicadores diferentes, prevalece o maior.
            if pontos_por_real > pontos_factor:
                pontos_factor = pontos_por_real

        if pontos_factor <= 0:
            continue

        cfg = cfg_by_emp.get(emp_key) or cfg_global
        bucket = acc.setdefault(
            (emp_key, vend_key),
            {
                "valor_vendido": Decimal("0"),
                "pontos": Decimal("0"),
                "base_reais": cfg["base_reais"],
                "valor_por_ponto": cfg["valor_por_ponto"],
            },
        )
        bucket["valor_vendido"] += total_dec
        bucket["pontos"] += total_dec * pontos_factor

    resultados_bulk = []
    utc_now = datetime.utcnow()
    for (emp_key, vend_key), data in acc.items():
        bonus_list = bonus_by_emp.get(emp_key) or bonus_global
        pontos_calculados = data["pontos"]
        pontos_fechados = _pontos_fechados_from_pontos(pontos_calculados)
        bonus_base = _bonus_base_from_pontos(pontos_fechados, data["valor_por_ponto"])
        bonus_extra = Decimal("0")
        for min_pontos, bonus_valor in bonus_list:
            if pontos_fechados >= min_pontos:
                bonus_extra = bonus_valor
        total_final = bonus_base + bonus_extra

        resultados_bulk.append(
            ItensParadosPontosResultado(
                fechamento_id=int(fechamento.id),
                emp=emp_key,
                vendedor=vend_key,
                valor_vendido=float(_round2(data["valor_vendido"])),
                pontos=float(_round2(pontos_fechados)),
                base_reais=float(_round2(data["base_reais"])),
                valor_por_ponto=float(_round2(data["valor_por_ponto"])),
                bonus_extra=float(_round2(bonus_extra)),
                total=float(_round2(total_final)),
                status_pagamento="PENDENTE",
                criado_em=utc_now,
                atualizado_em=utc_now,
            )
        )

    if resultados_bulk:
        db.bulk_save_objects(resultados_bulk)

    return fechamento



def register_admin_itens_parados_routes(
    app,
    *,
    SessionLocal,
    ItemParado: Type,
    login_required_fn: Callable[[], object | None],
    admin_required_fn: Callable[[], object | None],
    usuario_logado_fn: Callable[[], object],
):
    def admin_itens_parados():
        red = login_required_fn()
        if red:
            return red
        red = admin_required_fn()
        if red:
            return red

        # Garante o schema somente quando o módulo é realmente acessado.
        # Isso elimina conexão/DDL no boot do worker.
        _ensure_itens_parados_schema()

        erro = None
        ok = None
        ver_fech = (request.args.get("ver_fech") or "").strip()
        import_preview = None

        with SessionLocal() as db:
            try:
                acao = (request.form.get("acao") or "").strip().lower()
                if request.method == "POST" and acao:
                    if acao == "criar_item":
                        emp = (request.form.get("emp") or "").strip()
                        codigo = (request.form.get("codigo") or "").strip()
                        descricao = (request.form.get("descricao") or "").strip()
                        interno = (request.form.get("interno") or "").strip()
                        mult_raw = (request.form.get("multiplicador_pontos") or "").strip().replace(",", ".")
                        di_raw = (request.form.get("data_inicio") or "").strip()
                        df_raw = (request.form.get("data_fim") or "").strip()

                        if not emp:
                            raise ValueError("Informe a EMP.")
                        if not codigo:
                            raise ValueError("Informe o código do item.")

                        mult = float(mult_raw) if mult_raw else 1.0
                        if mult <= 0:
                            mult = 1.0

                        di = date.fromisoformat(di_raw) if di_raw else None
                        df = date.fromisoformat(df_raw) if df_raw else None
                        if di and df and df < di:
                            di, df = df, di

                        db.add(
                            ItemParado(
                                emp=str(emp),
                                codigo=str(codigo),
                                interno=interno or None,
                                descricao=descricao or None,
                                quantidade=None,
                                recompensa_pct=0.0,
                                modo="PONTOS",
                                multiplicador_pontos=mult,
                                data_inicio=di,
                                data_fim=df,
                                ativo=True,
                                criado_em=datetime.utcnow(),
                                atualizado_em=datetime.utcnow(),
                            )
                        )
                        db.commit()
                        _invalidate_admin_itens_parados_aux_cache()
                        ok = "Item parado cadastrado com sucesso."

                    elif acao == "toggle_item":
                        item_id = int(request.form.get("item_id") or 0)
                        it = db.query(ItemParado).filter(ItemParado.id == item_id).first()
                        if not it:
                            raise ValueError("Item não encontrado.")
                        it.ativo = not bool(it.ativo)
                        it.atualizado_em = datetime.utcnow()
                        db.commit()
                        _invalidate_admin_itens_parados_aux_cache()
                        ok = "Status do item atualizado."

                    elif acao == "excluir_item":
                        item_id = int(request.form.get("item_id") or 0)
                        it = db.query(ItemParado).filter(ItemParado.id == item_id).first()
                        if not it:
                            raise ValueError("Item não encontrado.")
                        db.delete(it)
                        db.commit()
                        _invalidate_admin_itens_parados_aux_cache()
                        ok = "Item removido."

                    elif acao == "salvar_config":
                        emp = (request.form.get("cfg_emp") or "").strip() or None
                        base_reais = int(float((request.form.get("base_reais") or "0").strip().replace(",", ".")))
                        valor_por_ponto = float((request.form.get("valor_por_ponto") or "0").strip().replace(",", "."))
                        if base_reais <= 0:
                            raise ValueError("Base em reais deve ser maior que zero.")

                        q_old = db.query(ItensParadosPontosConfig)
                        q_old = q_old.filter(ItensParadosPontosConfig.emp == emp) if emp else q_old.filter(ItensParadosPontosConfig.emp.is_(None))
                        q_old.update({"ativo": False, "atualizado_em": datetime.utcnow()}, synchronize_session=False)

                        db.add(
                            ItensParadosPontosConfig(
                                emp=emp,
                                base_reais=base_reais,
                                valor_por_ponto=valor_por_ponto,
                                ativo=True,
                                criado_em=datetime.utcnow(),
                                atualizado_em=datetime.utcnow(),
                            )
                        )
                        db.commit()
                        _invalidate_admin_itens_parados_aux_cache()
                        ok = "Configuração salva."

                    elif acao == "criar_bonus":
                        emp = (request.form.get("bonus_emp") or "").strip() or None
                        min_pontos = float((request.form.get("min_pontos") or "0").strip().replace(",", "."))
                        bonus_valor = float((request.form.get("bonus_valor") or "0").strip().replace(",", "."))
                        if min_pontos <= 0:
                            raise ValueError("Mínimo de pontos deve ser maior que zero.")

                        db.add(
                            ItensParadosPontosBonus(
                                emp=emp,
                                min_pontos=min_pontos,
                                bonus_valor=bonus_valor,
                                ativo=True,
                                criado_em=datetime.utcnow(),
                                atualizado_em=datetime.utcnow(),
                            )
                        )
                        db.commit()
                        _invalidate_admin_itens_parados_aux_cache()
                        ok = "Faixa de bônus cadastrada."

                    elif acao == "toggle_bonus":
                        bonus_id = int(request.form.get("bonus_id") or 0)
                        bonus = db.query(ItensParadosPontosBonus).filter(ItensParadosPontosBonus.id == bonus_id).first()
                        if not bonus:
                            raise ValueError("Faixa de bônus não encontrada.")
                        bonus.ativo = not bool(bonus.ativo)
                        bonus.atualizado_em = datetime.utcnow()
                        db.commit()
                        _invalidate_admin_itens_parados_aux_cache()
                        ok = "Status da faixa atualizado."

                    elif acao == "excluir_bonus":
                        bonus_id = int(request.form.get("bonus_id") or 0)
                        bonus = db.query(ItensParadosPontosBonus).filter(ItensParadosPontosBonus.id == bonus_id).first()
                        if not bonus:
                            raise ValueError("Faixa de bônus não encontrada.")
                        db.delete(bonus)
                        db.commit()
                        _invalidate_admin_itens_parados_aux_cache()
                        ok = "Faixa de bônus removida."

                    elif acao == "validar_importacao":
                        arquivo = request.files.get("arquivo_itens")
                        if not arquivo:
                            raise ValueError("Selecione a planilha de itens parados.")
                        import_preview = _validar_importacao_itens_parados(db, arquivo)
                        token = _save_import_payload({"validos": import_preview.get("validos") or []})
                        import_preview["token"] = token
                        ok = f"Planilha validada: {import_preview['total_validos']} item(ns) válido(s), {import_preview['total_invalidos']} inválido(s)."

                    elif acao == "confirmar_importacao":
                        token = (request.form.get("import_token") or "").strip()
                        payload = _load_import_payload(token)
                        rows_validos = payload.get("validos") or []
                        if not rows_validos:
                            raise ValueError("Nenhum item válido encontrado na importação. Valide a planilha novamente.")

                        emps = _parse_emp_list(request.form.getlist("import_emps"), request.form.get("import_emps_manual") or "")
                        if not emps:
                            raise ValueError("Selecione pelo menos uma loja/EMP para aplicar os itens validados.")

                        di_raw = (request.form.get("import_data_inicio") or "").strip()
                        df_raw = (request.form.get("import_data_fim") or "").strip()
                        if not di_raw or not df_raw:
                            raise ValueError("Informe a data inicial e final de vigência.")
                        di = date.fromisoformat(di_raw)
                        df = date.fromisoformat(df_raw)
                        if df < di:
                            di, df = df, di

                        criados = 0
                        atualizados = 0
                        utc_now = datetime.utcnow()
                        has_interno = hasattr(ItemParado, "interno")
                        for emp_item in emps:
                            emp_txt = str(emp_item).strip()
                            if not emp_txt:
                                continue
                            for row in rows_validos:
                                codigo = _clean_import_code(row.get("mestre"))
                                if not codigo:
                                    continue
                                descricao = _clean_import_text(row.get("descricao")) or _clean_import_text(row.get("descricao_base")) or None
                                interno = _clean_import_code(row.get("interno")) or None
                                it = (
                                    db.query(ItemParado)
                                    .filter(ItemParado.emp == emp_txt)
                                    .filter(ItemParado.codigo == codigo)
                                    .filter(ItemParado.data_inicio == di)
                                    .filter(ItemParado.data_fim == df)
                                    .first()
                                )
                                if it:
                                    if has_interno:
                                        setattr(it, "interno", interno)
                                    it.descricao = descricao
                                    it.quantidade = None
                                    it.recompensa_pct = 0.0
                                    it.modo = "PONTOS"
                                    it.multiplicador_pontos = 1.0
                                    it.ativo = True
                                    it.atualizado_em = utc_now
                                    atualizados += 1
                                else:
                                    kwargs = {
                                        "emp": emp_txt,
                                        "codigo": codigo,
                                        "descricao": descricao,
                                        "quantidade": None,
                                        "recompensa_pct": 0.0,
                                        "modo": "PONTOS",
                                        "multiplicador_pontos": 1.0,
                                        "data_inicio": di,
                                        "data_fim": df,
                                        "ativo": True,
                                        "criado_em": utc_now,
                                        "atualizado_em": utc_now,
                                    }
                                    if has_interno:
                                        kwargs["interno"] = interno
                                    db.add(ItemParado(**kwargs))
                                    criados += 1

                        db.commit()
                        _discard_import_payload(token)
                        _invalidate_admin_itens_parados_aux_cache()
                        ok = f"Importação concluída: {criados} item(ns) criado(s) e {atualizados} atualizado(s) em {len(emps)} loja(s)."

                    elif acao == "fechar_periodo":
                        emp = (request.form.get("fech_emp") or "").strip() or None
                        di_raw = (request.form.get("fech_di") or "").strip()
                        df_raw = (request.form.get("fech_df") or "").strip()
                        if not di_raw or not df_raw:
                            raise ValueError("Informe data inicial e final do fechamento.")
                        di = date.fromisoformat(di_raw)
                        df = date.fromisoformat(df_raw)
                        if df < di:
                            di, df = df, di

                        emps = [emp] if emp else [
                            str(x[0])
                            for x in db.query(ItemParado.emp).filter(ItemParado.ativo.is_(True)).distinct().all()
                        ]
                        emps = sort_emp_codes({str(e).strip() for e in emps if e and str(e).strip()})
                        if not emps:
                            raise ValueError("Não existem EMPs com itens parados ativos.")

                        fechamento = _processar_fechamento_itens_parados(
                            db,
                            ItemParado=ItemParado,
                            emps=emps,
                            di=di,
                            df=df,
                            usuario_logado_fn=usuario_logado_fn,
                        )
                        db.commit()
                        _invalidate_admin_itens_parados_aux_cache()
                        return redirect(url_for("admin_itens_parados", ver_fech=int(fechamento.id), ok="1"))

                    else:
                        raise ValueError("Ação inválida.")

            except Exception as e:
                db.rollback()
                erro = str(e)
                current_app.logger.exception("Erro no admin de itens parados")

            if request.args.get("ok") == "1" and not erro:
                ok = "Fechamento criado com sucesso."

            filtro_emp = (request.args.get("f_emp") or "").strip()
            filtro_codigo = (request.args.get("f_codigo") or "").strip()
            filtro_status = (request.args.get("f_status") or "").strip().lower()
            pagina = max(int(request.args.get("page") or 1), 1)
            limite = 150

            itens_q = db.query(ItemParado)
            if filtro_emp:
                itens_q = itens_q.filter(ItemParado.emp == filtro_emp)
            if filtro_codigo:
                itens_q = itens_q.filter(ItemParado.codigo.ilike(f"%{filtro_codigo}%"))
            if filtro_status == "ativos":
                itens_q = itens_q.filter(ItemParado.ativo.is_(True))
            elif filtro_status == "inativos":
                itens_q = itens_q.filter(ItemParado.ativo.is_(False))

            offset = (pagina - 1) * limite
            itens_page = (
                itens_q
                .order_by(ItemParado.emp.asc(), ItemParado.codigo.asc(), ItemParado.id.desc())
                .offset(offset)
                .limit(limite + 1)
                .all()
            )
            has_next = len(itens_page) > limite
            itens = itens_page[:limite]
            total_itens = None if has_next else (offset + len(itens))

            aux_data = _load_admin_itens_parados_aux(db)
            cfg_by_emp = aux_data["cfg_by_emp"]
            cfg_global = aux_data["cfg_global"]
            bonus_by_emp = aux_data["bonus_by_emp"]
            bonus_global = aux_data["bonus_global"]
            fechamentos = aux_data["fechamentos"]
            res_fech = []
            if ver_fech.isdigit():
                res_fech = (
                    db.query(ItensParadosPontosResultado)
                    .filter(ItensParadosPontosResultado.fechamento_id == int(ver_fech))
                    .order_by(ItensParadosPontosResultado.emp.asc(), ItensParadosPontosResultado.total.desc())
                    .limit(500)
                    .all()
                )

            emps_vendas = [
                str(x[0]).strip()
                for x in db.query(Venda.emp).filter(Venda.emp.isnot(None)).distinct().order_by(Venda.emp.asc()).all()
                if x and x[0] and str(x[0]).strip()
            ]
            emps_itens = [
                str(x[0]).strip()
                for x in db.query(ItemParado.emp).filter(ItemParado.emp.isnot(None)).distinct().all()
                if x and x[0] and str(x[0]).strip()
            ]
            emps_options = sort_emp_codes(emps_vendas + emps_itens)

        total_paginas = max((total_itens + limite - 1) // limite, 1) if total_itens is not None else max(pagina + (1 if has_next else 0), 1)

        return render_template(
            "admin_itens_parados.html",
            usuario=usuario_logado_fn(),
            itens=itens,
            erro=erro,
            ok=ok,
            cfg_by_emp=cfg_by_emp,
            cfg_global=cfg_global,
            bonus_by_emp=bonus_by_emp,
            bonus_global=bonus_global,
            fechamentos=fechamentos,
            ver_fech=ver_fech,
            res_fech=res_fech,
            filtro_emp=filtro_emp,
            filtro_codigo=filtro_codigo,
            filtro_status=filtro_status,
            pagina=pagina,
            limite=limite,
            total_itens=total_itens,
            total_paginas=total_paginas,
            has_next=has_next,
            total_itens_label=(str(total_itens) if total_itens is not None else f"mais de {offset + len(itens)}"),
            import_preview=import_preview,
            emps_options=emps_options,
            role=(session.get("role") or ""),
            emp=session.get("emp"),
        )

    def admin_itens_parados_modelo():
        red = login_required_fn()
        if red:
            return red
        red = admin_required_fn()
        if red:
            return red
        bio = _create_modelo_itens_parados_workbook()
        return send_file(
            bio,
            as_attachment=True,
            download_name="modelo_importacao_itens_parados.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

    app.add_url_rule(
        "/admin/itens_parados/modelo",
        endpoint="admin_itens_parados_modelo",
        view_func=admin_itens_parados_modelo,
        methods=["GET"],
    )

    app.add_url_rule(
        "/admin/itens_parados",
        endpoint="admin_itens_parados",
        view_func=admin_itens_parados,
        methods=["GET", "POST"],
    )
