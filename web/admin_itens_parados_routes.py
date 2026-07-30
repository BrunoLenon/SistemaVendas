# -*- coding: utf-8 -*-
"""Administração enxuta de Itens Parados.

Mantém apenas:
* cadastro/ativação dos produtos por EMP;
* importação do modelo CODIGO, DESCRICAO e LOJA_ATIVA;
* painel da última importação das vendas consolidadas.

Os cálculos antigos por pontos e fechamentos deixaram de ser consultados.
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import date, datetime
from io import BytesIO
from typing import Callable, Type

from flask import current_app, render_template, request, send_file, session

from db import (
    ItensParadosVendaUsuario,
    ensure_itens_parados_snapshot_schema,
)
from itens_parados_snapshot import batch_warnings, latest_batch, norm_emp
from sv_utils import emp_sort_key


MAX_ITEMS_IMPORT = 20000


def _clean_text(value) -> str:
    if value is None:
        return ""
    raw = str(value).replace("\xa0", " ").strip()
    if raw.lower() in {"nan", "none", "null"}:
        return ""
    return re.sub(r"\s+", " ", raw)


def _clean_code(value) -> str:
    raw = _clean_text(value)
    if re.fullmatch(r"\d+\.0+", raw):
        return raw.split(".", 1)[0]
    return raw


def _norm_header(value) -> str:
    raw = unicodedata.normalize("NFKD", str(value or ""))
    raw = "".join(ch for ch in raw if not unicodedata.combining(ch))
    return re.sub(r"[^A-Za-z0-9]", "", raw).upper()


def _read_active_items_file(file_storage) -> tuple[list[dict], list[str]]:
    filename = (getattr(file_storage, "filename", "") or "").lower().strip()
    if not filename:
        raise ValueError("Selecione a planilha de itens parados.")
    if not filename.endswith((".xlsx", ".xlsm", ".csv")):
        raise ValueError("Formato inválido. Envie .xlsx, .xlsm ou .csv.")

    try:
        import pandas as pd
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("Pandas não está disponível no servidor.") from exc

    file_storage.stream.seek(0)
    try:
        if filename.endswith(".csv"):
            df = pd.read_csv(
                file_storage.stream,
                dtype=str,
                keep_default_na=False,
                sep=None,
                engine="python",
            )
        else:
            df = pd.read_excel(file_storage.stream, dtype=str, keep_default_na=False)
    except Exception as exc:
        raise ValueError(f"Não foi possível ler a planilha: {exc}") from exc

    if df is None or df.empty:
        raise ValueError("A planilha está vazia.")
    if len(df.index) > MAX_ITEMS_IMPORT:
        raise ValueError(
            f"A planilha possui {len(df.index)} linhas. Limite: {MAX_ITEMS_IMPORT}."
        )

    aliases = {
        "codigo": {"CODIGO", "MESTRE", "CODIGOPRODUTO", "CODPRODUTO"},
        "descricao": {"DESCRICAO", "DESCRICAOPRODUTO", "PRODUTO", "NOME"},
        "emp": {"LOJAATIVA", "EMP", "EMPRESA", "LOJA", "LOJAACA0", "LOJAACAO"},
    }
    mapping: dict[str, str] = {}
    for column in df.columns:
        normalized = _norm_header(column)
        for field, names in aliases.items():
            if field not in mapping and normalized in names:
                mapping[field] = column
                break

    missing = [field for field in ("codigo", "descricao", "emp") if field not in mapping]
    if missing:
        raise ValueError(
            "O modelo precisa conter CODIGO, DESCRICAO e LOJA_ATIVA. "
            f"Colunas ausentes: {', '.join(missing).upper()}."
        )

    records: list[dict] = []
    warnings: list[str] = []
    seen: set[tuple[str, str]] = set()
    for index, row in df.iterrows():
        line = int(index) + 2
        codigo = _clean_code(row.get(mapping["codigo"]))
        descricao = _clean_text(row.get(mapping["descricao"]))
        emp = norm_emp(row.get(mapping["emp"]))
        if not codigo and not descricao and not emp:
            continue
        if not codigo or not emp:
            warnings.append(
                f"Linha {line} ignorada: CODIGO e LOJA_ATIVA são obrigatórios."
            )
            continue
        key = (emp, codigo.upper())
        if key in seen:
            warnings.append(
                f"Linha {line} ignorada: código {codigo} duplicado para a EMP {emp}."
            )
            continue
        seen.add(key)
        records.append(
            {
                "linha": line,
                "codigo": codigo,
                "descricao": descricao or None,
                "emp": emp,
            }
        )
    if not records:
        raise ValueError("Nenhuma linha válida foi encontrada no modelo.")
    return records, warnings


def _create_model_workbook() -> BytesIO:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
        from openpyxl.worksheet.table import Table, TableStyleInfo
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("openpyxl não está disponível para gerar o modelo.") from exc

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Itens Parados"
    sheet.append(["CODIGO", "DESCRICAO", "LOJA_ATIVA"])
    sheet.append(["345269", "CARENAGEM LAT FAROL TITAN 160", "101"])
    sheet.append(["373126", "FILTRO AR ESPORTIVO TITAN/FAN", "501"])

    header_fill = PatternFill("solid", fgColor="111827")
    header_font = Font(color="FFFFFF", bold=True)
    thin = Side(style="thin", color="D1D5DB")
    for row in sheet.iter_rows(min_row=1, max_row=3, min_col=1, max_col=3):
        for cell in row:
            cell.alignment = Alignment(vertical="center", wrap_text=True)
            cell.border = Border(left=thin, right=thin, top=thin, bottom=thin)
            if cell.row == 1:
                cell.fill = header_fill
                cell.font = header_font
    sheet.column_dimensions["A"].width = 20
    sheet.column_dimensions["B"].width = 58
    sheet.column_dimensions["C"].width = 18
    sheet.freeze_panes = "A2"
    table = Table(displayName="ModeloItensParados", ref="A1:C3")
    table.tableStyleInfo = TableStyleInfo(
        name="TableStyleMedium2",
        showFirstColumn=False,
        showLastColumn=False,
        showRowStripes=True,
        showColumnStripes=False,
    )
    sheet.add_table(table)

    info = workbook.create_sheet("Instrucoes")
    info.append(["Campo", "Como preencher"])
    info.append(["CODIGO", "Obrigatório. Código/MESTRE do produto da ação."])
    info.append(["DESCRICAO", "Descrição do produto para conferência."])
    info.append(
        [
            "LOJA_ATIVA",
            "Obrigatório. Informe uma EMP por linha. Para o mesmo produto em várias lojas, repita o código em uma linha para cada EMP.",
        ]
    )
    info.column_dimensions["A"].width = 22
    info.column_dimensions["B"].width = 90
    for row in info.iter_rows(min_row=1, max_row=4, min_col=1, max_col=2):
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)
            if cell.row == 1:
                cell.fill = header_fill
                cell.font = header_font

    bio = BytesIO()
    workbook.save(bio)
    bio.seek(0)
    return bio


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

        ensure_itens_parados_snapshot_schema()
        erro = None
        ok = None
        avisos_acao: list[str] = []

        with SessionLocal() as db:
            try:
                action = (request.form.get("acao") or "").strip().lower()
                if request.method == "POST" and action:
                    if action == "criar_item":
                        emp = norm_emp(request.form.get("emp"))
                        codigo = _clean_code(request.form.get("codigo"))
                        descricao = _clean_text(request.form.get("descricao")) or None
                        if not emp or not codigo:
                            raise ValueError("Informe EMP e código.")
                        item = (
                            db.query(ItemParado)
                            .filter(ItemParado.emp == emp, ItemParado.codigo == codigo)
                            .order_by(ItemParado.id.desc())
                            .first()
                        )
                        if item:
                            item.descricao = descricao or item.descricao
                            item.ativo = True
                            item.atualizado_em = datetime.utcnow()
                            ok = "Item atualizado e ativado."
                        else:
                            db.add(
                                ItemParado(
                                    emp=emp,
                                    codigo=codigo,
                                    descricao=descricao,
                                    quantidade=None,
                                    recompensa_pct=0,
                                    modo="PONTOS",
                                    multiplicador_pontos=1,
                                    ativo=True,
                                    criado_em=datetime.utcnow(),
                                    atualizado_em=datetime.utcnow(),
                                )
                            )
                            ok = "Item cadastrado."
                        db.commit()

                    elif action == "alternar_item":
                        item_id = int(request.form.get("item_id") or 0)
                        item = db.get(ItemParado, item_id)
                        if not item:
                            raise ValueError("Item não encontrado.")
                        item.ativo = not bool(item.ativo)
                        item.atualizado_em = datetime.utcnow()
                        db.commit()
                        ok = "Status do item atualizado."

                    elif action == "excluir_item":
                        item_id = int(request.form.get("item_id") or 0)
                        item = db.get(ItemParado, item_id)
                        if not item:
                            raise ValueError("Item não encontrado.")
                        db.delete(item)
                        db.commit()
                        ok = "Item removido."

                    elif action == "importar_itens":
                        file_storage = request.files.get("arquivo_itens")
                        records, avisos_acao = _read_active_items_file(file_storage)
                        created = 0
                        updated = 0
                        now = datetime.utcnow()
                        for record in records:
                            item = (
                                db.query(ItemParado)
                                .filter(
                                    ItemParado.emp == record["emp"],
                                    ItemParado.codigo == record["codigo"],
                                )
                                .order_by(ItemParado.id.desc())
                                .first()
                            )
                            if item:
                                item.descricao = record["descricao"] or item.descricao
                                item.ativo = True
                                item.atualizado_em = now
                                updated += 1
                            else:
                                db.add(
                                    ItemParado(
                                        emp=record["emp"],
                                        codigo=record["codigo"],
                                        descricao=record["descricao"],
                                        quantidade=None,
                                        recompensa_pct=0,
                                        modo="PONTOS",
                                        multiplicador_pontos=1,
                                        ativo=True,
                                        criado_em=now,
                                        atualizado_em=now,
                                    )
                                )
                                created += 1
                        db.commit()
                        ok = (
                            f"Importação concluída: {created} item(ns) criado(s) e "
                            f"{updated} atualizado(s)."
                        )
                    else:
                        raise ValueError("Ação inválida.")
            except Exception as exc:
                db.rollback()
                erro = str(exc)
                current_app.logger.exception("Erro no admin de itens parados")

            filter_emp = norm_emp(request.args.get("f_emp"))
            filter_code = _clean_code(request.args.get("f_codigo"))
            filter_status = (request.args.get("f_status") or "ativos").strip().lower()
            page = max(int(request.args.get("page") or 1), 1)
            limit = 150
            query = db.query(ItemParado)
            if filter_emp:
                query = query.filter(ItemParado.emp == filter_emp)
            if filter_code:
                query = query.filter(ItemParado.codigo.ilike(f"%{filter_code}%"))
            if filter_status == "ativos":
                query = query.filter(ItemParado.ativo.is_(True))
            elif filter_status == "inativos":
                query = query.filter(ItemParado.ativo.is_(False))
            total_items = query.count()
            items = (
                query.order_by(ItemParado.emp.asc(), ItemParado.codigo.asc())
                .offset((page - 1) * limit)
                .limit(limit)
                .all()
            )
            total_pages = max((total_items + limit - 1) // limit, 1)
            emp_options = sorted(
                {
                    str(row[0]).strip()
                    for row in db.query(ItemParado.emp).distinct().all()
                    if row and row[0]
                },
                key=emp_sort_key,
            )

            today = date.today()
            ano_vendas = int(request.args.get("ano_vendas") or today.year)
            mes_vendas = int(request.args.get("mes_vendas") or today.month)
            sales_batch = latest_batch(db, ano_vendas, mes_vendas)
            sales_warnings = batch_warnings(sales_batch)
            sales_rows = (
                db.query(ItensParadosVendaUsuario)
                .filter(
                    ItensParadosVendaUsuario.ano == ano_vendas,
                    ItensParadosVendaUsuario.mes == mes_vendas,
                )
                .order_by(
                    ItensParadosVendaUsuario.emp.asc(),
                    ItensParadosVendaUsuario.valor_total.desc(),
                )
                .limit(200)
                .all()
            )

        return render_template(
            "admin_itens_parados.html",
            usuario=usuario_logado_fn(),
            role=(session.get("role") or ""),
            itens=items,
            erro=erro,
            ok=ok,
            avisos_acao=avisos_acao,
            filtro_emp=filter_emp,
            filtro_codigo=filter_code,
            filtro_status=filter_status,
            pagina=page,
            total_paginas=total_pages,
            total_itens=total_items,
            emps_options=emp_options,
            ano_vendas=ano_vendas,
            mes_vendas=mes_vendas,
            sales_batch=sales_batch,
            sales_warnings=sales_warnings,
            sales_rows=sales_rows,
        )

    def admin_itens_parados_modelo():
        red = login_required_fn()
        if red:
            return red
        red = admin_required_fn()
        if red:
            return red
        return send_file(
            _create_model_workbook(),
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
