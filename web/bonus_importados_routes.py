# -*- coding: utf-8 -*-
"""Importação e consulta do snapshot mensal da aba ``BONUS FINAL``.

A planilha continua responsável por todas as regras e cálculos. O SistemaVendas
apenas lê as colunas autorizadas para cada função, grava os valores prontos e
aplica a hierarquia de visualização:

* vendedor: somente os próprios dados;
* mecânico: somente os próprios dados;
* gerente: os próprios dados e os vendedores/mecânicos das EMPs vinculadas;
* administrador: todos os registros e a importação da competência.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections import defaultdict
from datetime import date, datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from io import BytesIO
from typing import Any

from flask import current_app, flash, redirect, render_template, request, session, url_for
from sqlalchemy import or_
from werkzeug.utils import secure_filename

from auth_helpers import _allowed_emps, _login_required, _role, _usuario_logado
from db import (
    BonusImportacaoLote,
    BonusUsuarioImportado,
    SessionLocal,
    Usuario,
    UsuarioEmp,
    ensure_bonus_importados_schema,
    ensure_itens_parados_snapshot_schema,
    ensure_bonus_outros_valores_schema,
)
from security_utils import audit, normalize_role
from sv_utils import business_today, emp_sort_key
from itens_parados_snapshot import attach_saldos_to_bonus_rows
from bonus_outros_valores import attach_outros_valores_to_bonus_rows, bonus_row_options


MAX_UPLOAD_BYTES = 15 * 1024 * 1024
VALID_EXTENSIONS = {".xlsx", ".xlsm"}
SUPPORTED_FUNCTIONS = {"VENDEDOR", "GERENTE", "MECANICO"}

# Posições fixas informadas para a nova aba BONUS FINAL. A validação da letra e
# do cabeçalho impede que uma coluna movida seja importada como outra métrica.
COLUMN_LAYOUT: dict[str, dict[str, Any]] = {
    "funcao": {"index": 1, "letter": "B", "headers": {"FUNCAO"}, "label": "FUNÇÃO"},
    "emp": {"index": 2, "letter": "C", "headers": {"EMP"}, "label": "EMP"},
    "usuario_nome": {
        "index": 3,
        "letter": "D",
        "headers": {"FUNCIONARIO", "USUARIO", "VENDEDOR"},
        "label": "FUNCIONARIO",
    },
    "produto_vendedor": {
        "index": 4,
        "letter": "E",
        "headers": {"PRODUTOVENDEDOR", "PRODUTOSVENDEDOR"},
        "label": "PRODUTO VENDEDOR",
    },
    "mecanico_faturado": {
        "index": 5,
        "letter": "F",
        "headers": {"MECANICO"},
        "label": "MECANICO",
    },
    "venda_anterior": {
        "index": 6,
        "letter": "G",
        "headers": {"VENDAANTERIOR"},
        "label": "VENDA ANTERIOR",
    },
    "venda_atual": {
        "index": 7,
        "letter": "H",
        "headers": {"VENDAATUAL"},
        "label": "VENDA ATUAL",
    },
    "crescimento": {
        "index": 8,
        "letter": "I",
        "headers": {"CRESCIMENTO"},
        "label": "CRESCIMENTO",
    },
    "loja_anterior": {
        "index": 9,
        "letter": "J",
        "headers": {"LOJAANTERIOR"},
        "label": "LOJA ANTERIOR",
    },
    "loja_atual": {
        "index": 10,
        "letter": "K",
        "headers": {"LOJAATUAL"},
        "label": "LOJA ATUAL",
    },
    "produto_gerente": {
        "index": 12,
        "letter": "M",
        "headers": {"PRODUTOGERENTE", "PRODUTOSGERENTE"},
        "label": "PRODUTO GERENTE",
    },
    "importado_vendedor": {
        "index": 13,
        "letter": "N",
        "headers": {"IMPORTADOVENDEDOR"},
        "label": "IMPORTADO VENDEDOR",
    },
    "importado_loja": {
        "index": 14,
        "letter": "O",
        "headers": {"IMPORTADOLOJA"},
        "label": "IMPORTADO LOJA",
    },
    "bonus_importado": {
        "index": 17,
        "letter": "R",
        "headers": {"BONUSIMPORTADO"},
        "label": "BONUS IMPORTADO",
    },
    "valor_meta": {
        "index": 19,
        "letter": "T",
        "headers": {"VALORMETA"},
        "label": "VALOR META",
    },
    "valor_parcial": {
        "index": 20,
        "letter": "U",
        "headers": {"VALORPARCIAL"},
        "label": "VALOR PARCIAL",
    },
    "bonus_final": {
        "index": 21,
        "letter": "V",
        "headers": {"VALORFINAL", "BONUSFINAL"},
        "label": "VALOR FINAL",
    },
}

ROLE_FIELDS = {
    "VENDEDOR": (
        "produto_vendedor",
        "venda_anterior",
        "venda_atual",
        "crescimento",
        "importado_vendedor",
        "bonus_importado",
        "valor_meta",
        "valor_parcial",
        "bonus_final",
    ),
    "GERENTE": (
        # Alguns gerentes também realizam vendas próprias. A coluna E deve ser
        # preservada junto aos valores agregados da loja.
        "produto_vendedor",
        "loja_anterior",
        "loja_atual",
        "produto_gerente",
        "importado_loja",
        "bonus_importado",
        "valor_meta",
        "valor_parcial",
        "bonus_final",
    ),
    "MECANICO": (
        "mecanico_faturado",
        "valor_parcial",
        "bonus_final",
    ),
}

MONEY_FIELDS = {
    "produto_vendedor",
    "produto_gerente",
    "mecanico_faturado",
    "venda_anterior",
    "venda_atual",
    "loja_anterior",
    "loja_atual",
    "importado_vendedor",
    "importado_loja",
    "bonus_importado",
    "valor_meta",
    "valor_parcial",
    "bonus_final",
}
PERCENT_FIELDS = {"crescimento"}
ALL_IMPORTED_FIELDS = MONEY_FIELDS | PERCENT_FIELDS
REQUIRED_CALCULATED_FIELDS = {"valor_parcial", "bonus_final"}
ROLE_SORT_ORDER = {"GERENTE": 0, "VENDEDOR": 1, "MECANICO": 2}


def register_bonus_importados_routes(app) -> None:
    # URL canônica do módulo de varejo. O endpoint é preservado para não quebrar
    # templates e redirecionamentos existentes.
    app.add_url_rule(
        "/bonus-varejo",
        endpoint="bonus_importados",
        view_func=bonus_importados,
        methods=["GET"],
    )

    # Compatibilidade com favoritos e links antigos.
    def _bonus_legacy_redirect():
        return redirect(url_for("bonus_importados", **request.args.to_dict(flat=True)))

    app.add_url_rule(
        "/bonus",
        endpoint="bonus_importados_legacy",
        view_func=_bonus_legacy_redirect,
        methods=["GET"],
    )
    app.add_url_rule(
        "/admin/bonus/importar",
        endpoint="admin_bonus_importar",
        view_func=admin_bonus_importar,
        methods=["POST"],
    )


def _strip_accents(value: object) -> str:
    raw = str(value or "")
    return "".join(
        ch for ch in unicodedata.normalize("NFKD", raw) if not unicodedata.combining(ch)
    )


def _norm_header(value: object) -> str:
    raw = _strip_accents(value).strip().upper().replace("%", " PERCENTUAL ")
    return re.sub(r"[^A-Z0-9]", "", raw)


def _norm_username(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).upper()


def _norm_function(value: object) -> str:
    raw = re.sub(r"\s+", " ", _strip_accents(value).strip()).upper()
    aliases = {
        "MEC": "MECANICO",
        "OFICINA": "MECANICO",
        "VENDEDORA": "VENDEDOR",
        "GERENCIA": "GERENTE",
        "MANAGER": "GERENTE",
    }
    return aliases.get(raw, raw)


def _norm_emp(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value).upper()
    if isinstance(value, (int, float, Decimal)):
        try:
            number = Decimal(str(value))
            if number == number.to_integral_value():
                return str(int(number))
        except Exception:
            pass
    raw = str(value).strip()
    if re.fullmatch(r"[+-]?\d+[.,]0+", raw):
        return raw.split(".", 1)[0].split(",", 1)[0]
    return raw.upper()


def _decimal_from_cell(
    cell,
    *,
    field: str,
    is_percent: bool,
) -> Decimal | None:
    value = cell.value
    if getattr(cell, "data_type", None) == "e" or (
        isinstance(value, str) and value.strip().startswith("#")
    ):
        raise ValueError(f"erro do Excel ({value})")

    if value is None or (isinstance(value, str) and not value.strip()):
        if field in REQUIRED_CALCULATED_FIELDS:
            raise ValueError(
                "sem valor calculado; abra a planilha no Excel, recalcule e salve antes de importar"
            )
        return None if is_percent else Decimal("0")

    had_percent_symbol = False
    if isinstance(value, str):
        raw = value.strip()
        had_percent_symbol = "%" in raw
        raw = raw.replace("R$", "").replace("%", "").replace(" ", "")
        if not raw:
            return None if is_percent else Decimal("0")
        if "," in raw:
            raw = raw.replace(".", "").replace(",", ".")
        elif raw.count(".") > 1:
            raw = raw.replace(".", "")
        value = raw

    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError(f"valor numérico inválido ({value})") from exc
    if not result.is_finite():
        raise ValueError(f"valor numérico inválido ({value})")

    number_format = str(getattr(cell, "number_format", "") or "")
    if is_percent and not had_percent_symbol and "%" in number_format:
        # O Excel armazena 10% como 0,10. No banco persistimos 10,000000.
        result *= Decimal("100")

    quantum = Decimal("0.000001") if is_percent else Decimal("0.0001")
    return result.quantize(quantum, rounding=ROUND_HALF_UP)


def _find_final_bonus_sheet(workbook):
    for sheet in workbook.worksheets:
        if _norm_header(sheet.title) == "BONUSFINAL":
            return sheet
    available = ", ".join(sheet.title for sheet in workbook.worksheets)
    raise ValueError(
        "A aba 'BONUS FINAL' não foi encontrada. Abas disponíveis: " + available
    )


def _find_header(sheet) -> tuple[int, dict[str, int]]:
    max_index = max(int(config["index"]) for config in COLUMN_LAYOUT.values())
    best_row = 1
    best_score = -1
    best_cells: list[Any] = []

    for row_number, cells_tuple in enumerate(
        sheet.iter_rows(min_row=1, max_row=min(sheet.max_row or 1, 30), max_col=max_index + 1),
        start=1,
    ):
        cells = list(cells_tuple)
        score = 0
        for config in COLUMN_LAYOUT.values():
            index = int(config["index"])
            value = cells[index].value if index < len(cells) else None
            if _norm_header(value) in config["headers"]:
                score += 1
        if score > best_score:
            best_row, best_score, best_cells = row_number, score, cells
        if score == len(COLUMN_LAYOUT):
            return row_number, {
                field: int(config["index"]) for field, config in COLUMN_LAYOUT.items()
            }

    mismatches = []
    for config in COLUMN_LAYOUT.values():
        index = int(config["index"])
        found = best_cells[index].value if index < len(best_cells) else None
        if _norm_header(found) not in config["headers"]:
            mismatches.append(
                f"{config['letter']} deveria ser '{config['label']}' (encontrado: {found or 'vazio'})"
            )
    detail = "; ".join(mismatches[:8])
    raise ValueError(
        "O cabeçalho da aba BONUS FINAL não corresponde ao layout combinado. " + detail
    )


def _read_bonus_workbook(content: bytes) -> dict[str, Any]:
    try:
        from openpyxl import load_workbook
    except Exception as exc:  # pragma: no cover - depende do ambiente do deploy
        raise RuntimeError(
            "A biblioteca openpyxl não está disponível no servidor. Inclua openpyxl nas dependências."
        ) from exc

    try:
        workbook = load_workbook(
            filename=BytesIO(content),
            read_only=True,
            data_only=True,
            keep_links=False,
        )
    except Exception as exc:
        raise ValueError("Não foi possível abrir o arquivo Excel enviado.") from exc

    try:
        sheet = _find_final_bonus_sheet(workbook)
        header_row, mapping = _find_header(sheet)

        records: list[dict[str, Any]] = []
        warnings: list[str] = []
        duplicate_keys: dict[tuple[str, str], int] = {}
        rows_read = 0
        rows_skipped = 0

        for source_row, cells_tuple in enumerate(
            sheet.iter_rows(min_row=header_row + 1, max_col=22), start=header_row + 1
        ):
            cells = list(cells_tuple)
            identity_values = [
                cells[mapping[field]].value for field in ("funcao", "emp", "usuario_nome")
            ]
            if not any(value not in (None, "") for value in identity_values):
                continue

            rows_read += 1
            username = _norm_username(cells[mapping["usuario_nome"]].value)
            function = _norm_function(cells[mapping["funcao"]].value)
            emp = _norm_emp(cells[mapping["emp"]].value)

            identity_missing = []
            if not username:
                identity_missing.append("usuário")
            if not function:
                identity_missing.append("função")
            if not emp:
                identity_missing.append("EMP")
            if identity_missing:
                rows_skipped += 1
                warnings.append(
                    f"Linha {source_row} ignorada: sem {', '.join(identity_missing)}."
                )
                continue

            if function not in SUPPORTED_FUNCTIONS:
                rows_skipped += 1
                warnings.append(
                    f"Linha {source_row} ignorada: função '{function}' não é VENDEDOR, GERENTE ou MECANICO."
                )
                continue

            record: dict[str, Any] = {
                "linha_origem": source_row,
                "usuario_nome": username,
                "funcao": function,
                "emp": emp,
            }
            for field in MONEY_FIELDS:
                record[field] = Decimal("0")
            for field in PERCENT_FIELDS:
                record[field] = None

            numeric_error = None
            for field in ROLE_FIELDS[function]:
                try:
                    record[field] = _decimal_from_cell(
                        cells[mapping[field]],
                        field=field,
                        is_percent=(field in PERCENT_FIELDS),
                    )
                except ValueError as exc:
                    if field == "crescimento":
                        # Crescimento pode ficar indisponível quando a venda anterior é zero.
                        # Mantemos o usuário e exibimos "não disponível" em vez de inventar 0%.
                        record[field] = None
                        warnings.append(
                            f"Linha {source_row}: Crescimento não disponível para {username} ({exc})."
                        )
                        continue
                    numeric_error = f"coluna {COLUMN_LAYOUT[field]['letter']} ({COLUMN_LAYOUT[field]['label']}): {exc}"
                    break

            if numeric_error:
                rows_skipped += 1
                warnings.append(f"Linha {source_row} ignorada: {numeric_error}.")
                continue

            key = (emp, username)
            if key in duplicate_keys:
                first_row = duplicate_keys[key]
                raise ValueError(
                    f"Duplicidade na aba BONUS FINAL: usuário {username}, EMP {emp}, "
                    f"linhas {first_row} e {source_row}."
                )
            duplicate_keys[key] = source_row
            records.append(record)

        if not records:
            raise ValueError("Nenhuma linha válida foi encontrada na aba BONUS FINAL.")

        return {
            "records": records,
            "warnings": warnings,
            "rows_read": rows_read,
            "rows_skipped": rows_skipped,
        }
    finally:
        workbook.close()


def _role_from_function(function: str) -> str:
    return {
        "VENDEDOR": "vendedor",
        "GERENTE": "gerente",
        "MECANICO": "mecanico",
    }.get(function, function.lower())


def _bind_users_and_validate(db, records: list[dict[str, Any]], warnings: list[str]) -> None:
    users = db.query(Usuario).all()
    users_by_name = {_norm_username(user.username): user for user in users}
    links = db.query(UsuarioEmp).filter(UsuarioEmp.ativo.is_(True)).all()
    emps_by_user: dict[int, set[str]] = defaultdict(set)
    for link in links:
        emps_by_user[int(link.usuario_id)].add(_norm_emp(link.emp))

    for record in records:
        user = users_by_name.get(record["usuario_nome"])
        if user is None:
            record["usuario_id"] = None
            warnings.append(
                f"Linha {record['linha_origem']}: usuário {record['usuario_nome']} ainda não está cadastrado no sistema."
            )
            continue

        record["usuario_id"] = user.id
        current_role = normalize_role(getattr(user, "role", None))
        sheet_role = _role_from_function(record["funcao"])
        if current_role != sheet_role:
            warnings.append(
                f"Linha {record['linha_origem']}: função da planilha ({record['funcao']}) difere do cadastro ({current_role.upper()})."
            )

        allowed = set(emps_by_user.get(int(user.id), set()))
        legacy_emp = _norm_emp(getattr(user, "emp", None))
        if legacy_emp:
            allowed.add(legacy_emp)
        if allowed and record["emp"] not in allowed:
            warnings.append(
                f"Linha {record['linha_origem']}: EMP {record['emp']} não está vinculada ao usuário {record['usuario_nome']}."
            )


def _safe_period(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(str(value).strip())
    except Exception:
        return default
    return max(minimum, min(maximum, parsed))


def admin_bonus_importar():
    red = _login_required()
    if red:
        return red
    if _role() != "admin":
        flash("Acesso restrito ao administrador.", "warning")
        return redirect(url_for("bonus_importados"))

    today = business_today()
    ano = _safe_period(request.form.get("ano"), today.year, 2000, 2100)
    mes = _safe_period(request.form.get("mes"), today.month, 1, 12)
    uploaded = request.files.get("arquivo")

    if uploaded is None or not uploaded.filename:
        flash("Selecione a planilha que contém a aba BONUS FINAL.", "warning")
        return redirect(url_for("bonus_importados", ano=ano, mes=mes))

    filename = secure_filename(uploaded.filename) or "bonus_final.xlsx"
    extension = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if extension not in VALID_EXTENSIONS:
        flash("Envie um arquivo .xlsx ou .xlsm.", "warning")
        return redirect(url_for("bonus_importados", ano=ano, mes=mes))

    content = uploaded.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        flash("A planilha excede o limite de 15 MB.", "danger")
        return redirect(url_for("bonus_importados", ano=ano, mes=mes))
    if not content:
        flash("O arquivo enviado está vazio.", "warning")
        return redirect(url_for("bonus_importados", ano=ano, mes=mes))

    try:
        parsed = _read_bonus_workbook(content)
        ensure_bonus_importados_schema()

        username = _norm_username(_usuario_logado())
        user_id = session.get("user_id")
        imported_at = datetime.utcnow()
        warnings = list(parsed["warnings"])

        with SessionLocal() as db:
            _bind_users_and_validate(db, parsed["records"], warnings)

            # Substituição atômica: uma falha preserva a competência anterior.
            db.query(BonusUsuarioImportado).filter(
                BonusUsuarioImportado.ano == ano,
                BonusUsuarioImportado.mes == mes,
            ).delete(synchronize_session=False)

            batch = BonusImportacaoLote(
                ano=ano,
                mes=mes,
                arquivo_origem=filename,
                importado_por_user_id=int(user_id) if user_id else None,
                importado_por=username,
                importado_em=imported_at,
                linhas_lidas=int(parsed["rows_read"]),
                linhas_importadas=len(parsed["records"]),
                linhas_ignoradas=int(parsed["rows_skipped"]),
                avisos_json=json.dumps(warnings, ensure_ascii=False),
            )
            db.add(batch)
            db.flush()

            rows = []
            for record in parsed["records"]:
                payload = {
                    **record,
                    "lote_id": batch.id,
                    "ano": ano,
                    "mes": mes,
                    "importado_em": imported_at,
                }
                rows.append(BonusUsuarioImportado(**payload))
            db.add_all(rows)
            db.commit()

        audit(
            "bonus_final_snapshot_imported",
            ano=ano,
            mes=mes,
            arquivo=filename,
            linhas=len(parsed["records"]),
            ignoradas=parsed["rows_skipped"],
            avisos=len(warnings),
        )
        flash(
            f"BONUS FINAL de {mes:02d}/{ano} importado: {len(parsed['records'])} usuários. "
            f"Linhas ignoradas: {parsed['rows_skipped']}.",
            "success",
        )
        if warnings:
            flash(
                f"A importação terminou com {len(warnings)} aviso(s). Consulte a validação da última importação.",
                "warning",
            )
    except Exception as exc:
        current_app.logger.exception("Falha ao importar aba BONUS FINAL")
        audit(
            "bonus_final_snapshot_import_failed",
            ano=ano,
            mes=mes,
            arquivo=filename,
            erro=str(exc),
        )
        flash(f"Não foi possível importar a planilha: {exc}", "danger")

    return redirect(url_for("bonus_importados", ano=ano, mes=mes))


def _sum_field(rows: list[BonusUsuarioImportado], field: str) -> Decimal:
    total = Decimal("0")
    for row in rows:
        value = getattr(row, field, None)
        if value is not None:
            total += Decimal(str(value))
    return total


def _period_options(db) -> list[tuple[int, int]]:
    rows = (
        db.query(BonusUsuarioImportado.ano, BonusUsuarioImportado.mes)
        .distinct()
        .order_by(BonusUsuarioImportado.ano.desc(), BonusUsuarioImportado.mes.desc())
        .all()
    )
    return [(int(row[0]), int(row[1])) for row in rows]


def _load_warnings(batch: BonusImportacaoLote | None) -> list[str]:
    if not batch or not batch.avisos_json:
        return []
    try:
        value = json.loads(batch.avisos_json)
        return [str(item) for item in value] if isinstance(value, list) else []
    except Exception:
        return []


def bonus_importados():
    red = _login_required()
    if red:
        return red

    try:
        ensure_bonus_importados_schema()
    except Exception:
        current_app.logger.exception("Falha ao garantir schema de bônus")
        flash(
            "As tabelas/colunas do módulo de bônus ainda não estão disponíveis. Execute o SQL de implantação no Supabase.",
            "danger",
        )
        return render_template(
            "bonus_importados.html",
            role=_role(),
            ano=business_today().year,
            mes=business_today().month,
            rows=[],
            own_rows=[],
            team_rows=[],
            seller_rows=[],
            manager_rows=[],
            mechanic_rows=[],
            selected=None,
            periods=[],
            emp_options=[],
            user_options=[],
            summary={},
            batch=None,
            batch_warnings=[],
            team_by_emp=[],
            admin_user_options=[],
            db_unavailable=True,
        )

    role = _role()
    current_username = _norm_username(_usuario_logado())
    today = business_today()

    with SessionLocal() as db:
        periods = _period_options(db)
        default_year, default_month = today.year, today.month
        ano = _safe_period(request.args.get("ano"), default_year, 2000, 2100)
        mes = _safe_period(request.args.get("mes"), default_month, 1, 12)

        period_query = db.query(BonusUsuarioImportado).filter(
            BonusUsuarioImportado.ano == ano,
            BonusUsuarioImportado.mes == mes,
        )

        all_period_rows = period_query.all() if role == "admin" else []
        emp_filter = _norm_emp(request.args.get("emp")) if role == "admin" else ""
        user_filter = _norm_username(request.args.get("usuario")) if role == "admin" else ""

        if role == "admin":
            query = period_query
            if emp_filter:
                query = query.filter(BonusUsuarioImportado.emp == emp_filter)
            if user_filter:
                query = query.filter(BonusUsuarioImportado.usuario_nome == user_filter)
            rows = query.all()
            emp_options = sorted(
                {row.emp for row in all_period_rows if row.emp}, key=emp_sort_key
            )
            user_options = sorted(
                {row.usuario_nome for row in all_period_rows if row.usuario_nome}
            )
        elif role == "gerente":
            allowed_emps = sorted(
                {_norm_emp(emp) for emp in _allowed_emps() if _norm_emp(emp)},
                key=emp_sort_key,
            )
            if allowed_emps:
                rows = (
                    period_query.filter(BonusUsuarioImportado.emp.in_(allowed_emps))
                    .filter(
                        or_(
                            BonusUsuarioImportado.usuario_nome == current_username,
                            BonusUsuarioImportado.funcao.in_(["VENDEDOR", "MECANICO"]),
                        )
                    )
                    .all()
                )
            else:
                rows = period_query.filter(
                    BonusUsuarioImportado.usuario_nome == current_username
                ).all()
            emp_options = []
            user_options = []
        else:
            # Vendedor e mecânico jamais recebem registros de outro usuário.
            rows = period_query.filter(
                BonusUsuarioImportado.usuario_nome == current_username
            ).all()
            emp_options = []
            user_options = []

        rows.sort(
            key=lambda row: (
                emp_sort_key(row.emp),
                ROLE_SORT_ORDER.get(row.funcao, 99),
                row.usuario_nome,
            )
        )
        try:
            ensure_itens_parados_snapshot_schema()
            itens_parados_summary = attach_saldos_to_bonus_rows(
                db, rows, ano=ano, mes=mes
            )
        except Exception:
            current_app.logger.exception(
                "Falha ao carregar saldo de itens parados no Bônus Varejo"
            )
            itens_parados_summary = {
                "total_visivel": Decimal("0"),
                "total_lojas": Decimal("0"),
            }
            for row in rows:
                row.saldo_itens_parados = Decimal("0")
                row.saldo_itens_parados_usuario = Decimal("0")
                row.saldo_itens_parados_loja = Decimal("0")

        try:
            ensure_bonus_outros_valores_schema()
            outros_valores_summary = attach_outros_valores_to_bonus_rows(
                db,
                rows,
                ano=ano,
                mes=mes,
                origem="VAREJO",
                bonus_field="bonus_final",
            )
        except Exception:
            current_app.logger.exception(
                "Falha ao carregar Outros Valores no Bônus Varejo"
            )
            outros_valores_summary = {
                "total_visivel": Decimal("0"),
                "quantidade": 0,
            }
            for row in rows:
                row.outros_valores_total = Decimal("0")
                row.outros_valores_detalhes = []
                row.valor_bonus_base = Decimal(str(row.bonus_final or 0))
                row.total_geral = row.valor_bonus_base + Decimal(
                    str(getattr(row, "saldo_itens_parados", 0) or 0)
                )

        seller_rows = [row for row in rows if row.funcao == "VENDEDOR"]
        manager_rows = [row for row in rows if row.funcao == "GERENTE"]
        mechanic_rows = [row for row in rows if row.funcao == "MECANICO"]
        own_rows = [row for row in rows if row.usuario_nome == current_username]
        team_rows = []
        if role == "gerente":
            team_rows = [
                row
                for row in rows
                if row.usuario_nome != current_username
                and row.funcao in {"VENDEDOR", "MECANICO"}
            ]

        selected_id = request.args.get("registro", type=int)
        detail_candidates = rows if role in {"admin", "gerente"} else own_rows
        selected = next(
            (row for row in detail_candidates if selected_id and row.id == selected_id),
            None,
        )
        if selected is None and detail_candidates:
            selected = next(
                (row for row in detail_candidates if row.usuario_nome == current_username),
                detail_candidates[0],
            )

        batch = (
            db.query(BonusImportacaoLote)
            .filter(BonusImportacaoLote.ano == ano, BonusImportacaoLote.mes == mes)
            .order_by(BonusImportacaoLote.importado_em.desc(), BonusImportacaoLote.id.desc())
            .first()
        )
        batch_warnings = _load_warnings(batch)

        team_by_emp_map: dict[str, dict[str, Any]] = {}
        for row in team_rows:
            item = team_by_emp_map.setdefault(
                row.emp,
                {
                    "emp": row.emp,
                    "quantidade": 0,
                    "valor_parcial": Decimal("0"),
                    "bonus_final": Decimal("0"),
                    "itens_parados": Decimal("0"),
                    "outros_valores": Decimal("0"),
                    "total_geral": Decimal("0"),
                },
            )
            item["quantidade"] += 1
            item["valor_parcial"] += Decimal(str(row.valor_parcial or 0))
            item["bonus_final"] += Decimal(str(row.bonus_final or 0))
            item["itens_parados"] += Decimal(
                str(getattr(row, "saldo_itens_parados_usuario", 0) or 0)
            )
            item["outros_valores"] += Decimal(
                str(getattr(row, "outros_valores_total", 0) or 0)
            )
            item["total_geral"] += (
                Decimal(str(row.bonus_final or 0))
                + Decimal(str(getattr(row, "saldo_itens_parados_usuario", 0) or 0))
                + Decimal(str(getattr(row, "outros_valores_total", 0) or 0))
            )
        team_by_emp = sorted(
            team_by_emp_map.values(), key=lambda item: emp_sort_key(item["emp"])
        )

        bonus_visivel = _sum_field(rows, "bonus_final")
        bonus_proprio = _sum_field(own_rows, "bonus_final")
        bonus_equipe = _sum_field(team_rows, "bonus_final")
        outros_proprio = sum(
            (Decimal(str(getattr(row, "outros_valores_total", 0) or 0)) for row in own_rows),
            Decimal("0"),
        )
        outros_equipe = sum(
            (Decimal(str(getattr(row, "outros_valores_total", 0) or 0)) for row in team_rows),
            Decimal("0"),
        )
        itens_proprio = sum(
            (Decimal(str(getattr(row, "saldo_itens_parados", 0) or 0)) for row in own_rows),
            Decimal("0"),
        )
        itens_equipe = sum(
            (Decimal(str(getattr(row, "saldo_itens_parados_usuario", 0) or 0)) for row in team_rows),
            Decimal("0"),
        )
        summary = {
            "registros": len(rows),
            "valor_parcial_visivel": _sum_field(rows, "valor_parcial"),
            "bonus_visivel": bonus_visivel,
            "bonus_vendedores": _sum_field(seller_rows, "bonus_final"),
            "bonus_gerentes": _sum_field(manager_rows, "bonus_final"),
            "bonus_mecanicos": _sum_field(mechanic_rows, "bonus_final"),
            "valor_parcial_proprio": _sum_field(own_rows, "valor_parcial"),
            "bonus_proprio": bonus_proprio,
            "valor_parcial_equipe": _sum_field(team_rows, "valor_parcial"),
            "bonus_equipe": bonus_equipe,
            "quantidade_equipe": len(team_rows),
            "itens_parados_visivel": itens_parados_summary["total_visivel"],
            "itens_parados_lojas": itens_parados_summary["total_lojas"],
            "outros_valores_visivel": outros_valores_summary["total_visivel"],
            "outros_valores_proprio": outros_proprio,
            "outros_valores_equipe": outros_equipe,
            "total_geral_visivel": (
                bonus_visivel
                + itens_parados_summary["total_visivel"]
                + outros_valores_summary["total_visivel"]
            ),
            "total_geral_proprio": bonus_proprio + itens_proprio + outros_proprio,
            "total_geral_equipe": bonus_equipe + itens_equipe + outros_equipe,
            "nao_vinculados": sum(1 for row in rows if row.usuario_id is None),
        }
        admin_user_options = bonus_row_options(all_period_rows) if role == "admin" else []

        return render_template(
            "bonus_importados.html",
            role=role,
            ano=ano,
            mes=mes,
            rows=rows,
            own_rows=own_rows,
            team_rows=team_rows,
            seller_rows=seller_rows,
            manager_rows=manager_rows,
            mechanic_rows=mechanic_rows,
            selected=selected,
            periods=periods,
            emp_options=emp_options,
            user_options=user_options,
            emp_filter=emp_filter,
            user_filter=user_filter,
            summary=summary,
            batch=batch,
            batch_warnings=batch_warnings,
            team_by_emp=team_by_emp,
            admin_user_options=admin_user_options,
            db_unavailable=False,
        )
