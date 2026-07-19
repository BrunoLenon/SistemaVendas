# -*- coding: utf-8 -*-
"""Página e importação do snapshot mensal de bônus.

A aba ``Final Bonus`` continua sendo calculada fora do SistemaVendas. Este
módulo apenas valida os valores salvos no Excel, substitui de forma atômica a
competência escolhida e controla quais linhas cada perfil pode consultar.
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
)
from security_utils import audit, normalize_role
from sv_utils import emp_sort_key


MAX_UPLOAD_BYTES = 15 * 1024 * 1024
VALID_EXTENSIONS = {".xlsx", ".xlsm"}

MONEY_FIELDS = {
    "importado",
    "faturamento_individual_anterior",
    "faturamento_individual_atual",
    "final_vendedor",
    "final_gerente",
    "valor_meta",
    "bonus_gerente_total",
    "bonus_importado_vendedor",
    "importado_loja",
    "bonus_importado_loja",
    "meta_loja",
    "venda_loja_atual",
    "bonus_gerente",
    "bonus_final",
}

PERCENT_FIELDS = {
    "percentual_faturamento",
    "percentual_meta",
    "percentual_importado",
    "percentual_bonus_importado_vendedor",
    "percentual_importado_gerente",
    "percentual_bonus_importado_loja",
    "crescimento_loja",
    "percentual_crescimento",
}

HEADER_ALIASES = {
    # Identificação
    "TABFUNCIONARIOFUNCAO": "funcao",
    "FUNCAO": "funcao",
    "VENDEDOR": "usuario_nome",
    "USUARIO": "usuario_nome",
    "NOMEDOUSUARIO": "usuario_nome",
    "TABFUNCIONARIOEMP": "emp",
    "EMP": "emp",
    "EMPRESA": "emp",
    # Individual / produtos
    "IMPORTADO": "importado",
    "FATURAMENTOANTATUALVALORINDIVIDUALANTERIOR": "faturamento_individual_anterior",
    "VALORINDIVIDUALANTERIOR": "faturamento_individual_anterior",
    "FATURAMENTOANTATUALVALORINDIVIDUALATUAL": "faturamento_individual_atual",
    "VALORINDIVIDUALATUAL": "faturamento_individual_atual",
    "FINALVENDEDOR": "final_vendedor",
    "FINALGERENTE": "final_gerente",
    # Meta individual
    "PERCENTUALFATURAMENTO": "percentual_faturamento",
    "PERCENTUALMETA": "percentual_meta",
    "VALORMETA": "valor_meta",
    "BONUSGERENTETOTAL": "bonus_gerente_total",
    # Importados vendedor
    "PERCENTUALIMPORTADO": "percentual_importado",
    "PERCENTUALBONUSIMPORTADOVENDEDOR": "percentual_bonus_importado_vendedor",
    "BONUSIMPORTADOVENDEDOR": "bonus_importado_vendedor",
    "BONUSIMPORTADOVENDDOR": "bonus_importado_vendedor",  # compatibilidade com a planilha atual
    # Importados loja / gerente
    "IMPORTADOLOJA": "importado_loja",
    "PERCENTUALIMPORTADOGERENTE": "percentual_importado_gerente",
    "PERCENTUALBONUSIMPORTADOLOJA": "percentual_bonus_importado_loja",
    "BONUSIMPORTADOLOJA": "bonus_importado_loja",
    # Loja / gerente
    "METALOJA": "meta_loja",
    "VENDALOJAATUAL": "venda_loja_atual",
    "CRESCIMENTOLOJA": "crescimento_loja",
    "PERCENTUALCRESCIMENTO": "percentual_crescimento",
    "BONUSGERENTE": "bonus_gerente",
    "BONUSFINAL": "bonus_final",
}

REQUIRED_FIELDS = {"funcao", "usuario_nome", "emp"}
KNOWN_FUNCTIONS = {"VENDEDOR", "GERENTE", "MECANICO", "SUPERVISOR"}


def register_bonus_importados_routes(app) -> None:
    app.add_url_rule(
        "/bonus",
        endpoint="bonus_importados",
        view_func=bonus_importados,
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
        "MECANICO": "MECANICO",
        "MEC": "MECANICO",
        "OFICINA": "MECANICO",
        "VENDEDORA": "VENDEDOR",
        "GERENCIA": "GERENTE",
        "MANAGER": "GERENTE",
        "SUP": "SUPERVISOR",
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


def _decimal_from_cell(cell, *, field: str, is_percent: bool) -> Decimal:
    value = cell.value
    if getattr(cell, "data_type", None) == "e" or (
        isinstance(value, str) and value.strip().startswith("#")
    ):
        raise ValueError(f"erro do Excel ({value})")

    if value is None and field == "bonus_final":
        raise ValueError(
            "sem valor calculado; abra a planilha no Excel, recalcule e salve antes de importar"
        )
    if value is None or (isinstance(value, str) and not value.strip()):
        return Decimal("0")

    had_percent_symbol = False
    if isinstance(value, str):
        raw = value.strip()
        had_percent_symbol = "%" in raw
        raw = raw.replace("R$", "").replace("%", "").replace(" ", "")
        if not raw:
            return Decimal("0")
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
    if is_percent and not had_percent_symbol:
        # O Excel armazena percentuais formatados como fração (0,15 = 15%).
        # A coluna Crescimento Loja da planilha atual também é uma razão, mas
        # está com formatação contábil; por isso ela precisa da mesma conversão.
        if "%" in number_format or field == "crescimento_loja":
            result *= Decimal("100")

    quantum = Decimal("0.000001") if is_percent else Decimal("0.0001")
    return result.quantize(quantum, rounding=ROUND_HALF_UP)


def _find_final_bonus_sheet(workbook):
    for sheet in workbook.worksheets:
        if _norm_header(sheet.title) == "FINALBONUS":
            return sheet
    available = ", ".join(sheet.title for sheet in workbook.worksheets)
    raise ValueError(
        "A aba 'Final Bonus' não foi encontrada. Abas disponíveis: " + available
    )


def _find_header(sheet) -> tuple[int, dict[str, int]]:
    best_row = None
    best_mapping: dict[str, int] = {}
    for row_number, cells in enumerate(
        sheet.iter_rows(min_row=1, max_row=min(sheet.max_row or 1, 30)), start=1
    ):
        mapping: dict[str, int] = {}
        for index, cell in enumerate(cells):
            field = HEADER_ALIASES.get(_norm_header(cell.value))
            if field and field not in mapping:
                mapping[field] = index
        if len(mapping) > len(best_mapping):
            best_row, best_mapping = row_number, mapping
        if REQUIRED_FIELDS.issubset(mapping) and len(mapping) >= 20:
            return row_number, mapping

    missing = sorted(REQUIRED_FIELDS - set(best_mapping))
    detail = f" Campos obrigatórios ausentes: {', '.join(missing)}." if missing else ""
    raise ValueError("Não foi possível reconhecer o cabeçalho da aba Final Bonus." + detail)


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
        missing_columns = sorted(
            ({"funcao", "usuario_nome", "emp"} | MONEY_FIELDS | PERCENT_FIELDS) - set(mapping)
        )
        if missing_columns:
            raise ValueError(
                "A aba Final Bonus não possui todas as colunas esperadas: "
                + ", ".join(missing_columns)
            )

        records: list[dict[str, Any]] = []
        warnings: list[str] = []
        duplicate_keys: dict[tuple[str, str], int] = {}
        rows_read = 0
        rows_skipped = 0

        for source_row, cells in enumerate(
            sheet.iter_rows(min_row=header_row + 1), start=header_row + 1
        ):
            relevant_cells = [cells[index] for index in mapping.values() if index < len(cells)]
            if not any(cell.value not in (None, "") for cell in relevant_cells):
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

            if function not in KNOWN_FUNCTIONS:
                warnings.append(
                    f"Linha {source_row}: função '{function}' não está entre os perfis padrão."
                )

            record: dict[str, Any] = {
                "linha_origem": source_row,
                "usuario_nome": username,
                "funcao": function,
                "emp": emp,
            }
            numeric_error = None
            for field in MONEY_FIELDS | PERCENT_FIELDS:
                try:
                    record[field] = _decimal_from_cell(
                        cells[mapping[field]],
                        field=field,
                        is_percent=(field in PERCENT_FIELDS),
                    )
                except ValueError as exc:
                    numeric_error = f"coluna {field}: {exc}"
                    break

            if numeric_error:
                rows_skipped += 1
                warnings.append(f"Linha {source_row} ignorada: {numeric_error}.")
                continue

            key = (emp, username)
            if key in duplicate_keys:
                first_row = duplicate_keys[key]
                raise ValueError(
                    f"Duplicidade na aba Final Bonus: usuário {username}, EMP {emp}, "
                    f"linhas {first_row} e {source_row}."
                )
            duplicate_keys[key] = source_row
            records.append(record)

        if not records:
            raise ValueError("Nenhuma linha válida foi encontrada na aba Final Bonus.")

        return {
            "records": records,
            "warnings": warnings,
            "rows_read": rows_read,
            "rows_skipped": rows_skipped,
        }
    finally:
        workbook.close()


def _role_from_function(function: str) -> str:
    mapping = {
        "VENDEDOR": "vendedor",
        "GERENTE": "gerente",
        "MECANICO": "mecanico",
        "SUPERVISOR": "supervisor",
    }
    return mapping.get(function, function.lower())


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

        allowed = emps_by_user.get(int(user.id), set())
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

    today = date.today()
    ano = _safe_period(request.form.get("ano"), today.year, 2000, 2100)
    mes = _safe_period(request.form.get("mes"), today.month, 1, 12)
    uploaded = request.files.get("arquivo")

    if uploaded is None or not uploaded.filename:
        flash("Selecione a planilha que contém a aba Final Bonus.", "warning")
        return redirect(url_for("bonus_importados", ano=ano, mes=mes))

    filename = secure_filename(uploaded.filename) or "final_bonus.xlsx"
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

            # A substituição ocorre dentro de uma única transação: ou a nova
            # competência entra completa, ou o snapshot anterior é preservado.
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
            "bonus_snapshot_imported",
            ano=ano,
            mes=mes,
            arquivo=filename,
            linhas=len(parsed["records"]),
            ignoradas=parsed["rows_skipped"],
            avisos=len(warnings),
        )
        flash(
            f"Bônus de {mes:02d}/{ano} importados: {len(parsed['records'])} usuários. "
            f"Linhas ignoradas: {parsed['rows_skipped']}.",
            "success",
        )
        if warnings:
            flash(
                f"A importação terminou com {len(warnings)} aviso(s). Consulte o painel da última importação.",
                "warning",
            )
    except Exception as exc:
        current_app.logger.exception("Falha ao importar snapshot de bônus")
        audit("bonus_snapshot_import_failed", ano=ano, mes=mes, arquivo=filename, erro=str(exc))
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
            "As tabelas do módulo de bônus ainda não estão disponíveis. Execute o SQL de implantação no Supabase.",
            "danger",
        )
        return render_template(
            "bonus_importados.html",
            role=_role(),
            ano=date.today().year,
            mes=date.today().month,
            rows=[],
            own_rows=[],
            team_rows=[],
            seller_rows=[],
            manager_rows=[],
            other_rows=[],
            selected=None,
            periods=[],
            emp_options=[],
            user_options=[],
            summary={},
            batch=None,
            batch_warnings=[],
            team_by_emp=[],
            db_unavailable=True,
        )

    role = _role()
    current_username = _norm_username(_usuario_logado())
    today = date.today()

    with SessionLocal() as db:
        periods = _period_options(db)
        default_year, default_month = periods[0] if periods else (today.year, today.month)
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
            allowed_emps = [_norm_emp(emp) for emp in _allowed_emps() if _norm_emp(emp)]
            query = period_query
            if allowed_emps:
                query = query.filter(BonusUsuarioImportado.emp.in_(allowed_emps)).filter(
                    or_(
                        BonusUsuarioImportado.usuario_nome == current_username,
                        BonusUsuarioImportado.funcao.notin_(["GERENTE", "ADMIN", "FINANCEIRO"]),
                    )
                )
            else:
                query = query.filter(BonusUsuarioImportado.usuario_nome == current_username)
            rows = query.all()
            emp_options = []
            user_options = []
        else:
            rows = period_query.filter(
                BonusUsuarioImportado.usuario_nome == current_username
            ).all()
            emp_options = []
            user_options = []

        rows.sort(key=lambda row: (emp_sort_key(row.emp), row.funcao, row.usuario_nome))
        seller_rows = [row for row in rows if row.funcao == "VENDEDOR"]
        manager_rows = [row for row in rows if row.funcao == "GERENTE"]
        other_rows = [row for row in rows if row.funcao not in {"VENDEDOR", "GERENTE"}]
        own_rows = [row for row in rows if row.usuario_nome == current_username]
        team_rows = []
        if role == "gerente":
            team_rows = [
                row
                for row in rows
                if row.usuario_nome != current_username
                and row.funcao not in {"GERENTE", "ADMIN", "FINANCEIRO"}
            ]

        selected_id = request.args.get("registro", type=int)
        detail_candidates = rows if role == "admin" else own_rows
        selected = next(
            (row for row in detail_candidates if selected_id and row.id == selected_id),
            None,
        )
        if selected is None and detail_candidates:
            selected = detail_candidates[0]

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
                {"emp": row.emp, "quantidade": 0, "bonus_final": Decimal("0")},
            )
            item["quantidade"] += 1
            item["bonus_final"] += Decimal(str(row.bonus_final or 0))
        team_by_emp = sorted(team_by_emp_map.values(), key=lambda item: emp_sort_key(item["emp"]))

        summary = {
            "registros": len(rows),
            "bonus_visivel": _sum_field(rows, "bonus_final"),
            "bonus_vendedores": _sum_field(seller_rows, "bonus_final"),
            "bonus_gerentes": _sum_field(manager_rows, "bonus_final"),
            "bonus_proprio": _sum_field(own_rows, "bonus_final"),
            "bonus_equipe": _sum_field(team_rows, "bonus_final"),
            "bonus_produtos_vendedor": _sum_field(own_rows, "final_vendedor"),
            "bonus_meta_vendedor": _sum_field(own_rows, "valor_meta"),
            "bonus_importado_vendedor": _sum_field(own_rows, "bonus_importado_vendedor"),
            "bonus_produtos_gerente": _sum_field(own_rows, "bonus_gerente_total"),
            "bonus_importado_gerente": _sum_field(own_rows, "bonus_importado_loja"),
            "bonus_crescimento_gerente": _sum_field(own_rows, "bonus_gerente"),
            "nao_vinculados": sum(1 for row in rows if row.usuario_id is None),
        }

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
            other_rows=other_rows,
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
            db_unavailable=False,
        )
