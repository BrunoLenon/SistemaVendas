from __future__ import annotations

from calendar import monthrange
from datetime import date, datetime, timedelta
import threading
import time
from decimal import Decimal, ROUND_HALF_UP
from io import BytesIO
from typing import Callable

from flask import flash, redirect, render_template, request, send_file, url_for
from sqlalchemy import func, inspect, or_, text

from db import (
    engine,
    ItemParado,
    ItensParadosPontosBonus,
    ItensParadosPontosConfig,
    SessionLocal,
    Venda,
)

# ---------------------------------------------------------------------
# Injeção de dependências (refatoração pura)
# ---------------------------------------------------------------------

_login_required: Callable[[], object] | None = None
_mes_ano_from_request: Callable[[], tuple[int, int]] | None = None
_role: Callable[[], str | None] | None = None
_emp: Callable[[], str | None] | None = None
_allowed_emps: Callable[[], list[str]] | None = None
_usuario_logado: Callable[[], str | None] | None = None
_get_vendedores_db: Callable[..., list[str]] | None = None
_periodo_bounds: Callable[[int, int], tuple[object, object]] | None = None


TWOPLACES = Decimal("0.01")
_SCHEMA_LOCK = threading.Lock()
_SCHEMA_READY = False
_SCHEMA_READY_AT = 0.0
_SCHEMA_TTL_SECONDS = 1800


SCHEMA_SQL = """
ALTER TABLE IF EXISTS itens_parados
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

CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_cfg_emp ON itens_parados_pontos_config(emp);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_bonus_emp ON itens_parados_pontos_bonus(emp);
CREATE INDEX IF NOT EXISTS ix_itens_parados_pontos_bonus_min ON itens_parados_pontos_bonus(min_pontos);
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
            conn.execute(text("""
                INSERT INTO itens_parados_pontos_config(emp, base_reais, valor_por_ponto, ativo)
                SELECT NULL, 100, 10.0, true
                WHERE NOT EXISTS (SELECT 1 FROM itens_parados_pontos_config WHERE emp IS NULL AND ativo = true)
            """))

        _SCHEMA_READY = True
        _SCHEMA_READY_AT = time.time()


def _d(value) -> Decimal:
    try:
        return Decimal(str(value or 0))
    except Exception:
        return Decimal("0")


def _round2(value: Decimal) -> Decimal:
    return value.quantize(TWOPLACES, rounding=ROUND_HALF_UP)


def _fmt_brl(value) -> str:
    valor = float(value or 0.0)
    return f"R$ {valor:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


def _parse_periodo(mes: int, ano: int) -> tuple[date, date, str, str]:
    di_raw = (request.args.get("data_inicio") or "").strip()
    df_raw = (request.args.get("data_fim") or "").strip()

    di = None
    df = None
    try:
        di = date.fromisoformat(di_raw) if di_raw else None
    except Exception:
        di = None
    try:
        df = date.fromisoformat(df_raw) if df_raw else None
    except Exception:
        df = None

    if di and df:
        if df < di:
            di, df = df, di
        return di, df, di.isoformat(), df.isoformat()

    inicio_mes = date(int(ano), int(mes), 1)
    fim_mes = date(int(ano), int(mes), monthrange(int(ano), int(mes))[1])
    return inicio_mes, fim_mes, "", ""


def _emp_scope_for_role(role: str, vendedor_alvo: str | None) -> list[str]:
    emp_param = (request.args.get("emp") or "").strip()
    emp_scopes: list[str] = []

    if role == "admin":
        if emp_param:
            emp_scopes = [str(emp_param)]
        else:
            with SessionLocal() as db:
                emp_scopes = [
                    str(x[0])
                    for x in db.query(ItemParado.emp)
                    .filter(ItemParado.ativo.is_(True))
                    .distinct()
                    .all()
                ]
    elif role == "supervisor":
        emps = _allowed_emps() if _allowed_emps else []
        emp_scopes = emps if emps else ([str(_emp())] if (_emp and _emp()) else [])
    else:
        emps = _allowed_emps() if _allowed_emps else []
        if emps:
            emp_scopes = emps
        else:
            with SessionLocal() as db:
                emp_scopes = [
                    str(x[0])
                    for x in db.query(Venda.emp)
                    .filter(Venda.vendedor == vendedor_alvo)
                    .distinct()
                    .all()
                ]

    return sorted({str(e).strip() for e in emp_scopes if e and str(e).strip()})


def _load_campaign_view():
    _ensure_itens_parados_schema()
    red = _login_required() if _login_required else None
    if red:
        return {"redirect": red}

    mes, ano = _mes_ano_from_request() if _mes_ano_from_request else (datetime.now().month, datetime.now().year)
    role = ((_role() or "") if _role else "").lower()
    vendedor_alvo = None
    vendedores_lista: list[str] = []

    if role in {"admin", "supervisor"}:
        emp_supervisor = (_emp() if _emp else None) if role == "supervisor" else None
        if role == "supervisor" and not emp_supervisor:
            return {
                "mes": mes,
                "ano": ano,
                "role": role,
                "vendedor": vendedor_alvo,
                "vendedores_lista": vendedores_lista,
                "emp_param": (request.args.get("emp") or "").strip(),
                "emp_scopes": [],
                "emp_cards": [],
                "periodo_inicio": date(int(ano), int(mes), 1),
                "periodo_fim": date(int(ano), int(mes), monthrange(int(ano), int(mes))[1]),
                "data_inicio_param": "",
                "data_fim_param": "",
                "periodo_label": f"{date(int(ano), int(mes), 1).strftime('%d/%m/%Y')} até {date(int(ano), int(mes), monthrange(int(ano), int(mes))[1]).strftime('%d/%m/%Y')}",
                "flash": ("Seu usuário supervisor não possui EMP cadastrada. Solicite ao ADMIN para cadastrar.", "warning"),
            }

        vendedores_lista = _get_vendedores_db(role, emp_supervisor) if _get_vendedores_db else []
        vendedor_req = (request.args.get("vendedor") or "").strip().upper() or None
        vendedor_alvo = vendedor_req if vendedor_req and vendedor_req in vendedores_lista else None
    else:
        vendedor_alvo = ((_usuario_logado() or "") if _usuario_logado else "").strip().upper()

    periodo_inicio, periodo_fim, data_inicio_param, data_fim_param = _parse_periodo(int(mes), int(ano))
    emp_scopes = _emp_scope_for_role(role, vendedor_alvo)

    if not emp_scopes:
        return {
            "mes": mes,
            "ano": ano,
            "role": role,
            "vendedor": vendedor_alvo,
            "vendedores_lista": vendedores_lista,
            "emp_param": (request.args.get("emp") or "").strip(),
            "emp_scopes": [],
            "emp_cards": [],
            "periodo_inicio": periodo_inicio,
            "periodo_fim": periodo_fim,
            "data_inicio_param": data_inicio_param,
            "data_fim_param": data_fim_param,
            "periodo_label": f"{periodo_inicio.strftime('%d/%m/%Y')} até {periodo_fim.strftime('%d/%m/%Y')}",
            "flash": ("Nenhuma EMP com campanha ativa foi encontrada para o seu escopo atual.", "warning"),
        }

    with SessionLocal() as db:
        itens_all = (
            db.query(ItemParado)
            .filter(ItemParado.emp.in_(emp_scopes))
            .filter(ItemParado.ativo.is_(True))
            .filter(or_(ItemParado.data_inicio.is_(None), ItemParado.data_inicio <= periodo_fim))
            .filter(or_(ItemParado.data_fim.is_(None), ItemParado.data_fim >= periodo_inicio))
            .order_by(ItemParado.emp.asc(), ItemParado.codigo.asc(), ItemParado.id.asc())
            .all()
        )

        if not itens_all:
            return {
                "mes": mes,
                "ano": ano,
                "role": role,
                "vendedor": vendedor_alvo,
                "vendedores_lista": vendedores_lista,
                "emp_param": (request.args.get("emp") or "").strip(),
                "emp_scopes": [],
                "emp_cards": [],
                "periodo_inicio": periodo_inicio,
                "periodo_fim": periodo_fim,
                "data_inicio_param": data_inicio_param,
                "data_fim_param": data_fim_param,
                "periodo_label": f"{periodo_inicio.strftime('%d/%m/%Y')} até {periodo_fim.strftime('%d/%m/%Y')}",
            }

        emps_com_itens = sorted({str(it.emp).strip() for it in itens_all if it.emp is not None and str(it.emp).strip()})

        codigos = sorted({(it.codigo or "").strip() for it in itens_all if (it.codigo or "").strip()})

        q_vendas = (
            db.query(
                Venda.emp,
                Venda.vendedor,
                Venda.mestre,
                Venda.movimento,
                func.coalesce(func.sum(Venda.valor_total), 0.0),
            )
            .filter(Venda.emp.in_(emps_com_itens))
            .filter(Venda.movimento >= periodo_inicio)
            .filter(Venda.movimento <= periodo_fim)
            .filter(Venda.mov_tipo_movto == "OA")
            .filter(Venda.mestre.in_(codigos))
        )
        if vendedor_alvo:
            q_vendas = q_vendas.filter(Venda.vendedor == vendedor_alvo)

        vendas_rows = q_vendas.group_by(
            Venda.emp,
            Venda.vendedor,
            Venda.mestre,
            Venda.movimento,
        ).all()

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

    cfg_global = next((c for c in cfg_rows if c.emp in (None, "", "NULL")), None)
    cfg_by_emp = {}
    for cfg in cfg_rows:
        key = str(cfg.emp).strip() if cfg.emp not in (None, "") else None
        if key is not None and key not in cfg_by_emp:
            cfg_by_emp[key] = cfg

    bonus_global = [b for b in bonus_rows if b.emp in (None, "", "NULL")]
    bonus_by_emp: dict[str, list[ItensParadosPontosBonus]] = {}
    for b in bonus_rows:
        if b.emp in (None, "", "NULL"):
            continue
        key = str(b.emp).strip()
        bonus_by_emp.setdefault(key, []).append(b)

    itens_por_emp_codigo: dict[tuple[str, str], list[ItemParado]] = {}
    itens_por_emp: dict[str, list[ItemParado]] = {}
    for it in itens_all:
        emp_key = str(it.emp).strip()
        cod_key = (it.codigo or "").strip()
        itens_por_emp.setdefault(emp_key, []).append(it)
        itens_por_emp_codigo.setdefault((emp_key, cod_key), []).append(it)

    acc: dict[tuple[str, str], dict] = {}
    for emp_v, vend, mestre, movimento, total in vendas_rows:
        emp_key = str(emp_v).strip() if emp_v is not None else ""
        vend_key = (vend or "").strip().upper()
        cod_key = (mestre or "").strip()
        if not emp_key or not vend_key or not cod_key:
            continue

        itens_match = itens_por_emp_codigo.get((emp_key, cod_key), [])
        if not itens_match:
            continue

        mov_date = movimento if isinstance(movimento, date) else None
        total_dec = _d(total)
        if total_dec <= 0:
            continue

        pontos_sale = Decimal("0")
        elegivel = False
        for it in itens_match:
            di = getattr(it, "data_inicio", None)
            df = getattr(it, "data_fim", None)
            if mov_date and di and mov_date < di:
                continue
            if mov_date and df and mov_date > df:
                continue
            mult = _d(getattr(it, "multiplicador_pontos", 1.0) or 1.0)
            if mult <= 0:
                mult = Decimal("1")
            cfg_emp = cfg_by_emp.get(emp_key)
            base_reais = _d(getattr(cfg_emp, "base_reais", None) or getattr(cfg_global, "base_reais", 100) or 100)
            if base_reais <= 0:
                base_reais = Decimal("100")
            pontos_sale += (total_dec / base_reais) * mult
            elegivel = True

        if not elegivel:
            continue

        cfg_emp = cfg_by_emp.get(emp_key)
        valor_por_ponto = _d(getattr(cfg_emp, "valor_por_ponto", None) or getattr(cfg_global, "valor_por_ponto", 10.0) or 10.0)
        base_reais = _d(getattr(cfg_emp, "base_reais", None) or getattr(cfg_global, "base_reais", 100) or 100)

        key = (emp_key, vend_key)
        acc.setdefault(
            key,
            {
                "emp": emp_key,
                "vendedor": vend_key,
                "valor_vendido": Decimal("0"),
                "pontos": Decimal("0"),
                "base_reais": base_reais,
                "valor_por_ponto": valor_por_ponto,
            },
        )
        acc[key]["valor_vendido"] += total_dec
        acc[key]["pontos"] += pontos_sale

    emp_cards = []
    for emp_key in emps_com_itens:
        ranking_rows = []
        total_vendido_emp = Decimal("0")
        total_bonus_base_emp = Decimal("0")
        total_bonus_extra_emp = Decimal("0")
        total_total_emp = Decimal("0")

        cfg_emp = cfg_by_emp.get(emp_key)
        base_reais = _d(getattr(cfg_emp, "base_reais", None) or getattr(cfg_global, "base_reais", 100) or 100)
        valor_por_ponto = _d(getattr(cfg_emp, "valor_por_ponto", None) or getattr(cfg_global, "valor_por_ponto", 10.0) or 10.0)
        bonus_list = bonus_by_emp.get(emp_key) or bonus_global

        for (row_emp, vendedor_key), data in acc.items():
            if row_emp != emp_key:
                continue

            pontos = data["pontos"]
            elegivel_pagamento = pontos >= MIN_PONTOS_PAGAMENTO_ITENS_PARADOS
            bonus_base = (pontos * valor_por_ponto) if elegivel_pagamento else Decimal("0")
            bonus_extra = Decimal("0")
            if elegivel_pagamento:
                for faixa in bonus_list:
                    min_pontos = _d(getattr(faixa, "min_pontos", 0) or 0)
                    if pontos >= min_pontos:
                        bonus_extra = _d(getattr(faixa, "bonus_valor", 0) or 0)
            total_final = bonus_base + bonus_extra

            vendido = data["valor_vendido"]
            total_vendido_emp += vendido
            total_bonus_base_emp += bonus_base
            total_bonus_extra_emp += bonus_extra
            total_total_emp += total_final

            ranking_rows.append(
                {
                    "vendedor": vendedor_key,
                    "valor_vendido": float(_round2(vendido)),
                    "pontos": float(_round2(pontos)),
                    "bonus_base": float(_round2(bonus_base)),
                    "bonus_extra": float(_round2(bonus_extra)),
                    "total": float(_round2(total_final)),
                }
            )

        ranking_rows.sort(key=lambda r: (-r["total"], -r["pontos"], r["vendedor"]))
        for idx, row in enumerate(ranking_rows, start=1):
            row["posicao"] = idx

        faixas = [
            {
                "min_pontos": float(_d(getattr(b, "min_pontos", 0) or 0)),
                "bonus_valor": float(_round2(_d(getattr(b, "bonus_valor", 0) or 0))),
                "ativo": bool(getattr(b, "ativo", True)),
            }
            for b in bonus_list
        ]

        itens_card = []
        for it in itens_por_emp.get(emp_key, []):
            itens_card.append(
                {
                    "id": it.id,
                    "codigo": (it.codigo or "").strip(),
                    "descricao": it.descricao or "",
                    "multiplicador_pontos": float(_d(getattr(it, "multiplicador_pontos", 1.0) or 1.0)),
                    "data_inicio": getattr(it, "data_inicio", None),
                    "data_fim": getattr(it, "data_fim", None),
                    "ativo": bool(getattr(it, "ativo", True)),
                }
            )

        emp_cards.append(
            {
                "emp": emp_key,
                "base_reais": float(_round2(base_reais)),
                "valor_por_ponto": float(_round2(valor_por_ponto)),
                "itens": itens_card,
                "faixas": faixas,
                "ranking": ranking_rows,
                "total_vendido": float(_round2(total_vendido_emp)),
                "total_bonus_base": float(_round2(total_bonus_base_emp)),
                "total_bonus_extra": float(_round2(total_bonus_extra_emp)),
                "total_total": float(_round2(total_total_emp)),
                "total_vendedores": len(ranking_rows),
                "total_itens": len(itens_card),
                "regra_descricao": f"1 ponto a cada {_fmt_brl(base_reais)} vendidos • {_fmt_brl(valor_por_ponto)} por ponto • pagamento só a partir de 10,00 pontos",
            }
        )

    emp_cards = [c for c in emp_cards if c["itens"]]

    return {
        "mes": mes,
        "ano": ano,
        "role": role,
        "vendedor": vendedor_alvo,
        "vendedores_lista": vendedores_lista,
        "emp_param": (request.args.get("emp") or "").strip(),
        "emp_scopes": [c["emp"] for c in emp_cards],
        "emp_cards": emp_cards,
        "periodo_inicio": periodo_inicio,
        "periodo_fim": periodo_fim,
        "data_inicio_param": data_inicio_param,
        "data_fim_param": data_fim_param,
        "periodo_label": f"{periodo_inicio.strftime('%d/%m/%Y')} até {periodo_fim.strftime('%d/%m/%Y')}",
        "fmt_brl": _fmt_brl,
    }



def register_itens_parados_routes(
    app,
    *,
    login_required_fn: Callable[[], object],
    mes_ano_from_request_fn: Callable[[], tuple[int, int]],
    role_fn: Callable[[], str | None],
    emp_fn: Callable[[], str | None],
    allowed_emps_fn: Callable[[], list[str]],
    usuario_logado_fn: Callable[[], str | None],
    get_vendedores_db_fn: Callable[..., list[str]],
    periodo_bounds_fn: Callable[[int, int], tuple[object, object]],
):
    global _login_required, _mes_ano_from_request, _role, _emp, _allowed_emps
    global _usuario_logado, _get_vendedores_db, _periodo_bounds

    _login_required = login_required_fn
    _mes_ano_from_request = mes_ano_from_request_fn
    _role = role_fn
    _emp = emp_fn
    _allowed_emps = allowed_emps_fn
    _usuario_logado = usuario_logado_fn
    _get_vendedores_db = get_vendedores_db_fn
    _periodo_bounds = periodo_bounds_fn

    app.add_url_rule("/itens_parados", endpoint="itens_parados", view_func=itens_parados, methods=["GET"])
    app.add_url_rule("/itens_parados/pdf", endpoint="itens_parados_pdf", view_func=itens_parados_pdf, methods=["GET"])



def itens_parados():
    ctx = _load_campaign_view()
    if ctx.get("flash"):
        flash(*ctx["flash"])
    if ctx.get("redirect"):
        return ctx["redirect"]
    return render_template("itens_parados.html", **ctx)



def itens_parados_pdf():
    ctx = _load_campaign_view()
    if ctx.get("flash"):
        flash(*ctx["flash"])
    if ctx.get("redirect"):
        return ctx["redirect"]

    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4

    agora = datetime.now().strftime("%d/%m/%Y %H:%M")
    vendedor_txt = ctx.get("vendedor") or "Todos"

    def header():
        y = height - 16 * mm
        c.setFont("Helvetica-Bold", 14)
        c.drawString(15 * mm, y, "Itens Parados - Campanha por EMP")
        c.setFont("Helvetica", 9)
        c.drawString(15 * mm, y - 6 * mm, f"Período: {ctx['periodo_label']}")
        c.drawString(15 * mm, y - 11 * mm, f"Vendedor: {vendedor_txt}")
        c.drawRightString(width - 15 * mm, y - 6 * mm, f"Gerado em: {agora}")
        return y - 18 * mm

    y = header()

    for card in ctx.get("emp_cards", []):
        if y < 45 * mm:
            c.showPage()
            y = header()

        c.setFont("Helvetica-Bold", 11)
        c.drawString(15 * mm, y, f"EMP {card['emp']}")
        y -= 5 * mm
        c.setFont("Helvetica", 9)
        c.drawString(15 * mm, y, card["regra_descricao"][:100])
        y -= 5 * mm
        c.drawString(15 * mm, y, f"Itens ativos: {card['total_itens']}  |  Vendedores pontuados: {card['total_vendedores']}")
        y -= 5 * mm
        c.drawString(15 * mm, y, f"Total pago: {_fmt_brl(card['total_total'])}")
        y -= 7 * mm

        c.setFont("Helvetica-Bold", 8)
        c.drawString(15 * mm, y, "#")
        c.drawString(22 * mm, y, "Vendedor")
        c.drawRightString(width - 78 * mm, y, "Vendeu")
        c.drawRightString(width - 56 * mm, y, "Pontos")
        c.drawRightString(width - 34 * mm, y, "B. extra")
        c.drawRightString(width - 15 * mm, y, "Total")
        y -= 3 * mm
        c.line(15 * mm, y, width - 15 * mm, y)
        y -= 5 * mm
        c.setFont("Helvetica", 8)

        ranking = card.get("ranking") or []
        if not ranking:
            c.drawString(15 * mm, y, "Nenhum vendedor pontuou no período.")
            y -= 6 * mm
        else:
            for row in ranking:
                if y < 20 * mm:
                    c.showPage()
                    y = header()
                    c.setFont("Helvetica", 8)
                c.drawString(15 * mm, y, str(row["posicao"]))
                c.drawString(22 * mm, y, row["vendedor"][:24])
                c.drawRightString(width - 78 * mm, y, _fmt_brl(row["valor_vendido"]))
                c.drawRightString(width - 56 * mm, y, f"{row['pontos']:.2f}")
                c.drawRightString(width - 34 * mm, y, _fmt_brl(row["bonus_extra"]))
                c.drawRightString(width - 15 * mm, y, _fmt_brl(row["total"]))
                y -= 5 * mm

        y -= 4 * mm

    c.save()
    buf.seek(0)
    filename = f"itens_parados_{ctx['periodo_inicio'].strftime('%Y%m%d')}_{ctx['periodo_fim'].strftime('%Y%m%d')}.pdf"
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)
