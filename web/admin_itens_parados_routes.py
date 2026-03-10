"""Rotas: Admin Itens Parados (cadastro/configuração/fechamento)."""

from __future__ import annotations

from datetime import date, datetime
import threading
import time
from decimal import Decimal, ROUND_HALF_UP
from typing import Callable, Type

from flask import current_app, redirect, render_template, request, session, url_for
from sqlalchemy import func, inspect, or_, text

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
_SCHEMA_LOCK = threading.Lock()
_SCHEMA_READY = False
_SCHEMA_READY_AT = 0.0
_SCHEMA_TTL_SECONDS = 1800
_AUX_CACHE_LOCK = threading.Lock()
_AUX_CACHE = {"payload": None, "ready_at": 0.0}
_AUX_CACHE_TTL_SECONDS = 60


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
        .filter(Venda.mov_tipo_movto == "OA")
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
            pontos_factor += pontos_por_real

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
        pontos = data["pontos"]
        elegivel_pagamento = pontos >= MIN_PONTOS_PAGAMENTO_ITENS_PARADOS
        bonus_base = (pontos * data["valor_por_ponto"]) if elegivel_pagamento else Decimal("0")
        bonus_extra = Decimal("0")
        if elegivel_pagamento:
            for min_pontos, bonus_valor in bonus_list:
                if pontos >= min_pontos:
                    bonus_extra = bonus_valor
        total_final = bonus_base + bonus_extra

        resultados_bulk.append(
            ItensParadosPontosResultado(
                fechamento_id=int(fechamento.id),
                emp=emp_key,
                vendedor=vend_key,
                valor_vendido=float(_round2(data["valor_vendido"])),
                pontos=float(_round2(pontos)),
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
    _ensure_itens_parados_schema()

    def admin_itens_parados():
        red = login_required_fn()
        if red:
            return red
        red = admin_required_fn()
        if red:
            return red

        erro = None
        ok = None
        ver_fech = (request.args.get("ver_fech") or "").strip()

        with SessionLocal() as db:
            try:
                acao = (request.form.get("acao") or "").strip().lower()
                if request.method == "POST" and acao:
                    if acao == "criar_item":
                        emp = (request.form.get("emp") or "").strip()
                        codigo = (request.form.get("codigo") or "").strip()
                        descricao = (request.form.get("descricao") or "").strip()
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
                        emps = sorted({str(e).strip() for e in emps if e and str(e).strip()})
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
            role=(session.get("role") or ""),
            emp=session.get("emp"),
        )

    app.add_url_rule(
        "/admin/itens_parados",
        endpoint="admin_itens_parados",
        view_func=admin_itens_parados,
        methods=["GET", "POST"],
    )
