"""Rotas: Admin Itens Parados (cadastro/configuração/fechamento)."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal, ROUND_HALF_UP
from typing import Callable, Type

from flask import current_app, redirect, render_template, request, url_for
from sqlalchemy import func, or_

from db import (
    ItensParadosPontosBonus,
    ItensParadosPontosConfig,
    ItensParadosPontosFechamento,
    ItensParadosPontosResultado,
    Venda,
)

TWOPLACES = Decimal("0.01")


def _d(value) -> Decimal:
    try:
        return Decimal(str(value or 0))
    except Exception:
        return Decimal("0")



def _round2(value: Decimal) -> Decimal:
    return value.quantize(TWOPLACES, rounding=ROUND_HALF_UP)



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
                        ok = "Item parado cadastrado com sucesso."

                    elif acao == "toggle_item":
                        item_id = int(request.form.get("item_id") or 0)
                        it = db.query(ItemParado).filter(ItemParado.id == item_id).first()
                        if not it:
                            raise ValueError("Item não encontrado.")
                        it.ativo = not bool(it.ativo)
                        it.atualizado_em = datetime.utcnow()
                        db.commit()
                        ok = "Status do item atualizado."

                    elif acao == "excluir_item":
                        item_id = int(request.form.get("item_id") or 0)
                        it = db.query(ItemParado).filter(ItemParado.id == item_id).first()
                        if not it:
                            raise ValueError("Item não encontrado.")
                        db.delete(it)
                        db.commit()
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
                        ok = "Faixa de bônus cadastrada."

                    elif acao == "toggle_bonus":
                        bonus_id = int(request.form.get("bonus_id") or 0)
                        bonus = db.query(ItensParadosPontosBonus).filter(ItensParadosPontosBonus.id == bonus_id).first()
                        if not bonus:
                            raise ValueError("Faixa de bônus não encontrada.")
                        bonus.ativo = not bool(bonus.ativo)
                        bonus.atualizado_em = datetime.utcnow()
                        db.commit()
                        ok = "Status da faixa atualizado."

                    elif acao == "excluir_bonus":
                        bonus_id = int(request.form.get("bonus_id") or 0)
                        bonus = db.query(ItensParadosPontosBonus).filter(ItensParadosPontosBonus.id == bonus_id).first()
                        if not bonus:
                            raise ValueError("Faixa de bônus não encontrada.")
                        db.delete(bonus)
                        db.commit()
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

                        fechamento = ItensParadosPontosFechamento(
                            emp=emp,
                            data_inicio=di,
                            data_fim=df,
                            criado_por=str(usuario_logado_fn() or ""),
                            criado_em=datetime.utcnow(),
                        )
                        db.add(fechamento)
                        db.commit()

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
                        bonus_by_emp = {}
                        for b in bonus_rows:
                            if b.emp in (None, "", "NULL"):
                                continue
                            bonus_by_emp.setdefault(str(b.emp).strip(), []).append(b)

                        itens_all = (
                            db.query(ItemParado)
                            .filter(ItemParado.emp.in_(emps))
                            .filter(ItemParado.ativo.is_(True))
                            .filter(or_(ItemParado.data_inicio.is_(None), ItemParado.data_inicio <= df))
                            .filter(or_(ItemParado.data_fim.is_(None), ItemParado.data_fim >= di))
                            .all()
                        )
                        if not itens_all:
                            raise ValueError("Nenhum item ativo foi encontrado no período informado.")

                        codigos = sorted({(it.codigo or "").strip() for it in itens_all if (it.codigo or "").strip()})
                        vendas_rows = (
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
                            .all()
                        )

                        itens_idx = {}
                        for it in itens_all:
                            itens_idx.setdefault((str(it.emp).strip(), (it.codigo or "").strip()), []).append(it)

                        acc = {}
                        for emp_v, vend, mestre, movimento, total in vendas_rows:
                            emp_key = str(emp_v).strip() if emp_v is not None else ""
                            vend_key = (vend or "").strip().upper()
                            cod_key = (mestre or "").strip()
                            if not emp_key or not vend_key or not cod_key:
                                continue
                            itens_match = itens_idx.get((emp_key, cod_key), [])
                            if not itens_match:
                                continue

                            total_dec = _d(total)
                            pontos_sale = Decimal("0")
                            for it in itens_match:
                                mov = movimento
                                if it.data_inicio and mov < it.data_inicio:
                                    continue
                                if it.data_fim and mov > it.data_fim:
                                    continue
                                cfg_emp = cfg_by_emp.get(emp_key)
                                base_reais = _d(getattr(cfg_emp, "base_reais", None) or getattr(cfg_global, "base_reais", 100) or 100)
                                if base_reais <= 0:
                                    base_reais = Decimal("100")
                                mult = _d(getattr(it, "multiplicador_pontos", 1.0) or 1.0)
                                if mult <= 0:
                                    mult = Decimal("1")
                                pontos_sale += (total_dec / base_reais) * mult

                            if pontos_sale <= 0:
                                continue

                            cfg_emp = cfg_by_emp.get(emp_key)
                            base_reais = _d(getattr(cfg_emp, "base_reais", None) or getattr(cfg_global, "base_reais", 100) or 100)
                            valor_por_ponto = _d(getattr(cfg_emp, "valor_por_ponto", None) or getattr(cfg_global, "valor_por_ponto", 10.0) or 10.0)
                            acc.setdefault(
                                (emp_key, vend_key),
                                {
                                    "valor_vendido": Decimal("0"),
                                    "pontos": Decimal("0"),
                                    "base_reais": base_reais,
                                    "valor_por_ponto": valor_por_ponto,
                                },
                            )
                            acc[(emp_key, vend_key)]["valor_vendido"] += total_dec
                            acc[(emp_key, vend_key)]["pontos"] += pontos_sale

                        for (emp_key, vend_key), data in acc.items():
                            bonus_list = bonus_by_emp.get(emp_key) or bonus_global
                            pontos = data["pontos"]
                            bonus_base = pontos * data["valor_por_ponto"]
                            bonus_extra = Decimal("0")
                            for faixa in bonus_list:
                                if pontos >= _d(getattr(faixa, "min_pontos", 0) or 0):
                                    bonus_extra = _d(getattr(faixa, "bonus_valor", 0) or 0)
                            total_final = bonus_base + bonus_extra

                            db.add(
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
                                    criado_em=datetime.utcnow(),
                                    atualizado_em=datetime.utcnow(),
                                )
                            )

                        db.commit()
                        return redirect(url_for("admin_itens_parados", ver_fech=int(fechamento.id), ok="1"))

                    else:
                        raise ValueError("Ação inválida.")

            except Exception as e:
                db.rollback()
                erro = str(e)
                current_app.logger.exception("Erro no admin de itens parados")

            if request.args.get("ok") == "1" and not erro:
                ok = "Fechamento criado com sucesso."

            itens = db.query(ItemParado).order_by(ItemParado.emp.asc(), ItemParado.codigo.asc(), ItemParado.id.desc()).all()
            cfg_by_emp = (
                db.query(ItensParadosPontosConfig)
                .filter(ItensParadosPontosConfig.emp.isnot(None))
                .order_by(ItensParadosPontosConfig.emp.asc(), ItensParadosPontosConfig.id.desc())
                .all()
            )
            cfg_global = (
                db.query(ItensParadosPontosConfig)
                .filter(ItensParadosPontosConfig.emp.is_(None))
                .order_by(ItensParadosPontosConfig.id.desc())
                .all()
            )
            bonus_by_emp = (
                db.query(ItensParadosPontosBonus)
                .filter(ItensParadosPontosBonus.emp.isnot(None))
                .order_by(ItensParadosPontosBonus.emp.asc(), ItensParadosPontosBonus.min_pontos.asc())
                .all()
            )
            bonus_global = (
                db.query(ItensParadosPontosBonus)
                .filter(ItensParadosPontosBonus.emp.is_(None))
                .order_by(ItensParadosPontosBonus.min_pontos.asc())
                .all()
            )
            fechamentos = (
                db.query(ItensParadosPontosFechamento)
                .order_by(ItensParadosPontosFechamento.id.desc())
                .limit(30)
                .all()
            )
            res_fech = []
            if ver_fech.isdigit():
                res_fech = (
                    db.query(ItensParadosPontosResultado)
                    .filter(ItensParadosPontosResultado.fechamento_id == int(ver_fech))
                    .order_by(ItensParadosPontosResultado.emp.asc(), ItensParadosPontosResultado.total.desc())
                    .all()
                )

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
        )

    app.add_url_rule(
        "/admin/itens_parados",
        endpoint="admin_itens_parados",
        view_func=admin_itens_parados,
        methods=["GET", "POST"],
    )
