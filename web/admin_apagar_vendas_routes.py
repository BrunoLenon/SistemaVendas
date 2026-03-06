# -*- coding: utf-8 -*-
"""
Admin - Apagar Vendas

Refatoração pura: este módulo apenas moveu a rota /admin/apagar_vendas do app.py
para um arquivo dedicado, mantendo URLs, endpoint e comportamento externo.
"""

from __future__ import annotations

import calendar
from datetime import date, datetime

from flask import flash, redirect, request, url_for
from sqlalchemy import and_


def register_admin_apagar_vendas_routes(
    app,
    *,
    SessionLocal,
    Venda,
    limpar_cache_df,
    login_required_fn,
    admin_required_fn,
):
    """
    Registra a rota POST /admin/apagar_vendas.

    Dependências são injetadas para evitar import circular e manter compatibilidade.
    """

    def admin_apagar_vendas():
        """Apaga vendas por dia ou por mes.

        Usado pela tela /admin/importar (admin_importar.html).
        """
        red = login_required_fn()
        if red:
            return red
        red = admin_required_fn()
        if red:
            return red

        tipo = (request.form.get("tipo") or "").strip().lower()
        valor = (request.form.get("valor") or "").strip()
        if tipo not in {"dia", "mes"}:
            flash("Tipo invalido para apagar vendas.", "danger")
            return redirect(url_for("admin_importar"))
        if not valor:
            flash("Informe uma data/mes para apagar.", "warning")
            return redirect(url_for("admin_importar"))

        db = SessionLocal()
        try:
            if tipo == "dia":
                # valor: YYYY-MM-DD
                try:
                    dt = datetime.strptime(valor, "%Y-%m-%d").date()
                except Exception:
                    flash("Data invalida. Use o seletor de data.", "danger")
                    return redirect(url_for("admin_importar"))

                q = db.query(Venda).filter(Venda.movimento == dt)
                apagadas = q.delete(synchronize_session=False)
                db.commit()
                try:
                    limpar_cache_df()
                except Exception:
                    pass
                flash(
                    f"Apagadas {apagadas} vendas do dia {dt.strftime('%d/%m/%Y')}.",
                    "success",
                )
                return redirect(url_for("admin_importar"))

            # tipo == "mes"  valor: YYYY-MM
            try:
                ano = int(valor[:4])
                mes = int(valor[5:7])
                if mes < 1 or mes > 12:
                    raise ValueError
            except Exception:
                flash("Mes invalido. Use o seletor de mes.", "danger")
                return redirect(url_for("admin_importar"))

            last_day = calendar.monthrange(ano, mes)[1]
            d_ini = date(ano, mes, 1)
            d_fim = date(ano, mes, last_day)

            q = db.query(Venda).filter(and_(Venda.movimento >= d_ini, Venda.movimento <= d_fim))
            apagadas = q.delete(synchronize_session=False)
            db.commit()
            try:
                limpar_cache_df()
            except Exception:
                pass
            flash(f"Apagadas {apagadas} vendas de {mes:02d}/{ano}.", "success")
            return redirect(url_for("admin_importar"))

        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            # Mantém logging igual ao original (usava app.logger.exception)
            try:
                app.logger.exception("Erro ao apagar vendas")
            except Exception:
                pass
            flash("Erro ao apagar vendas. Veja os logs.", "danger")
            return redirect(url_for("admin_importar"))
        finally:
            try:
                db.close()
            except Exception:
                pass

    # Endpoint explícito para manter backward-compat (mesmo nome do handler original)
    app.add_url_rule(
        "/admin/apagar_vendas",
        endpoint="admin_apagar_vendas",
        view_func=admin_apagar_vendas,
        methods=["POST"],
    )
