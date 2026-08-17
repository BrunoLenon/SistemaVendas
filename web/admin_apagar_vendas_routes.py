# -*- coding: utf-8 -*-
"""
Admin - Apagar Vendas

Refatoração pura: este módulo apenas moveu a rota /admin/apagar_vendas do app.py
para um arquivo dedicado, mantendo URLs, endpoint e comportamento externo..
"""

from __future__ import annotations

import calendar
from datetime import date, datetime

from flask import flash, redirect, request, url_for
from sqlalchemy import and_, text


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



    def admin_reprocessar_vendas_periodo():
        """Remove duplicidades de um mês/EMP e atualiza caches sem apagar vendas válidas."""
        red = login_required_fn()
        if red:
            return red
        red = admin_required_fn()
        if red:
            return red

        valor = (request.form.get("valor") or "").strip()
        emp_filtro = (request.form.get("emp") or "").strip()
        if not valor:
            flash("Informe o mês para reprocessar.", "warning")
            return redirect(url_for("admin_importar"))

        try:
            ano = int(valor[:4])
            mes = int(valor[5:7])
            if mes < 1 or mes > 12:
                raise ValueError
        except Exception:
            flash("Mês inválido. Use o seletor de mês.", "danger")
            return redirect(url_for("admin_importar"))

        last_day = calendar.monthrange(ano, mes)[1]
        d_ini = date(ano, mes, 1)
        d_fim = date(ano, mes, last_day)

        db = SessionLocal()
        try:
            params = {"ini": d_ini, "fim": d_fim}
            emp_clause = ""
            if emp_filtro:
                params["emp"] = emp_filtro
                emp_clause = " AND COALESCE(emp, '') = :emp"

            emps_sql = f"""
                SELECT DISTINCT COALESCE(emp, '') AS emp
                FROM vendas
                WHERE movimento >= :ini AND movimento <= :fim
                {emp_clause}
                ORDER BY 1
            """
            emps_afetadas = [str(x or '').strip() for x in db.execute(text(emps_sql), params).scalars().all()]

            # Deduplica pelo mesmo conceito da chave de importação principal:
            # MESTRE + MARCA + MOVIMENTO + VENDEDOR + NOTA + MOV_TIPO_MOVTO + EMP.
            # Mantém o registro mais antigo (menor id) e remove somente repetições da mesma chave.
            dedup_sql = f"""
                WITH ranked AS (
                    SELECT
                        id,
                        ROW_NUMBER() OVER (
                            PARTITION BY
                                COALESCE(mestre, ''),
                                COALESCE(marca, ''),
                                COALESCE(vendedor, ''),
                                movimento,
                                COALESCE(mov_tipo_movto, ''),
                                COALESCE(nota, ''),
                                COALESCE(emp, '')
                            ORDER BY id ASC
                        ) AS rn
                    FROM vendas
                    WHERE movimento >= :ini AND movimento <= :fim
                    {emp_clause}
                ),
                deleted AS (
                    DELETE FROM vendas v
                    USING ranked r
                    WHERE v.id = r.id
                      AND r.rn > 1
                    RETURNING v.id
                )
                SELECT COUNT(*) FROM deleted
            """
            removidas = int(db.execute(text(dedup_sql), params).scalar() or 0)
            db.commit()

            try:
                limpar_cache_df()
            except Exception:
                pass

            try:
                from dashboard_cache import refresh_dashboard_cache
                for emp_item in emps_afetadas:
                    if emp_item:
                        refresh_dashboard_cache(emp_item, ano, mes)
            except Exception:
                # Cache não pode bloquear a correção do período.
                pass

            escopo = f"EMP {emp_filtro}" if emp_filtro else "todas as EMPs"
            if removidas:
                flash(
                    f"Reprocessamento concluído em {mes:02d}/{ano} ({escopo}). "
                    f"Duplicidades removidas: {removidas}.",
                    "success",
                )
            else:
                flash(
                    f"Reprocessamento concluído em {mes:02d}/{ano} ({escopo}). "
                    "Nenhuma duplicidade encontrada.",
                    "info",
                )
            return redirect(url_for("admin_importar"))

        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
            try:
                app.logger.exception("Erro ao reprocessar vendas do período")
            except Exception:
                pass
            flash("Erro ao reprocessar período. Veja os logs no Render.", "danger")
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

    app.add_url_rule(
        "/admin/reprocessar_vendas_periodo",
        endpoint="admin_reprocessar_vendas_periodo",
        view_func=admin_reprocessar_vendas_periodo,
        methods=["POST"],
    )
