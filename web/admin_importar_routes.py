from __future__ import annotations

import os

from flask import flash, redirect, render_template, request, session, url_for

from importar_servicos_oficina import importar_servicos_oficina


def register_admin_importar_routes(
    app,
    *,
    importar_planilha,
    limpar_cache_df,
    login_required_fn,
    admin_required_fn,
):
    """Registra a rota de importação de vendas (Admin).

    Refatoração pura: mantém URL, endpoint e comportamento externo.
    """

    def _parse_competencia(value: str | None) -> tuple[int | None, int | None]:
        value = (value or "").strip()
        if not value:
            return None, None
        try:
            parts = value.replace("/", "-").split("-")
            if len(parts) >= 2:
                if len(parts[0]) == 4:
                    return int(parts[0]), int(parts[1])
                return int(parts[1]), int(parts[0])
        except Exception:
            return None, None
        return None, None

    def admin_importar():
        red = login_required_fn()
        if red:
            return red
        red = admin_required_fn()
        if red:
            return red

        if request.method == "GET":
            return render_template("admin_importar.html", role=(session.get("role") or ""), emp=session.get("emp"))

        arquivo = request.files.get("arquivo")
        if not arquivo or not arquivo.filename:
            flash("Selecione um arquivo .xlsx para importar.", "warning")
            return redirect(url_for("admin_importar"))

        filename_lower = arquivo.filename.lower()
        if not (filename_lower.endswith(".xlsx") or filename_lower.endswith(".csv")):
            flash("Formato inválido. Envie um arquivo .xlsx ou .csv.", "danger")
            return redirect(url_for("admin_importar"))

        modo = request.form.get("modo", "ignorar_duplicados")
        # IMPORTANTISSIMO:
        # A chave de deduplicidade precisa bater com o indice/constraint UNIQUE do banco.
        # Seu banco foi padronizado com:
        #   (mestre, marca, vendedor, movimento, mov_tipo_movto, nota, emp)
        # Se a chave nao incluir MOVIMENTO e MOV_TIPO_MOVTO (DS/CA/OA), o Postgres
        # pode retornar erro de ON CONFLICT e/ou DS/CA pode ser ignorado.
        chave = request.form.get("chave", "mestre_movimento_vendedor_nota_tipo_emp")

        # Salva temporariamente
        import tempfile

        suffix = ".csv" if filename_lower.endswith(".csv") else ".xlsx"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            arquivo.save(tmp.name)
            tmp_path = tmp.name

        try:
            # Não recalcula dashboard_cache dentro da requisição.
            # Isso evita POST de importação com 2-3 minutos e queda/502 no Render.
            resumo = importar_planilha(
                tmp_path,
                modo=modo,
                chave=chave,
                batch_size=1000,
                csv_chunksize=5000,
                reprocessar_competencia=True,
                atualizar_cache_dashboard=False,
            )
            if not resumo.get("ok"):
                faltando = resumo.get("faltando")
                if faltando:
                    flash("Colunas faltando: " + ", ".join(faltando), "danger")
                else:
                    flash(resumo.get("msg", "Falha ao importar."), "danger")
                return redirect(url_for("admin_importar"))

            apagadas = int(resumo.get("linhas_reprocessadas_apagadas") or 0)
            recortes = int((resumo.get("reprocessamento") or {}).get("recortes") or 0)
            total_bruto = float(resumo.get("total_bruto") or 0.0)
            total_cancelamentos = float(resumo.get("total_cancelamentos") or 0.0)
            total_devolucoes = float(resumo.get("total_devolucoes") or 0.0)
            total_liquido = float(resumo.get("total_liquido") or 0.0)
            mov_ignorados = int(resumo.get("movimentos_ignorados_linhas") or 0)
            flash(
                (
                    f"Importação concluída. Válidas: {resumo['validas']} | "
                    f"Inseridas: {resumo['inseridas']} | "
                    f"Ignoradas: {resumo['ignoradas']} | "
                    f"Erros: {resumo['erros_linha']} | "
                    f"Bruto vendas: R$ {total_bruto:,.2f} | "
                    f"Cancelamentos: R$ {total_cancelamentos:,.2f} | "
                    f"Devoluções: R$ {total_devolucoes:,.2f} | "
                    f"Líquido: R$ {total_liquido:,.2f} | "
                    f"Mov. fora da regra: {mov_ignorados} | "
                    f"Reprocessamento automático: {recortes} recorte(s), {apagadas} linha(s) substituída(s) | "
                    f"Cache do dashboard: pendente para atualização manual"
                ).replace(",", "X").replace(".", ",").replace("X", "."),
                "success",
            )

            # Limpa cache do DataFrame para refletir novos dados imediatamente
            try:
                limpar_cache_df()
            except Exception:
                pass

            return redirect(url_for("admin_importar"))

        except Exception:
            app.logger.exception("Erro ao importar planilha")
            flash("Erro ao importar. Veja os logs no Render.", "danger")
            return redirect(url_for("admin_importar"))
        finally:
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    def admin_importar_oficina():
        red = login_required_fn()
        if red:
            return red
        red = admin_required_fn()
        if red:
            return red

        arquivo = request.files.get("arquivo_oficina")
        if not arquivo or not arquivo.filename:
            flash("Selecione um arquivo .xlsx ou .csv de mão de obra/oficina.", "warning")
            return redirect(url_for("admin_importar"))

        filename_lower = arquivo.filename.lower()
        if not (filename_lower.endswith(".xlsx") or filename_lower.endswith(".csv")):
            flash("Formato inválido para oficina. Envie um arquivo .xlsx ou .csv.", "danger")
            return redirect(url_for("admin_importar"))

        ano, mes = _parse_competencia(request.form.get("competencia_oficina"))
        modo = (request.form.get("modo_oficina") or "substituir").strip().lower()

        import tempfile

        suffix = ".csv" if filename_lower.endswith(".csv") else ".xlsx"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            arquivo.save(tmp.name)
            tmp_path = tmp.name

        try:
            resumo = importar_servicos_oficina(
                tmp_path,
                ano=ano,
                mes=mes,
                modo=modo,
                arquivo_origem=arquivo.filename,
                importado_por=(session.get("usuario") or session.get("vendedor") or ""),
            )
            if not resumo.get("ok"):
                faltando = resumo.get("faltando")
                if faltando:
                    flash("Colunas faltando na oficina: " + ", ".join([str(x) for x in faltando]), "danger")
                else:
                    flash(resumo.get("msg", "Falha ao importar mão de obra/oficina."), "danger")
                return redirect(url_for("admin_importar"))

            total_servico = float(resumo.get("total_servico") or 0.0)
            periodos = resumo.get("periodos") or []
            qtd_periodos = len(periodos)
            flash(
                (
                    f"Mão de obra importada. Linhas válidas: {resumo.get('validas', 0)} | "
                    f"Registros por usuário/EMP: {resumo.get('registros_competencia', 0)} | "
                    f"Erros: {resumo.get('erros_linha', 0)} | "
                    f"Total serviço: R$ {total_servico:,.2f} | "
                    f"Competências afetadas: {qtd_periodos}. "
                    f"Recalcule metas/relatório de campanhas para atualizar snapshots já gravados."
                ).replace(",", "X").replace(".", ",").replace("X", "."),
                "success",
            )

            try:
                limpar_cache_df()
            except Exception:
                pass

            return redirect(url_for("admin_importar"))
        except Exception:
            app.logger.exception("Erro ao importar mão de obra/oficina")
            flash("Erro ao importar mão de obra/oficina. Veja os logs no Render.", "danger")
            return redirect(url_for("admin_importar"))
        finally:
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    # Mantém endpoint = "admin_importar" (backward compatible com url_for)
    app.add_url_rule(
        "/admin/importar",
        endpoint="admin_importar",
        view_func=admin_importar,
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/admin/importar/oficina",
        endpoint="admin_importar_oficina",
        view_func=admin_importar_oficina,
        methods=["POST"],
    )
