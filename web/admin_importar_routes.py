from __future__ import annotations

import os

from flask import flash, redirect, render_template, request, url_for


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

    def admin_importar():
        red = login_required_fn()
        if red:
            return red
        red = admin_required_fn()
        if red:
            return red

        if request.method == "GET":
            return render_template("admin_importar.html")

        arquivo = request.files.get("arquivo")
        if not arquivo or not arquivo.filename:
            flash("Selecione um arquivo .xlsx para importar.", "warning")
            return redirect(url_for("admin_importar"))

        if not arquivo.filename.lower().endswith(".xlsx"):
            flash("Formato inválido. Envie um arquivo .xlsx.", "danger")
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

        with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as tmp:
            arquivo.save(tmp.name)
            tmp_path = tmp.name

        try:
            resumo = importar_planilha(tmp_path, modo=modo, chave=chave)
            if not resumo.get("ok"):
                faltando = resumo.get("faltando")
                if faltando:
                    flash("Colunas faltando: " + ", ".join(faltando), "danger")
                else:
                    flash(resumo.get("msg", "Falha ao importar."), "danger")
                return redirect(url_for("admin_importar"))

            flash(
                (
                    f"Importação concluída. Válidas: {resumo['validas']} | "
                    f"Inseridas: {resumo['inseridas']} | "
                    f"Ignoradas: {resumo['ignoradas']} | "
                    f"Erros: {resumo['erros_linha']}"
                ),
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

    # Mantém endpoint = "admin_importar" (backward compatible com url_for)
    app.add_url_rule(
        "/admin/importar",
        endpoint="admin_importar",
        view_func=admin_importar,
        methods=["GET", "POST"],
    )
