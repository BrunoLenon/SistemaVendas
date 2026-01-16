"""Flask app (trecho) - patch para pagina de importacao do ADMIN.

ATENCAO:
- Este arquivo assume que seu app principal ja existe.
- Integre apenas os trechos marcados (imports + rota).
"""

import os
import tempfile

from flask import Flask, render_template, request, redirect, url_for, flash

# >>> ADICIONE no seu app.py principal:
from importar_excel import importar_planilha

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev")


def _is_admin() -> bool:
    # Ajuste conforme sua sessao/autenticacao.
    # Exemplo comum:
    # return session.get("role") == "admin"
    return True


@app.get("/admin/importar")
def admin_importar_get():
    if not _is_admin():
        return redirect(url_for("dashboard"))
    return render_template("admin_importar.html")


@app.post("/admin/importar")
def admin_importar_post():
    if not _is_admin():
        return redirect(url_for("dashboard"))

    arquivo = request.files.get("arquivo")
    if not arquivo or not arquivo.filename:
        flash("Selecione um arquivo .xlsx para importar.", "warning")
        return redirect(url_for("admin_importar_get"))

    if not arquivo.filename.lower().endswith(".xlsx"):
        flash("Formato invalido. Envie um arquivo .xlsx.", "danger")
        return redirect(url_for("admin_importar_get"))

    modo = request.form.get("modo", "ignorar_duplicados")
    chave = request.form.get("chave", "mestre_vendedor_nota_emp")

    # Salva temporariamente
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
            return redirect(url_for("admin_importar_get"))

        flash(
            f"Importacao concluida. Validas: {resumo['validas']} | Inseridas: {resumo['inseridas']} | Ignoradas: {resumo['ignoradas']} | Erros: {resumo['erros_linha']}",
            "success",
        )
        return redirect(url_for("admin_importar_get"))

    except Exception as e:
        flash(f"Erro ao importar: {e}", "danger")
        return redirect(url_for("admin_importar_get"))

    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
