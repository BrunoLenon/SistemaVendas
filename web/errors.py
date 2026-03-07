from __future__ import annotations


def register_error_handlers(app) -> None:
    """Registra handlers globais de erro sem alterar o comportamento externo."""

    @app.errorhandler(500)
    def err_500(e):
        app.logger.exception("Erro 500: %s", e)
        return ("Erro interno. Verifique os logs no Render (ou fale com o admin).", 500)
