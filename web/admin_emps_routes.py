from __future__ import annotations

from datetime import datetime
from flask import request, render_template


def register_admin_emps_routes(
    app,
    *,
    SessionLocal,
    Emp,
    login_required_fn,
    admin_required_fn,
    usuario_logado_fn,
):
    """Registra as rotas de cadastro de EMPs (Admin).

    Refatoração pura: mantém URLs, endpoints e comportamento externo.
    """

    def admin_emps():
        """Cadastro de EMPs (ADMIN).

        Permite cadastrar nome/cidade/UF para cada código EMP (loja/filial).
        """
        red = login_required_fn()
        if red:
            return red
        red = admin_required_fn()
        if red:
            return red

        usuario = usuario_logado_fn()
        erro = None
        ok = None

        with SessionLocal() as db:
            if request.method == "POST":
                acao = (request.form.get("acao") or "").strip()
                try:
                    codigo = (request.form.get("codigo") or "").strip()
                    nome = (request.form.get("nome") or "").strip()
                    cidade = (request.form.get("cidade") or "").strip()
                    uf = (request.form.get("uf") or "").strip().upper()
                    ativo_raw = (request.form.get("ativo") or "1").strip()
                    ativo = ativo_raw in {"1", "true", "True", "on", "SIM", "sim"}

                    if acao in {"criar", "atualizar"}:
                        if not codigo:
                            raise ValueError("Informe o código EMP (ex.: 101).")
                        if not nome:
                            raise ValueError("Informe o nome da EMP.")
                        if uf and len(uf) != 2:
                            raise ValueError("UF inválida (use 2 letras, ex.: SP).")

                        emp = db.query(Emp).filter(Emp.codigo == codigo).first()
                        if emp:
                            emp.nome = nome
                            emp.cidade = cidade or None
                            emp.uf = uf or None
                            emp.ativo = ativo
                            emp.updated_at = datetime.utcnow()
                            ok = f"EMP {codigo} atualizada."
                        else:
                            db.add(
                                Emp(
                                    codigo=codigo,
                                    nome=nome,
                                    cidade=cidade or None,
                                    uf=uf or None,
                                    ativo=ativo,
                                )
                            )
                            ok = f"EMP {codigo} criada."
                        db.commit()

                    elif acao == "toggle":
                        if not codigo:
                            raise ValueError("Informe o código EMP.")
                        emp = db.query(Emp).filter(Emp.codigo == codigo).first()
                        if not emp:
                            raise ValueError("EMP não encontrada.")
                        emp.ativo = not bool(emp.ativo)
                        emp.updated_at = datetime.utcnow()
                        db.commit()
                        ok = f"EMP {codigo} agora está {'ATIVA' if emp.ativo else 'INATIVA'}."
                    else:
                        raise ValueError("Ação inválida.")
                except Exception as e:
                    db.rollback()
                    erro = str(e)
                    app.logger.exception("Erro na admin/emps")

            emps = db.query(Emp).order_by(Emp.ativo.desc(), Emp.codigo.asc()).all()

        return render_template(
            "admin_emps.html",
            usuario=usuario,
            erro=erro,
            ok=ok,
            emps=emps,
        )

    # Mantém endpoint = "admin_emps" (backward compatible com url_for)
    app.add_url_rule(
        "/admin/emps",
        endpoint="admin_emps",
        view_func=admin_emps,
        methods=["GET", "POST"],
    )
