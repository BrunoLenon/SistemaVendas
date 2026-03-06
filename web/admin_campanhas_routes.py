# -*- coding: utf-8 -*-
"""
Rotas do Admin: Campanhas (Qtd) - legado (/admin/campanhas)

Refatoração pura: extraído do app.py sem alterar comportamento externo.
"""
from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Callable

from flask import redirect, render_template, request


def register_admin_campanhas_routes(
    app,
    *,
    SessionLocal,
    CampanhaQtd,
    CampanhaQtdResultado,
    login_required_fn: Callable[[], Any],
    admin_required_fn: Callable[[], Any],
    competencia_fechada_fn: Callable[[Any, str, int, int], bool],
    usuario_logado_fn: Callable[[], Any],
) -> None:
    """
    Registra rotas de cadastro/administração de campanhas de recompensa por quantidade.

    Mantém endpoint compatível: "admin_campanhas_qtd".
    """

    def admin_campanhas_qtd():
        """Cadastro de campanhas de recompensa por quantidade.

        Campos:
        - EMP (obrigatório)
        - Vendedor (opcional; vazio = todos da EMP)
        - Produto prefixo (obrigatório)
        - Marca (obrigatório)
        - Recompensa (R$/un)
        - Quantidade mínima (opcional)
        - Período (data início/fim)
        """
        red = login_required_fn()
        if red:
            return red
        red = admin_required_fn()
        if red:
            return red

        erro = None
        ok = None

        hoje = date.today()
        mes = int(request.values.get("mes") or hoje.month)
        ano = int(request.values.get("ano") or hoje.year)

        with SessionLocal() as db:
            if request.method == "POST":
                acao = (request.form.get("acao") or "").strip().lower()

                # Se a competência estiver FECHADA, bloqueia alterações de campanhas (mantém integridade do fechamento)
                try:
                    emp_post = (request.form.get("emp") or "").strip()
                    if not emp_post and request.form.get("id"):
                        try:
                            cid = int(request.form.get("id") or 0)
                            obj = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                            if obj:
                                emp_post = (obj.emp or "").strip()
                        except Exception:
                            emp_post = ""
                    if emp_post and competencia_fechada_fn(db, emp_post, ano, mes):
                        erro = f"Competência {mes:02d}/{ano} da EMP {emp_post} está FECHADA. Reabra em /admin/fechamento para editar campanhas."
                        # impede execução do POST
                        return redirect('/admin/fechamento' + f'?emp={emp_post}&mes={mes}&ano={ano}')
                except Exception:
                    pass


                try:
                    if acao == "criar":
                        emp = (request.form.get("emp") or "").strip()
                        vendedor = (request.form.get("vendedor") or "").strip().upper() or None
                        titulo = (request.form.get("titulo") or "").strip() or None

                        campo_match = (request.form.get("campo_match") or "codigo").strip().lower()
                        if campo_match not in {"codigo", "descricao"}:
                            campo_match = "codigo"

                        produto_prefixo = (request.form.get("produto_prefixo") or "").strip()
                        descricao_prefixo = (request.form.get("descricao_prefixo") or "").strip()
                        marca = (request.form.get("marca") or "").strip()

                        recompensa_raw = (request.form.get("recompensa_unit") or "").strip().replace(",", ".")
                        qtd_min_raw = (request.form.get("qtd_minima") or "").strip().replace(",", ".")
                        valor_min_raw = (request.form.get("valor_minimo") or "").strip().replace(",", ".")

                        data_ini_raw = (request.form.get("data_inicio") or "").strip()
                        data_fim_raw = (request.form.get("data_fim") or "").strip()

                        if not emp:
                            raise ValueError("Informe a EMP.")
                        if campo_match == "descricao":
                            if not descricao_prefixo and not produto_prefixo:
                                raise ValueError("Informe a descrição (início).")
                        else:
                            if not produto_prefixo:
                                raise ValueError("Informe o código/prefixo do produto.")
                        if not marca:
                            raise ValueError("Informe a marca.")
                        if not recompensa_raw:
                            raise ValueError("Informe a recompensa (R$/un).")
                        if not data_ini_raw or not data_fim_raw:
                            raise ValueError("Informe data início e fim.")

                        def _to_dec(s: str) -> Decimal:
                            try:
                                return Decimal(s)
                            except Exception:
                                raise ValueError("Número inválido.")

                        recompensa_unit = _to_dec(recompensa_raw)
                        if recompensa_unit < 0:
                            raise ValueError("Recompensa não pode ser negativa.")

                        qtd_minima = _to_dec(qtd_min_raw) if qtd_min_raw else None
                        if qtd_minima is not None and qtd_minima < 0:
                            raise ValueError("Quantidade mínima não pode ser negativa.")

                        valor_minimo = _to_dec(valor_min_raw) if valor_min_raw else None
                        if valor_minimo is not None and valor_minimo < 0:
                            raise ValueError("Valor mínimo não pode ser negativo.")

                        # Persistimos como float (compatibilidade), mas com precisão controlada
                        recompensa_unit = float(recompensa_unit.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP))
                        if qtd_minima is not None:
                            qtd_minima = float(qtd_minima)
                        if valor_minimo is not None:
                            valor_minimo = float(valor_minimo)
                        data_inicio = datetime.strptime(data_ini_raw, "%Y-%m-%d").date()
                        data_fim = datetime.strptime(data_fim_raw, "%Y-%m-%d").date()
                        if data_fim < data_inicio:
                            raise ValueError("Data fim não pode ser menor que data início.")

                        db.add(
                            CampanhaQtd(
                                emp=str(emp),
                                vendedor=vendedor,
                                titulo=titulo,
                                produto_prefixo=(produto_prefixo or '').upper(),
                                descricao_prefixo=(descricao_prefixo or '').strip(),
                                campo_match=campo_match,
                                marca=marca.upper(),
                                recompensa_unit=float(recompensa_unit),
                                qtd_minima=float(qtd_minima) if qtd_minima is not None else None,
                                valor_minimo=float(valor_minimo) if valor_minimo is not None else None,
                                data_inicio=data_inicio,
                                data_fim=data_fim,
                                ativo=1,
                            )
                        )
                        db.commit()
                        ok = "Campanha cadastrada com sucesso."

                    elif acao == "toggle":
                        cid = int(request.form.get("campanha_id") or 0)
                        c = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                        if not c:
                            raise ValueError("Campanha não encontrada.")
                        c.ativo = 0 if int(c.ativo or 0) == 1 else 1
                        c.atualizado_em = datetime.utcnow()
                        db.commit()
                        ok = "Status da campanha atualizado."

                    elif acao == "remover":
                        cid = int(request.form.get("campanha_id") or 0)
                        c = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                        if not c:
                            raise ValueError("Campanha não encontrada.")

                        # Remove também o histórico/snapshot mensal dessa campanha
                        db.query(CampanhaQtdResultado).filter(CampanhaQtdResultado.campanha_id == cid).delete(synchronize_session=False)

                        db.delete(c)
                        db.commit()
                        ok = "Campanha removida."

                    elif acao == "pagar":
                        rid = int(request.form.get("resultado_id") or 0)
                        r = db.query(CampanhaQtdResultado).filter(CampanhaQtdResultado.id == rid).first()
                        if not r:
                            raise ValueError("Resultado não encontrado.")
                        if (r.status_pagamento or "PENDENTE") == "PAGO":
                            r.status_pagamento = "PENDENTE"
                            r.pago_em = None
                        else:
                            r.status_pagamento = "PAGO"
                            r.pago_em = datetime.utcnow()
                        r.atualizado_em = datetime.utcnow()
                        db.commit()
                        ok = "Status de pagamento atualizado."

                    else:
                        raise ValueError("Ação inválida.")

                except Exception as e:
                    db.rollback()
                    erro = str(e)
                    app.logger.exception("Erro ao gerenciar campanhas")

            campanhas = db.query(CampanhaQtd).order_by(CampanhaQtd.emp.asc(), CampanhaQtd.data_inicio.desc()).all()
            resultados = (
                db.query(CampanhaQtdResultado)
                .filter(
                    CampanhaQtdResultado.competencia_ano == int(ano),
                    CampanhaQtdResultado.competencia_mes == int(mes),
                )
                .order_by(CampanhaQtdResultado.valor_recompensa.desc())
                .all()
            )

    
        # UX: agrupa por competência (mês/ano) na lista
        try:
            for c in (campanhas or []):
                di = getattr(c, "data_inicio", None)
                if di:
                    setattr(c, "competencia_label", f"{int(di.month):02d}/{int(di.year)}")
                else:
                    setattr(c, "competencia_label", "")
        except Exception:
            pass

        return render_template(
                "admin_campanhas_qtd.html",
                usuario=usuario_logado_fn(),
                campanhas=campanhas,
                resultados=resultados,
                ano=ano,
                mes=mes,
                erro=erro,
                ok=ok,
            )

    app.add_url_rule(
        "/admin/campanhas",
        endpoint="admin_campanhas_qtd",
        view_func=admin_campanhas_qtd,
        methods=["GET", "POST"],
    )
