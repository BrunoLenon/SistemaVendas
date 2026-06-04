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

    def _to_dec(raw: str, *, field_label: str = "Número") -> Decimal:
        value = (raw or "").strip().replace(".", "").replace(",", ".") if "," in (raw or "") else (raw or "").strip().replace(",", ".")
        try:
            return Decimal(value)
        except Exception:
            raise ValueError(f"{field_label} inválido.")

    def _parse_campaign_payload(form, *, current_obj=None) -> dict[str, Any]:
        """Valida e normaliza dados do formulário de campanha."""
        emp = (form.get("emp") or "").strip()
        vendedor = (form.get("vendedor") or "").strip().upper() or None
        titulo = (form.get("titulo") or "").strip() or None
        campanha_tipo = (form.get("campanha_tipo") or "VENDEDOR").strip().upper()
        if campanha_tipo not in {"VENDEDOR", "GERENTE"}:
            campanha_tipo = "VENDEDOR"

        campo_match = (form.get("campo_match") or "codigo").strip().lower()
        if campo_match not in {"codigo", "descricao"}:
            campo_match = "codigo"

        produto_prefixo = (form.get("produto_prefixo") or "").strip()
        descricao_prefixo = (form.get("descricao_prefixo") or "").strip()
        marca = (form.get("marca") or "").strip()

        recompensa_raw = (form.get("recompensa_unit") or "").strip()
        qtd_min_raw = (form.get("qtd_minima") or "").strip()
        valor_min_raw = (form.get("valor_minimo") or "").strip()
        fat_min_emp_raw = (form.get("faturamento_minimo_emp") or "").strip()

        data_ini_raw = (form.get("data_inicio") or "").strip()
        data_fim_raw = (form.get("data_fim") or "").strip()

        if campanha_tipo == "GERENTE":
            vendedor = None
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

        recompensa_unit = _to_dec(recompensa_raw, field_label="Recompensa")
        if recompensa_unit < 0:
            raise ValueError("Recompensa não pode ser negativa.")

        qtd_minima = _to_dec(qtd_min_raw, field_label="Quantidade mínima") if qtd_min_raw else None
        if qtd_minima is not None and qtd_minima < 0:
            raise ValueError("Quantidade mínima não pode ser negativa.")

        valor_minimo = _to_dec(valor_min_raw, field_label="Valor mínimo") if valor_min_raw else None
        if valor_minimo is not None and valor_minimo < 0:
            raise ValueError("Valor mínimo não pode ser negativo.")

        faturamento_minimo_emp = None
        if fat_min_emp_raw:
            faturamento_minimo_emp = _to_dec(fat_min_emp_raw, field_label="Faturamento mínimo da EMP")
            if faturamento_minimo_emp < 0:
                raise ValueError("Faturamento mínimo da EMP não pode ser negativo.")
        elif current_obj is not None and hasattr(current_obj, "faturamento_minimo_emp"):
            faturamento_minimo_emp = getattr(current_obj, "faturamento_minimo_emp", None)

        data_inicio = datetime.strptime(data_ini_raw, "%Y-%m-%d").date()
        data_fim = datetime.strptime(data_fim_raw, "%Y-%m-%d").date()
        if data_fim < data_inicio:
            raise ValueError("Data fim não pode ser menor que data início.")

        payload = {
            "emp": str(emp),
            "campanha_tipo": campanha_tipo,
            "vendedor": vendedor,
            "titulo": titulo,
            "produto_prefixo": (produto_prefixo or "").upper(),
            "descricao_prefixo": (descricao_prefixo or "").strip(),
            "campo_match": campo_match,
            "marca": marca.upper(),
            "recompensa_unit": float(recompensa_unit.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)),
            "qtd_minima": float(qtd_minima) if qtd_minima is not None else None,
            "valor_minimo": float(valor_minimo) if valor_minimo is not None else None,
            "data_inicio": data_inicio,
            "data_fim": data_fim,
        }
        if hasattr(CampanhaQtd, "faturamento_minimo_emp"):
            payload["faturamento_minimo_emp"] = float(faturamento_minimo_emp) if faturamento_minimo_emp not in (None, "") else None
        return payload

    def _apply_campaign_payload(obj, payload: dict[str, Any]) -> None:
        for key, value in payload.items():
            if hasattr(obj, key):
                setattr(obj, key, value)
        if hasattr(obj, "updated_at"):
            obj.updated_at = datetime.utcnow()

    def _get_campaign_id_from_form(form) -> int:
        return int(form.get("campanha_id") or form.get("id") or 0)

    def admin_campanhas_qtd():
        """Cadastro e administração de campanhas de recompensa por quantidade."""
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

                # Se a competência estiver FECHADA, bloqueia alterações de campanhas (mantém integridade do fechamento).
                try:
                    emp_post = (request.form.get("emp") or "").strip()
                    if not emp_post:
                        cid_check = _get_campaign_id_from_form(request.form)
                        if cid_check:
                            obj_check = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid_check).first()
                            if obj_check:
                                emp_post = (obj_check.emp or "").strip()
                    if emp_post and competencia_fechada_fn(db, emp_post, ano, mes):
                        return redirect('/admin/fechamento' + f'?emp={emp_post}&mes={mes}&ano={ano}')
                except Exception:
                    pass

                try:
                    if acao == "criar":
                        payload = _parse_campaign_payload(request.form)
                        db.add(CampanhaQtd(**payload, ativo=1))
                        db.commit()
                        ok = "Campanha cadastrada com sucesso."

                    elif acao == "editar":
                        cid = _get_campaign_id_from_form(request.form)
                        c = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                        if not c:
                            raise ValueError("Campanha não encontrada.")
                        payload = _parse_campaign_payload(request.form, current_obj=c)
                        _apply_campaign_payload(c, payload)
                        db.commit()
                        ok = "Campanha atualizada com sucesso."

                    elif acao == "duplicar":
                        cid = _get_campaign_id_from_form(request.form)
                        c = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                        if not c:
                            raise ValueError("Campanha não encontrada.")

                        clone_title = (request.form.get("titulo") or "").strip()
                        if not clone_title:
                            base_title = c.titulo or f"Campanha #{c.id}"
                            clone_title = f"Cópia — {base_title}"[:120]

                        data_inicio_raw = (request.form.get("data_inicio") or "").strip()
                        data_fim_raw = (request.form.get("data_fim") or "").strip()
                        data_inicio = datetime.strptime(data_inicio_raw, "%Y-%m-%d").date() if data_inicio_raw else c.data_inicio
                        data_fim = datetime.strptime(data_fim_raw, "%Y-%m-%d").date() if data_fim_raw else c.data_fim
                        if data_fim < data_inicio:
                            raise ValueError("Data fim não pode ser menor que data início.")

                        payload = {
                            "emp": c.emp,
                            "campanha_tipo": c.campanha_tipo or "VENDEDOR",
                            "vendedor": None if (c.campanha_tipo or "VENDEDOR") == "GERENTE" else c.vendedor,
                            "titulo": clone_title,
                            "produto_prefixo": c.produto_prefixo,
                            "descricao_prefixo": c.descricao_prefixo,
                            "campo_match": c.campo_match or "codigo",
                            "marca": c.marca,
                            "recompensa_unit": c.recompensa_unit or 0,
                            "qtd_minima": c.qtd_minima,
                            "valor_minimo": c.valor_minimo,
                            "data_inicio": data_inicio,
                            "data_fim": data_fim,
                        }
                        if hasattr(CampanhaQtd, "faturamento_minimo_emp"):
                            payload["faturamento_minimo_emp"] = getattr(c, "faturamento_minimo_emp", None)

                        # Segurança: cópia nasce inativa para evitar pagamento/cálculo duplicado sem revisão.
                        db.add(CampanhaQtd(**payload, ativo=0))
                        db.commit()
                        ok = "Campanha duplicada como inativa. Revise e ative quando estiver correta."

                    elif acao == "toggle":
                        cid = _get_campaign_id_from_form(request.form)
                        c = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                        if not c:
                            raise ValueError("Campanha não encontrada.")
                        c.ativo = 0 if int(c.ativo or 0) == 1 else 1
                        if hasattr(c, "updated_at"):
                            c.updated_at = datetime.utcnow()
                        db.commit()
                        ok = "Status da campanha atualizado."

                    elif acao == "remover":
                        cid = _get_campaign_id_from_form(request.form)
                        c = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                        if not c:
                            raise ValueError("Campanha não encontrada.")

                        # Remove também o histórico/snapshot mensal dessa campanha.
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
                        if hasattr(r, "updated_at"):
                            r.updated_at = datetime.utcnow()
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

        # UX: agrupa por competência (mês/ano) na lista.
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
