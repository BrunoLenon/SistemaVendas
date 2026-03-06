from __future__ import annotations

from datetime import datetime, date
from typing import Callable, Any

from flask import request, redirect, url_for, render_template


def register_admin_fechamento_routes(
    app,
    *,
    SessionLocal,
    Emp,
    FechamentoMensal,
    admin_required_fn: Callable[[], Any],
    parse_multi_args_fn: Callable[[str], list[str]],
    emp_norm_fn: Callable[[str], str],
    get_emps_com_vendas_no_periodo_fn: Callable[[int, int], list[str]],
    get_emp_options_fn: Callable[[list[str]], list[dict]],
    role_fn: Callable[[], str | None],
) -> None:
    """Registra as rotas do fechamento mensal (ADMIN).

    Refatoração pura: mantém URLs, endpoints, templates e comportamento.
    """

    # Aliases para manter o corpo da função o mais idêntico possível ao legado.
    _admin_required = admin_required_fn
    _parse_multi_args = parse_multi_args_fn
    _emp_norm = emp_norm_fn
    _get_emps_com_vendas_no_periodo = get_emps_com_vendas_no_periodo_fn
    _get_emp_options = get_emp_options_fn
    _role = role_fn

    def admin_fechamento():
        """Página dedicada de fechamento mensal (ADMIN).

        Responsável por travar/reativar a competência (EMP + mês/ano), servindo de base
        para relatórios consolidados e impedindo alterações em campanhas/resumos quando fechado.
        """
        red = _admin_required()
        if red:
            return red

        hoje = datetime.now()
        ano = int(request.values.get("ano") or hoje.year)
        mes = int(request.values.get("mes") or hoje.month)

        # multi-EMP: fecha em lote quando selecionar mais de uma EMP
        # multi-EMP: lê tanto querystring (?emp=101&emp=102) quanto POST (inputs hidden name=emp)
        emps_sel = []
        try:
            emps_sel = [str(e).strip() for e in request.values.getlist("emp") if str(e).strip()]
        except Exception:
            emps_sel = []
        if not emps_sel:
            emps_sel = [str(e).strip() for e in _parse_multi_args("emp") if str(e).strip()]
        if not emps_sel:
            # fallback: tenta usar emp único (mantém compatibilidade com versões antigas)
            emp_single = _emp_norm(request.values.get("emp", ""))
            emps_sel = [emp_single] if emp_single else []

        msgs: list[str] = []
        status_por_emp: dict[str, dict] = {}

        # Normaliza a ação vinda do formulário (alguns navegadores/JS podem enviar
        # variações, ex.: sem underscore, com hífen ou com espaços).
        acao_raw = (request.values.get("acao") or request.values.get("action") or request.form.get("acao") or "").strip().lower()
        acao = {
            "fechar_a_pagar": "fechar_a_pagar",
            "fechar_apagar": "fechar_a_pagar",
            "fechar-a-pagar": "fechar_a_pagar",
            "a_pagar": "fechar_a_pagar",
            "fechar_pago": "fechar_pago",
            "fechar-pago": "fechar_pago",
            "pago": "fechar_pago",
            "reabrir": "reabrir",
            "abrir": "reabrir",
        }.get(acao_raw, acao_raw)

        with SessionLocal() as db:
            # Carrega opções de EMP para o filtro (admin: todas cadastradas, fallback: EMPs com vendas no período)
            try:
                emps_all = [str(r.codigo).strip() for r in db.query(Emp).order_by(Emp.codigo.asc()).all()]
            except Exception:
                emps_all = []
            if not emps_all:
                try:
                    emps_all = _get_emps_com_vendas_no_periodo(ano, mes)
                except Exception:
                    emps_all = []

            if request.method == "POST" and acao in {"fechar_a_pagar", "fechar_pago", "reabrir"}:
                app.logger.info(
                    "FECHAMENTO POST: form=%s values=%s",
                    dict(request.form),
                    {k: request.values.getlist(k) for k in request.values.keys()},
                )
                if not emps_sel:
                    msgs.append("⚠️ Selecione ao menos 1 EMP para fechar/reabrir.")
                else:
                    alvo_status = None
                    updated_count = 0
                    if acao == "fechar_a_pagar":
                        alvo_status = "a_pagar"
                    elif acao == "fechar_pago":
                        alvo_status = "pago"
                    for emp in emps_sel:
                        emp = _emp_norm(emp)
                        if not emp:
                            continue
                        try:
                            rec = (
                                db.query(FechamentoMensal)
                                .filter(
                                    FechamentoMensal.emp == emp,
                                    FechamentoMensal.ano == int(ano),
                                    FechamentoMensal.mes == int(mes),
                                )
                                .first()
                            )
                            if not rec:
                                rec = FechamentoMensal(emp=emp, ano=int(ano), mes=int(mes), fechado=False)
                                db.add(rec)

                            if acao in {"fechar_a_pagar", "fechar_pago"}:
                                rec.fechado = True
                                rec.fechado_em = datetime.utcnow()
                                # status financeiro (controle)
                                if hasattr(rec, "status") and alvo_status:
                                    rec.status = alvo_status
                            else:
                                rec.fechado = False
                                rec.fechado_em = None  # reabrir zera timestamp
                                if hasattr(rec, "status"):
                                    rec.status = "aberto"
                            updated_count += 1
                            # commit no final do lote (mais rápido e consistente)
                        except Exception:
                            app.logger.exception("Erro ao preparar fechamento mensal")
                            msgs.append(f"❌ Falha ao atualizar fechamento da EMP {emp}.")
                    if updated_count > 0:
                        try:
                            db.commit()
                            msgs.append(f"✅ Operação concluída ({updated_count} EMPs).")

                            # PRG: evita reenvio e garante recarregar status
                            return redirect(url_for("admin_fechamento", emp=emps_sel, mes=mes, ano=ano))
                        except Exception:
                            db.rollback()
                            app.logger.exception("Erro ao commitar fechamento mensal")
                            msgs.append("❌ Falha ao salvar alterações no fechamento.")
                    else:
                        if not msgs:
                            msgs.append("⚠️ Nenhuma EMP válida para atualizar.")

            # Status para tela
            for emp in (emps_sel or []):
                emp = _emp_norm(emp)
                if not emp:
                    continue
                fechado = False
                fechado_em = None
                status_fin = "aberto"
                try:
                    rec = (
                        db.query(FechamentoMensal)
                        .filter(
                            FechamentoMensal.emp == emp,
                            FechamentoMensal.ano == int(ano),
                            FechamentoMensal.mes == int(mes),
                        )
                        .first()
                    )
                    if rec:
                        if getattr(rec, "status", None):
                            status_fin = rec.status
                        if rec.fechado:
                            fechado = True
                            fechado_em = rec.fechado_em
                except Exception:
                    fechado = False
                status_por_emp[emp] = {"fechado": fechado, "fechado_em": fechado_em, "status": status_fin}

        emps_options = _get_emp_options(emps_all)

        return render_template(
            "admin_fechamento.html",
            role=_role() or "",
            ano=ano,
            mes=mes,
            emps_sel=emps_sel,
            emps_options=emps_options,
            status_por_emp=status_por_emp,
            msgs=msgs,
        )

    app.add_url_rule(
        "/admin/fechamento",
        endpoint="admin_fechamento",
        view_func=admin_fechamento,
        methods=["GET", "POST"],
    )
