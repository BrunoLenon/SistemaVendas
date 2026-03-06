from __future__ import annotations

from datetime import datetime

import pandas as pd
from flask import request, session, render_template
from sqlalchemy import or_


def register_admin_resumos_periodo_routes(
    app,
    *,
    SessionLocal,
    Venda,
    VendasResumoPeriodo,
    FechamentoMensal,
    admin_required_fn,
    allowed_emps_fn,
    emp_norm_fn,
    parse_num_ptbr_fn,
    periodo_bounds_fn,
    mes_fechado_fn,
):
    """
    Rotas: Admin Resumos por Período.

    Refatoração pura:
    - mantém URLs e endpoints
    - mantém regras (fechamento, edição ano passado, import XLSX/CSV)
    - injeta dependências para evitar import circular
    """

    def admin_resumos_periodo():
        red = admin_required_fn()
        if red:
            return red

        # filtros
        emp = emp_norm_fn(request.values.get("emp", ""))
        vendedor = (request.values.get("vendedor") or "").strip().upper()
        ano = int(request.values.get("ano") or datetime.now().year)
        mes = int(request.values.get("mes") or datetime.now().month)

        msgs: list[str] = []

        acao = (request.form.get("acao") or "").strip().lower()
        if request.method == "POST" and acao:
            # alvo do POST (permite editar/cadastrar resumos em um período diferente do filtro)
            emp_alvo = emp_norm_fn(request.form.get("emp_edit") or emp)

            # Se a EMP não vier no POST (alguns modais não enviam), tenta inferir pelo escopo do usuário.
            # Importante para que Dashboard/Metas encontrem a base do ano passado corretamente.
            if not emp_alvo:
                try:
                    allowed_tmp = session.get("allowed_emps") or allowed_emps_fn()
                except Exception:
                    allowed_tmp = []
                if isinstance(allowed_tmp, (list, tuple)) and len(allowed_tmp) == 1:
                    emp_alvo = emp_norm_fn(allowed_tmp[0])

            try:
                ano_alvo = int(request.form.get("ano_edit") or ano)
            except Exception:
                ano_alvo = ano
            try:
                mes_alvo = int(request.form.get("mes_edit") or mes)
            except Exception:
                mes_alvo = mes

            ano_passado = ano - 1

            # Regra: permitir edição/importação manual apenas para anos anteriores ao ano filtrado.
            if acao in {"salvar", "excluir", "salvar_lote", "importar_xlsx"} and ano_alvo >= ano:
                msgs.append("⚠️ Edição/importação manual permitida apenas para anos anteriores ao ano filtrado.")
                acao = ""

            if acao in {"salvar", "excluir"} and mes_fechado_fn(emp_alvo, ano_alvo, mes_alvo):
                msgs.append("⚠️ Mês fechado. Reabra o mês para editar os resumos.")
            else:
                with SessionLocal() as db:
                    if acao == "fechar":
                        rec = (
                            db.query(FechamentoMensal)
                            .filter(
                                FechamentoMensal.emp == emp,
                                FechamentoMensal.ano == ano,
                                FechamentoMensal.mes == mes,
                            )
                            .one_or_none()
                        )
                        if rec is None:
                            rec = FechamentoMensal(
                                emp=emp, ano=ano, mes=mes, fechado=True, fechado_em=datetime.utcnow()
                            )
                            db.add(rec)
                        else:
                            rec.fechado = True
                            rec.fechado_em = datetime.utcnow()
                        db.commit()
                        msgs.append("✅ Mês fechado. Edição travada.")

                    elif acao == "reabrir":
                        rec = (
                            db.query(FechamentoMensal)
                            .filter(
                                FechamentoMensal.emp == emp,
                                FechamentoMensal.ano == ano,
                                FechamentoMensal.mes == mes,
                            )
                            .one_or_none()
                        )
                        if rec is None:
                            rec = FechamentoMensal(emp=emp, ano=ano, mes=mes, fechado=False)
                            db.add(rec)
                        else:
                            rec.fechado = False
                        db.commit()
                        msgs.append("✅ Mês reaberto. Edição liberada.")

                    elif acao == "salvar":
                        vend = (request.form.get("vendedor_edit") or "").strip().upper()
                        if not vend:
                            msgs.append("⚠️ Informe o vendedor.")
                        else:
                            try:
                                valor_venda = parse_num_ptbr_fn(request.form.get("valor_venda"))
                            except Exception:
                                valor_venda = 0.0
                            try:
                                mix_produtos = int(request.form.get("mix_produtos") or 0)
                            except Exception:
                                mix_produtos = 0

                            rec = (
                                db.query(VendasResumoPeriodo)
                                .filter(
                                    VendasResumoPeriodo.emp == emp_alvo,
                                    VendasResumoPeriodo.vendedor == vend,
                                    VendasResumoPeriodo.ano == ano_alvo,
                                    VendasResumoPeriodo.mes == mes_alvo,
                                )
                                .one_or_none()
                            )
                            if rec is None:
                                rec = VendasResumoPeriodo(
                                    emp=emp_alvo,
                                    vendedor=vend,
                                    ano=ano_alvo,
                                    mes=mes_alvo,
                                    valor_venda=valor_venda,
                                    mix_produtos=mix_produtos,
                                    created_at=datetime.utcnow(),
                                    updated_at=datetime.utcnow(),
                                )
                                db.add(rec)
                            else:
                                rec.valor_venda = valor_venda
                                rec.mix_produtos = mix_produtos
                                rec.updated_at = datetime.utcnow()
                            db.commit()
                            msgs.append("✅ Resumo salvo.")

                    elif acao == "salvar_lote":
                        # Cadastro em lote destinado ao ano passado (ano-1), permitindo informar MÊS por linha.
                        # Campos esperados: vendedor_lote, mes_ref, valor_venda_lote, mix_produtos_lote (listas)
                        emp_lote = emp_norm_fn(request.form.get("emp_edit") or emp)
                        ano_lote = ano_alvo

                        vendedores_l = [(v or "").strip().upper() for v in request.form.getlist("vendedor_lote")]
                        meses_l = request.form.getlist("mes_ref")
                        valores_l = request.form.getlist("valor_venda_lote")
                        mix_l = request.form.getlist("mix_produtos_lote")

                        total_linhas = max(len(vendedores_l), len(meses_l), len(valores_l), len(mix_l))

                        # Normaliza tamanhos
                        def _get(lst, i, default=""):
                            try:
                                return lst[i]
                            except Exception:
                                return default

                        salvos = 0
                        pulados = 0
                        fechados = 0

                        for i in range(total_linhas):
                            vend = _get(vendedores_l, i, "").strip().upper()
                            if not vend:
                                pulados += 1
                                continue
                            try:
                                mes_ref = int(str(_get(meses_l, i, mes)).strip() or mes)
                            except Exception:
                                mes_ref = mes
                            if mes_ref < 1 or mes_ref > 12:
                                msgs.append(f"⚠️ Linha {i+1}: mês inválido ({_get(meses_l, i, '')}).")
                                pulados += 1
                                continue

                            # Mês fechado? trava edição para aquele mês
                            if mes_fechado_fn(emp_lote, ano_lote, mes_ref):
                                fechados += 1
                                continue

                            try:
                                valor_venda = parse_num_ptbr_fn(str(_get(valores_l, i, "0")))
                            except Exception:
                                valor_venda = 0.0
                            try:
                                mix_produtos = int(str(_get(mix_l, i, "0")).strip() or 0)
                            except Exception:
                                mix_produtos = 0

                            rec = (
                                db.query(VendasResumoPeriodo)
                                .filter(
                                    VendasResumoPeriodo.emp == emp_lote,
                                    VendasResumoPeriodo.vendedor == vend,
                                    VendasResumoPeriodo.ano == ano_lote,
                                    VendasResumoPeriodo.mes == mes_ref,
                                )
                                .one_or_none()
                            )
                            if rec is None:
                                rec = VendasResumoPeriodo(
                                    emp=emp_lote,
                                    vendedor=vend,
                                    ano=ano_lote,
                                    mes=mes_ref,
                                    valor_venda=valor_venda,
                                    mix_produtos=mix_produtos,
                                    created_at=datetime.utcnow(),
                                    updated_at=datetime.utcnow(),
                                )
                                db.add(rec)
                            else:
                                rec.valor_venda = valor_venda
                                rec.mix_produtos = mix_produtos
                                rec.updated_at = datetime.utcnow()
                            salvos += 1

                        db.commit()
                        if fechados:
                            msgs.append(
                                f"⚠️ {fechados} linha(s) não foram salvas porque o mês está fechado."
                            )
                        msgs.append(
                            f"✅ Lote concluído: {salvos} salvo(s), {pulados} linha(s) em branco/ inválida(s)."
                        )

                    elif acao == "importar_xlsx":
                        # Importação de resumos por Excel (.xlsx) / CSV
                        # Colunas aceitas (case-insensitive):
                        # ANO, MES, EMP(opcional), VENDEDOR, VALOR_VENDA/VALOR, MIX
                        file = request.files.get("arquivo")
                        if not file or not getattr(file, "filename", ""):
                            msgs.append("⚠️ Selecione um arquivo .xlsx ou .csv para importar.")
                        else:
                            filename = (file.filename or "").lower()
                            try:
                                if filename.endswith(".csv"):
                                    df = pd.read_csv(file, dtype=str)
                                else:
                                    df = pd.read_excel(file, dtype=str)
                            except Exception:
                                msgs.append("❌ Não consegui ler o arquivo. Verifique se é um .xlsx válido.")
                                df = None

                            if df is not None:
                                # normaliza colunas
                                cols = {c.strip().upper(): c for c in df.columns}

                                def _col(*names):
                                    for n in names:
                                        if n in cols:
                                            return cols[n]
                                    return None

                                c_ano = _col("ANO")
                                c_mes = _col("MES", "MÊS")
                                c_emp = _col("EMP")
                                c_vend = _col("VENDEDOR", "VEND", "VENDEDOR_NOME")
                                c_val = _col("VALOR_VENDA", "VALOR", "VALORVENDA")
                                c_mix = _col("MIX")

                                if not c_ano or not c_mes or not c_vend or not c_val:
                                    msgs.append(
                                        "❌ Colunas obrigatórias: ANO, MES, VENDEDOR, VALOR_VENDA (ou VALOR)."
                                    )
                                else:
                                    total = 0
                                    salvos = 0
                                    pulados = 0
                                    fechados = 0

                                    for _, row in df.iterrows():
                                        total += 1
                                        try:
                                            ano_ref = int(str(row.get(c_ano, "")).strip())
                                            mes_ref = int(str(row.get(c_mes, "")).strip())
                                        except Exception:
                                            pulados += 1
                                            continue
                                        if mes_ref < 1 or mes_ref > 12:
                                            pulados += 1
                                            continue

                                        vend = str(row.get(c_vend, "")).strip().upper()
                                        if not vend:
                                            pulados += 1
                                            continue

                                        emp_ref = emp  # padrão do filtro, se vier em branco
                                        if c_emp:
                                            raw_emp = str(row.get(c_emp, "")).strip()
                                            if raw_emp.lower() in {"nan", "none", "null"}:
                                                raw_emp = ""
                                            emp_ref = emp_norm_fn(raw_emp) or emp

                                        # regra: não permite importar para ano atual/futuro
                                        if ano_ref >= ano:
                                            pulados += 1
                                            continue

                                        if mes_fechado_fn(emp_ref, ano_ref, mes_ref):
                                            fechados += 1
                                            continue

                                        valor_venda = parse_num_ptbr_fn(str(row.get(c_val, "0")))
                                        try:
                                            if c_mix:
                                                raw_mix = str(row.get(c_mix, "")).strip()
                                                if raw_mix.lower() in {"", "nan", "none", "null"}:
                                                    mix_produtos = 0
                                                else:
                                                    try:
                                                        mix_produtos = int(float(raw_mix.replace(",", ".")))
                                                    except Exception:
                                                        mix_produtos = 0
                                            else:
                                                mix_produtos = 0
                                        except Exception:
                                            mix_produtos = 0

                                        rec = (
                                            db.query(VendasResumoPeriodo)
                                            .filter(
                                                VendasResumoPeriodo.emp == emp_ref,
                                                VendasResumoPeriodo.vendedor == vend,
                                                VendasResumoPeriodo.ano == ano_ref,
                                                VendasResumoPeriodo.mes == mes_ref,
                                            )
                                            .one_or_none()
                                        )
                                        if rec is None:
                                            rec = VendasResumoPeriodo(
                                                emp=emp_ref,
                                                vendedor=vend,
                                                ano=ano_ref,
                                                mes=mes_ref,
                                                valor_venda=valor_venda,
                                                mix_produtos=mix_produtos,
                                                created_at=datetime.utcnow(),
                                                updated_at=datetime.utcnow(),
                                            )
                                            db.add(rec)
                                        else:
                                            rec.valor_venda = valor_venda
                                            rec.mix_produtos = mix_produtos
                                            rec.updated_at = datetime.utcnow()
                                        salvos += 1

                                    db.commit()
                                    if fechados:
                                        msgs.append(f"⚠️ {fechados} linha(s) não importadas: mês fechado.")
                                    msgs.append(
                                        f"✅ Importação concluída: {salvos} salvo(s) de {total} linha(s). {pulados} pulada(s)."
                                    )

                    elif acao == "excluir":
                        vend = (request.form.get("vendedor_edit") or "").strip().upper()
                        if not vend:
                            msgs.append("⚠️ Informe o vendedor para excluir.")
                        else:
                            rec = (
                                db.query(VendasResumoPeriodo)
                                .filter(
                                    VendasResumoPeriodo.emp == emp_alvo,
                                    VendasResumoPeriodo.vendedor == vend,
                                    VendasResumoPeriodo.ano == ano_alvo,
                                    VendasResumoPeriodo.mes == mes_alvo,
                                )
                                .one_or_none()
                            )
                            if rec is None:
                                msgs.append("⚠️ Não encontrei esse resumo para excluir.")
                            else:
                                db.delete(rec)
                                db.commit()
                                msgs.append("✅ Resumo excluído.")

        # carregar lista e status de fechamento
        fechado = mes_fechado_fn(emp, ano, mes)
        with SessionLocal() as db:
            # EMP e vendedor são opcionais: quando vierem em branco, listamos TODOS.
            q = db.query(VendasResumoPeriodo).filter(
                VendasResumoPeriodo.ano == ano,
                VendasResumoPeriodo.mes == mes,
            )
            if emp:
                q = q.filter(or_(VendasResumoPeriodo.emp == emp, VendasResumoPeriodo.emp.in_(["", "EMPTY"])))
            if vendedor:
                q = q.filter(VendasResumoPeriodo.vendedor == vendedor)
            registros = q.order_by(VendasResumoPeriodo.vendedor.asc()).all()

            # Resumos do mesmo período no ano passado (ano-1) para conferência/edição rápida
            ano_passado = ano - 1
            q2 = db.query(VendasResumoPeriodo).filter(
                VendasResumoPeriodo.ano == ano_passado,
            )
            if emp:
                q2 = q2.filter(or_(VendasResumoPeriodo.emp == emp, VendasResumoPeriodo.emp.in_(["", "EMPTY"])))
            if vendedor:
                q2 = q2.filter(VendasResumoPeriodo.vendedor == vendedor)

            # Carrega TODOS os meses do ano passado (ano-1) para permitir cadastro/edição independente do mês atual.
            _res_all = q2.order_by(VendasResumoPeriodo.mes.asc(), VendasResumoPeriodo.vendedor.asc()).all()

            resumos_ano_passado_por_mes = {m: [] for m in range(1, 13)}
            for r in _res_all:
                try:
                    resumos_ano_passado_por_mes[int(r.mes)].append(r)
                except Exception:
                    pass

            # contagem por mês (para renderizar os "chips")
            counts_ano_passado = {m: len(resumos_ano_passado_por_mes.get(m, [])) for m in range(1, 13)}

            # Sugestão rápida de vendedores (com base em vendas do período)
            # Ajuda o admin a não digitar errado
            start, end = periodo_bounds_fn(ano, mes)
            vs_q = db.query(Venda.vendedor).filter(Venda.movimento >= start, Venda.movimento < end)
            if emp:
                vs_q = vs_q.filter(Venda.emp == emp)
            vendedores_sugeridos = vs_q.distinct().order_by(Venda.vendedor.asc()).all()
            vendedores_sugeridos = [v[0] for v in vendedores_sugeridos if v and v[0]]

        return render_template(
            "admin_resumos_periodo.html",
            emp=emp,
            ano=ano,
            mes=mes,
            vendedor_filtro=vendedor,
            registros=registros,
            rows=registros,
            vendedor=vendedor,
            ano_passado=ano_passado,
            resumos_ano_passado_por_mes=resumos_ano_passado_por_mes,
            counts_ano_passado=counts_ano_passado,
            fechado=fechado,
            vendedores_sugeridos=vendedores_sugeridos,
            msgs=msgs,
        )

    app.add_url_rule(
        "/admin/resumos_periodo",
        endpoint="admin_resumos_periodo",
        view_func=admin_resumos_periodo,
        methods=["GET", "POST"],
    )
