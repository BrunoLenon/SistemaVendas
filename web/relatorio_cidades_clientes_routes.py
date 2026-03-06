# -*- coding: utf-8 -*-
"""Rotas do Relatório: Cidades & Clientes.

Extraído do app.py como refatoração pura (sem alterar comportamento externo).
- Mantém os mesmos paths
- Mantém os mesmos nomes de endpoint usados em url_for(...)
"""

from __future__ import annotations

from datetime import date
from typing import Callable, Any

from flask import jsonify, render_template, request
from sqlalchemy import case, extract, func, or_, text

from db import SessionLocal, Venda


def register_relatorio_cidades_clientes_routes(
    app,
    *,
    login_required_fn: Callable[[], Any],
    role_fn: Callable[[], str | None],
    emp_fn: Callable[[], str | None],
    allowed_emps_fn: Callable[[], list[str]],
    usuario_logado_fn: Callable[[], str | None],
) -> None:
    """Registra rotas do relatório Cidades & Clientes.

    Importante: não usa Blueprint para não alterar nomes de endpoints.
    Endpoints são fixados explicitamente para 100% backward compatibility.
    """

    def relatorio_cidades_clientes():
        """Relatórios por EMP (Cidades e Clientes) — mês/ano.

        Permissões:
        - ADMIN: todas as EMPs (pode filtrar por EMP e vendedor)
        - SUPERVISOR: apenas EMP vinculada (pode filtrar por vendedor)
        - VENDEDOR: apenas o próprio vendedor (agrupado por EMP)
        """
        red = login_required_fn()
        if red:
            return red

        role = (role_fn() or "").strip().lower()
        emp_usuario = emp_fn()
        vendedor_logado = (usuario_logado_fn() or "").strip().upper()

        hoje = date.today()
        mes = int(request.args.get("mes") or hoje.month)
        ano = int(request.args.get("ano") or hoje.year)

        emp_filtro = (request.args.get("emp") or "").strip()
        vendedor_filtro = (request.args.get("vendedor") or "").strip().upper()

        # janela do período
        inicio = date(ano, mes, 1)
        fim = date(ano + 1, 1, 1) if mes == 12 else date(ano, mes + 1, 1)

        db = SessionLocal()
        try:
            base = db.query(Venda).filter(Venda.movimento >= inicio, Venda.movimento < fim)
            base_hist = db.query(Venda).filter(Venda.movimento.isnot(None))

            escopo_label = None
            pode_filtrar_emp = False
            pode_filtrar_vendedor = False

            if role == "admin":
                pode_filtrar_emp = True
                pode_filtrar_vendedor = True
                if emp_filtro:
                    base = base.filter(Venda.emp == emp_filtro)
                    base_hist = base_hist.filter(Venda.emp == emp_filtro)
                    escopo_label = f"EMP {emp_filtro}"
                if vendedor_filtro:
                    base = base.filter(func.upper(Venda.vendedor) == vendedor_filtro)
                    base_hist = base_hist.filter(func.upper(Venda.vendedor) == vendedor_filtro)
                    escopo_label = (escopo_label + " • " if escopo_label else "") + f"Vendedor {vendedor_filtro}"

            elif role == "supervisor":
                # Supervisor: acesso às Empresas vinculadas via usuario_emps (pode ser 1 ou várias)
                allowed_emps = allowed_emps_fn()
                if allowed_emps:
                    base = base.filter(Venda.emp.in_(allowed_emps))
                    base_hist = base_hist.filter(Venda.emp.in_(allowed_emps))
                    # permite filtrar por uma Empresa específica dentro do escopo
                    if emp_filtro and emp_filtro in allowed_emps:
                        base = base.filter(Venda.emp == emp_filtro)
                        base_hist = base_hist.filter(Venda.emp == emp_filtro)
                        escopo_label = f"Empresa {emp_filtro}"
                    else:
                        escopo_label = "Empresas vinculadas"
                else:
                    # sem Empresas vinculadas -> sem dados
                    base = base.filter(text("1=0"))
                    base_hist = base_hist.filter(text("1=0"))
                    escopo_label = "Sem empresas vinculadas"
                pode_filtrar_vendedor = True
                if vendedor_filtro:
                    base = base.filter(func.upper(Venda.vendedor) == vendedor_filtro)
                    base_hist = base_hist.filter(func.upper(Venda.vendedor) == vendedor_filtro)
                    escopo_label += f" • Vendedor {vendedor_filtro}"

            else:
                base = base.filter(func.upper(Venda.vendedor) == vendedor_logado)
                base_hist = base_hist.filter(func.upper(Venda.vendedor) == vendedor_logado)
                escopo_label = f"Vendedor {vendedor_logado}"

            # EMPs no período
            emps = [
                str(e[0])
                for e in base.with_entities(Venda.emp).distinct().order_by(Venda.emp).all()
                if e[0] is not None
            ]

            # Totais por EMP
            totais_rows = (
                base.with_entities(
                    Venda.emp.label("emp"),
                    func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor_total"),
                    func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd_total"),
                    func.coalesce(func.count(func.distinct(Venda.mestre)), 0).label("mix_itens"),
                    func.count(func.distinct(func.upper(Venda.vendedor))).label("vendedores"),
                    func.count(func.distinct(Venda.cliente_id_norm)).label("clientes_unicos"),
                    func.count(func.distinct(Venda.cidade_norm)).label("cidades"),
                )
                .group_by(Venda.emp)
                .all()
            )
            totais_map = {
                str(r.emp): {
                    "valor_total": float(r.valor_total or 0.0),
                    "qtd_total": float(r.qtd_total or 0.0),
                    "mix_itens": int(getattr(r, "mix_itens", 0) or 0),
                    "vendedores": int(r.vendedores or 0),
                    "clientes_unicos": int(r.clientes_unicos or 0),
                    "cidades": int(r.cidades or 0),
                }
                for r in totais_rows
            }

            # Ranking de cidades por EMP
            city_rows = (
                base.with_entities(
                    Venda.emp.label("emp"),
                    func.coalesce(Venda.cidade_norm, "sem_cidade").label("cidade_norm"),
                    func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor_total"),
                    func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd_total"),
                    func.coalesce(func.count(func.distinct(Venda.mestre)), 0).label("mix_itens"),
                    func.count(func.distinct(Venda.cliente_id_norm)).label("clientes_unicos"),
                )
                .group_by(Venda.emp, func.coalesce(Venda.cidade_norm, "sem_cidade"))
                .order_by(Venda.emp, func.sum(Venda.valor_total).desc())
                .all()
            )

            cidades_por_emp: dict[str, list[dict[str, Any]]] = {}
            for r in city_rows:
                emp = str(r.emp)
                total_emp = (totais_map.get(emp, {}) or {}).get("valor_total", 0.0) or 0.0
                cidade_norm = r.cidade_norm
                label = "SEM CIDADE" if (cidade_norm in (None, "", "sem_cidade")) else str(cidade_norm).upper()
                valor = float(r.valor_total or 0.0)
                pct = (valor / total_emp * 100.0) if total_emp > 0 else 0.0
                cidades_por_emp.setdefault(emp, []).append(
                    {
                        "cidade_norm": cidade_norm,
                        "cidade_label": label,
                        "valor_total": valor,
                        "pct": pct,
                        "qtd_total": float(r.qtd_total or 0.0),
                        "mix_itens": int(getattr(r, "mix_itens", 0) or 0),
                        "clientes_unicos": int(r.clientes_unicos or 0),
                    }
                )

            # Top clientes por EMP (por valor no período)
            signed_val = case(
                (Venda.mov_tipo_movto.in_(["DS", "CA"]), -Venda.valor_total),
                else_=Venda.valor_total,
            )

            cliente_rows = (
                base.with_entities(
                    Venda.emp.label("emp"),
                    Venda.cliente_id_norm.label("cliente_id"),
                    func.coalesce(func.max(Venda.razao), "").label("cliente_label"),
                    func.coalesce(func.max(Venda.razao_norm), "").label("razao_norm"),
                    func.coalesce(func.sum(signed_val), 0.0).label("valor_total"),
                    func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd_total"),
                    func.coalesce(func.count(func.distinct(Venda.mestre)), 0).label("mix_itens"),
                )
                .filter(Venda.cliente_id_norm.isnot(None))
                .group_by(Venda.emp, Venda.cliente_id_norm)
                .order_by(Venda.emp, func.coalesce(func.sum(signed_val), 0.0).desc())
                .all()
            )

            clientes_por_emp: dict[str, list[dict[str, Any]]] = {}
            for r in cliente_rows:
                emp = str(r.emp)
                cliente_id = str(getattr(r, "cliente_id", "") or "").strip()
                label = (getattr(r, "cliente_label", "") or "").strip() or cliente_id or "SEM CLIENTE"
                clientes_por_emp.setdefault(emp, []).append(
                    {
                        "cliente_id": cliente_id,
                        "cliente_label": label,
                        "razao_norm": (getattr(r, "razao_norm", "") or "").strip(),
                        "valor_total": float(r.valor_total or 0.0),
                        "qtd_total": float(r.qtd_total or 0.0),
                        "mix_itens": int(getattr(r, "mix_itens", 0) or 0),
                    }
                )

            # Clientes novos vs recorrentes por EMP
            clientes_periodo = (
                base.with_entities(
                    Venda.emp.label("emp"),
                    Venda.cliente_id_norm.label("cid"),
                )
                .filter(Venda.cliente_id_norm.isnot(None))
                .distinct()
                .subquery()
            )

            min_datas = (
                base_hist.with_entities(
                    Venda.emp.label("emp"),
                    Venda.cliente_id_norm.label("cid"),
                    func.min(Venda.movimento).label("min_data"),
                )
                .filter(Venda.cliente_id_norm.isnot(None))
                .group_by(Venda.emp, Venda.cliente_id_norm)
                .subquery()
            )

            novos_rows = (
                db.query(clientes_periodo.c.emp.label("emp"), func.count().label("qtd"))
                .select_from(
                    clientes_periodo.join(
                        min_datas,
                        (clientes_periodo.c.emp == min_datas.c.emp) & (clientes_periodo.c.cid == min_datas.c.cid),
                    )
                )
                .filter(min_datas.c.min_data >= inicio)
                .group_by(clientes_periodo.c.emp)
                .all()
            )
            recorr_rows = (
                db.query(clientes_periodo.c.emp.label("emp"), func.count().label("qtd"))
                .select_from(
                    clientes_periodo.join(
                        min_datas,
                        (clientes_periodo.c.emp == min_datas.c.emp) & (clientes_periodo.c.cid == min_datas.c.cid),
                    )
                )
                .filter(min_datas.c.min_data < inicio)
                .group_by(clientes_periodo.c.emp)
                .all()
            )
            novos_map = {str(r.emp): int(r.qtd or 0) for r in novos_rows}
            recorr_map = {str(r.emp): int(r.qtd or 0) for r in recorr_rows}

            # Cards por EMP (preview + detalhe)
            emp_cards: list[dict[str, Any]] = []
            for emp in emps:
                t = totais_map.get(emp) or {"valor_total": 0.0, "qtd_total": 0.0, "vendedores": 0, "clientes_unicos": 0, "cidades": 0}
                cities_full = cidades_por_emp.get(emp, [])
                clients_full = clientes_por_emp.get(emp, [])

                emp_cards.append(
                    {
                        "emp": emp,
                        "image_url": None,  # preparado para imagem da loja futuramente
                        "totais": {
                            **t,
                            "clientes_novos": novos_map.get(emp, 0),
                            "clientes_recorrentes": recorr_map.get(emp, 0),
                        },
                        "cidades_preview": cities_full[:5],
                        "cidades_full": cities_full,
                        "clientes_preview": clients_full[:5],
                        "clientes_full": clients_full,
                    }
                )

            return render_template(
                "relatorio_cidades_clientes.html",
                mes=mes,
                ano=ano,
                escopo_label=escopo_label,
                pode_filtrar_emp=pode_filtrar_emp,
                pode_filtrar_vendedor=pode_filtrar_vendedor,
                emp_filtro=emp_filtro,
                vendedor_filtro=vendedor_filtro,
                emp_cards=emp_cards,
            )
        finally:
            db.close()

    def relatorio_cidade_clientes_api():
        """Retorna JSON com ranking de clientes dentro de uma cidade no período.

        Parâmetros:
          - emp (obrigatório)
          - cidade_norm (obrigatório; use 'sem_cidade' para vazio)
          - mes, ano (obrigatórios)
          - vendedor (opcional, ADMIN/SUPERVISOR)
        """
        red = login_required_fn()
        if red:
            return red

        role = (role_fn() or "").strip().lower()
        emp_usuario = emp_fn()
        vendedor_logado = (usuario_logado_fn() or "").strip().upper()

        emp = (request.args.get("emp") or "").strip()
        cidade_norm = (request.args.get("cidade_norm") or "").strip()
        mes = int(request.args.get("mes") or 0)
        ano = int(request.args.get("ano") or 0)
        vendedor = (request.args.get("vendedor") or "").strip().upper()

        if not emp or not cidade_norm or not mes or not ano:
            return jsonify({"error": "Parâmetros inválidos"}), 400

        # Permissões
        if role == "supervisor":
            allowed_emps = allowed_emps_fn()
            if allowed_emps and str(emp) not in set(allowed_emps):
                return jsonify({"error": "Acesso negado"}), 403
        elif role == "vendedor":
            vendedor = vendedor_logado

        inicio = date(int(ano), int(mes), 1)
        fim = date(int(ano) + 1, 1, 1) if int(mes) == 12 else date(int(ano), int(mes) + 1, 1)

        signed_val = case(
            (Venda.mov_tipo_movto.in_(["DS", "CA"]), -Venda.valor_total),
            else_=Venda.valor_total,
        )

        with SessionLocal() as db:
            base = db.query(Venda).filter(
                Venda.emp == str(emp),
                Venda.movimento >= inicio,
                Venda.movimento < fim,
            )

            if cidade_norm == "sem_cidade":
                base = base.filter(or_(Venda.cidade_norm.is_(None), Venda.cidade_norm == "", Venda.cidade_norm == "sem_cidade"))
            else:
                base = base.filter(Venda.cidade_norm == cidade_norm)

            if vendedor:
                base = base.filter(func.upper(Venda.vendedor) == vendedor)

            rows = (
                base.with_entities(
                    Venda.cliente_id_norm.label("cliente_id"),
                    func.coalesce(func.max(Venda.razao), "").label("cliente"),
                    func.coalesce(func.sum(signed_val), 0.0).label("valor_total"),
                    func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd_total"),
                    func.count(func.distinct(Venda.mestre)).label("mix_itens"),
                )
                .filter(Venda.cliente_id_norm.isnot(None))
                .group_by(Venda.cliente_id_norm)
                .order_by(func.coalesce(func.sum(signed_val), 0.0).desc())
                .all()
            )

        out: list[dict[str, Any]] = []
        for r in rows:
            label = (r.cliente or "").strip() or str(r.cliente_id)
            out.append(
                {
                    "cliente_id": str(r.cliente_id),
                    "cliente": label,
                    "valor_total": float(r.valor_total or 0.0),
                    "qtd_total": float(r.qtd_total or 0.0),
                    "mix_itens": int(r.mix_itens or 0),
                }
            )

        return jsonify({"emp": emp, "cidade_norm": cidade_norm, "ano": ano, "mes": mes, "clientes": out})

    def relatorio_cliente_marcas_api():
        """Retorna JSON com participação por marca para um cliente (RAZAO_NORM) no período."""
        red = login_required_fn()
        if red:
            return red

        role = (role_fn() or "").strip().lower()
        allowed_emps = allowed_emps_fn()
        vendedor_logado = (usuario_logado_fn() or "").strip().upper()

        emp = (request.args.get("emp") or "").strip()
        # compat: o front antigo mandava razao_norm; o novo usa cliente_id (cliente_id_norm)
        razao_norm = (request.args.get("razao_norm") or "").strip()
        cliente_id = (request.args.get("cliente_id") or request.args.get("cliente") or "").strip()
        cidade_norm = (request.args.get("cidade_norm") or "").strip()
        mes = int(request.args.get("mes") or 0)
        ano = int(request.args.get("ano") or 0)
        vendedor = (request.args.get("vendedor") or "").strip().upper()

        # Requer emp + (razao_norm ou cliente_id) + período
        if not emp or (not razao_norm and not cliente_id) or not mes or not ano:
            return jsonify({"error": "Parâmetros inválidos"}), 400

        # Permissões
        if role == "supervisor":
            if allowed_emps and str(emp) not in [str(e) for e in allowed_emps]:
                return jsonify({"error": "Acesso negado"}), 403
        elif role == "vendedor":
            vendedor = vendedor_logado  # vendedor não pode consultar outro vendedor

        with SessionLocal() as db:
            base = db.query(Venda).filter(
                Venda.emp == str(emp),
                extract("month", Venda.movimento) == mes,
                extract("year", Venda.movimento) == ano,
            )

            # Identificação do cliente (compat)
            if cliente_id and razao_norm:
                base = base.filter(or_(Venda.cliente_id_norm == cliente_id, Venda.razao_norm == razao_norm))
            elif cliente_id:
                base = base.filter(Venda.cliente_id_norm == cliente_id)
            elif razao_norm:
                base = base.filter(Venda.razao_norm == razao_norm)
            else:
                return jsonify({"error": "Parâmetros inválidos"}), 400

            # Cidade (opcional)
            if cidade_norm:
                if cidade_norm == "sem_cidade":
                    base = base.filter(or_(Venda.cidade_norm.is_(None), Venda.cidade_norm == "", Venda.cidade_norm == "sem_cidade"))
                else:
                    base = base.filter(Venda.cidade_norm == cidade_norm)

            if vendedor:
                base = base.filter(func.upper(Venda.vendedor) == vendedor)

            signed_val = case(
                (Venda.mov_tipo_movto.in_(["DS", "CA"]), -Venda.valor_total),
                else_=Venda.valor_total,
            )

            rows = (
                base.with_entities(
                    func.coalesce(Venda.marca, "SEM MARCA").label("marca"),
                    func.coalesce(func.sum(signed_val), 0.0).label("valor_total"),
                    func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd_total"),
                    func.count(func.distinct(Venda.mestre)).label("mix_itens"),
                )
                .group_by(func.coalesce(Venda.marca, "SEM MARCA"))
                .order_by(func.coalesce(func.sum(signed_val), 0.0).desc())
                .all()
            )

        out: list[dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "marca": (r.marca or "SEM MARCA").strip(),
                    "valor_total": float(r.valor_total or 0.0),
                    "qtd_total": float(r.qtd_total or 0.0),
                    "mix_itens": int(r.mix_itens or 0),
                }
            )

        return jsonify(
            {
                "emp": emp,
                "cliente_id": cliente_id,
                "razao_norm": razao_norm,
                "cidade_norm": cidade_norm,
                "ano": ano,
                "mes": mes,
                "marcas": out,
            }
        )

    def relatorio_cliente_marca_itens_api():
        """Retorna JSON com itens comprados por um cliente filtrado por marca no período."""
        red = login_required_fn()
        if red:
            return red

        role = (role_fn() or "").strip().lower()
        allowed_emps = allowed_emps_fn()
        vendedor_logado = (usuario_logado_fn() or "").strip().upper()

        emp = (request.args.get("emp") or "").strip()
        marca = (request.args.get("marca") or "").strip()
        razao_norm = (request.args.get("razao_norm") or "").strip()
        cliente_id = (request.args.get("cliente_id") or request.args.get("cliente") or "").strip()
        cidade_norm = (request.args.get("cidade_norm") or "").strip()
        mes = int(request.args.get("mes") or 0)
        ano = int(request.args.get("ano") or 0)
        vendedor = (request.args.get("vendedor") or "").strip().upper()

        if not emp or not marca or (not razao_norm and not cliente_id) or not mes or not ano:
            return jsonify({"error": "Parâmetros inválidos"}), 400

        # Permissões
        if role == "supervisor":
            if allowed_emps and str(emp) not in [str(e) for e in allowed_emps]:
                return jsonify({"error": "Acesso negado"}), 403
        elif role == "vendedor":
            vendedor = vendedor_logado  # vendedor não pode consultar outro vendedor

        with SessionLocal() as db:
            base = db.query(Venda).filter(
                Venda.emp == str(emp),
                extract("month", Venda.movimento) == mes,
                extract("year", Venda.movimento) == ano,
            )

            # Identificação do cliente (compat)
            if cliente_id and razao_norm:
                base = base.filter(or_(Venda.cliente_id_norm == cliente_id, Venda.razao_norm == razao_norm))
            elif cliente_id:
                base = base.filter(Venda.cliente_id_norm == cliente_id)
            elif razao_norm:
                base = base.filter(Venda.razao_norm == razao_norm)
            else:
                return jsonify({"error": "Parâmetros inválidos"}), 400

            # Cidade (opcional)
            if cidade_norm:
                if cidade_norm == "sem_cidade":
                    base = base.filter(or_(Venda.cidade_norm.is_(None), Venda.cidade_norm == "", Venda.cidade_norm == "sem_cidade"))
                else:
                    base = base.filter(Venda.cidade_norm == cidade_norm)

            if vendedor:
                base = base.filter(func.upper(Venda.vendedor) == vendedor)

            # Marca
            if marca.upper() in ("SEM MARCA", "SEM_MARCA"):
                base = base.filter(or_(Venda.marca.is_(None), Venda.marca == "", Venda.marca == "SEM MARCA"))
            else:
                base = base.filter(Venda.marca == marca)

            signed_val = case(
                (Venda.mov_tipo_movto.in_(["DS", "CA"]), -Venda.valor_total),
                else_=Venda.valor_total,
            )
            signed_qtd = case(
                (Venda.mov_tipo_movto.in_(["DS", "CA"]), -Venda.qtdade_vendida),
                else_=Venda.qtdade_vendida,
            )

            itens_rows = (
                base.with_entities(
                    Venda.mestre.label("mestre"),
                    Venda.descricao.label("descricao"),
                    func.coalesce(func.sum(signed_qtd), 0.0).label("qtd_total"),
                    func.coalesce(func.sum(signed_val), 0.0).label("valor_total"),
                )
                .group_by(Venda.mestre, Venda.descricao)
                .order_by(func.coalesce(func.sum(signed_val), 0.0).desc())
                .all()
            )

        itens: list[dict[str, Any]] = []
        for r in itens_rows:
            itens.append(
                {
                    "mestre": (r.mestre or "").strip(),
                    "descricao": (r.descricao or "").strip(),
                    "qtd_total": float(r.qtd_total or 0.0),
                    "valor_total": float(r.valor_total or 0.0),
                }
            )

        return jsonify(
            {
                "emp": emp,
                "marca": marca,
                "cliente_id": cliente_id,
                "razao_norm": razao_norm,
                "ano": ano,
                "mes": mes,
                "itens": itens,
            }
        )

    def relatorio_cliente_itens_api():
        """Retorna JSON com itens comprados por um cliente no período."""
        red = login_required_fn()
        if red:
            return red

        role = (role_fn() or "").strip().lower()
        allowed_emps = allowed_emps_fn()
        vendedor_logado = (usuario_logado_fn() or "").strip().upper()

        emp = (request.args.get("emp") or "").strip()
        # compat: o front antigo mandava razao_norm; o novo usa cliente_id (cliente_id_norm)
        razao_norm = (request.args.get("razao_norm") or "").strip()
        cliente_id = (request.args.get("cliente_id") or request.args.get("cliente") or "").strip()
        cidade_norm = (request.args.get("cidade_norm") or "").strip()
        mes = int(request.args.get("mes") or 0)
        ano = int(request.args.get("ano") or 0)
        vendedor = (request.args.get("vendedor") or "").strip().upper()

        if not emp or (not razao_norm and not cliente_id) or not mes or not ano:
            return jsonify({"error": "Parâmetros inválidos"}), 400

        # Permissões
        if role == "supervisor":
            if allowed_emps and str(emp) not in [str(e) for e in allowed_emps]:
                return jsonify({"error": "Acesso negado"}), 403
        elif role == "vendedor":
            vendedor = vendedor_logado  # vendedor não pode consultar outro vendedor

        with SessionLocal() as db:
            base = db.query(Venda).filter(
                Venda.emp == str(emp),
                extract("month", Venda.movimento) == mes,
                extract("year", Venda.movimento) == ano,
            )

            if cliente_id and razao_norm:
                base = base.filter(or_(Venda.cliente_id_norm == cliente_id, Venda.razao_norm == razao_norm))
            elif cliente_id:
                base = base.filter(Venda.cliente_id_norm == cliente_id)
            elif razao_norm:
                base = base.filter(Venda.razao_norm == razao_norm)
            else:
                return jsonify({"error": "Parâmetros inválidos"}), 400

            if cidade_norm:
                if cidade_norm == "sem_cidade":
                    base = base.filter(or_(Venda.cidade_norm.is_(None), Venda.cidade_norm == "", Venda.cidade_norm == "sem_cidade"))
                else:
                    base = base.filter(Venda.cidade_norm == cidade_norm)

            if vendedor:
                base = base.filter(func.upper(Venda.vendedor) == vendedor)

            signed_val = case(
                (Venda.mov_tipo_movto.in_(["DS", "CA"]), -Venda.valor_total),
                else_=Venda.valor_total,
            )
            signed_qtd = case(
                (Venda.mov_tipo_movto.in_(["DS", "CA"]), -Venda.qtdade_vendida),
                else_=Venda.qtdade_vendida,
            )

            itens_rows = (
                base.with_entities(
                    Venda.mestre.label("mestre"),
                    Venda.descricao.label("descricao"),
                    func.coalesce(func.sum(signed_qtd), 0.0).label("qtd_total"),
                    func.coalesce(func.sum(signed_val), 0.0).label("valor_total"),
                )
                .group_by(Venda.mestre, Venda.descricao)
                .order_by(func.coalesce(func.sum(signed_val), 0.0).desc())
                .all()
            )

        itens: list[dict[str, Any]] = []
        for r in itens_rows:
            itens.append(
                {
                    "mestre": (r.mestre or "").strip(),
                    "descricao": (r.descricao or "").strip(),
                    "qtd_total": float(r.qtd_total or 0.0),
                    "valor_total": float(r.valor_total or 0.0),
                }
            )

        return jsonify(
            {
                "emp": emp,
                "cliente_id": cliente_id,
                "razao_norm": razao_norm,
                "cidade_norm": cidade_norm,
                "ano": ano,
                "mes": mes,
                "itens": itens,
            }
        )

    # --- registro das rotas mantendo endpoints antigos ---
    app.add_url_rule(
        "/relatorios/cidades-clientes",
        endpoint="relatorio_cidades_clientes",
        view_func=relatorio_cidades_clientes,
        methods=["GET"],
    )
    app.add_url_rule(
        "/relatorios/cidade-clientes",
        endpoint="relatorio_cidade_clientes_api",
        view_func=relatorio_cidade_clientes_api,
        methods=["GET"],
    )
    app.add_url_rule(
        "/relatorios/cliente-marcas",
        endpoint="relatorio_cliente_marcas_api",
        view_func=relatorio_cliente_marcas_api,
        methods=["GET"],
    )
    app.add_url_rule(
        "/relatorios/cliente-marca-itens",
        endpoint="relatorio_cliente_marca_itens_api",
        view_func=relatorio_cliente_marca_itens_api,
        methods=["GET"],
    )
    app.add_url_rule(
        "/relatorios/cliente-itens",
        endpoint="relatorio_cliente_itens_api",
        view_func=relatorio_cliente_itens_api,
        methods=["GET"],
    )
