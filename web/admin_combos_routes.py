from __future__ import annotations

from datetime import date, datetime

from flask import request, render_template
from sqlalchemy import text, and_, or_


def register_admin_combos_routes(
    app,
    *,
    SessionLocal,
    Emp,
    CampanhaCombo,
    CampanhaComboItem,
    login_required_fn,
    admin_required_fn,
    periodo_bounds_fn,
):
    """
    Registra rotas de Admin/Combos mantendo total compatibilidade:
      - URL: /admin/combos
      - Endpoint: admin_combos
      - Sem alterar comportamento observável (refatoração pura).
    """

    def admin_combos():
        """Cadastro de Campanhas Combo (SIMPLES).
        Regra (venda casada):
          - Cada requisito define um MESTRE (match em vendas.mestre), uma quantidade mínima e um Valor R$ (recompensa).
          - O vendedor só ganha se bater o mínimo em TODOS os requisitos do combo (gate).
          - Ao bater o gate, a recompensa do combo é a SOMA dos valores R$ cadastrados nos requisitos (recompensa fixa por requisito atingido).
        Observação: mantemos campos extras do modelo (marca/modelo/etc) com defaults para compatibilidade do banco.
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

        inicio_mes, fim_mes = periodo_bounds_fn(ano, mes)
        default_data_inicio = request.values.get("data_inicio") or inicio_mes.isoformat()
        default_data_fim = request.values.get("data_fim") or fim_mes.isoformat()

        with SessionLocal() as db:
            # Carrega EMPs (tabela emps)
            try:
                emps = db.query(Emp).order_by(Emp.codigo.asc()).all()
            except Exception:
                emps = []

            if request.method == "POST":
                acao = (request.form.get("acao") or "").strip().lower()

                # Remover combo (e seus itens/resultados)
                if acao == "remover":
                    try:
                        combo_id = int(request.form.get("combo_id") or 0)
                        if not combo_id:
                            raise ValueError("combo_id inválido.")
                        # remove itens + resultados + combo
                        db.execute(text("DELETE FROM campanhas_combo_itens WHERE combo_id = :cid"), {"cid": combo_id})
                        db.execute(text("DELETE FROM campanhas_combo_resultados WHERE combo_id = :cid"), {"cid": combo_id})
                        db.execute(text("DELETE FROM campanhas_combo WHERE id = :cid"), {"cid": combo_id})
                        db.commit()
                        ok = "Combo removido."
                    except Exception as e:
                        db.rollback()
                        erro = str(e)

                # Criar combo simples
                elif acao == "criar":
                    try:
                        titulo = (request.form.get("titulo") or "").strip()
                        emp = (request.form.get("emp") or "").strip()
                        vig_ini = request.form.get("data_inicio") or inicio_mes.isoformat()
                        vig_fim = request.form.get("data_fim") or fim_mes.isoformat()

                        if not titulo:
                            raise ValueError("Título é obrigatório.")

                        # Parse datas
                        try:
                            d_ini = datetime.fromisoformat(vig_ini).date()
                            d_fim = datetime.fromisoformat(vig_fim).date()
                        except Exception:
                            raise ValueError("Datas inválidas. Use o seletor de datas.")

                        if d_fim < d_ini:
                            raise ValueError("Data fim não pode ser menor que data início.")

                        # Campos obrigatórios no banco/modelo (mantemos defaults)
                        combo = CampanhaCombo(
                            titulo=titulo,
                            nome=titulo,
                            emp=emp if emp else None,
                            marca="COMBO",  # NOT NULL no banco
                            data_inicio=d_ini,
                            data_fim=d_fim,
                            ano=int(d_ini.year),
                            mes=int(d_ini.month),
                            valor_unitario_global=None,
                            modelo_pagamento="TODOS_ITENS",  # mantém compat
                            filtro_marca=None,
                            filtro_descricao_prefixo=None,
                            valor_unitario_modelo2=None,
                            ativo=True,
                            created_at=datetime.utcnow(),
                            updated_at=datetime.utcnow(),
                        )
                        db.add(combo)
                        db.flush()  # obtém combo.id

                        mestres = request.form.getlist("mestre_prefixo[]")
                        minimos = request.form.getlist("minimo_qtd[]")
                        vals = request.form.getlist("valor_unitario[]")

                        itens = []
                        n = max(len(mestres), len(minimos), len(vals))
                        for i in range(n):
                            mp = (mestres[i] if i < len(mestres) else "") or ""
                            mi = (minimos[i] if i < len(minimos) else "") or ""
                            vu = (vals[i] if i < len(vals) else "") or ""

                            mp = str(mp).strip()
                            if not mp:
                                continue

                            # mínimo (int)
                            try:
                                minimo_qtd = int(float(str(mi).replace(",", ".") or 0))
                            except Exception:
                                minimo_qtd = 0

                            vu_raw = str(vu).strip().replace(",", ".")
                            if not vu_raw:
                                raise ValueError("Valor R$ é obrigatório em cada requisito do combo simples.")
                            try:
                                valor_unit = float(vu_raw)
                            except Exception:
                                raise ValueError("Valor R$ inválido.")

                            itens.append(
                                {
                                    "combo_id": combo.id,
                                    "mestre_prefixo": mp,
                                    "descricao_contains": None,
                                    "match_mestre": mp,
                                    "minimo_qtd": int(minimo_qtd or 0),
                                    "valor_unitario": float(valor_unit),
                                    "ordem": i + 1,
                                    "criado_em": datetime.utcnow(),
                                }
                            )

                        if not itens:
                            raise ValueError("Adicione pelo menos 1 requisito (MESTRE, mínimo e Valor R$).")

                        sql = text(
                            "INSERT INTO campanhas_combo_itens (combo_id, mestre_prefixo, descricao_contains, match_mestre, minimo_qtd, valor_unitario, ordem, criado_em) "
                            "VALUES (:combo_id, :mestre_prefixo, :descricao_contains, :match_mestre, :minimo_qtd, :valor_unitario, :ordem, :criado_em)"
                        )
                        db.execute(sql, itens)
                        db.commit()
                        ok = "Combo criado com sucesso."
                    except Exception as e:
                        db.rollback()
                        erro = str(e)

            # lista combos que intersectam o mês/ano (inclui globais)
            combos = (
                db.query(CampanhaCombo)
                .filter(
                    CampanhaCombo.ativo.is_(True),
                    or_(CampanhaCombo.emp.is_(None), CampanhaCombo.emp == ""),
                )
                .all()
            )

            # Também inclui combos da EMP específica quando filtrada na criação (para admin ver tudo)
            # (Na tela simples, o admin quer ver todos no período filtrado)
            combos = (
                db.query(CampanhaCombo)
                .filter(
                    CampanhaCombo.ativo.is_(True),
                    or_(
                        and_(CampanhaCombo.data_inicio <= fim_mes, CampanhaCombo.data_fim >= inicio_mes),
                        and_(CampanhaCombo.ano == ano, CampanhaCombo.mes == mes),
                    ),
                )
                .order_by(CampanhaCombo.data_inicio.desc(), CampanhaCombo.id.desc())
                .all()
            )

            combo_ids = [c.id for c in combos]
            combos_itens_map = {}
            if combo_ids:
                itens_rows = (
                    db.query(CampanhaComboItem)
                    .filter(CampanhaComboItem.combo_id.in_(combo_ids))
                    .order_by(CampanhaComboItem.combo_id.asc(), CampanhaComboItem.ordem.asc(), CampanhaComboItem.id.asc())
                    .all()
                )
                for it in itens_rows:
                    combos_itens_map.setdefault(it.combo_id, []).append(it)

        return render_template(
            "admin_combos.html",
            mes=mes,
            ano=ano,
            emps=emps,
            combos=combos,
            combos_itens_map=combos_itens_map,
            default_data_inicio=default_data_inicio,
            default_data_fim=default_data_fim,
            erro=erro,
            ok=ok,
        )

    app.add_url_rule("/admin/combos", endpoint="admin_combos", view_func=admin_combos, methods=["GET", "POST"])
