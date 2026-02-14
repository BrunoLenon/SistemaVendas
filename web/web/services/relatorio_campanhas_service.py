from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
import datetime
from typing import Any, Callable

from sqlalchemy import or_

from db import (
    SessionLocal,
    Venda,
    CampanhaQtdResultado,
    CampanhaQtd,
    CampanhaCombo,
    CampanhaComboItem,
    CampanhaComboResultado,
    ItemParado,
    FechamentoMensal,
)

from services.campanhas_service import CampanhasDeps


def _calc_qtd_por_vendedor_para_combo_item(
    db,
    *,
    emp: str,
    item: CampanhaComboItem,
    marca: str,
    periodo_ini: date,
    periodo_fim: date,
) -> dict[str, float]:
    """Retorna dict vendedor -> qtd para um item do combo no período.

    Copiado do app.py para evitar dependência circular.

    Regras de match (compatível com banco antigo):
      - Se item.mestre_prefixo existir: prefix match em Venda.mestre
      - Se item.descricao_contains existir: contains case-insensitive em descricao_norm/descricao
      - Se ambos vazios: usa item.match_mestre como fallback (prefixo se parecer código; senão contains)
    """
    emp = str(emp)
    marca_up = (marca or "").strip().upper()

    conds = [
        Venda.emp == emp,
        Venda.movimento >= periodo_ini,
        Venda.movimento <= periodo_fim,
        ~Venda.mov_tipo_movto.in_(["DS", "CA"]),
    ]

    mp = (getattr(item, "mestre_prefixo", None) or "").strip()
    dc = (getattr(item, "descricao_contains", None) or "").strip()

    if not mp and not dc:
        mm = (getattr(item, "match_mestre", None) or "").strip()
        if mm:
            # se parece um código, tratamos como prefixo, senão como contains
            if " " not in mm and len(mm) <= 40:
                mp = mm
            else:
                dc = mm

    if mp:
        conds.append(Venda.mestre.ilike(f"{mp}%"))
    if dc:
        # descricao_norm é preferível (normalizada), mas fazemos fallback em descricao também
        conds.append(or_(Venda.descricao_norm.ilike(f"%{dc}%"), Venda.descricao.ilike(f"%{dc}%")))
    if marca_up:
        conds.append(Venda.marca.ilike(marca_up))

    rows = (
        db.query(Venda.vendedor, Venda.qtdade_vendida)
        .filter(*conds)
        .all()
    )

    out: dict[str, float] = {}
    for vend, qtd in rows:
        v = (vend or "").strip().upper()
        if not v:
            continue
        out[v] = float(out.get(v, 0.0) + float(qtd or 0.0))
    return out


def build_relatorio_campanhas_context(
    deps: CampanhasDeps,
    *,
    role: str,
    vendedor_logado: str,
    ano: int,
    mes: int,
    emps_scope: list[str],
    emps_sel: list[str],
    vendedores_sel: list[str],
    vendedores_por_emp: dict[str, list[str]],
    flash: Callable[[str, str], None],
) -> dict[str, Any]:
    """Monta o contexto completo do template relatorio_campanhas.html.

    Mantém a lógica existente do app.py, mas isolada em service para reduzir regressões e
    permitir otimizações futuras (índices/cache) sem mexer na rota.
    """
    role_l = (role or "").strip().lower()

    # Para vendedor/supervisor: se não selecionou explicitamente EMP, assume escopo permitido
    if role_l != "admin" and not emps_sel and emps_scope:
        emps_sel = [str(e) for e in emps_scope]

    # Recalcula snapshots do escopo para garantir relatório correto
    # Compatibilidade: em versões antigas o helper recebe `emps`, em outras `emps_scope`.
    try:
        try:
            deps.recalcular_resultados_campanhas_para_scope(ano=ano, mes=mes, emps=emps_scope, vendedores_por_emp=vendedores_por_emp)
        except TypeError:
            deps.recalcular_resultados_campanhas_para_scope(ano=ano, mes=mes, emps_scope=emps_scope, vendedores_por_emp=vendedores_por_emp)

        try:
            deps.recalcular_resultados_combos_para_scope(ano=ano, mes=mes, emps=emps_scope, vendedores_por_emp=vendedores_por_emp)
        except TypeError:
            deps.recalcular_resultados_combos_para_scope(ano=ano, mes=mes, emps_scope=emps_scope, vendedores_por_emp=vendedores_por_emp)
    except Exception as e:
        print(f"[RELATORIO_CAMPANHAS] erro ao recalcular snapshots: {e}")
        flash("Não foi possível recalcular os resultados das campanhas agora. Exibindo dados já salvos.", "warning")

    emps_todos: list[dict[str, Any]] = []  # tab A (cadastros)
    emps_abertas: list[dict[str, Any]] = []
    emps_fechadas: list[dict[str, Any]] = []

    periodo_ini, periodo_fim = deps.periodo_bounds(int(ano), int(mes))

    with deps.SessionLocal() as db:
        # mapa de fechamento por EMP na competência
        fech_map: dict[str, bool] = {}
        try:
            rows_f = db.query(FechamentoMensal.emp, FechamentoMensal.fechado).filter(
                FechamentoMensal.ano == int(ano),
                FechamentoMensal.mes == int(mes),
                FechamentoMensal.emp.in_([str(e) for e in emps_scope]),
            ).all()
            fech_map = {str(e): bool(f) for e, f in rows_f}
        except Exception:
            fech_map = {}

        emps_process = emps_sel or emps_scope

        for emp in emps_process:
            emp = str(emp)
            vendedores = vendedores_por_emp.get(emp) or []
            if not vendedores:
                continue

            # -------- Cadastros (Tab A) --------
            # Campanhas Qtd que intersectam o mês
            campanhas_qtd_defs = deps.campanhas_mes_overlap(int(ano), int(mes), emp)

            # Combos que intersectam o mês (global ou da EMP)
            combos_defs = (
                db.query(CampanhaCombo)
                .filter(
                    CampanhaCombo.ativo.is_(True),
                    or_(CampanhaCombo.emp.is_(None), CampanhaCombo.emp == "", CampanhaCombo.emp == emp),
                    CampanhaCombo.data_inicio <= periodo_fim,
                    CampanhaCombo.data_fim >= periodo_ini,
                )
                .order_by(CampanhaCombo.data_inicio.desc())
                .all()
            )

            combos_payload: list[dict[str, Any]] = []
            for c in combos_defs:
                try:
                    itens = (
                        db.query(CampanhaComboItem)
                        .filter(CampanhaComboItem.combo_id == c.id)
                        .order_by(CampanhaComboItem.ordem.asc(), CampanhaComboItem.id.asc())
                        .all()
                    )
                    combos_payload.append({"combo": c, "itens": itens})
                except Exception as _e:
                    print(f"[RELATORIO_CAMPANHAS] erro ao montar detalhes de combo: {_e}")
                    combos_payload.append({"combo": c, "itens": []})

            # Itens Parados ativos por EMP
            itens_parados_defs: list[ItemParado] = []
            try:
                itens_parados_defs = (
                    db.query(ItemParado)
                    .filter(ItemParado.ativo.is_(True), ItemParado.emp == emp)
                    .order_by(ItemParado.descricao.asc())
                    .all()
                )
            except Exception as _e:
                print(f"[RELATORIO_CAMPANHAS] erro ao carregar itens_parados da EMP {emp}: {_e}")
                itens_parados_defs = []

            emps_todos.append({
                "emp": emp,
                "fechado": bool(fech_map.get(emp, False)),
                "campanhas_qtd": campanhas_qtd_defs,
                "combos": combos_payload,
                "itens_parados": itens_parados_defs,
            })

            # -------- Resultados (Tabs B/C) --------
            # QTD resultados
            qtd_rows = (
                db.query(CampanhaQtdResultado)
                .filter(
                    CampanhaQtdResultado.competencia_ano == int(ano),
                    CampanhaQtdResultado.competencia_mes == int(mes),
                    CampanhaQtdResultado.emp == emp,
                    CampanhaQtdResultado.vendedor.in_(vendedores),
                    CampanhaQtdResultado.valor_recompensa > 0,
                )
                .all()
            )

            # Combo resultados
            
            # Mapear campanhas QTD (para vigência quando não estiver duplicada no resultado)
            qtd_camp_map: dict[int, Any] = {}
            try:
                qtd_ids = {getattr(r, "campanha_id", None) for r in qtd_rows}
                qtd_ids |= {getattr(r, "campanha_qtd_id", None) for r in qtd_rows}
                qtd_ids = {int(i) for i in qtd_ids if i is not None}
                if qtd_ids:
                    for c in db.query(CampanhaQtd).filter(CampanhaQtd.id.in_(qtd_ids)).all():
                        cid = getattr(c, "id", None)
                        if cid is not None:
                            qtd_camp_map[int(cid)] = c
            except Exception:
                qtd_camp_map = {}
            combo_rows = (
                db.query(CampanhaComboResultado)
                .filter(
                    CampanhaComboResultado.competencia_ano == int(ano),
                    CampanhaComboResultado.competencia_mes == int(mes),
                    CampanhaComboResultado.emp == emp,
                    CampanhaComboResultado.vendedor.in_(vendedores),
                    CampanhaComboResultado.valor_recompensa > 0,
                )
                .all()
            )

            # Itens Parados resultados (calculado ao vivo com base em vendas)
            parados_itens = itens_parados_defs or []
            parados_por_vendedor: dict[str, list[dict[str, Any]]] = {v: [] for v in vendedores}

            if parados_itens:
                try:
                    for ip in parados_itens:
                        codigo = (ip.codigo or "").strip()
                        if not codigo:
                            continue
                        pct = float(ip.recompensa_pct or 0.0)
                        if pct <= 0:
                            continue

                        rows = (
                            db.query(Venda.vendedor, Venda.valor_total)
                            .filter(
                                Venda.emp == emp,
                                Venda.movimento >= periodo_ini,
                                Venda.movimento <= periodo_fim,
                                ~Venda.mov_tipo_movto.in_(["DS", "CA"]),
                                Venda.mestre == codigo,
                                Venda.vendedor.in_(vendedores),
                            )
                            .all()
                        )
                        base_por_v: dict[str, float] = {}
                        for vend, val in rows:
                            v = (vend or "").strip().upper()
                            if not v:
                                continue
                            base_por_v[v] = float(base_por_v.get(v, 0.0) + float(val or 0.0))

                        for v, base_val in base_por_v.items():
                            recompensa = float(base_val) * (pct / 100.0)
                            if recompensa <= 0:
                                continue
                            parados_por_vendedor.setdefault(v, []).append({
                                "tipo": "PARADO",
                                "titulo": f"Parado: {ip.descricao or ip.codigo}",
                                # campos esperados pelo template
                                "marca": "",
                                "item": f"Base: {float(base_val):.2f} - %: {float(pct):.1f}",
                                "qtd_vendida": None,
                                "valor_vendido": float(base_val),
                                "valor_recompensa": float(recompensa),
                                "atingiu": True,
                                "vigencia": f"Competência {int(mes):02d}/{int(ano)}",
                                "status_pagamento": "PENDENTE",
                                "origem": "PARADO",
                            })
                except Exception as _e:
                    print(f"[RELATORIO_CAMPANHAS] erro ao calcular itens_parados da EMP {emp}: {_e}")

            # Monta itens por vendedor (QTD + Combo + Parados)
            by_vend: dict[str, list[dict[str, Any]]] = {v: [] for v in vendedores}

            for r in qtd_rows:
                # Monta campos completos p/ o template (Marca/Item/Atingiu/Vigência)
                di = getattr(r, "data_inicio", None) or getattr(r, "campanha_data_inicio", None)
                df = getattr(r, "data_fim", None) or getattr(r, "campanha_data_fim", None)

                # Fallback: buscar vigência no cadastro da campanha
                camp_id = getattr(r, "campanha_id", None)
                if camp_id is None:
                    camp_id = getattr(r, "campanha_qtd_id", None)
                if (not di or not df) and camp_id is not None:
                    cdef = qtd_camp_map.get(int(camp_id))
                    if cdef is not None:
                        di = di or getattr(cdef, "data_inicio", None)
                        df = df or getattr(cdef, "data_fim", None)
                vig = ""
                try:
                    def _fmt(d):
                        if not d:
                            return ""
                        if isinstance(d, datetime.datetime):
                            d = d.date()
                        if isinstance(d, datetime.date):
                            return d.strftime("%d/%m/%Y")
                        return str(d)

                    if di and df:
                        vig = f"{_fmt(di)} → {_fmt(df)}"
                        try:
                            _df = df
                            if isinstance(_df, datetime.datetime):
                                _df = _df.date()
                            if isinstance(_df, datetime.date) and datetime.date.today() > _df:
                                vig += " (ENCERRADA)"
                        except Exception:
                            pass
                except Exception:
                    vig = ""

                marca = (getattr(r, "marca", None) or getattr(r, "campanha_marca", None) or "").strip()

                # Melhor esforço para descrever o critério de match
                mestre_pref = getattr(r, "produto_prefixo", None) or getattr(r, "mestre_prefixo", None) or ""
                desc_pref = getattr(r, "descricao_prefixo", None) or ""
                if mestre_pref:
                    item_desc = f"MESTRE: {mestre_pref}"
                elif desc_pref:
                    item_desc = f"DESCRIÇÃO: {desc_pref}"
                else:
                    item_desc = (getattr(r, "campo_match", None) or getattr(r, "match", None) or "").strip()

                atingiu = getattr(r, "atingiu_minimo", None)
                if atingiu is None:
                    # fallback: se gerou recompensa > 0, atingiu
                    atingiu = float(getattr(r, "valor_recompensa", 0) or 0) > 0

                by_vend.setdefault((r.vendedor or "").strip().upper(), []).append({
                    "tipo": "QTD",
                    "titulo": getattr(r, "titulo", None) or getattr(r, "campanha_titulo", None) or "Campanha QTD",
                    "marca": marca,
                    "item": item_desc,
                    "qtd_vendida": float(getattr(r, "qtd_vendida", 0) or 0),
                    "valor_vendido": float(getattr(r, "valor_vendido", 0) or 0),
                    "valor_recompensa": float(getattr(r, "valor_recompensa", 0) or 0),
                    "atingiu": bool(atingiu),
                    "vigencia": vig,
                    "status_pagamento": getattr(r, "status_pagamento", None) or "PENDENTE",
                    "origem": "QTD",
                })

            # Detalhe de combo: opcional - itens por combo (para não "sumir" no relatório)
            combos_itens_map: dict[int, list[CampanhaComboItem]] = {}
            try:
                combo_ids = sorted({int(r.combo_id) for r in combo_rows if getattr(r, "combo_id", None) is not None})
                if combo_ids:
                    itens_all = (
                        db.query(CampanhaComboItem)
                        .filter(CampanhaComboItem.combo_id.in_(combo_ids))
                        .order_by(CampanhaComboItem.combo_id.asc(), CampanhaComboItem.ordem.asc(), CampanhaComboItem.id.asc())
                        .all()
                    )
                    for it in itens_all:
                        combos_itens_map.setdefault(int(it.combo_id), []).append(it)
            except Exception as _e:
                print(f"[RELATORIO_CAMPANHAS] erro ao carregar itens de combos: {_e}")
                combos_itens_map = {}

            for r in combo_rows:
                cid = int(getattr(r, "combo_id", 0) or 0)
                titulo = getattr(r, "titulo", None) or getattr(r, "nome", None) or f"Combo #{cid}"
                payload = {
                    "tipo": "COMBO",
                    "titulo": titulo,
                    "marca": "",
                    "item": "",
                    "qtd_vendida": None,
                    "valor_vendido": None,
                    "valor_recompensa": float(getattr(r, "valor_recompensa", 0) or 0),
                    "atingiu": bool(getattr(r, "atingiu_gate", None) if getattr(r, "atingiu_gate", None) is not None else (float(getattr(r, "valor_recompensa", 0) or 0) > 0)),
                    "vigencia": "",
                    "status_pagamento": getattr(r, "status_pagamento", None) or "PENDENTE",
                    "origem": "COMBO",
                    "combo_id": cid,
                    "combo_itens": [],
                }

                # monta detalhe por item (qtd no mês), apenas para exibição
                try:
                    c = db.query(CampanhaCombo).filter(CampanhaCombo.id == cid).first()
                    marca = (getattr(c, "marca", "") or "").strip()
                    payload["marca"] = marca
                    try:
                        if getattr(c, "data_inicio", None) and getattr(c, "data_fim", None):
                            payload["vigencia"] = f"{c.data_inicio.strftime('%d/%m/%Y')} → {c.data_fim.strftime('%d/%m/%Y')}"
                            try:
                                if datetime.date.today() > c.data_fim:
                                    payload["vigencia"] += " (ENCERRADA)"
                            except Exception:
                                pass
                    except Exception:
                        pass
                    itens = combos_itens_map.get(cid) or []
                    if itens:
                        qtds = []
                        for it in itens:
                            mp = _calc_qtd_por_vendedor_para_combo_item(
                                db,
                                emp=emp,
                                item=it,
                                marca=marca,
                                periodo_ini=periodo_ini,
                                periodo_fim=periodo_fim,
                            )
                            vq = float(mp.get((r.vendedor or "").strip().upper(), 0.0))
                            qtds.append({
                                "nome_item": getattr(it, "nome_item", None) or "Item",
                                "minimo_qtd": int(getattr(it, "minimo_qtd", 0) or 0),
                                "qtd": float(vq),
                                "valor_unitario": float(getattr(it, "valor_unitario", 0) or 0),
                            })
                        payload["combo_itens"] = qtds
                        # Texto curto para coluna "Item" (mantém layout atual)
                        payload["item"] = ", ".join([q["nome_item"] for q in qtds][:3])
                except Exception as _e:
                    print(f"[RELATORIO_CAMPANHAS] erro ao montar detalhe do combo: {_e}")

                by_vend.setdefault((r.vendedor or "").strip().upper(), []).append(payload)

            # Parados
            for v, itens in (parados_por_vendedor or {}).items():
                if itens:
                    by_vend.setdefault(v, []).extend(itens)

            vendedores_cards = []
            for v in vendedores:
                v = (v or "").strip().upper()
                itens = by_vend.get(v) or []
                itens.sort(key=lambda x: (x.get("valor_recompensa", 0.0)), reverse=True)
                total_v = sum(float(x.get("valor_recompensa") or 0.0) for x in itens)
                vendedores_cards.append({
                    "vendedor": v,
                    "total_recompensa": float(total_v),
                    "itens": itens,
                })

            emp_payload = {
                "emp": emp,
                "fechado": bool(fech_map.get(emp, False)),
                "vendedores": vendedores_cards,
            }
            if emp_payload["fechado"]:
                emps_fechadas.append(emp_payload)
            else:
                emps_abertas.append(emp_payload)

    # Opções de EMP para o filtro (multi)
    try:
        emps_options = deps.get_emp_options(emps_scope)
    except Exception:
        emps_options = []

    # Opções de vendedor para o filtro (multi)
    try:
        vset: list[str] = []
        for _emp, vs in (vendedores_por_emp or {}).items():
            for v in (vs or []):
                vv = (v or "").strip().upper()
                if vv and vv not in vset:
                    vset.append(vv)
        vendedores_options = [{"value": v, "label": v} for v in vset]
    except Exception:
        vendedores_options = []

    return {
        "role": role,
        "ano": int(ano),
        "mes": int(mes),
        "emps_todos": emps_todos,
        "emps_abertas": emps_abertas,
        "emps_fechadas": emps_fechadas,
        "emps_scope": emps_scope,
        "emps_sel": emps_sel,
        "emps_options": emps_options,
        "vendedores_sel": vendedores_sel,
        "vendedores_options": vendedores_options,
        "vendedor": vendedor_logado,
    }
