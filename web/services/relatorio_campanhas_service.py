from __future__ import annotations

def _sanitize_emps(emp_list):
    """Normalize lista de EMPs vindas de args/sessão.

    Remove None/'' e tokens tipo 'todas', mantendo ordem e sem duplicar.
    Campanhas globais devem ser tratadas via emp IS NULL ou emp == '' no SQL,
    então NÃO incluímos '' na lista selecionada.
    """
    if not emp_list:
        return []
    out = []
    seen = set()
    for e in emp_list:
        if e is None:
            continue
        s = str(e).strip()
        if not s:
            continue
        sl = s.lower()
        if sl in ("todas", "todos", "all", "*"):
            continue
        if s not in seen:
            out.append(s)
            seen.add(s)
    return out


from dataclasses import dataclass
from datetime import date, datetime
import datetime
import os
import threading
import time
from typing import Any, Callable

from sqlalchemy import func, or_
from sv_utils import MOVIMENTOS_VENDA

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

from services.campanhas_v2_service import list_resultados_v2

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
        func.upper(func.coalesce(Venda.mov_tipo_movto, "")).in_(MOVIMENTOS_VENDA),
        func.coalesce(Venda.qtdade_vendida, 0.0) > 0,
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
    emps_base: list[str] | None = None,
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

    # Sanitiza EMPs (evita '' quebrar queries)
    emps_scope = _sanitize_emps(emps_scope)
    emps_sel = _sanitize_emps(emps_sel)

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
        try:
            deps.db.rollback()
        except Exception:
            pass
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
                    or_(
                        CampanhaQtdResultado.valor_recompensa > 0,
                        CampanhaQtdResultado.premio_potencial > 0,
                        CampanhaQtdResultado.bloqueado_faturamento_emp == 1,
                    ),
                )
                .all()
            )

            # Combo resultados
            
            # Mapear campanhas QTD (para vigência quando não estiver duplicada no resultado)
            qtd_camp_map: dict[int, Any] = {}
            try:
                qtd_ids = {getattr(r, "campanha_id", None) for r in qtd_rows}
                qtd_ids = {i for i in qtd_ids if i is not None}
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
                                func.upper(func.coalesce(Venda.mov_tipo_movto, "")).in_(MOVIMENTOS_VENDA),
                                func.coalesce(Venda.qtdade_vendida, 0.0) > 0,
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
                                "vigencia": "",
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
                    "tipo": ("GERENTE" if str(getattr(r, "campanha_tipo", "") or "").strip().upper() == "GERENTE" else "QTD"),
                    "titulo": getattr(r, "titulo", None) or getattr(r, "campanha_titulo", None) or "Campanha QTD",
                    "marca": marca,
                    "item": item_desc,
                    "qtd_vendida": float(getattr(r, "qtd_vendida", 0) or 0),
                    "valor_vendido": float(getattr(r, "valor_vendido", 0) or 0),
                    "valor_recompensa": float(getattr(r, "valor_recompensa", 0) or 0),
                    "premio_potencial": float(getattr(r, "premio_potencial", getattr(r, "valor_recompensa", 0)) or 0),
                    "faturamento_minimo_emp": float(getattr(r, "faturamento_minimo_emp", 0) or 0) or None,
                    "faturamento_emp": float(getattr(r, "faturamento_emp", 0) or 0) if getattr(r, "faturamento_emp", None) is not None else None,
                    "faltante_faturamento_emp": float(getattr(r, "faltante_faturamento_emp", 0) or 0) if getattr(r, "faltante_faturamento_emp", None) is not None else None,
                    "bloqueado_faturamento_emp": bool(int(getattr(r, "bloqueado_faturamento_emp", 0) or 0)),
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
                            payload["vigencia"] = f"{c.data_inicio} → {c.data_fim}"
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
        emps_options = deps.get_emp_options(emps_base or emps_scope)
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



from services.relatorio_unificado_service import (
    build_unified_rows,
    aggregate_for_charts,
    rebuild_itens_parados_snapshot,
)

_RELATORIO_UNIFICADO_CACHE: dict[tuple, tuple[float, list[Any], dict[str, Any]]] = {}
_RELATORIO_UNIFICADO_CACHE_LOCK = threading.Lock()
_RELATORIO_UNIFICADO_INFLIGHT_LOCKS: dict[tuple, threading.Lock] = {}
_RELATORIO_UNIFICADO_INFLIGHT_LOCKS_GUARD = threading.Lock()


def _relatorio_inflight_lock_for(key: tuple) -> threading.Lock:
    """Um lock por chave de relatório para evitar cache_miss duplicado.

    Em produção foi observado duas requisições iguais de /relatorios/campanhas
    calculando 17 EMPs ao mesmo tempo. A primeira monta e grava o cache; a
    segunda espera e tenta ler o cache novamente, em vez de refazer tudo.
    """
    with _RELATORIO_UNIFICADO_INFLIGHT_LOCKS_GUARD:
        if len(_RELATORIO_UNIFICADO_INFLIGHT_LOCKS) > 64:
            # Melhor esforço: não remove locks em uso, apenas limita crescimento.
            for old_key in list(_RELATORIO_UNIFICADO_INFLIGHT_LOCKS.keys())[:16]:
                lock = _RELATORIO_UNIFICADO_INFLIGHT_LOCKS.get(old_key)
                if lock is not None and not lock.locked():
                    _RELATORIO_UNIFICADO_INFLIGHT_LOCKS.pop(old_key, None)
        lock = _RELATORIO_UNIFICADO_INFLIGHT_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _RELATORIO_UNIFICADO_INFLIGHT_LOCKS[key] = lock
        return lock


def _relatorio_cache_ttl_seconds() -> int:
    try:
        # O relatório agora é aquecido automaticamente após a importação diária.
        # Um TTL curto (5 min) fazia a página voltar a dar cache_miss ao longo do dia.
        # Mantemos 8h por padrão e limpamos/aquecemos novamente quando entra nova importação.
        return max(0, int(os.environ.get("RELATORIO_CAMPANHAS_CACHE_TTL_SECONDS", "28800") or 0))
    except Exception:
        return 28800


def _relatorio_vendedores_key(vendedores_por_emp: dict[str, list[str]] | None, emps: list[str]) -> tuple:
    """Chave estável do escopo efetivo usado no relatório.

    Não usamos request args crus: usamos apenas EMPs e vendedores já autorizados
    pela regra de escopo. Assim o cache não muda permissão nem resultado.
    """
    out = []
    mapa = vendedores_por_emp or {}
    for emp in sorted({str(e).strip() for e in (emps or []) if str(e).strip()}):
        vendedores = sorted({str(v or "").strip().upper() for v in (mapa.get(emp) or []) if str(v or "").strip()})
        out.append((emp, tuple(vendedores)))
    return tuple(out)


def _relatorio_cache_key(*, role: str, vendedor_logado: str, ano: int, mes: int, emps: list[str], vendedores_por_emp: dict[str, list[str]]) -> tuple:
    role_l = str(role or "").strip().lower()
    # Admin/financeiro enxergam o mesmo escopo quando EMP/vendedores são os mesmos.
    # Remover o usuário da chave permite que o aquecimento pós-importação sirva
    # para qualquer admin, sem recalcular a mesma competência por usuário.
    actor = "__GLOBAL__" if role_l in ("admin", "financeiro") else str(vendedor_logado or "").strip().upper()
    return (
        "relatorio_campanhas_unificado_v8_alvo_base_gerente",
        role_l,
        actor,
        int(ano),
        int(mes),
        tuple(sorted({str(e).strip() for e in (emps or []) if str(e).strip()})),
        _relatorio_vendedores_key(vendedores_por_emp, emps),
    )


def _relatorio_cache_get(key: tuple) -> tuple[list[Any], dict[str, Any]] | None:
    ttl = _relatorio_cache_ttl_seconds()
    if ttl <= 0:
        return None
    now = time.monotonic()
    with _RELATORIO_UNIFICADO_CACHE_LOCK:
        item = _RELATORIO_UNIFICADO_CACHE.get(key)
        if not item:
            return None
        created, rows, charts = item
        if now - created > ttl:
            _RELATORIO_UNIFICADO_CACHE.pop(key, None)
            return None
        return rows, charts


def _relatorio_cache_set(key: tuple, rows: list[Any], charts: dict[str, Any]) -> None:
    ttl = _relatorio_cache_ttl_seconds()
    if ttl <= 0:
        return
    with _RELATORIO_UNIFICADO_CACHE_LOCK:
        # Evita crescimento indefinido em processos longos.
        if len(_RELATORIO_UNIFICADO_CACHE) > 32:
            oldest = sorted(_RELATORIO_UNIFICADO_CACHE.items(), key=lambda kv: kv[1][0])[:8]
            for old_key, _ in oldest:
                _RELATORIO_UNIFICADO_CACHE.pop(old_key, None)
        _RELATORIO_UNIFICADO_CACHE[key] = (time.monotonic(), rows, charts)


def _relatorio_cache_clear() -> None:
    with _RELATORIO_UNIFICADO_CACHE_LOCK:
        _RELATORIO_UNIFICADO_CACHE.clear()


def _relatorio_cache_warm_aliases(
    *,
    ano: int,
    mes: int,
    emps: list[str],
    vendedores_por_emp: dict[str, list[str]],
    rows: list[Any],
    charts: dict[str, Any] | None = None,
) -> None:
    """Aquece chaves comuns do relatório após importação/recálculo.

    A página costuma ser aberta por admin/financeiro com 1 EMP selecionada.
    Além do cache combinado, deixamos cada EMP individual pronta para evitar
    cache_miss ao alternar entre lojas.
    """
    emps_clean = _sanitize_emps(emps)
    if not emps_clean:
        return

    roles = ("admin", "financeiro")
    all_rows = list(rows or [])

    # Cache do escopo completo.
    full_charts = charts if charts is not None else aggregate_for_charts(all_rows)
    for role_name in roles:
        _relatorio_cache_set(
            _relatorio_cache_key(
                role=role_name,
                vendedor_logado="",
                ano=int(ano),
                mes=int(mes),
                emps=emps_clean,
                vendedores_por_emp=vendedores_por_emp,
            ),
            all_rows,
            full_charts,
        )

    # Cache por EMP, que é o uso mais comum na tela de conferência.
    for emp in emps_clean:
        emp_rows = [r for r in all_rows if str(getattr(r, "emp", "") or "").strip() == str(emp)]
        emp_vendedores = {str(emp): list((vendedores_por_emp or {}).get(str(emp)) or [])}
        emp_charts = aggregate_for_charts(emp_rows)
        for role_name in roles:
            _relatorio_cache_set(
                _relatorio_cache_key(
                    role=role_name,
                    vendedor_logado="",
                    ano=int(ano),
                    mes=int(mes),
                    emps=[str(emp)],
                    vendedores_por_emp=emp_vendedores,
                ),
                emp_rows,
                emp_charts,
            )


def rebuild_relatorio_campanhas_unificado_cache(
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
    clear_existing: bool = True,
) -> dict[str, Any]:
    """Executa o recálculo pesado fora da request HTTP e aquece o cache do relatório.

    Esta função é usada pelo botão /relatorios/campanhas/recalcular em modo
    background. O objetivo é evitar timeout/502 no Render: a rota responde rápido
    e este job atualiza snapshots + cache no processo atual.
    """
    started = time.perf_counter()
    role_l = (role or "").strip().lower()
    emps_scope = _sanitize_emps(emps_scope)
    emps_sel = _sanitize_emps(emps_sel)

    if role_l != "admin" and not emps_sel and emps_scope:
        emps_sel = [str(e) for e in emps_scope]
    if not emps_sel:
        emps_sel = [str(e) for e in emps_scope]

    stats: dict[str, Any] = {
        "status": "ok",
        "ano": int(ano),
        "mes": int(mes),
        "emps": list(emps_sel),
        "rows": 0,
        "duration_ms": 0,
        "errors": [],
    }

    if not emps_sel:
        stats["status"] = "skipped"
        stats["errors"].append("sem_emp")
        return stats

    try:
        try:
            deps.recalcular_resultados_campanhas_para_scope(ano=ano, mes=mes, emps=emps_sel, vendedores_por_emp=vendedores_por_emp)
        except TypeError:
            deps.recalcular_resultados_campanhas_para_scope(ano=ano, mes=mes, emps_scope=emps_sel, vendedores_por_emp=vendedores_por_emp)
    except Exception as exc:
        stats["errors"].append(f"qtd:{exc}")
        try:
            print(f"[RELATORIO_UNIFICADO] recalc_background erro QTD: {exc}")
        except Exception:
            pass

    try:
        try:
            deps.recalcular_resultados_combos_para_scope(ano=ano, mes=mes, emps=emps_sel, vendedores_por_emp=vendedores_por_emp)
        except TypeError:
            deps.recalcular_resultados_combos_para_scope(ano=ano, mes=mes, emps_scope=emps_sel, vendedores_por_emp=vendedores_por_emp)
    except Exception as exc:
        stats["errors"].append(f"combo:{exc}")
        try:
            print(f"[RELATORIO_UNIFICADO] recalc_background erro COMBO: {exc}")
        except Exception:
            pass

    try:
        snap_stats = rebuild_itens_parados_snapshot(
            ano=int(ano),
            mes=int(mes),
            emps=emps_sel,
            vendedores_por_emp=vendedores_por_emp,
        )
        stats["itens_parados_snapshot"] = snap_stats
    except Exception as exc:
        stats["errors"].append(f"itens_parados:{exc}")
        try:
            print(f"[RELATORIO_UNIFICADO] recalc_background erro Itens Parados: {exc}")
        except Exception:
            pass

    rows: list[Any] = []
    charts: dict[str, Any] = {}
    try:
        rows = build_unified_rows(
            ano=int(ano),
            mes=int(mes),
            emps=emps_sel,
            vendedores_por_emp=vendedores_por_emp,
            incluir_zerados=False,
            usar_snapshot_itens_parados=True,
            incluir_participacao_ativa=True,
            metas_live=True,
            ensure_missing_gerente_snapshots=False,
        ) or []
        charts = aggregate_for_charts(rows or [])
        cache_key = _relatorio_cache_key(
            role=role_l,
            vendedor_logado=vendedor_logado,
            ano=int(ano),
            mes=int(mes),
            emps=emps_sel,
            vendedores_por_emp=vendedores_por_emp,
        )
        # Snapshots foram alterados: invalida caches antigos e deixa o escopo atual aquecido.
        if clear_existing:
            _relatorio_cache_clear()
        _relatorio_cache_set(cache_key, rows, charts)
        _relatorio_cache_warm_aliases(
            ano=int(ano),
            mes=int(mes),
            emps=emps_sel,
            vendedores_por_emp=vendedores_por_emp,
            rows=rows,
            charts=charts,
        )
        stats["rows"] = len(rows or [])
    except Exception as exc:
        stats["status"] = "partial_error"
        stats["errors"].append(f"cache:{exc}")
        try:
            print(f"[RELATORIO_UNIFICADO] recalc_background erro ao aquecer cache: {exc}")
        except Exception:
            pass

    stats["duration_ms"] = int((time.perf_counter() - started) * 1000)
    try:
        print(
            "[RELATORIO_UNIFICADO] recalc_background_done "
            f"status={stats.get('status')} duration_ms={stats.get('duration_ms')} "
            f"rows={stats.get('rows')} ano={ano} mes={mes} emps={len(emps_sel or [])} "
            f"errors={len(stats.get('errors') or [])}"
        )
    except Exception:
        pass
    return stats


_RELATORIO_IMPORT_REFRESH_JOBS: dict[tuple, dict[str, Any]] = {}
_RELATORIO_IMPORT_REFRESH_JOBS_LOCK = threading.Lock()


def _normalize_affected_periods(affected_periods: list[Any] | tuple[Any, ...] | None) -> dict[tuple[int, int], list[str]]:
    grouped: dict[tuple[int, int], list[str]] = {}
    for item in affected_periods or []:
        try:
            emp, ano, mes = item[0], item[1], item[2]
            emp_s = str(emp or '').strip()
            ano_i = int(ano)
            mes_i = int(mes)
        except Exception:
            continue
        if not emp_s or mes_i < 1 or mes_i > 12:
            continue
        key = (ano_i, mes_i)
        grouped.setdefault(key, [])
        if emp_s not in grouped[key]:
            grouped[key].append(emp_s)
    for key in list(grouped.keys()):
        grouped[key] = sorted(grouped[key], key=lambda x: (0, int(x)) if str(x).isdigit() else (1, str(x)))
        if not grouped[key]:
            grouped.pop(key, None)
    return grouped


def _refresh_import_job_key(grouped: dict[tuple[int, int], list[str]]) -> tuple:
    return (
        'relatorio_campanhas_import_refresh_v1',
        tuple((int(ano), int(mes), tuple(str(e) for e in emps)) for (ano, mes), emps in sorted(grouped.items())),
    )


def _vendedores_por_emp_refresh(deps: CampanhasDeps, *, ano: int, mes: int, emps: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for emp in _sanitize_emps(emps):
        vendedores: list[str] = []
        try:
            vendedores = [str(v or '').strip().upper() for v in (deps.get_vendedores_emp_no_periodo(str(emp), int(ano), int(mes)) or []) if str(v or '').strip()]
        except Exception:
            vendedores = []
        # Fallback direto em vendas, útil se a função injetada falhar durante boot/deploy.
        if not vendedores:
            try:
                periodo_ini, periodo_fim = deps.periodo_bounds(int(ano), int(mes))
                with deps.SessionLocal() as db:
                    rows_v = (
                        db.query(func.distinct(Venda.vendedor))
                        .filter(
                            Venda.emp == str(emp),
                            Venda.movimento >= periodo_ini,
                            Venda.movimento <= periodo_fim,
                        )
                        .all()
                    )
                    vendedores = sorted({str(r[0] or '').strip().upper() for r in rows_v if r and str(r[0] or '').strip()})
            except Exception:
                vendedores = []
        out[str(emp)] = sorted({v for v in vendedores if v})
    return out


def _run_import_refresh_job(
    deps: CampanhasDeps,
    *,
    grouped: dict[tuple[int, int], list[str]],
    job_key: tuple,
) -> None:
    started_all = time.perf_counter()
    total_rows = 0
    errors: list[str] = []
    detalhes: list[dict[str, Any]] = []

    with _RELATORIO_IMPORT_REFRESH_JOBS_LOCK:
        job = _RELATORIO_IMPORT_REFRESH_JOBS.get(job_key) or {}
        job.update({'status': 'running', 'started_at': time.monotonic(), 'ended_at': None})
        _RELATORIO_IMPORT_REFRESH_JOBS[job_key] = job

    try:
        # Entra venda nova: caches antigos deixam de ser confiáveis.
        _relatorio_cache_clear()
        for (ano, mes), emps in sorted(grouped.items()):
            started = time.perf_counter()
            emps_clean = _sanitize_emps(emps)
            if not emps_clean:
                continue
            vendedores_por_emp = _vendedores_por_emp_refresh(deps, ano=int(ano), mes=int(mes), emps=emps_clean)
            try:
                stats = rebuild_relatorio_campanhas_unificado_cache(
                    deps,
                    role='admin',
                    vendedor_logado='',
                    ano=int(ano),
                    mes=int(mes),
                    emps_scope=emps_clean,
                    emps_sel=emps_clean,
                    vendedores_sel=[],
                    vendedores_por_emp=vendedores_por_emp,
                    clear_existing=False,
                )
                total_rows += int(stats.get('rows') or 0)
                if stats.get('errors'):
                    errors.extend([str(e) for e in (stats.get('errors') or [])])
                detalhes.append({
                    'ano': int(ano),
                    'mes': int(mes),
                    'emps': len(emps_clean),
                    'rows': int(stats.get('rows') or 0),
                    'duration_ms': int((time.perf_counter() - started) * 1000),
                    'status': stats.get('status') or 'ok',
                })
            except Exception as exc:
                errors.append(f'{ano}-{mes:02d}:{exc}')
                detalhes.append({
                    'ano': int(ano),
                    'mes': int(mes),
                    'emps': len(emps_clean),
                    'rows': 0,
                    'duration_ms': int((time.perf_counter() - started) * 1000),
                    'status': 'error',
                    'error': str(exc),
                })
                try:
                    print(f'[RELATORIO_IMPORT_REFRESH] erro competencia={ano}-{mes:02d} emps={len(emps_clean)} erro={exc}')
                except Exception:
                    pass
    finally:
        ended = time.monotonic()
        status = 'partial_error' if errors else 'done'
        duration_ms = int((time.perf_counter() - started_all) * 1000)
        with _RELATORIO_IMPORT_REFRESH_JOBS_LOCK:
            job = _RELATORIO_IMPORT_REFRESH_JOBS.get(job_key) or {}
            job.update({
                'status': status,
                'ended_at': ended,
                'duration_ms': duration_ms,
                'rows': int(total_rows),
                'errors': errors[:20],
                'detalhes': detalhes,
            })
            _RELATORIO_IMPORT_REFRESH_JOBS[job_key] = job
        try:
            print(
                '[RELATORIO_IMPORT_REFRESH] done '
                f'status={status} duration_ms={duration_ms} rows={int(total_rows)} '
                f'competencias={len(grouped)} errors={len(errors)}'
            )
        except Exception:
            pass


def start_relatorio_campanhas_refresh_after_import(
    deps: CampanhasDeps | None,
    *,
    affected_periods: list[Any] | tuple[Any, ...] | None,
) -> dict[str, Any]:
    """Dispara atualização automática dos snapshots/cache após importação de vendas.

    A importação diária substitui EMP+DATA e informa `affected_periods`.
    Para cada competência afetada, recalculamos QTD, Combo, Itens Parados e Metas,
    depois aquecemos o cache do relatório para admin/financeiro por EMP.
    """
    grouped = _normalize_affected_periods(affected_periods)
    if deps is None or not grouped:
        return {'started': False, 'reason': 'sem_deps_ou_periodos', 'competencias': 0, 'emps': 0}

    job_key = _refresh_import_job_key(grouped)
    now = time.monotonic()
    with _RELATORIO_IMPORT_REFRESH_JOBS_LOCK:
        # Limpeza simples de jobs antigos.
        for k, j in list(_RELATORIO_IMPORT_REFRESH_JOBS.items()):
            if j.get('status') == 'running':
                continue
            ended = float(j.get('ended_at') or j.get('started_at') or 0)
            if ended and now - ended > 3600:
                _RELATORIO_IMPORT_REFRESH_JOBS.pop(k, None)

        current = _RELATORIO_IMPORT_REFRESH_JOBS.get(job_key)
        if current and current.get('status') == 'running':
            return {
                'started': False,
                'already_running': True,
                'competencias': len(grouped),
                'emps': sum(len(v) for v in grouped.values()),
            }

        _RELATORIO_IMPORT_REFRESH_JOBS[job_key] = {
            'status': 'queued',
            'started_at': now,
            'ended_at': None,
            'competencias': len(grouped),
            'emps': sum(len(v) for v in grouped.values()),
            'rows': 0,
            'errors': [],
        }

    th = threading.Thread(
        target=_run_import_refresh_job,
        args=(deps,),
        kwargs={'grouped': grouped, 'job_key': job_key},
        name='relatorio-campanhas-import-refresh',
        daemon=True,
    )
    th.start()
    return {
        'started': True,
        'competencias': len(grouped),
        'emps': sum(len(v) for v in grouped.values()),
    }


def build_relatorio_campanhas_unificado_context(
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
    recalc: bool,
    flash: Callable[[str, str], None],
) -> dict[str, Any]:
    """
    Novo contexto (v2) para relatorio_campanhas.html — visão consolidada.

    - NÃO recalcula por padrão (performance).
    - Se `recalc=True`, dispara recálculo dos snapshots QTD/COMBO e (opcionalmente) persiste snapshot de Itens Parados.
    """

    role_l = (role or "").strip().lower()
    emps_scope = _sanitize_emps(emps_scope)
    emps_sel = _sanitize_emps(emps_sel)

    # Para vendedor/supervisor: se não selecionou explicitamente EMP, assume escopo permitido
    if role_l != "admin" and not emps_sel and emps_scope:
        emps_sel = [str(e) for e in emps_scope]

    # Se ainda vazio (ex: admin sem filtro), usa emps_scope (que para admin tende a ser todas)
    if not emps_sel:
        emps_sel = [str(e) for e in emps_scope]

    # Recalcular (on-demand)
    if recalc:
        try:
            try:
                deps.recalcular_resultados_campanhas_para_scope(ano=ano, mes=mes, emps=emps_sel, vendedores_por_emp=vendedores_por_emp)
            except TypeError:
                deps.recalcular_resultados_campanhas_para_scope(ano=ano, mes=mes, emps_scope=emps_sel, vendedores_por_emp=vendedores_por_emp)

            try:
                deps.recalcular_resultados_combos_para_scope(ano=ano, mes=mes, emps=emps_sel, vendedores_por_emp=vendedores_por_emp)
            except TypeError:
                deps.recalcular_resultados_combos_para_scope(ano=ano, mes=mes, emps_scope=emps_sel, vendedores_por_emp=vendedores_por_emp)

            # Passo 3: gera snapshot mensal de Itens Parados no recálculo manual.
            # A tela e o PDF passam a ler esse snapshot nas próximas aberturas,
            # evitando cálculo pesado ao vivo em cima de vendas.
            try:
                snap_stats = rebuild_itens_parados_snapshot(
                    ano=int(ano),
                    mes=int(mes),
                    emps=emps_sel,
                    vendedores_por_emp=vendedores_por_emp,
                )
                print(
                    "[RELATORIO_UNIFICADO] itens_parados_snapshot "
                    f"emps={snap_stats.get('emps', 0)} rows={snap_stats.get('rows', 0)} skipped={snap_stats.get('skipped', 0)}"
                )
            except Exception as snap_exc:
                print(f"[RELATORIO_UNIFICADO] erro snapshot itens parados: {snap_exc}")
        except Exception as e:
            try:
                deps.SessionLocal().rollback()
            except Exception:
                pass
            flash("Não foi possível recalcular agora. Tente novamente em instantes.", "warning")
            print(f"[RELATORIO_UNIFICADO] erro recalc: {e}")

    cache_key = _relatorio_cache_key(
        role=role_l,
        vendedor_logado=vendedor_logado,
        ano=ano,
        mes=mes,
        emps=emps_sel,
        vendedores_por_emp=vendedores_por_emp,
    )

    # Recalcular deve sempre invalidar cache do processo atual.
    if recalc:
        _relatorio_cache_clear()

    cached = None if recalc else _relatorio_cache_get(cache_key)
    if cached is not None:
        rows, charts = cached
        try:
            print(f"[RELATORIO_UNIFICADO] cache_hit rows={len(rows or [])} ano={ano} mes={mes} emps={len(emps_sel or [])}")
        except Exception:
            pass
    else:
        lock = _relatorio_inflight_lock_for(cache_key)
        with lock:
            # Segunda checagem depois de aguardar outra request idêntica terminar.
            cached_after_wait = None if recalc else _relatorio_cache_get(cache_key)
            if cached_after_wait is not None:
                rows, charts = cached_after_wait
                try:
                    print(f"[RELATORIO_UNIFICADO] cache_hit_after_wait rows={len(rows or [])} ano={ano} mes={mes} emps={len(emps_sel or [])}")
                except Exception:
                    pass
            else:
                started = time.perf_counter()
                try:
                    rows = build_unified_rows(
                        ano=ano,
                        mes=mes,
                        emps=emps_sel,
                        vendedores_por_emp=vendedores_por_emp,
                        incluir_zerados=False,
                        usar_snapshot_itens_parados=True,
                        incluir_participacao_ativa=True,
                        metas_live=False,
                        ensure_missing_gerente_snapshots=False,
                    )
                    if rows is None:
                        rows = []
                except Exception as e:
                    try:
                        deps.SessionLocal().rollback()
                    except Exception:
                        pass
                    print(f"[RELATORIO_UNIFICADO] erro ao montar rows: {e}")
                    rows = []

                charts = aggregate_for_charts(rows or [])
                _relatorio_cache_set(cache_key, rows, charts)
                try:
                    elapsed_ms = int((time.perf_counter() - started) * 1000)
                    print(f"[RELATORIO_UNIFICADO] cache_miss duration_ms={elapsed_ms} rows={len(rows or [])} ano={ano} mes={mes} emps={len(emps_sel or [])}")
                except Exception:
                    pass

    # Stats básicos
    total_linhas = len(rows or [])
    total_recompensa = charts.get("total_recompensa", 0.0)

    return {
        "ano": ano,
        "mes": mes,
        "role": role_l,
        "vendedor_logado": vendedor_logado,
        "emps_scope": emps_scope,
        "emps_sel": emps_sel,
        "vendedores_sel": vendedores_sel,
        "vendedores_por_emp": vendedores_por_emp,
        "rows": rows,
        "charts": charts,
        "total_linhas": total_linhas,
        "total_recompensa": total_recompensa,
        "recalc": recalc,
    }
