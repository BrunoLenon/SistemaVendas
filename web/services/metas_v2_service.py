from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text, func
from sqlalchemy.orm import Session

from db import Venda, ItemParado, VendasResumoPeriodo

# =========================
# Helpers
# =========================

def periodo_bounds(ano: int, mes: int) -> Tuple[date, date]:
    if mes < 1 or mes > 12:
        raise ValueError("mes inválido")
    start = date(ano, mes, 1)
    if mes == 12:
        end = date(ano + 1, 1, 1)
    else:
        end = date(ano, mes + 1, 1)
    return start, end


def sort_faixas_desc(faixas: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(faixas, key=lambda x: float(x.get("limite", 0)), reverse=True)


# =========================
# CRUD - Programas
# =========================

def list_programas(db: Session, ano: int, mes: int) -> List[Dict[str, Any]]:
    q = text(
        """
        select p.id, p.nome, p.ano, p.mes, p.ativo,
               p.baseline_tipo, p.baseline_janela_meses,
               p.gate_itens_parados_enabled, p.gate_itens_parados_min_valor
        from metas_v2_programas p
        where p.ano = :ano and p.mes = :mes
        order by p.id desc
        """
    )
    rows = db.execute(q, {"ano": ano, "mes": mes}).mappings().all()
    out = []
    for r in rows:
        pid = int(r["id"])
        emps = db.execute(
            text("select emp from metas_v2_programa_emps where programa_id=:pid order by emp"),
            {"pid": pid},
        ).scalars().all()
        out.append({**dict(r), "emps": list(emps)})
    return out


def get_programa(db: Session, programa_id: int) -> Optional[Dict[str, Any]]:
    r = db.execute(
        text(
            """
            select p.*
            from metas_v2_programas p
            where p.id = :pid
            """
        ),
        {"pid": programa_id},
    ).mappings().first()
    if not r:
        return None
    emps = db.execute(
        text("select emp from metas_v2_programa_emps where programa_id=:pid order by emp"),
        {"pid": programa_id},
    ).scalars().all()
    criterios = db.execute(
        text("select id, tipo, ativo, params from metas_v2_criterios where programa_id=:pid order by id"),
        {"pid": programa_id},
    ).mappings().all()
    crit_out = []
    for c in criterios:
        faixas = db.execute(
            text("select limite, recompensa_pct, ordem from metas_v2_faixas where criterio_id=:cid order by ordem asc, limite asc"),
            {"cid": int(c["id"])},
        ).mappings().all()
        crit_out.append({**dict(c), "faixas": [dict(f) for f in faixas]})
    return {**dict(r), "emps": list(emps), "criterios": crit_out}


def upsert_programa(
    db: Session,
    *,
    programa_id: Optional[int],
    nome: str,
    ano: int,
    mes: int,
    ativo: bool,
    baseline_tipo: str,
    baseline_janela_meses: int,
    gate_enabled: bool,
    gate_min_valor: float,
    emps: List[str],
    crescimento_faixas: List[Dict[str, Any]],
    mix_faixas: List[Dict[str, Any]],
) -> int:
    # programa
    if programa_id:
        db.execute(
            text(
                """
                update metas_v2_programas
                   set nome=:nome,
                       ano=:ano,
                       mes=:mes,
                       ativo=:ativo,
                       baseline_tipo=:baseline_tipo,
                       baseline_janela_meses=:baseline_janela_meses,
                       gate_itens_parados_enabled=:gate_enabled,
                       gate_itens_parados_min_valor=:gate_min_valor,
                       atualizado_em=now()
                 where id=:pid
                """
            ),
            {
                "pid": programa_id,
                "nome": nome,
                "ano": ano,
                "mes": mes,
                "ativo": ativo,
                "baseline_tipo": baseline_tipo,
                "baseline_janela_meses": baseline_janela_meses,
                "gate_enabled": gate_enabled,
                "gate_min_valor": gate_min_valor,
            },
        )
        pid = int(programa_id)
    else:
        r = db.execute(
            text(
                """
                insert into metas_v2_programas
                    (nome, ano, mes, ativo, baseline_tipo, baseline_janela_meses,
                     gate_itens_parados_enabled, gate_itens_parados_min_valor)
                values
                    (:nome, :ano, :mes, :ativo, :baseline_tipo, :baseline_janela_meses,
                     :gate_enabled, :gate_min_valor)
                returning id
                """
            ),
            {
                "nome": nome,
                "ano": ano,
                "mes": mes,
                "ativo": ativo,
                "baseline_tipo": baseline_tipo,
                "baseline_janela_meses": baseline_janela_meses,
                "gate_enabled": gate_enabled,
                "gate_min_valor": gate_min_valor,
            },
        ).scalar_one()
        pid = int(r)

    # emps
    db.execute(text("delete from metas_v2_programa_emps where programa_id=:pid"), {"pid": pid})
    for e in sorted({(e or "").strip() for e in emps if (e or "").strip()}):
        db.execute(
            text("insert into metas_v2_programa_emps (programa_id, emp) values (:pid, :emp)"),
            {"pid": pid, "emp": e},
        )

    # criterios + faixas (crescimento, mix)
    _upsert_criterio_faixas(db, pid, "crescimento", crescimento_faixas, params={})
    _upsert_criterio_faixas(db, pid, "mix", mix_faixas, params={})

    return pid


def _upsert_criterio_faixas(
    db: Session,
    programa_id: int,
    tipo: str,
    faixas: List[Dict[str, Any]],
    params: Dict[str, Any],
) -> None:
    c = db.execute(
        text("select id from metas_v2_criterios where programa_id=:pid and tipo=:tipo limit 1"),
        {"pid": programa_id, "tipo": tipo},
    ).scalar()
    if c:
        cid = int(c)
        db.execute(
            text("update metas_v2_criterios set ativo=true, params=:params where id=:cid"),
            {"cid": cid, "params": params},
        )
    else:
        cid = int(
            db.execute(
                text(
                    "insert into metas_v2_criterios (programa_id, tipo, ativo, params) values (:pid,:tipo,true,:params) returning id"
                ),
                {"pid": programa_id, "tipo": tipo, "params": params},
            ).scalar_one()
        )

    db.execute(text("delete from metas_v2_faixas where criterio_id=:cid"), {"cid": cid})

    # ordena por limite asc para exibição; cálculo usa maior atingida
    cleaned = []
    for f in faixas or []:
        try:
            limite = float(str(f.get("limite", "")).replace(",", "."))
            recompensa = float(str(f.get("recompensa_pct", "")).replace(",", "."))
        except Exception:
            continue
        if limite <= 0 or recompensa <= 0:
            continue
        cleaned.append({"limite": limite, "recompensa_pct": recompensa})
    cleaned = sorted(cleaned, key=lambda x: x["limite"])
    for i, f in enumerate(cleaned):
        db.execute(
            text("insert into metas_v2_faixas (criterio_id, limite, recompensa_pct, ordem) values (:cid,:lim,:rec,:ord)"),
            {"cid": cid, "lim": f["limite"], "rec": f["recompensa_pct"], "ord": i},
        )


# =========================
# Cálculo + Snapshot
# =========================

def calcular_e_snapshot(
    db: Session,
    programa_id: int,
    *,
    ano: int,
    mes: int,
    emp_scopes: List[str],
    vendedor_scopes: Optional[List[str]] = None,
) -> None:
    programa = get_programa(db, programa_id)
    if not programa:
        return

    start, end = periodo_bounds(ano, mes)

    # vendedores alvo: união do que existe no resumo e do que vendeu no mês
    vendedores_set = set()

    qv = db.query(Venda.vendedor).filter(Venda.emp.in_(emp_scopes)).filter(Venda.movimento >= start).filter(Venda.movimento < end).distinct()
    for (vend,) in qv.all():
        if vend:
            vendedores_set.add(str(vend).strip())

    qr = db.query(VendasResumoPeriodo.vendedor).filter(VendasResumoPeriodo.emp.in_(emp_scopes)).filter(VendasResumoPeriodo.ano == ano).filter(VendasResumoPeriodo.mes == mes).distinct()
    for (vend,) in qr.all():
        if vend:
            vendedores_set.add(str(vend).strip())

    if vendedor_scopes:
        allowed = {v.strip() for v in vendedor_scopes if v and v.strip()}
        vendedores_set = {v for v in vendedores_set if v in allowed}

    vendedores = sorted(vendedores_set)

    # faixas
    crescimento_faixas = []
    mix_faixas = []
    for c in (programa.get("criterios") or []):
        if c.get("tipo") == "crescimento":
            crescimento_faixas = sort_faixas_desc(c.get("faixas") or [])
        if c.get("tipo") == "mix":
            mix_faixas = sort_faixas_desc(c.get("faixas") or [])

    for emp in emp_scopes:
        # gate: lista de códigos itens parados por EMP
        codigos = [
            (i.codigo or "").strip()
            for i in db.query(ItemParado).filter(ItemParado.emp == str(emp)).all()
            if (i.codigo or "").strip()
        ]
        codigos = sorted(set(codigos))

        for vendedor in vendedores:
            # valor líquido do mês (OA - (DS,CA))
            total_oa = (
                db.query(func.coalesce(func.sum(Venda.valor_total), 0.0))
                .filter(Venda.emp == str(emp))
                .filter(Venda.vendedor == vendedor)
                .filter(Venda.movimento >= start)
                .filter(Venda.movimento < end)
                .filter(Venda.mov_tipo_movto == "OA")
                .scalar()
                or 0.0
            )
            total_dev = (
                db.query(func.coalesce(func.sum(Venda.valor_total), 0.0))
                .filter(Venda.emp == str(emp))
                .filter(Venda.vendedor == vendedor)
                .filter(Venda.movimento >= start)
                .filter(Venda.movimento < end)
                .filter(Venda.mov_tipo_movto.in_(["DS", "CA"]))
                .scalar()
                or 0.0
            )
            valor_liquido = float(total_oa) - float(total_dev)

            # gate itens parados (OA nos códigos cadastrados)
            itens_parados_valor = 0.0
            if programa.get("gate_itens_parados_enabled") and codigos:
                itens_parados_valor = float(
                    (
                        db.query(func.coalesce(func.sum(Venda.valor_total), 0.0))
                        .filter(Venda.emp == str(emp))
                        .filter(Venda.vendedor == vendedor)
                        .filter(Venda.movimento >= start)
                        .filter(Venda.movimento < end)
                        .filter(Venda.mov_tipo_movto == "OA")
                        .filter(Venda.mestre.in_(codigos))
                        .scalar()
                        or 0.0
                    )
                )

            gate_ok = True
            if programa.get("gate_itens_parados_enabled"):
                gate_ok = itens_parados_valor >= float(programa.get("gate_itens_parados_min_valor") or 0.0)

            # MIX do mês: tenta resumo, senão calcula distinct mestre
            mix_mes = db.query(VendasResumoPeriodo.mix_produtos).filter(
                VendasResumoPeriodo.emp == str(emp),
                VendasResumoPeriodo.vendedor == vendedor,
                VendasResumoPeriodo.ano == ano,
                VendasResumoPeriodo.mes == mes,
            ).scalar()
            if mix_mes is None:
                mix_mes = int(
                    (
                        db.query(func.count(func.distinct(Venda.mestre)))
                        .filter(Venda.emp == str(emp))
                        .filter(Venda.vendedor == vendedor)
                        .filter(Venda.movimento >= start)
                        .filter(Venda.movimento < end)
                        .filter(Venda.mov_tipo_movto == "OA")
                        .scalar()
                        or 0
                    )
                )
            else:
                try:
                    mix_mes = int(mix_mes)
                except Exception:
                    mix_mes = 0

            # CRESCIMENTO: baseline via resumo
            baseline_tipo = (programa.get("baseline_tipo") or "ano_passado").strip()
            baseline = None
            atual_ref = None

            # atual_ref: tenta resumo do mês atual, senão usa total_oa (mais estável que líquido para comparar com resumo desconhecido)
            atual_ref = db.query(VendasResumoPeriodo.valor_venda).filter(
                VendasResumoPeriodo.emp == str(emp),
                VendasResumoPeriodo.vendedor == vendedor,
                VendasResumoPeriodo.ano == ano,
                VendasResumoPeriodo.mes == mes,
            ).scalar()
            if atual_ref is None:
                atual_ref = float(total_oa)

            if baseline_tipo == "media_meses":
                n = int(programa.get("baseline_janela_meses") or 3)
                # média dos N meses imediatamente anteriores (no resumo)
                # exemplo: se mes=2, pega 11,12 do ano anterior e 1 do ano atual (se existirem)
                months = []
                y, m = ano, mes
                for _ in range(n):
                    m -= 1
                    if m <= 0:
                        y -= 1
                        m = 12
                    months.append((y, m))
                vals = []
                for y, m in months:
                    v = db.query(VendasResumoPeriodo.valor_venda).filter(
                        VendasResumoPeriodo.emp == str(emp),
                        VendasResumoPeriodo.vendedor == vendedor,
                        VendasResumoPeriodo.ano == y,
                        VendasResumoPeriodo.mes == m,
                    ).scalar()
                    if v is not None:
                        try:
                            vals.append(float(v))
                        except Exception:
                            pass
                baseline = (sum(vals) / len(vals)) if vals else None
            else:
                # ano passado
                baseline = db.query(VendasResumoPeriodo.valor_venda).filter(
                    VendasResumoPeriodo.emp == str(emp),
                    VendasResumoPeriodo.vendedor == vendedor,
                    VendasResumoPeriodo.ano == (ano - 1),
                    VendasResumoPeriodo.mes == mes,
                ).scalar()
                if baseline is not None:
                    try:
                        baseline = float(baseline)
                    except Exception:
                        baseline = None

            crescimento_pct = None
            if baseline and float(baseline) > 0:
                crescimento_pct = ((float(atual_ref) - float(baseline)) / float(baseline)) * 100.0

            # pontuações por critério
            pct_crescimento = 0.0
            if gate_ok and crescimento_pct is not None:
                for f in crescimento_faixas:
                    lim = float(f.get("limite") or 0)
                    rec = float(f.get("recompensa_pct") or 0)
                    if float(crescimento_pct) >= lim:
                        pct_crescimento = rec
                        break

            pct_mix = 0.0
            if gate_ok:
                for f in mix_faixas:
                    lim = float(f.get("limite") or 0)
                    rec = float(f.get("recompensa_pct") or 0)
                    if float(mix_mes) >= lim:
                        pct_mix = rec
                        break

            pct_total = (pct_crescimento + pct_mix) if gate_ok else 0.0
            valor_premio = (pct_total / 100.0) * float(valor_liquido) if pct_total > 0 else 0.0

            breakdown = {
                "gate": {
                    "enabled": bool(programa.get("gate_itens_parados_enabled")),
                    "min_valor": float(programa.get("gate_itens_parados_min_valor") or 0.0),
                    "itens_parados_valor": float(itens_parados_valor),
                    "ok": bool(gate_ok),
                },
                "crescimento": {
                    "baseline_tipo": baseline_tipo,
                    "baseline": float(baseline) if baseline is not None else None,
                    "atual_ref": float(atual_ref) if atual_ref is not None else None,
                    "pct": float(crescimento_pct) if crescimento_pct is not None else None,
                    "pct_recompensa": float(pct_crescimento),
                },
                "mix": {
                    "mix_mes": int(mix_mes),
                    "pct_recompensa": float(pct_mix),
                },
            }

            # upsert snapshot
            db.execute(
                text(
                    """
                    insert into metas_v2_resultados
                        (programa_id, emp, vendedor, ano, mes,
                         valor_liquido, itens_parados_valor,
                         crescimento_base, crescimento_atual_ref, crescimento_pct,
                         mix_produtos, pct_total, valor_premio, breakdown)
                    values
                        (:programa_id, :emp, :vendedor, :ano, :mes,
                         :valor_liquido, :itens_parados_valor,
                         :crescimento_base, :crescimento_atual_ref, :crescimento_pct,
                         :mix_produtos, :pct_total, :valor_premio, :breakdown::jsonb)
                    on conflict (programa_id, emp, vendedor, ano, mes)
                    do update set
                        valor_liquido=excluded.valor_liquido,
                        itens_parados_valor=excluded.itens_parados_valor,
                        crescimento_base=excluded.crescimento_base,
                        crescimento_atual_ref=excluded.crescimento_atual_ref,
                        crescimento_pct=excluded.crescimento_pct,
                        mix_produtos=excluded.mix_produtos,
                        pct_total=excluded.pct_total,
                        valor_premio=excluded.valor_premio,
                        breakdown=excluded.breakdown,
                        criado_em=now()
                    """
                ),
                {
                    "programa_id": programa_id,
                    "emp": str(emp),
                    "vendedor": vendedor,
                    "ano": ano,
                    "mes": mes,
                    "valor_liquido": float(valor_liquido),
                    "itens_parados_valor": float(itens_parados_valor),
                    "crescimento_base": float(baseline) if baseline is not None else None,
                    "crescimento_atual_ref": float(atual_ref) if atual_ref is not None else None,
                    "crescimento_pct": float(crescimento_pct) if crescimento_pct is not None else None,
                    "mix_produtos": int(mix_mes),
                    "pct_total": float(pct_total),
                    "valor_premio": float(valor_premio),
                    "breakdown": json_dumps_safe(breakdown),
                },
            )


def list_resultados(db: Session, programa_id: int, ano: int, mes: int, emp_scopes: List[str], vendedor: Optional[str]=None) -> List[Dict[str, Any]]:
    q = text(
        """
        select emp, vendedor, valor_liquido, itens_parados_valor,
               crescimento_pct, mix_produtos,
               pct_total, valor_premio, breakdown
          from metas_v2_resultados
         where programa_id = :pid
           and ano = :ano and mes = :mes
           and emp = any(:emps)
        """
        + (" and vendedor = :vendedor " if vendedor else "")
        + " order by emp asc, valor_premio desc, pct_total desc, vendedor asc"
    )
    params = {"pid": programa_id, "ano": ano, "mes": mes, "emps": emp_scopes}
    if vendedor:
        params["vendedor"] = vendedor
    rows = db.execute(q, params).mappings().all()
    return [dict(r) for r in rows]


def json_dumps_safe(obj: Any) -> str:
    import json
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return "{}"
