from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, func, or_

from db import SessionLocal, Venda, CampanhaV2Master, CampanhaV2Resultado, CampanhaV2Audit


ALLOWED_STATUS = {"PENDENTE", "A_PAGAR", "PAGO"}


@dataclass
class V2RecalcStats:
    campanhas_processadas: int = 0
    resultados_upsertados: int = 0


def _safe_json_loads(s: Optional[str]) -> Dict[str, Any]:
    if not s:
        return {}
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _safe_json_dumps(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return "{}"


def _prev_competencia(ano: int, mes: int) -> Tuple[int, int]:
    if mes <= 1:
        return ano - 1, 12
    return ano, mes - 1


def _iter_emps_from_json(emps_json: Optional[str]) -> List[int]:
    if not emps_json:
        return []
    try:
        arr = json.loads(emps_json)
        if isinstance(arr, list):
            out = []
            for x in arr:
                try:
                    out.append(int(x))
                except Exception:
                    continue
            return sorted(set(out))
    except Exception:
        pass
    return []


def list_campanhas_v2(session, *, include_inactive: bool = False) -> List[CampanhaV2Master]:
    q = session.query(CampanhaV2Master)
    if not include_inactive:
        q = q.filter(CampanhaV2Master.ativo.is_(True))
    return q.order_by(CampanhaV2Master.id.desc()).all()


def upsert_campanha_v2(
    session,
    *,
    campanha_id: Optional[int],
    titulo: str,
    tipo: str,
    escopo: str,
    emps: List[int],
    vigencia_ini: date,
    vigencia_fim: date,
    ativo: bool,
    regras: Dict[str, Any],
) -> CampanhaV2Master:
    escopo = (escopo or "EMP").strip().upper()
    if escopo not in ("EMP", "GLOBAL"):
        escopo = "EMP"

    obj: Optional[CampanhaV2Master] = None
    if campanha_id:
        obj = session.query(CampanhaV2Master).filter(CampanhaV2Master.id == campanha_id).first()
    if not obj:
        obj = CampanhaV2Master()
        session.add(obj)

    obj.titulo = (titulo or "").strip()[:160]
    obj.tipo = (tipo or "").strip().upper()[:40]
    obj.escopo = escopo
    obj.emps_json = _safe_json_dumps(emps) if escopo == "EMP" else None
    obj.vigencia_ini = vigencia_ini
    obj.vigencia_fim = vigencia_fim
    obj.ativo = bool(ativo)
    obj.regras_json = _safe_json_dumps(regras)

    session.commit()
    return obj


def delete_campanha_v2(session, campanha_id: int) -> None:
    obj = session.query(CampanhaV2Master).filter(CampanhaV2Master.id == campanha_id).first()
    if obj:
        session.delete(obj)
        session.commit()


def seed_defaults_if_empty(session) -> int:
    """Cria campanhas padrão se o cadastro estiver vazio.

    Retorna quantas campanhas foram criadas.
    """
    if session.query(CampanhaV2Master.id).limit(1).first():
        return 0

    today = date.today()
    ini = date(today.year, 1, 1)
    fim = date(today.year, 12, 31)

    defaults = [
        # Ranking por marca (exemplo) - o usuário ajusta na tela
        {
            "titulo": "Ranking por valor - MAGNETRON (Top 1/2/3) - POR EMP",
            "tipo": "RANKING_VALOR",
            "escopo": "EMP",
            "emps": [],
            "regras": {
                "marca": "MAGNETRON",
                "escopo_ranking": "EMP",
                "top": [
                    {"pos": 1, "valor": 300},
                    {"pos": 2, "valor": 200},
                    {"pos": 3, "valor": 100},
                ],
            },
        },
        {
            "titulo": "Meta % vs Mês Anterior (+10%)",
            "tipo": "META_PERCENTUAL",
            "escopo": "EMP",
            "emps": [],
            "regras": {"ref_tipo": "MES_ANTERIOR", "pct": 10, "premio": 300},
        },
        {
            "titulo": "Meta % vs Ano Passado (+10%)",
            "tipo": "META_PERCENTUAL",
            "escopo": "EMP",
            "emps": [],
            "regras": {"ref_tipo": "ANO_PASSADO", "pct": 10, "premio": 300},
        },
        {
            "titulo": "Meta Absoluta (R$ 100.000)",
            "tipo": "META_ABSOLUTA",
            "escopo": "EMP",
            "emps": [],
            "regras": {"meta": 100000, "premio": 300},
        },
        {
            "titulo": "Mix de Produtos (10 distintos)",
            "tipo": "MIX",
            "escopo": "EMP",
            "emps": [],
            "regras": {"min_distintos": 10, "premio": 200},
        },
        {
            "titulo": "Acumulativa 3 meses (R$ 250.000)",
            "tipo": "ACUMULATIVA",
            "escopo": "EMP",
            "emps": [],
            "regras": {"janela_meses": 3, "meta": 250000, "premio": 500},
        },
    ]

    for d in defaults:
        upsert_campanha_v2(
            session,
            campanha_id=None,
            titulo=d["titulo"],
            tipo=d["tipo"],
            escopo=d["escopo"],
            emps=d.get("emps") or [],
            vigencia_ini=ini,
            vigencia_fim=fim,
            ativo=True,
            regras=d["regras"],
        )

    return len(defaults)


def _upsert_result(
    session,
    *,
    campanha: CampanhaV2Master,
    ano: int,
    mes: int,
    emp: int,
    vendedor: str,
    base_num: float,
    atingiu: bool,
    valor_recompensa: float,
    detalhes: Dict[str, Any],
) -> bool:
    obj = (
        session.query(CampanhaV2Resultado)
        .filter(
            CampanhaV2Resultado.campanha_id == campanha.id,
            CampanhaV2Resultado.competencia_ano == ano,
            CampanhaV2Resultado.competencia_mes == mes,
            CampanhaV2Resultado.emp == emp,
            CampanhaV2Resultado.vendedor == vendedor,
        )
        .first()
    )
    created = False
    if not obj:
        obj = CampanhaV2Resultado(
            campanha_id=campanha.id,
            competencia_ano=ano,
            competencia_mes=mes,
            emp=emp,
            vendedor=vendedor,
        )
        session.add(obj)
        created = True

    obj.tipo = campanha.tipo
    obj.base_num = float(base_num or 0)
    obj.atingiu = bool(atingiu)
    obj.valor_recompensa = float(valor_recompensa or 0)
    obj.detalhes_json = _safe_json_dumps(detalhes)
    obj.vigencia_ini = campanha.vigencia_ini
    obj.vigencia_fim = campanha.vigencia_fim
    obj.atualizado_em = datetime.utcnow()
    # mantém status/pago_em se já existir

    return created


def recalc_v2_for_competencia(
    ano: int,
    mes: int,
    *,
    actor: str = "system",
) -> V2RecalcStats:
    """Recalcula campanhas V2 para uma competência e grava em campanhas_resultados_v2.

    Observação: por padrão só gravamos linhas com valor_recompensa > 0.
    """

    stats = V2RecalcStats()

    with SessionLocal() as session:
        campanhas = list_campanhas_v2(session, include_inactive=False)

        # Limpa resultados V2 da competência para campanhas ativas (recalc total)
        camp_ids = [c.id for c in campanhas]
        if camp_ids:
            session.query(CampanhaV2Resultado).filter(
                CampanhaV2Resultado.campanha_id.in_(camp_ids),
                CampanhaV2Resultado.competencia_ano == ano,
                CampanhaV2Resultado.competencia_mes == mes,
            ).delete(synchronize_session=False)
            session.commit()

        for c in campanhas:
            stats.campanhas_processadas += 1
            regras = _safe_json_loads(c.regras_json)
            tipo = (c.tipo or "").upper()

            # Respeita vigência
            comp_date = date(ano, mes, 1)
            if c.vigencia_ini and comp_date < c.vigencia_ini.replace(day=1):
                continue
            if c.vigencia_fim and comp_date > c.vigencia_fim.replace(day=1):
                continue

            emps_alvo: List[int]
            if (c.escopo or "EMP").upper() == "GLOBAL":
                emps_alvo = []  # global não filtra por EMP
            else:
                emps_alvo = _iter_emps_from_json(c.emps_json)

            if tipo == "RANKING_VALOR":
                _calc_ranking_valor(session, c, ano, mes, regras, emps_alvo)
            elif tipo == "META_PERCENTUAL":
                _calc_meta_percentual(session, c, ano, mes, regras, emps_alvo)
            elif tipo == "META_ABSOLUTA":
                _calc_meta_absoluta(session, c, ano, mes, regras, emps_alvo)
            elif tipo == "MIX":
                _calc_mix(session, c, ano, mes, regras, emps_alvo)
            elif tipo == "ACUMULATIVA":
                _calc_acumulativa(session, c, ano, mes, regras, emps_alvo)
            elif tipo == "MARGEM":
                # Stand-by: ainda não existe margem/margem_padrao importados em vendas
                continue
            else:
                continue

        # Conta quantos resultados ficaram
        stats.resultados_upsertados = (
            session.query(func.count(CampanhaV2Resultado.id))
            .filter(CampanhaV2Resultado.competencia_ano == ano, CampanhaV2Resultado.competencia_mes == mes)
            .scalar()
            or 0
        )

        # Audit (recalc)
        session.add(
            CampanhaV2Audit(
                acao="recalc",
                competencia_ano=ano,
                competencia_mes=mes,
                actor=actor,
                payload_json=_safe_json_dumps({
                    "campanhas": stats.campanhas_processadas,
                    "resultados": stats.resultados_upsertados,
                }),
            )
        )
        session.commit()

    return stats


def _base_vendas_query(session, ano: int, mes: int):
    return (
        session.query(Venda)
        .filter(
            Venda.mov_tipo_movto == "OA",
            Venda.ano == ano,
            Venda.mes == mes,
        )
    )


def _apply_emp_filter(q, emps_alvo: List[int]):
    if emps_alvo:
        q = q.filter(Venda.emp.in_([str(e) for e in emps_alvo]) | Venda.emp.in_(emps_alvo))
    return q


def _calc_ranking_valor(session, campanha: CampanhaV2Master, ano: int, mes: int, regras: Dict[str, Any], emps_alvo: List[int]) -> None:
    marca = (regras.get("marca") or "").strip()
    escopo_ranking = (regras.get("escopo_ranking") or "EMP").strip().upper()  # EMP ou GLOBAL
    top = regras.get("top") or []
    premios = {int(t.get("pos")): float(t.get("valor") or 0) for t in top if isinstance(t, dict)}

    q = session.query(
        Venda.emp.label("emp"),
        Venda.vendedor.label("vendedor"),
        func.coalesce(func.sum(Venda.valor_total), 0).label("total"),
    ).filter(
        Venda.mov_tipo_movto == "OA",
        Venda.ano == ano,
        Venda.mes == mes,
    )
    if marca:
        q = q.filter(Venda.marca == marca)

    if escopo_ranking == "GLOBAL" or (campanha.escopo or "").upper() == "GLOBAL":
        # global: soma em todas EMPs por vendedor
        qg = session.query(
            Venda.vendedor.label("vendedor"),
            func.coalesce(func.sum(Venda.valor_total), 0).label("total"),
        ).filter(
            Venda.mov_tipo_movto == "OA",
            Venda.ano == ano,
            Venda.mes == mes,
        )
        if marca:
            qg = qg.filter(Venda.marca == marca)
        qg = qg.group_by(Venda.vendedor).order_by(func.coalesce(func.sum(Venda.valor_total), 0).desc())
        rows = qg.all()
        for idx, r in enumerate(rows, start=1):
            premio = float(premios.get(idx, 0))
            if premio <= 0:
                continue
            _upsert_result(
                session,
                campanha=campanha,
                ano=ano,
                mes=mes,
                emp=0,
                vendedor=str(r.vendedor or ""),
                base_num=float(r.total or 0),
                atingiu=True,
                valor_recompensa=premio,
                detalhes={"posicao": idx, "marca": marca or None, "escopo": "GLOBAL"},
            )
    else:
        # por EMP: ranking dentro de cada emp
        q = _apply_emp_filter(q, emps_alvo)
        q = q.group_by(Venda.emp, Venda.vendedor)
        rows = q.all()

        # agrupa por emp em python (n é grande por competência)
        by_emp: Dict[str, List[Tuple[str, float]]] = {}
        for r in rows:
            emp = str(r.emp)
            by_emp.setdefault(emp, []).append((str(r.vendedor or ""), float(r.total or 0)))

        for emp, arr in by_emp.items():
            arr.sort(key=lambda x: x[1], reverse=True)
            for idx, (vend, total) in enumerate(arr, start=1):
                premio = float(premios.get(idx, 0))
                if premio <= 0:
                    continue
                try:
                    emp_int = int(emp)
                except Exception:
                    continue
                _upsert_result(
                    session,
                    campanha=campanha,
                    ano=ano,
                    mes=mes,
                    emp=emp_int,
                    vendedor=vend,
                    base_num=total,
                    atingiu=True,
                    valor_recompensa=premio,
                    detalhes={"posicao": idx, "marca": marca or None, "escopo": "EMP"},
                )

    session.commit()


def _calc_meta_percentual(session, campanha: CampanhaV2Master, ano: int, mes: int, regras: Dict[str, Any], emps_alvo: List[int]) -> None:
    ref_tipo = (regras.get("ref_tipo") or "MES_ANTERIOR").strip().upper()  # MES_ANTERIOR / ANO_PASSADO
    pct = float(regras.get("pct") or 0)
    premio = float(regras.get("premio") or 0)
    marca = (regras.get("marca") or "").strip()  # opcional

    if pct <= 0 or premio <= 0:
        return

    # base atual
    qa = session.query(
        Venda.emp.label("emp"),
        Venda.vendedor.label("vendedor"),
        func.coalesce(func.sum(Venda.valor_total), 0).label("total"),
    ).filter(
        Venda.mov_tipo_movto == "OA",
        Venda.ano == ano,
        Venda.mes == mes,
    )
    if marca:
        qa = qa.filter(Venda.marca == marca)
    qa = _apply_emp_filter(qa, emps_alvo)
    qa = qa.group_by(Venda.emp, Venda.vendedor)
    atuais = {(str(r.emp), str(r.vendedor)): float(r.total or 0) for r in qa.all()}

    # base referência
    if ref_tipo == "ANO_PASSADO":
        ra, rm = ano - 1, mes
    else:
        ra, rm = _prev_competencia(ano, mes)

    qr = session.query(
        Venda.emp.label("emp"),
        Venda.vendedor.label("vendedor"),
        func.coalesce(func.sum(Venda.valor_total), 0).label("total"),
    ).filter(
        Venda.mov_tipo_movto == "OA",
        Venda.ano == ra,
        Venda.mes == rm,
    )
    if marca:
        qr = qr.filter(Venda.marca == marca)
    qr = _apply_emp_filter(qr, emps_alvo)
    qr = qr.group_by(Venda.emp, Venda.vendedor)
    refs = {(str(r.emp), str(r.vendedor)): float(r.total or 0) for r in qr.all()}

    for key, atual in atuais.items():
        emp, vend = key
        ref = float(refs.get(key, 0))
        if ref <= 0:
            continue
        alvo = ref * (1.0 + (pct / 100.0))
        atingiu = atual >= alvo
        if not atingiu:
            continue
        try:
            emp_int = int(emp)
        except Exception:
            continue
        _upsert_result(
            session,
            campanha=campanha,
            ano=ano,
            mes=mes,
            emp=emp_int,
            vendedor=vend,
            base_num=atual,
            atingiu=True,
            valor_recompensa=premio,
            detalhes={
                "ref_tipo": ref_tipo,
                "pct": pct,
                "base_ref": ref,
                "alvo": alvo,
                "marca": marca or None,
            },
        )

    session.commit()


def _calc_meta_absoluta(session, campanha: CampanhaV2Master, ano: int, mes: int, regras: Dict[str, Any], emps_alvo: List[int]) -> None:
    meta = float(regras.get("meta") or 0)
    premio = float(regras.get("premio") or 0)
    marca = (regras.get("marca") or "").strip()

    if meta <= 0 or premio <= 0:
        return

    q = session.query(
        Venda.emp.label("emp"),
        Venda.vendedor.label("vendedor"),
        func.coalesce(func.sum(Venda.valor_total), 0).label("total"),
    ).filter(
        Venda.mov_tipo_movto == "OA",
        Venda.ano == ano,
        Venda.mes == mes,
    )
    if marca:
        q = q.filter(Venda.marca == marca)
    q = _apply_emp_filter(q, emps_alvo)
    q = q.group_by(Venda.emp, Venda.vendedor)

    for r in q.all():
        total = float(r.total or 0)
        if total < meta:
            continue
        try:
            emp_int = int(r.emp)
        except Exception:
            continue
        _upsert_result(
            session,
            campanha=campanha,
            ano=ano,
            mes=mes,
            emp=emp_int,
            vendedor=str(r.vendedor or ""),
            base_num=total,
            atingiu=True,
            valor_recompensa=premio,
            detalhes={"meta": meta, "marca": marca or None},
        )

    session.commit()


def _calc_mix(session, campanha: CampanhaV2Master, ano: int, mes: int, regras: Dict[str, Any], emps_alvo: List[int]) -> None:
    min_dist = int(regras.get("min_distintos") or 0)
    premio = float(regras.get("premio") or 0)
    marca = (regras.get("marca") or "").strip()  # opcional: mix dentro de uma marca

    if min_dist <= 0 or premio <= 0:
        return

    q = session.query(
        Venda.emp.label("emp"),
        Venda.vendedor.label("vendedor"),
        func.count(func.distinct(Venda.mestre)).label("mix"),
    ).filter(
        Venda.mov_tipo_movto == "OA",
        Venda.ano == ano,
        Venda.mes == mes,
    )
    if marca:
        q = q.filter(Venda.marca == marca)
    q = _apply_emp_filter(q, emps_alvo)
    q = q.group_by(Venda.emp, Venda.vendedor)

    for r in q.all():
        mix = int(r.mix or 0)
        if mix < min_dist:
            continue
        try:
            emp_int = int(r.emp)
        except Exception:
            continue
        _upsert_result(
            session,
            campanha=campanha,
            ano=ano,
            mes=mes,
            emp=emp_int,
            vendedor=str(r.vendedor or ""),
            base_num=float(mix),
            atingiu=True,
            valor_recompensa=premio,
            detalhes={"min_distintos": min_dist, "mix": mix, "marca": marca or None},
        )

    session.commit()


def _calc_acumulativa(session, campanha: CampanhaV2Master, ano: int, mes: int, regras: Dict[str, Any], emps_alvo: List[int]) -> None:
    janela = int(regras.get("janela_meses") or 3)
    meta = float(regras.get("meta") or 0)
    premio = float(regras.get("premio") or 0)
    marca = (regras.get("marca") or "").strip()

    if janela <= 1 or meta <= 0 or premio <= 0:
        return

    # calcula lista de (ano,mes) na janela
    comps: List[Tuple[int, int]] = []
    a, m = ano, mes
    for _ in range(janela):
        comps.append((a, m))
        a, m = _prev_competencia(a, m)

    q = session.query(
        Venda.emp.label("emp"),
        Venda.vendedor.label("vendedor"),
        func.coalesce(func.sum(Venda.valor_total), 0).label("total"),
    ).filter(
        Venda.mov_tipo_movto == "OA",
        or_(*[and_(Venda.ano == aa, Venda.mes == mm) for aa, mm in comps]),
    )

    if marca:
        q = q.filter(Venda.marca == marca)
    q = _apply_emp_filter(q, emps_alvo)
    q = q.group_by(Venda.emp, Venda.vendedor)

    for r in q.all():
        total = float(r.total or 0)
        if total < meta:
            continue
        try:
            emp_int = int(r.emp)
        except Exception:
            continue
        _upsert_result(
            session,
            campanha=campanha,
            ano=ano,
            mes=mes,
            emp=emp_int,
            vendedor=str(r.vendedor or ""),
            base_num=total,
            atingiu=True,
            valor_recompensa=premio,
            detalhes={"janela": janela, "meta": meta, "comps": comps, "marca": marca or None},
        )

    session.commit()


def update_status_pagamento_v2(
    *,
    campanha_id: int,
    ano: int,
    mes: int,
    emp: int,
    vendedor: str,
    novo_status: str,
    actor: str,
) -> bool:
    novo_status = (novo_status or "").strip().upper()
    if novo_status not in ALLOWED_STATUS:
        return False

    with SessionLocal() as session:
        obj = (
            session.query(CampanhaV2Resultado)
            .filter(
                CampanhaV2Resultado.campanha_id == campanha_id,
                CampanhaV2Resultado.competencia_ano == ano,
                CampanhaV2Resultado.competencia_mes == mes,
                CampanhaV2Resultado.emp == emp,
                CampanhaV2Resultado.vendedor == vendedor,
            )
            .first()
        )
        if not obj:
            return False

        old = obj.status_pagamento
        obj.status_pagamento = novo_status
        if novo_status == "PAGO":
            obj.pago_em = datetime.utcnow()
        obj.atualizado_em = datetime.utcnow()

        session.add(
            CampanhaV2Audit(
                campanha_id=campanha_id,
                competencia_ano=ano,
                competencia_mes=mes,
                emp=emp,
                vendedor=vendedor,
                acao="status_update",
                de_status=old,
                para_status=novo_status,
                actor=actor,
                payload_json=_safe_json_dumps({"old": old, "new": novo_status}),
            )
        )

        session.commit()
        return True



def list_resultados_v2(
    db,
    *,
    ano: int,
    mes: int,
    emps_scope: list[int] | None = None,
    vendedores_scope: list[str] | None = None,
) -> list[dict]:
    """Lista resultados V2 já calculados (snapshot) para uma competência.

    Retorna dados enriquecidos com título/tipo da campanha para uso em páginas /campanhas e /relatorios/campanhas.
    - emps_scope: lista de EMPs permitidas/selecionadas (None = todas)
    - vendedores_scope: lista de vendedores permitidos/selecionados (None = todos)
    """
    emps_scope = emps_scope or []
    vendedores_scope = [v.strip().upper() for v in (vendedores_scope or []) if v and str(v).strip()]
    q = (
        db.query(CampanhaV2Resultado, CampanhaV2Master)
        .join(CampanhaV2Master, CampanhaV2Master.id == CampanhaV2Resultado.campanha_id)
        .filter(CampanhaV2Resultado.competencia_ano == int(ano))
        .filter(CampanhaV2Resultado.competencia_mes == int(mes))
    )

    if emps_scope:
        q = q.filter(CampanhaV2Resultado.emp.in_(emps_scope))

    if vendedores_scope:
        q = q.filter(func.upper(CampanhaV2Resultado.vendedor).in_(vendedores_scope))

    rows = q.order_by(CampanhaV2Master.id.desc(), CampanhaV2Resultado.emp.asc(), CampanhaV2Resultado.vendedor.asc()).all()

    out: list[dict] = []
    for r, c in rows:
        out.append(
            {
                "campanha_id": c.id,
                "titulo": c.titulo,
                "tipo": c.tipo,
                "emp": int(r.emp or 0),
                "vendedor": (r.vendedor or "").strip().upper(),
                "base_num": float(r.base_num or 0.0),
                "atingiu": bool(r.atingiu),
                "valor_recompensa": float(r.valor_recompensa or 0.0),
                "status_pagamento": (r.status_pagamento or "PENDENTE"),
                "detalhes_json": r.detalhes_json,
            }
        )
    return out
