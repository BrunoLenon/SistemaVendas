import json
import datetime
from dataclasses import dataclass
from typing import Any, Iterable

from sqlalchemy import func, and_, or_

from db import (
    CampanhaMasterV2,
    CampanhaResultadoV2,
    CampanhaAuditV2,
    Venda,
)


GLOBAL_EMP_TOKEN = "__GLOBAL__"


def _safe_json_load(s: str | None, default: Any) -> Any:
    if not s:
        return default
    try:
        return json.loads(s)
    except Exception:
        return default


def _periodo_bounds(ano: int, mes: int) -> tuple[datetime.date, datetime.date]:
    # usa o mesmo padrão do app: [ini, fim]
    ini = datetime.date(int(ano), int(mes), 1)
    if mes == 12:
        prox = datetime.date(int(ano) + 1, 1, 1)
    else:
        prox = datetime.date(int(ano), int(mes) + 1, 1)
    fim = prox - datetime.timedelta(days=1)
    return ini, fim


def _prev_competencia(ano: int, mes: int) -> tuple[int, int]:
    if int(mes) == 1:
        return int(ano) - 1, 12
    return int(ano), int(mes) - 1


def _date_fmt(d: Any) -> str:
    if not d:
        return ""
    if isinstance(d, datetime.datetime):
        d = d.date()
    if isinstance(d, datetime.date):
        return d.strftime("%d/%m/%Y")
    return str(d)


@dataclass
class CampanhaV2ResultRow:
    emp: str
    vendedor: str
    base_num: float
    base_ref: float | None
    pct_real: float | None
    pct_meta: float | None
    atingiu: bool
    valor_recompensa: float
    detalhes: dict[str, Any]


def recalcular_campanhas_v2(
    db,
    *,
    ano: int,
    mes: int,
    emps_scope: list[str],
    force: bool = False,
) -> None:
    """Recalcula resultados do engine V2 para a competência.

    - Não derruba o app se as tabelas não existirem.
    - Calcula apenas para campanhas ativas e vigentes.
    - Para campanhas globais, salva emp='__GLOBAL__' e depois a UI replica por EMP.
    """

    try:
        # Smoke test: se a tabela não existe, esta query vai falhar
        db.query(func.count(CampanhaMasterV2.id)).first()
    except Exception:
        return

    hoje = datetime.date.today()
    periodo_ini, periodo_fim = _periodo_bounds(int(ano), int(mes))

    # Carrega campanhas ativas que tenham interseção com a competência (por vigência)
    camps = (
        db.query(CampanhaMasterV2)
        .filter(CampanhaMasterV2.ativo.is_(True))
        .all()
    )

    for c in camps:
        try:
            # valida vigência (se não tiver, considera ativa)
            di = getattr(c, "vigencia_ini", None) or getattr(c, "data_inicio", None)
            df = getattr(c, "vigencia_fim", None) or getattr(c, "data_fim", None)
            if di and df:
                if df < periodo_ini or di > periodo_fim:
                    continue

            # escopo EMP
            escopo = (c.escopo or "").strip().upper() or "EMP"
            emps_alvo: list[str] = []
            if escopo == "EMP":
                emps_alvo = [str(e) for e in _safe_json_load(c.emps_json, []) if str(e).strip()]
                if emps_alvo:
                    emps_calc = [e for e in emps_scope if e in emps_alvo]
                else:
                    emps_calc = list(emps_scope)
            else:
                emps_calc = list(emps_scope)

            tipo = (c.tipo or "").strip().upper()

            if tipo == "RANKING_VALOR":
                rows = _calc_ranking_valor(db, c, ano, mes, emps_calc)

            # Compat: UI/cadastro usa META_PERCENTUAL com regras.ref_tipo
            elif tipo == "META_PERCENTUAL":
                ref_tipo = str(_safe_json_load(getattr(c, "regras_json", None), {}).get("ref_tipo") or "").strip().upper()
                if ref_tipo in ("ANO_PASSADO", "YOY", "YTD_YOY"):
                    rows = _calc_meta_pct_yoy(db, c, ano, mes, emps_calc)
                else:
                    # default: mês anterior
                    rows = _calc_meta_pct_mom(db, c, ano, mes, emps_calc)

            elif tipo == "META_PCT_MOM":
                rows = _calc_meta_pct_mom(db, c, ano, mes, emps_calc)
            elif tipo == "META_PCT_YOY":
                rows = _calc_meta_pct_yoy(db, c, ano, mes, emps_calc)

            # Compat: UI/cadastro usa META_ABSOLUTA
            elif tipo == "META_ABSOLUTA" or tipo == "META_ABS":
                rows = _calc_meta_abs(db, c, ano, mes, emps_calc)

            # Compat: UI/cadastro usa MIX
            elif tipo == "MIX" or tipo == "MIX_MESTRE":
                rows = _calc_mix_mestre(db, c, ano, mes, emps_calc)

            elif tipo == "ACUM_3M" or tipo == "ACUMULATIVA" or tipo == "ACUMULATIVA":
                rows = _calc_acumulativa(db, c, ano, mes, emps_calc)
            elif tipo == "MARGEM":
                # Stand-by
                continue
            else:
                continue

            _upsert_resultados(db, c, ano, mes, rows, force=force)
        except Exception as e:
            print(f"[CAMPANHAS_V2] erro ao recalcular campanha {getattr(c,'id',None)}: {e}")

    try:
        db.commit()
    except Exception:
        db.rollback()
def recalc_v2_competencia(
    db,
    *,
    ano: int,
    mes: int,
    actor: str = "system",
    emps_scope: list[str] | None = None,
    **kwargs,
):
    """Compat: alias esperado pelo app.py.

    Alguns patches/rotas chamam `recalc_v2_competencia(...)`. A implementação oficial do motor V2 é
    `recalcular_campanhas_v2(...)`. Mantemos este wrapper para evitar quebra de import e permitir
    chamadas com kwargs extras (ex.: actor).
    """
    if emps_scope is None:
        emps_scope = []
    return recalcular_campanhas_v2(db, ano=ano, mes=mes, emps_scope=emps_scope, actor=actor)



def recalc_v2_campanha(
    db,
    *,
    campanha_id: int,
    ano: int,
    mes: int,
    actor: str = "system",
    emps_scope: list[str] | None = None,
    force: bool = True,
):
    """Recalcula apenas UMA campanha V2 para a competência.

    Motivo: permite operação rápida no Admin sem precisar recalcular o mês inteiro.

    - Se a campanha não existir ou não estiver ativa/vigente, não faz nada.
    - Usa o mesmo motor interno (funções _calc_* + _upsert_resultados).
    """
    if emps_scope is None:
        emps_scope = []

    try:
        # Smoke test (tabela existe?)
        db.query(func.count(CampanhaMasterV2.id)).first()
    except Exception:
        return

    periodo_ini, periodo_fim = _periodo_bounds(int(ano), int(mes))

    c = db.query(CampanhaMasterV2).filter(CampanhaMasterV2.id == int(campanha_id)).one_or_none()
    if not c:
        return

    # Apenas campanhas ativas
    try:
        if not bool(getattr(c, 'ativo', True)):
            return
    except Exception:
        pass

    # Vigência (interseção com competência)
    try:
        di = getattr(c, 'data_inicio', None)
        df = getattr(c, 'data_fim', None)
        if di and df:
            if df < periodo_ini or di > periodo_fim:
                return
    except Exception:
        pass

    # Escopo EMP
    escopo = (getattr(c, 'escopo', None) or '').strip().upper() or 'EMP'
    if escopo == 'EMP':
        emps_alvo = [str(e) for e in _safe_json_load(getattr(c, 'emps_json', None), []) if str(e).strip()]
        if emps_alvo:
            emps_calc = [e for e in emps_scope if e in emps_alvo]
        else:
            emps_calc = list(emps_scope)
    else:
        emps_calc = list(emps_scope)

    tipo = (getattr(c, 'tipo', None) or '').strip().upper()

    if tipo == 'RANKING_VALOR':
        rows = _calc_ranking_valor(db, c, ano, mes, emps_calc)
    elif tipo == 'META_PCT_MOM':
        rows = _calc_meta_pct_mom(db, c, ano, mes, emps_calc)
    elif tipo == 'META_PCT_YOY':
        rows = _calc_meta_pct_yoy(db, c, ano, mes, emps_calc)
    elif tipo == 'META_ABS':
        rows = _calc_meta_abs(db, c, ano, mes, emps_calc)
    elif tipo == 'MIX_MESTRE':
        rows = _calc_mix_mestre(db, c, ano, mes, emps_calc)
    elif tipo in ('ACUM_3M', 'ACUMULATIVA'):
        rows = _calc_acumulativa(db, c, ano, mes, emps_calc)
    elif tipo == 'MARGEM':
        return
    else:
        return

    _upsert_resultados(db, c, ano, mes, rows, force=bool(force))

    try:
        db.commit()
    except Exception:
        db.rollback()


def _upsert_resultados(db, c: CampanhaMasterV2, ano: int, mes: int, rows: list[CampanhaV2ResultRow], *, force: bool) -> None:
    # estratégia simples: delete+insert quando force, senão upsert individual
    if force:
        try:
            db.query(CampanhaResultadoV2).filter(
                CampanhaResultadoV2.campanha_id == int(c.id),
                CampanhaResultadoV2.competencia_ano == int(ano),
                CampanhaResultadoV2.competencia_mes == int(mes),
            ).delete(synchronize_session=False)
            db.flush()
        except Exception:
            pass

    for r in rows:
        try:
            obj = (
                db.query(CampanhaResultadoV2)
                .filter(
                    CampanhaResultadoV2.campanha_id == int(c.id),
                    CampanhaResultadoV2.emp == str(r.emp),
                    CampanhaResultadoV2.vendedor == str(r.vendedor),
                    CampanhaResultadoV2.competencia_ano == int(ano),
                    CampanhaResultadoV2.competencia_mes == int(mes),
                )
                .one_or_none()
            )
            if obj is None:
                obj = CampanhaResultadoV2(
                    campanha_id=int(c.id),
                    tipo=str(c.tipo),
                    competencia_ano=int(ano),
                    competencia_mes=int(mes),
                    emp=str(r.emp),
                    vendedor=str(r.vendedor),
                    status_pagamento="PENDENTE",
                )
                db.add(obj)

            obj.base_num = float(r.base_num or 0.0)
            obj.base_ref = None if r.base_ref is None else float(r.base_ref)
            obj.pct_real = None if r.pct_real is None else float(r.pct_real)
            obj.pct_meta = None if r.pct_meta is None else float(r.pct_meta)
            obj.atingiu = bool(r.atingiu)
            obj.valor_recompensa = float(r.valor_recompensa or 0.0)
            obj.detalhes_json = json.dumps(r.detalhes or {}, ensure_ascii=False)
            obj.vigencia_ini = getattr(c, "data_inicio", None)
            obj.vigencia_fim = getattr(c, "data_fim", None)
            obj.atualizado_em = datetime.datetime.utcnow()
        except Exception as e:
            print(f"[CAMPANHAS_V2] erro upsert: {e}")


def _calc_ranking_valor(db, c: CampanhaMasterV2, ano: int, mes: int, emps_calc: list[str]) -> list[CampanhaV2ResultRow]:
    regras = _safe_json_load(c.regras_json, {})
    premiacao = _safe_json_load(c.premiacao_json, {})
    mov_tipo = (regras.get("mov_tipo") or "OA").strip().upper()
    marca_alvo = (c.marca_alvo or regras.get("marca") or "").strip()
    escopo = (c.escopo or "EMP").strip().upper()

    q = (
        db.query(
            Venda.emp,
            Venda.vendedor,
            func.sum(Venda.valor_total).label("total"),
        )
        .filter(Venda.ano == int(ano), Venda.mes == int(mes))
        .filter(Venda.mov_tipo_movto == mov_tipo)
    )
    if emps_calc:
        q = q.filter(Venda.emp.in_([str(e) for e in emps_calc]))
    if marca_alvo:
        q = q.filter(Venda.marca == marca_alvo)

    if escopo == "GLOBAL":
        q = q.group_by(Venda.vendedor)
        rows = q.all()
        rows = sorted(rows, key=lambda x: float(x[2] or 0.0), reverse=True)
        return _top3_rows(rows, emp_token=GLOBAL_EMP_TOKEN, marca=marca_alvo, premiacao=premiacao)
    else:
        q = q.group_by(Venda.emp, Venda.vendedor)
        rows = q.all()
        # agrupa por emp
        por_emp: dict[str, list[tuple[str, str, float]]] = {}
        for emp, vend, total in rows:
            por_emp.setdefault(str(emp), []).append((str(emp), str(vend), float(total or 0.0)))
        out: list[CampanhaV2ResultRow] = []
        for emp, lst in por_emp.items():
            lst_sorted = sorted(lst, key=lambda x: x[2], reverse=True)
            out.extend(_top3_rows(lst_sorted, emp_token=emp, marca=marca_alvo, premiacao=premiacao))
        return out


def _top3_rows(rows: list[Any], *, emp_token: str, marca: str, premiacao: dict[str, Any]) -> list[CampanhaV2ResultRow]:
    top_cfg = premiacao.get("top") or []
    premio_por_pos = {int(x.get("pos")): float(x.get("valor") or 0.0) for x in top_cfg if isinstance(x, dict) and x.get("pos")}
    out: list[CampanhaV2ResultRow] = []
    for idx, r in enumerate(rows[:3], start=1):
        # r pode ser (emp, vend, total) ou (vend, total)
        if len(r) == 3:
            _, vend, total = r
        else:
            vend, total = r
        premio = float(premio_por_pos.get(idx, 0.0))
        out.append(
            CampanhaV2ResultRow(
                emp=str(emp_token),
                vendedor=str(vend).strip().upper(),
                base_num=float(total or 0.0),
                base_ref=None,
                pct_real=None,
                pct_meta=None,
                atingiu=True,
                valor_recompensa=premio,
                detalhes={"posicao": idx, "marca": marca or "", "escopo": "GLOBAL" if emp_token == GLOBAL_EMP_TOKEN else "EMP"},
            )
        )
    return out


def _calc_meta_pct_mom(db, c: CampanhaMasterV2, ano: int, mes: int, emps_calc: list[str]) -> list[CampanhaV2ResultRow]:
    regras = _safe_json_load(c.regras_json, {})
    premiacao = _safe_json_load(c.premiacao_json, {})
    pct_meta = float(regras.get("pct_meta") or 0.0)
    premio = float((premiacao.get("premio") or 0.0))

    a_ref, m_ref = _prev_competencia(int(ano), int(mes))

    base_atual = _sum_por_emp_vend(db, ano, mes, emps_calc)
    base_ref = _sum_por_emp_vend(db, a_ref, m_ref, emps_calc)

    out: list[CampanhaV2ResultRow] = []
    for (emp, vend), atual in base_atual.items():
        ref = float(base_ref.get((emp, vend), 0.0))
        atingiu = False
        pct_real = None
        if ref > 0:
            pct_real = ((float(atual) - ref) / ref) * 100.0
            atingiu = float(atual) >= ref * (1.0 + pct_meta / 100.0)
        # se ref=0, não tem base (fica como não atingiu)
        recompensa = premio if atingiu else 0.0
        out.append(
            CampanhaV2ResultRow(
                emp=emp,
                vendedor=vend,
                base_num=float(atual),
                base_ref=ref,
                pct_real=pct_real,
                pct_meta=pct_meta,
                atingiu=atingiu,
                valor_recompensa=recompensa,
                detalhes={"ref_tipo": "MES_ANTERIOR"},
            )
        )
    return out


def _calc_meta_pct_yoy(db, c: CampanhaMasterV2, ano: int, mes: int, emps_calc: list[str]) -> list[CampanhaV2ResultRow]:
    regras = _safe_json_load(c.regras_json, {})
    premiacao = _safe_json_load(c.premiacao_json, {})
    pct_meta = float(regras.get("pct_meta") or 0.0)
    premio = float((premiacao.get("premio") or 0.0))

    base_atual = _sum_por_emp_vend(db, ano, mes, emps_calc)
    base_ref = _sum_por_emp_vend(db, int(ano) - 1, mes, emps_calc)

    out: list[CampanhaV2ResultRow] = []
    for (emp, vend), atual in base_atual.items():
        ref = float(base_ref.get((emp, vend), 0.0))
        atingiu = False
        pct_real = None
        if ref > 0:
            pct_real = ((float(atual) - ref) / ref) * 100.0
            atingiu = float(atual) >= ref * (1.0 + pct_meta / 100.0)
        recompensa = premio if atingiu else 0.0
        out.append(
            CampanhaV2ResultRow(
                emp=emp,
                vendedor=vend,
                base_num=float(atual),
                base_ref=ref,
                pct_real=pct_real,
                pct_meta=pct_meta,
                atingiu=atingiu,
                valor_recompensa=recompensa,
                detalhes={"ref_tipo": "ANO_PASSADO"},
            )
        )
    return out


def _calc_meta_abs(db, c: CampanhaMasterV2, ano: int, mes: int, emps_calc: list[str]) -> list[CampanhaV2ResultRow]:
    regras = _safe_json_load(c.regras_json, {})
    premiacao = _safe_json_load(c.premiacao_json, {})
    meta_val = float(regras.get("meta_valor") or 0.0)
    premio = float((premiacao.get("premio") or 0.0))

    base_atual = _sum_por_emp_vend(db, ano, mes, emps_calc)
    out: list[CampanhaV2ResultRow] = []
    for (emp, vend), atual in base_atual.items():
        atingiu = float(atual) >= meta_val if meta_val > 0 else False
        recompensa = premio if atingiu else 0.0
        out.append(
            CampanhaV2ResultRow(
                emp=emp,
                vendedor=vend,
                base_num=float(atual),
                base_ref=meta_val,
                pct_real=None,
                pct_meta=None,
                atingiu=atingiu,
                valor_recompensa=recompensa,
                detalhes={"meta_tipo": "ABS"},
            )
        )
    return out


def _calc_mix_mestre(db, c: CampanhaMasterV2, ano: int, mes: int, emps_calc: list[str]) -> list[CampanhaV2ResultRow]:
    regras = _safe_json_load(c.regras_json, {})
    premiacao = _safe_json_load(c.premiacao_json, {})
    minimo = int(regras.get("minimo") or 0)
    premio = float((premiacao.get("premio") or 0.0))

    q = (
        db.query(
            Venda.emp,
            Venda.vendedor,
            func.count(func.distinct(Venda.mestre)).label("mix"),
        )
        .filter(Venda.ano == int(ano), Venda.mes == int(mes))
        .filter(Venda.mov_tipo_movto == "OA")
    )
    if emps_calc:
        q = q.filter(Venda.emp.in_([str(e) for e in emps_calc]))
    q = q.group_by(Venda.emp, Venda.vendedor)
    rows = q.all()

    out: list[CampanhaV2ResultRow] = []
    for emp, vend, mix in rows:
        mix_n = int(mix or 0)
        atingiu = mix_n >= minimo if minimo > 0 else False
        recompensa = premio if atingiu else 0.0
        out.append(
            CampanhaV2ResultRow(
                emp=str(emp),
                vendedor=str(vend).strip().upper(),
                base_num=float(mix_n),
                base_ref=float(minimo),
                pct_real=None,
                pct_meta=None,
                atingiu=atingiu,
                valor_recompensa=recompensa,
                detalhes={"mix_tipo": "MESTRE"},
            )
        )
    return out


def _calc_acumulativa(db, c: CampanhaMasterV2, ano: int, mes: int, emps_calc: list[str]) -> list[CampanhaV2ResultRow]:
    regras = _safe_json_load(c.regras_json, {})
    premiacao = _safe_json_load(c.premiacao_json, {})
    meses_n = int(regras.get("meses") or 3)
    meta_val = float(regras.get("meta_valor") or 0.0)
    premio = float((premiacao.get("premio") or 0.0))

    # coleta competências: mes atual e anteriores
    comps: list[tuple[int, int]] = []
    a, m = int(ano), int(mes)
    for _ in range(max(1, meses_n)):
        comps.append((a, m))
        a, m = _prev_competencia(a, m)

    q = (
        db.query(
            Venda.emp,
            Venda.vendedor,
            func.sum(Venda.valor_total).label("total"),
        )
        .filter(Venda.mov_tipo_movto == "OA")
    )
    if emps_calc:
        q = q.filter(Venda.emp.in_([str(e) for e in emps_calc]))
    # filtro por lista de (ano,mes)
    conds = [and_(Venda.ano == int(a), Venda.mes == int(m)) for a, m in comps]
    q = q.filter(or_(*conds))
    q = q.group_by(Venda.emp, Venda.vendedor)
    rows = q.all()

    out: list[CampanhaV2ResultRow] = []
    for emp, vend, total in rows:
        total_f = float(total or 0.0)
        atingiu = total_f >= meta_val if meta_val > 0 else False
        recompensa = premio if atingiu else 0.0
        out.append(
            CampanhaV2ResultRow(
                emp=str(emp),
                vendedor=str(vend).strip().upper(),
                base_num=total_f,
                base_ref=meta_val,
                pct_real=None,
                pct_meta=None,
                atingiu=atingiu,
                valor_recompensa=recompensa,
                detalhes={"meses": meses_n},
            )
        )
    return out


def _sum_por_emp_vend(db, ano: int, mes: int, emps_calc: list[str]) -> dict[tuple[str, str], float]:
    q = (
        db.query(
            Venda.emp,
            Venda.vendedor,
            func.sum(Venda.valor_total).label("total"),
        )
        .filter(Venda.ano == int(ano), Venda.mes == int(mes))
        .filter(Venda.mov_tipo_movto == "OA")
    )
    if emps_calc:
        q = q.filter(Venda.emp.in_([str(e) for e in emps_calc]))
    q = q.group_by(Venda.emp, Venda.vendedor)
    rows = q.all()
    out: dict[tuple[str, str], float] = {}
    for emp, vend, total in rows:
        out[(str(emp), str(vend).strip().upper())] = float(total or 0.0)
    return out


def atualizar_status_pagamento_v2(
    db,
    *,
    campanha_id: int,
    ano: int,
    mes: int,
    emp: str,
    vendedor: str,
    novo_status: str,
    usuario: str,
) -> bool:
    """Atualiza status financeiro de um resultado (Admin/Financeiro)."""
    novo = (novo_status or "").strip().upper()
    if novo not in {"PENDENTE", "A_PAGAR", "PAGO"}:
        return False

    try:
        obj = (
            db.query(CampanhaResultadoV2)
            .filter(
                CampanhaResultadoV2.campanha_id == int(campanha_id),
                CampanhaResultadoV2.competencia_ano == int(ano),
                CampanhaResultadoV2.competencia_mes == int(mes),
                CampanhaResultadoV2.emp == str(emp),
                CampanhaResultadoV2.vendedor == str(vendedor).strip().upper(),
            )
            .one_or_none()
        )
        if obj is None:
            return False

        de = (obj.status_pagamento or "").strip().upper()
        obj.status_pagamento = novo
        obj.pago_em = datetime.datetime.utcnow() if novo == "PAGO" else None
        obj.atualizado_em = datetime.datetime.utcnow()

        audit = CampanhaAuditV2(
            campanha_id=int(campanha_id),
            competencia_ano=int(ano),
            competencia_mes=int(mes),
            emp=str(emp),
            vendedor=str(vendedor).strip().upper(),
            acao="STATUS_PAGAMENTO",
            de_status=de,
            para_status=novo,
            usuario=(usuario or "").strip().upper(),
            payload_json=json.dumps({"de": de, "para": novo}, ensure_ascii=False),
        )
        db.add(audit)
        db.commit()
        return True
    except Exception as e:
        print(f"[CAMPANHAS_V2] erro atualizar_status: {e}")
        db.rollback()
        return False