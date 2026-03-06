"""Helpers de Campanhas QTD (recompensa por quantidade).

Extraído do app.py em refatoração pura:
- melhora manutenibilidade e testabilidade
- sem alterar comportamento externo observável
"""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal, ROUND_HALF_UP
from typing import Callable

from sqlalchemy import and_, or_, func, cast, String

from sv_utils import _periodo_bounds
from db import SessionLocal, CampanhaQtd, CampanhaQtdResultado, Venda


def resolver_emp_scope_para_usuario_impl(
    vendedor: str,
    role: str,
    emp_usuario: str | None,
    *,
    allowed_emps_fn: Callable[[], list[str]],
    get_emps_vendedor_fn: Callable[[str], list[str]],
) -> list[str]:
    """Retorna lista de EMPs que o usuário pode visualizar (para campanhas e relatórios).

    Regra nova (recomendada):
    - Supervisor/Vendedor: usa usuario_emps (session['allowed_emps']) quando disponível.
    - Fallback: supervisor usa emp_usuario; vendedor infere pelas vendas.
    """
    role = (role or "").strip().lower()
    if role == "admin":
        return []

    if role in ("supervisor", "vendedor"):
        emps = allowed_emps_fn()
        if emps:
            return emps

    if role == "supervisor":
        return [str(emp_usuario)] if emp_usuario else []

    return get_emps_vendedor_fn(vendedor)



def _campanhas_mes_overlap(ano: int, mes: int, emp: str | None) -> list[CampanhaQtd]:
    """Retorna campanhas que intersectam o mês (e opcionalmente a EMP)."""
    inicio_mes, fim_mes = _periodo_bounds(int(ano), int(mes))
    with SessionLocal() as db:
        q = db.query(CampanhaQtd).filter(CampanhaQtd.ativo == 1)
        if emp:
            emp_str = str(emp)
            # suporta campanhas globais (emp = 'ALL'/'*'/'') e campanhas específicas da EMP
            q = q.filter(or_(CampanhaQtd.emp == emp_str, CampanhaQtd.emp.in_(['ALL', '*', ''])))
        # overlap: inicio <= fim_mes AND fim >= inicio_mes
        q = q.filter(and_(CampanhaQtd.data_inicio <= fim_mes, CampanhaQtd.data_fim >= inicio_mes))
        return q.order_by(CampanhaQtd.emp.asc(), CampanhaQtd.data_inicio.asc()).all()

def _upsert_resultado(
    db,
    campanha: CampanhaQtd,
    vendedor: str,
    emp: str,
    competencia_ano: int,
    competencia_mes: int,
    periodo_ini: date,
    periodo_fim: date,
) -> CampanhaQtdResultado:
    """Calcula e grava (upsert) o snapshot do resultado da campanha."""
    vendedor = (vendedor or "").strip().upper()
    emp = str(emp)

    # Campo usado para match do item:
    # - campo_match='codigo'   -> prefixo em Venda.mestre (compatibilidade com base antiga)
    # - campo_match='descricao'-> prefixo em Venda.descricao_norm (novo)
    campo_match = (getattr(campanha, "campo_match", None) or "codigo").strip().lower()

    def _norm_prefix(s: str) -> str:
        import unicodedata, re
        s = (s or "").strip()
        s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
        s = re.sub(r"\s+", " ", s).strip().lower()
        return s

    if campo_match == "descricao":
        prefix_raw = (getattr(campanha, "descricao_prefixo", "") or "").strip()
        # fallback: se não preencher descricao_prefixo, usa produto_prefixo como prefixo de descrição
        if not prefix_raw:
            prefix_raw = (campanha.produto_prefixo or "").strip()
        prefix = _norm_prefix(prefix_raw)
        # descricao_norm já é esperado estar normalizado; garantimos lower/trim para evitar mismatch
        campo_item = func.lower(func.trim(func.coalesce(Venda.descricao_norm, "")))
        cond_prefix = campo_item.like(prefix + "%")
    else:
        prefix_raw = (campanha.produto_prefixo or "").strip()
        prefix = prefix_raw
        prefix_up = prefix.upper()
        campo_item = func.upper(func.trim(cast(Venda.mestre, String)))
        cond_prefix = campo_item.like(prefix_up + "%")
    cond_marca = func.upper(func.trim(cast(Venda.marca, String))) == (campanha.marca or "").strip().upper()

    base = (
        db.query(
            func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd"),
            func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor"),
        )
        .filter(
            Venda.emp == emp,
            Venda.vendedor == vendedor,
            Venda.movimento >= periodo_ini,
            Venda.movimento <= periodo_fim,
            ~Venda.mov_tipo_movto.in_(["DS", "CA"]),
            cond_prefix,
            cond_marca,
        )
        .first()
    )
    qtd_vendida = float(base.qtd or 0.0)
    valor_vendido = float(base.valor or 0.0)

    min_qtd = getattr(campanha, "qtd_minima", None)
    min_val = getattr(campanha, "valor_minimo", None)

    atingiu = 1
    if min_qtd is not None and float(min_qtd) > 0:
        atingiu = 1 if qtd_vendida >= float(min_qtd) else 0
    if atingiu and min_val is not None and float(min_val) > 0:
        atingiu = 1 if valor_vendido >= float(min_val) else 0

    try:
        recompensa_unit_dec = Decimal(str(campanha.recompensa_unit or 0))
    except Exception:
        recompensa_unit_dec = Decimal("0")

    if atingiu:
        valor_recomp_dec = (Decimal(str(qtd_vendida)) * recompensa_unit_dec)
        # arredondamento monetário
        valor_recomp = float(valor_recomp_dec.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    else:
        valor_recomp = 0.0

    # Upsert por chave única
    res = (
        db.query(CampanhaQtdResultado)
        .filter(
            CampanhaQtdResultado.campanha_id == campanha.id,
            CampanhaQtdResultado.emp == emp,
            CampanhaQtdResultado.vendedor == vendedor,
            CampanhaQtdResultado.competencia_ano == int(competencia_ano),
            CampanhaQtdResultado.competencia_mes == int(competencia_mes),
        )
        .first()
    )
    if not res:
        res = CampanhaQtdResultado(
            campanha_id=campanha.id,
            emp=emp,
            vendedor=vendedor,
            competencia_ano=int(competencia_ano),
            competencia_mes=int(competencia_mes),
            status_pagamento="PENDENTE",
        )
        db.add(res)

    # snapshot
    res.titulo = campanha.titulo
    res.produto_prefixo = (locals().get('prefix_raw') or prefix)
    res.marca = (campanha.marca or "").strip()
    res.recompensa_unit = float(campanha.recompensa_unit or 0.0)
    res.qtd_minima = float(min_qtd) if (min_qtd is not None and float(min_qtd) > 0) else None
    res.data_inicio = campanha.data_inicio
    res.data_fim = campanha.data_fim

    res.qtd_vendida = qtd_vendida
    res.valor_vendido = valor_vendido
    res.atingiu_minimo = int(atingiu)
    res.valor_recompensa = float(valor_recomp)
    res.atualizado_em = datetime.utcnow()
    return res

def _calc_resultado_all_vendedores(
    db,
    campanha: CampanhaQtd,
    emp: str,
    competencia_ano: int,
    competencia_mes: int,
    periodo_ini: date,
    periodo_fim: date,
):
    """Calcula (sem persistir) o agregado da campanha para TODOS os vendedores da EMP no período.

    Otimização: evita multiplicar o custo por N vendedores quando o filtro está em 'TODOS'.
    Mantém as mesmas regras de cálculo (qtd_vendida/valor_total, exclusões DS/CA, match por prefixo+marca),
    apenas removendo o filtro por vendedor.
    """
    emp = str(emp)

    campo_match = (getattr(campanha, "campo_match", None) or "codigo").strip().lower()

    def _norm_prefix(s: str) -> str:
        import unicodedata, re
        s = (s or "").strip()
        s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
        s = re.sub(r"\s+", " ", s).strip().lower()
        return s

    if campo_match == "descricao":
        prefix_raw = (getattr(campanha, "descricao_prefixo", "") or "").strip()
        if not prefix_raw:
            prefix_raw = (campanha.produto_prefixo or "").strip()
        prefix = _norm_prefix(prefix_raw)
        campo_item = func.lower(func.trim(func.coalesce(Venda.descricao_norm, "")))
        cond_prefix = campo_item.like(prefix + "%")
    else:
        prefix_raw = (campanha.produto_prefixo or "").strip()
        prefix = prefix_raw
        prefix_up = prefix.upper()
        campo_item = func.upper(func.trim(cast(Venda.mestre, String)))
        cond_prefix = campo_item.like(prefix_up + "%")

    cond_marca = func.upper(func.trim(cast(Venda.marca, String))) == (campanha.marca or "").strip().upper()

    base = (
        db.query(
            func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd"),
            func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor"),
        )
        .filter(
            Venda.emp == emp,
            Venda.movimento >= periodo_ini,
            Venda.movimento <= periodo_fim,
            ~Venda.mov_tipo_movto.in_(["DS", "CA"]),
            cond_prefix,
            cond_marca,
        )
        .first()
    )

    qtd_vendida = float(getattr(base, "qtd", 0.0) or 0.0)
    valor_vendido = float(getattr(base, "valor", 0.0) or 0.0)

    min_qtd = getattr(campanha, "qtd_minima", None)
    min_val = getattr(campanha, "valor_minimo", None)

    atingiu = 1
    if min_qtd is not None and float(min_qtd) > 0:
        atingiu = 1 if qtd_vendida >= float(min_qtd) else 0
    if atingiu and min_val is not None and float(min_val) > 0:
        atingiu = 1 if valor_vendido >= float(min_val) else 0

    try:
        recompensa_unit_dec = Decimal(str(campanha.recompensa_unit or 0))
    except Exception:
        recompensa_unit_dec = Decimal("0")

    if atingiu:
        valor_recomp_dec = (Decimal(str(qtd_vendida)) * recompensa_unit_dec)
        valor_recomp = float(valor_recomp_dec.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    else:
        valor_recomp = 0.0

    # Objeto leve com os mesmos campos que o template usa
    from types import SimpleNamespace
    return SimpleNamespace(
        campanha_id=campanha.id,
        emp=emp,
        vendedor="__ALL__",
        competencia_ano=int(competencia_ano),
        competencia_mes=int(competencia_mes),
        status_pagamento="PENDENTE",
        titulo=campanha.titulo,
        produto_prefixo=prefix_raw,
        marca=(campanha.marca or "").strip(),
        recompensa_unit=float(campanha.recompensa_unit or 0.0),
        qtd_minima=float(min_qtd) if (min_qtd is not None and float(min_qtd) > 0) else None,
        data_inicio=campanha.data_inicio,
        data_fim=campanha.data_fim,
        qtd_vendida=qtd_vendida,
        valor_vendido=valor_vendido,
        atingiu_minimo=int(atingiu),
        valor_recompensa=float(valor_recomp),
        atualizado_em=datetime.utcnow(),
    )

def _calc_vendas_por_vendedor_para_campanha(db, emp: str, campanha: CampanhaQtd, periodo_ini: date, periodo_fim: date) -> dict[str, tuple[float, float]]:
    """Retorna dict vendedor -> (qtd_vendida, valor_vendido) para uma campanha no período.

    IMPORTANTE: usa a MESMA regra de match de itens do _upsert_resultado:
      - campo_match='codigo'    -> prefixo em Venda.mestre
      - campo_match='descricao' -> prefixo em Venda.descricao_norm (normalizada)
    """
    emp = str(emp)

    # Campo usado para match do item
    campo_match = (getattr(campanha, "campo_match", None) or "codigo").strip().lower()

    def _norm_prefix(s: str) -> str:
        import unicodedata, re as _re
        s = (s or "").strip()
        s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
        s = _re.sub(r"\s+", " ", s).strip().lower()
        return s

    if campo_match == "descricao":
        prefix_raw = (getattr(campanha, "descricao_prefixo", "") or "").strip()
        if not prefix_raw:
            prefix_raw = (campanha.produto_prefixo or "").strip()
        prefix = _norm_prefix(prefix_raw)
        campo_item = func.lower(func.trim(func.coalesce(Venda.descricao_norm, "")))
        cond_prefix = campo_item.like(prefix + "%")
    else:
        prefix = (campanha.produto_prefixo or "").strip()
        prefix_up = prefix.upper()
        campo_item = func.upper(func.trim(cast(Venda.mestre, String)))
        cond_prefix = campo_item.like(prefix_up + "%")

    cond_marca = func.upper(func.trim(cast(Venda.marca, String))) == (campanha.marca or "").strip().upper()

    q = (
        db.query(
            func.upper(func.trim(cast(Venda.vendedor, String))).label("vendedor"),
            func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd"),
            func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor"),
        )
        .filter(
            Venda.emp == emp,
            Venda.movimento >= periodo_ini,
            Venda.movimento <= periodo_fim,
            ~Venda.mov_tipo_movto.in_(["DS", "CA"]),
            cond_prefix,
            cond_marca,
        )
        .group_by(func.upper(func.trim(cast(Venda.vendedor, String))))
    )
    rows = q.all()
    out: dict[str, tuple[float, float]] = {}
    for r in rows:
        v = (r.vendedor or '').strip().upper()
        if not v:
            continue
        out[v] = (float(r.qtd or 0.0), float(r.valor or 0.0))
    return out
