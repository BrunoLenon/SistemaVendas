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
from db import SessionLocal, CampanhaQtd, CampanhaQtdResultado, Venda, Usuario, UsuarioEmp
from services.campanhas_qtd_gate import calcular_faturamento_emp_periodo, aplicar_trava_faturamento_emp


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

    if role in ("supervisor", "gerente", "vendedor"):
        emps = allowed_emps_fn()
        if emps:
            return emps

    if role in ("supervisor", "gerente"):
        return [str(emp_usuario)] if emp_usuario else []

    return get_emps_vendedor_fn(vendedor)



def _campanha_tipo(campanha: CampanhaQtd) -> str:
    return (getattr(campanha, "campanha_tipo", None) or "VENDEDOR").strip().upper()


def get_gerentes_emp(db, emp: str) -> list[str]:
    """Retorna gerentes ativos/vinculados à EMP. Regra operacional: 1 gerente por loja.

    Mantemos lista para ficar robusto se houver cadastro temporário duplicado.
    """
    emp_s = str(emp or "").strip()
    if not emp_s:
        return []
    try:
        rows = (
            db.query(Usuario.username)
            .join(UsuarioEmp, UsuarioEmp.usuario_id == Usuario.id)
            .filter(func.lower(func.trim(cast(Usuario.role, String))) == "gerente")
            .filter(UsuarioEmp.ativo.is_(True))
            .filter(UsuarioEmp.emp == emp_s)
            .order_by(Usuario.username.asc())
            .all()
        )
        out = sorted({str(r[0] or "").strip().upper() for r in rows if r and str(r[0] or "").strip()})
        if out:
            return out
    except Exception:
        pass
    try:
        rows = (
            db.query(Usuario.username)
            .filter(func.lower(func.trim(cast(Usuario.role, String))) == "gerente")
            .filter(cast(Usuario.emp, String) == emp_s)
            .order_by(Usuario.username.asc())
            .all()
        )
        return sorted({str(r[0] or "").strip().upper() for r in rows if r and str(r[0] or "").strip()})
    except Exception:
        return []


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
    """Calcula e grava (upsert) o snapshot do resultado da campanha.

    Também aplica a trava de faturamento mínimo da EMP:
    - premio_potencial = prêmio calculado pela regra do item;
    - valor_recompensa = valor efetivamente liberado para pagamento;
    - bloqueado_faturamento_emp = 1 quando a loja não atingiu o faturamento mínimo.
    """
    vendedor = (vendedor or "").strip().upper()
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

    marca_ref = (campanha.marca or "").strip().upper()
    cond_marca = func.upper(func.trim(cast(Venda.marca, String))) == marca_ref

    tipo_campanha = _campanha_tipo(campanha)
    filtros_venda = [
        Venda.emp == emp,
        Venda.movimento >= periodo_ini,
        Venda.movimento <= periodo_fim,
        ~Venda.mov_tipo_movto.in_(["DS", "CA"]),
        func.coalesce(Venda.qtdade_vendida, 0.0) > 0,
        cond_prefix,
    ]
    if marca_ref:
        filtros_venda.append(cond_marca)
    if tipo_campanha != "GERENTE":
        filtros_venda.append(Venda.vendedor == vendedor)

    base = (
        db.query(
            func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd"),
            func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor"),
        )
        .filter(*filtros_venda)
        .first()
    )
    qtd_vendida = float(base.qtd or 0.0)
    valor_vendido = float(base.valor or 0.0)

    min_qtd = getattr(campanha, "qtd_minima", None)
    min_val = getattr(campanha, "valor_minimo", None)

    atingiu_regras_item = 1
    if min_qtd is not None and float(min_qtd) > 0:
        atingiu_regras_item = 1 if qtd_vendida >= float(min_qtd) else 0
    if atingiu_regras_item and min_val is not None and float(min_val) > 0:
        atingiu_regras_item = 1 if valor_vendido >= float(min_val) else 0

    try:
        recompensa_unit_dec = Decimal(str(campanha.recompensa_unit or 0))
    except Exception:
        recompensa_unit_dec = Decimal("0")

    if atingiu_regras_item:
        valor_potencial_dec = Decimal(str(qtd_vendida)) * recompensa_unit_dec
        valor_potencial = float(valor_potencial_dec.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    else:
        valor_potencial = 0.0

    faturamento_emp = calcular_faturamento_emp_periodo(
        db,
        emp=emp,
        periodo_ini=periodo_ini,
        periodo_fim=periodo_fim,
    )
    gate_emp = aplicar_trava_faturamento_emp(
        campanha=campanha,
        emp=emp,
        faturamento_emp=faturamento_emp,
        premio_potencial=valor_potencial,
        atingiu_regras_item=bool(atingiu_regras_item),
    )

    valor_liberado = float(gate_emp.get("valor_recompensa") or 0.0)
    valor_potencial = float(gate_emp.get("premio_potencial") or 0.0)
    bloqueado_emp = 1 if gate_emp.get("bloqueado_faturamento_emp") else 0
    atingiu_final = 1 if gate_emp.get("atingiu_final") else 0

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

    try:
        res.campanha_tipo = tipo_campanha
    except Exception:
        pass
    res.titulo = campanha.titulo
    res.produto_prefixo = prefix_raw or prefix
    res.marca = (campanha.marca or "").strip()
    res.recompensa_unit = float(campanha.recompensa_unit or 0.0)
    res.qtd_minima = float(min_qtd) if (min_qtd is not None and float(min_qtd) > 0) else None
    res.data_inicio = campanha.data_inicio
    res.data_fim = campanha.data_fim
    res.qtd_vendida = qtd_vendida
    res.valor_vendido = valor_vendido
    res.atingiu_minimo = int(atingiu_final)
    res.valor_recompensa = float(valor_liberado)
    try:
        res.premio_potencial = float(valor_potencial)
        res.faturamento_minimo_emp = float(gate_emp.get("faturamento_minimo_emp") or 0.0) or None
        res.faturamento_emp = float(gate_emp.get("faturamento_emp") or 0.0)
        res.faltante_faturamento_emp = float(gate_emp.get("faltante_faturamento_emp") or 0.0)
        res.bloqueado_faturamento_emp = int(bloqueado_emp)
    except Exception:
        pass
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
    """Calcula (sem persistir) o agregado da campanha para TODOS os vendedores da EMP no período."""
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

    marca_ref = (campanha.marca or "").strip().upper()
    cond_marca = func.upper(func.trim(cast(Venda.marca, String))) == marca_ref

    filtros_venda = [
        Venda.emp == emp,
        Venda.movimento >= periodo_ini,
        Venda.movimento <= periodo_fim,
        ~Venda.mov_tipo_movto.in_(["DS", "CA"]),
        func.coalesce(Venda.qtdade_vendida, 0.0) > 0,
        cond_prefix,
    ]
    if marca_ref:
        filtros_venda.append(cond_marca)

    base = (
        db.query(
            func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd"),
            func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor"),
        )
        .filter(*filtros_venda)
        .first()
    )
    qtd_vendida = float(getattr(base, "qtd", 0.0) or 0.0)
    valor_vendido = float(getattr(base, "valor", 0.0) or 0.0)

    min_qtd = getattr(campanha, "qtd_minima", None)
    min_val = getattr(campanha, "valor_minimo", None)

    atingiu_regras_item = 1
    if min_qtd is not None and float(min_qtd) > 0:
        atingiu_regras_item = 1 if qtd_vendida >= float(min_qtd) else 0
    if atingiu_regras_item and min_val is not None and float(min_val) > 0:
        atingiu_regras_item = 1 if valor_vendido >= float(min_val) else 0

    try:
        recompensa_unit_dec = Decimal(str(campanha.recompensa_unit or 0))
    except Exception:
        recompensa_unit_dec = Decimal("0")

    if atingiu_regras_item:
        valor_potencial_dec = Decimal(str(qtd_vendida)) * recompensa_unit_dec
        valor_potencial = float(valor_potencial_dec.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    else:
        valor_potencial = 0.0

    faturamento_emp = calcular_faturamento_emp_periodo(db, emp=emp, periodo_ini=periodo_ini, periodo_fim=periodo_fim)
    gate_emp = aplicar_trava_faturamento_emp(
        campanha=campanha,
        emp=emp,
        faturamento_emp=faturamento_emp,
        premio_potencial=valor_potencial,
        atingiu_regras_item=bool(atingiu_regras_item),
    )
    valor_liberado = float(gate_emp.get("valor_recompensa") or 0.0)
    valor_potencial = float(gate_emp.get("premio_potencial") or 0.0)
    bloqueado_emp = 1 if gate_emp.get("bloqueado_faturamento_emp") else 0
    atingiu_final = 1 if gate_emp.get("atingiu_final") else 0

    from types import SimpleNamespace
    return SimpleNamespace(
        campanha_id=campanha.id,
        emp=emp,
        vendedor="__ALL__",
        competencia_ano=int(competencia_ano),
        competencia_mes=int(competencia_mes),
        status_pagamento="PENDENTE",
        campanha_tipo=_campanha_tipo(campanha),
        titulo=campanha.titulo,
        produto_prefixo=prefix_raw,
        marca=(campanha.marca or "").strip(),
        recompensa_unit=float(campanha.recompensa_unit or 0.0),
        qtd_minima=float(min_qtd) if (min_qtd is not None and float(min_qtd) > 0) else None,
        data_inicio=campanha.data_inicio,
        data_fim=campanha.data_fim,
        qtd_vendida=qtd_vendida,
        valor_vendido=valor_vendido,
        atingiu_minimo=int(atingiu_final),
        valor_recompensa=float(valor_liberado),
        premio_potencial=float(valor_potencial),
        faturamento_minimo_emp=float(gate_emp.get("faturamento_minimo_emp") or 0.0) or None,
        faturamento_emp=float(gate_emp.get("faturamento_emp") or 0.0),
        faltante_faturamento_emp=float(gate_emp.get("faltante_faturamento_emp") or 0.0),
        bloqueado_faturamento_emp=int(bloqueado_emp),
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

    marca_ref = (campanha.marca or "").strip().upper()
    cond_marca = func.upper(func.trim(cast(Venda.marca, String))) == marca_ref

    filtros_venda = [
        Venda.emp == emp,
        Venda.movimento >= periodo_ini,
        Venda.movimento <= periodo_fim,
        ~Venda.mov_tipo_movto.in_(["DS", "CA"]),
        func.coalesce(Venda.qtdade_vendida, 0.0) > 0,
        cond_prefix,
    ]
    if marca_ref:
        filtros_venda.append(cond_marca)

    q = (
        db.query(
            func.upper(func.trim(cast(Venda.vendedor, String))).label("vendedor"),
            func.coalesce(func.sum(Venda.qtdade_vendida), 0.0).label("qtd"),
            func.coalesce(func.sum(Venda.valor_total), 0.0).label("valor"),
        )
        .filter(*filtros_venda)
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
