from __future__ import annotations

"""Serviços de apoio para faturamento de oficina/mão de obra.

A oficina fica em tabela própria para não misturar serviço com venda de produto,
mas seus valores entram no faturamento usado por metas e travas de campanhas.
"""

from datetime import date
from decimal import Decimal, ROUND_HALF_UP
from typing import Any

from sqlalchemy import text


def normalize_emp(value: Any) -> str:
    return str(value or "").strip()


def normalize_usuario(value: Any) -> str:
    return str(value or "").strip().upper()


def _money(value: Any) -> float:
    try:
        return float(Decimal(str(value if value is not None else 0)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    except Exception:
        return 0.0


def sum_servicos_oficina_mes(db: Any, *, ano: int, mes: int, emp: str | None = None, usuario: str | None = None) -> float:
    """Soma mão de obra por competência.

    Quando ``usuario`` vem vazio, soma o total da EMP. Quando informado, soma
    apenas o mecânico/usuário. Apenas registros ativos entram no cálculo.
    """
    emp_s = normalize_emp(emp)
    usuario_s = normalize_usuario(usuario)
    clauses = ["ano = :ano", "mes = :mes", "ativo IS TRUE"]
    params: dict[str, Any] = {"ano": int(ano), "mes": int(mes)}
    if emp_s:
        clauses.append("emp = :emp")
        params["emp"] = emp_s
    if usuario_s:
        clauses.append("UPPER(TRIM(COALESCE(usuario,''))) = :usuario")
        params["usuario"] = usuario_s

    try:
        sql = "SELECT COALESCE(SUM(valor_servico),0)::double precision FROM oficina_servicos WHERE " + " AND ".join(clauses)
        row = db.execute(text(sql), params).fetchone()
        return _money(row[0] if row else 0.0)
    except Exception:
        # Compatibilidade: se a migration ainda não rodou, o sistema continua funcionando sem derrubar as telas.
        return 0.0


def sum_servicos_oficina_periodo(db: Any, *, emp: str, periodo_ini: date, periodo_fim: date, usuario: str | None = None) -> float:
    """Soma mão de obra em um intervalo de datas.

    A tabela guarda competência mensal. O intervalo é convertido para meses que
    intersectam o período; isso cobre campanhas com vigência dentro do mês e
    metas mensais sem exigir linha diária de serviço.
    """
    emp_s = normalize_emp(emp)
    if not emp_s or not periodo_ini or not periodo_fim:
        return 0.0

    # chave de cache por sessão SQLAlchemy para evitar repetir soma em relatório grande
    usuario_s = normalize_usuario(usuario)
    key = ("oficina", emp_s, str(periodo_ini), str(periodo_fim), usuario_s)
    cache = getattr(db, "_oficina_service_cache", None)
    if cache is None:
        cache = {}
        try:
            setattr(db, "_oficina_service_cache", cache)
        except Exception:
            cache = {}
    if key in cache:
        return _money(cache[key])

    months: list[tuple[int, int]] = []
    y, m = int(periodo_ini.year), int(periodo_ini.month)
    y_end, m_end = int(periodo_fim.year), int(periodo_fim.month)
    while (y, m) <= (y_end, m_end):
        months.append((y, m))
        m += 1
        if m > 12:
            y += 1
            m = 1

    total = 0.0
    for ano, mes in months:
        total += sum_servicos_oficina_mes(db, ano=ano, mes=mes, emp=emp_s, usuario=usuario_s or None)
    total = _money(total)
    try:
        cache[key] = total
    except Exception:
        pass
    return total


def get_usuarios_servico_no_periodo(db: Any, *, ano: int, mes: int, emps: list[str] | None = None) -> list[str]:
    allowed = [normalize_emp(e) for e in (emps or []) if normalize_emp(e)]
    params: dict[str, Any] = {"ano": int(ano), "mes": int(mes)}
    emp_clause = ""
    if allowed:
        emp_clause = "AND emp = ANY(:emps)"
        params["emps"] = allowed
    try:
        rows = db.execute(text(f"""
            SELECT DISTINCT UPPER(TRIM(COALESCE(usuario,''))) AS usuario
              FROM oficina_servicos
             WHERE ano = :ano
               AND mes = :mes
               AND ativo IS TRUE
               {emp_clause}
               AND COALESCE(usuario,'') <> ''
             ORDER BY usuario
        """), params).fetchall()
        return [normalize_usuario(r[0]) for r in rows if r and normalize_usuario(r[0])]
    except Exception:
        return []


def get_emps_servico_no_periodo(db: Any, *, ano: int, mes: int, allowed_emps: list[str] | None = None) -> list[str]:
    allowed = [normalize_emp(e) for e in (allowed_emps or []) if normalize_emp(e)]
    params: dict[str, Any] = {"ano": int(ano), "mes": int(mes)}
    emp_clause = ""
    if allowed:
        emp_clause = "AND emp = ANY(:emps)"
        params["emps"] = allowed
    try:
        rows = db.execute(text(f"""
            SELECT DISTINCT emp
              FROM oficina_servicos
             WHERE ano = :ano
               AND mes = :mes
               AND ativo IS TRUE
               {emp_clause}
               AND COALESCE(emp,'') <> ''
             ORDER BY emp
        """), params).fetchall()
        return [normalize_emp(r[0]) for r in rows if r and normalize_emp(r[0])]
    except Exception:
        return []
