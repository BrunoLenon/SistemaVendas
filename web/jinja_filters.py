"""Filtros Jinja usados pelo sistema (formatação BR).

Este módulo existe para reduzir o tamanho do app.py e concentrar formatações
que são 100% determinísticas e fáceis de testar.

Refatoração pura: NÃO altera o comportamento externo observável.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any


def brl(value: Any) -> str:
    """Formata números no padrão brasileiro (ex: 21.555.384,00).

    Retorna "0,00" para None/valores inválidos.
    """
    if value is None:
        return "0,00"
    try:
        num = float(value)
    except Exception:
        return "0,00"
    return f"{num:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


def brl_rs(value: Any) -> str:
    """Formata valores monetários no padrão brasileiro com prefixo 'R$' (ex: R$12.345,67)."""
    s = brl(value)
    # brl() já devolve '0,00' em erro
    if s.startswith("-"):
        return "R$-" + s[1:]
    return "R$" + s


def date_iso(value: Any) -> str:
    """Converte date/datetime/str para YYYY-MM-DD (compatível com <input type=\"date\">)."""
    if value is None:
        return ""
    try:
        if isinstance(value, datetime):
            return value.date().strftime("%Y-%m-%d")
        if isinstance(value, date):
            return value.strftime("%Y-%m-%d")
        if isinstance(value, str):
            s = value.strip()
            # aceita "YYYY-MM-DD", "YYYY-MM-DDTHH:MM:SS", "YYYY-MM-DD HH:MM:SS"
            if len(s) >= 10 and s[4] == "-" and s[7] == "-":
                return s[:10]
            # aceita "DD/MM/YYYY"
            if len(s) >= 10 and s[2] == "/" and s[5] == "/":
                dd, mm, yyyy = s[:2], s[3:5], s[6:10]
                return f"{yyyy}-{mm}-{dd}"
        return ""
    except Exception:
        return ""


def date_br(value: Any) -> str:
    """Converte date/datetime/str para DD/MM/AAAA (exibição)."""
    if value is None:
        return ""
    try:
        if isinstance(value, datetime):
            d = value.date()
            return d.strftime("%d/%m/%Y")
        if isinstance(value, date):
            return value.strftime("%d/%m/%Y")
        if isinstance(value, str):
            s = value.strip()
            # ISO
            if len(s) >= 10 and s[4] == "-" and s[7] == "-":
                yyyy, mm, dd = s[:4], s[5:7], s[8:10]
                return f"{dd}/{mm}/{yyyy}"
            # já BR
            if len(s) >= 10 and s[2] == "/" and s[5] == "/":
                return s[:10]
        return ""
    except Exception:
        return ""


def register_template_filters(app) -> None:
    """Registra filtros no Flask app.

    Mantém os nomes usados nos templates:
      - |brl
      - |brl_rs
      - |date_iso
      - |date_br
    """
    app.add_template_filter(brl, "brl")
    app.add_template_filter(brl_rs, "brl_rs")
    app.add_template_filter(date_iso, "date_iso")
    app.add_template_filter(date_br, "date_br")
