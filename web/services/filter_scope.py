"""Helpers de filtro (EMP/Vendedor) — camada única.

Objetivo: evitar regressões do tipo "dropdown some opções".

Conceito:
  - *_base: lista completa para UI (dropdown/checkbox)
  - *_scope: lista efetiva usada na query/cálculo (pode ser filtrada)
"""

from __future__ import annotations

from typing import Iterable


def unique_keep_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values or []:
        s = str(v).strip()
        if not s:
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def apply_selected_filter(base: Iterable[str], selected: Iterable[str] | None) -> tuple[list[str], list[str]]:
    """Retorna (base_list, scope_list) aplicando filtro de `selected` sobre `base`.

    Importante: base_list nunca encolhe.
    """
    base_list = unique_keep_order(base or [])
    sel = unique_keep_order(selected or [])
    if not sel:
        return base_list, base_list[:]
    wanted = {s for s in sel}
    scope = [b for b in base_list if b in wanted]
    return base_list, scope
