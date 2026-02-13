from __future__ import annotations

from typing import Any, Iterable

from flask import session

from db import UsuarioEmp


def _to_int_list(value: Any) -> list[int]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        out: list[int] = []
        for v in value:
            try:
                out.append(int(str(v).strip()))
            except Exception:
                continue
        return sorted(set(out))
    if isinstance(value, str):
        parts = [p.strip() for p in value.replace(";", ",").split(",") if p.strip()]
        out: list[int] = []
        for p in parts:
            try:
                out.append(int(p))
            except Exception:
                continue
        return sorted(set(out))
    try:
        return [int(value)]
    except Exception:
        return []


def get_session_emps() -> list[int]:
    """Obtém EMPs da sessão, aceitando os dois formatos legados.

    - Preferência: session['emps']
    - Compat: session['allowed_emps']
    """
    emps = session.get("emps")
    out = _to_int_list(emps)
    if out:
        return out
    return _to_int_list(session.get("allowed_emps"))


def set_session_emps(emps: Iterable[int | str]) -> list[int]:
    """Normaliza e salva EMPs na sessão, mantendo compat com chaves antigas."""
    out: list[int] = []
    for e in emps:
        try:
            out.append(int(str(e).strip()))
        except Exception:
            continue
    out = sorted(set(out))
    session["emps"] = out
    # compat: algumas rotas antigas leem allowed_emps como lista de strings
    session["allowed_emps"] = [str(e) for e in out]
    return out


def refresh_session_emps(db, usuario_id: int | None, fallback_emp: int | str | None = None) -> list[int]:
    """Recarrega EMPs permitidas a partir de usuario_emps (ativo=true).

    Se não houver vínculo ativo, usa fallback_emp (usuarios.emp).
    """
    if not usuario_id:
        # não tem como carregar; mantém o que estiver na sessão
        return get_session_emps()

    rows = (
        db.query(UsuarioEmp.emp)
        .filter(UsuarioEmp.usuario_id == usuario_id)
        .filter(UsuarioEmp.ativo.is_(True))
        .all()
    )
    emps = sorted({int(str(r[0]).strip()) for r in rows if r and r[0] is not None and str(r[0]).strip()})
    if not emps and fallback_emp is not None and str(fallback_emp).strip() != "":
        try:
            emps = [int(str(fallback_emp).strip())]
        except Exception:
            emps = []
    return set_session_emps(emps)
