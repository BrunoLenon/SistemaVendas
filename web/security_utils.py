"""Utilitários de segurança / auditoria.

Este módulo existe para evitar que `app.py` cresça indefinidamente.

Regras:
- Não importa `app` (evita import circular). Use `flask.current_app`.
- Mantém API simples (audit, normalize_role, rate_limit).
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from typing import Any

from flask import current_app, request, session


def normalize_role(role: str | None) -> str:
    r = (role or "").strip().lower()
    if r in ("admin", "administrador"):
        return "admin"
    if r in ("supervisor", "sup"):
        return "supervisor"
    return "vendedor"


# Rate limit simples (memória) para reduzir brute-force/abuso
_rl_store: dict[str, list[float]] = defaultdict(list)


def client_ip() -> str:
    # ProxyFix + X-Forwarded-For
    xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return xff or (request.remote_addr or "unknown")


def rate_limit(bucket: str, limit: int, window_sec: int) -> bool:
    """Retorna True se pode seguir, False se estourou."""
    now = datetime.utcnow().timestamp()
    key = f"{bucket}:{client_ip()}"
    arr = _rl_store[key]
    cutoff = now - window_sec
    i = 0
    while i < len(arr) and arr[i] < cutoff:
        i += 1
    if i:
        del arr[:i]
    if len(arr) >= limit:
        return False
    arr.append(now)
    return True


def audit(event: str, **data: Any) -> None:
    """Log estruturado (vai para os logs do Render)."""
    payload = {
        "event": event,
        "ts": datetime.utcnow().isoformat() + "Z",
        "ip": client_ip(),
        "user": session.get("usuario"),
        "role": session.get("role"),
        **data,
    }
    try:
        current_app.logger.info(json.dumps(payload, ensure_ascii=False))
    except Exception:
        current_app.logger.info(str(payload))
