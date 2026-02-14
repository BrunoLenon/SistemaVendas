from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

try:
    # Flask is available at runtime in app context
    from flask import Request
except Exception:  # pragma: no cover
    Request = object  # type: ignore


TRUE_SET = {"1", "true", "t", "yes", "y", "on"}


def wants_recalc(req: "Request") -> bool:
    """Return True when the request explicitly asks to recalculate.

    Convention:
      - ?recalc=1 (preferred)
      - ?recalc=true
      - ?force=1
      - ?refresh=1
    """
    if req is None:
        return False

    def _get(k: str) -> str:
        try:
            v = (req.args.get(k) or "").strip().lower()
        except Exception:
            v = ""
        return v

    if _get("recalc") in TRUE_SET:
        return True
    if _get("force") in TRUE_SET:
        return True
    if _get("refresh") in TRUE_SET:
        return True
    if _get("atualizar") in TRUE_SET:
        return True
    return False


def is_stale(updated_at: Optional[datetime], ttl_minutes: int) -> bool:
    """True if updated_at is missing or older than ttl_minutes."""
    if not updated_at:
        return True
    try:
        return updated_at < (datetime.utcnow() - timedelta(minutes=int(ttl_minutes)))
    except Exception:
        return True
