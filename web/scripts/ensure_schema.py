"""Script para garantir schema / executar criar_tabelas() de forma controlada.

Uso (local):
  python -m web.scripts.ensure_schema

Uso (Render one-off / manual):
  set DATABASE_URL=... (ou variáveis usadas pelo db.py)
  python -m web.scripts.ensure_schema

Obs: este script importa db.criar_tabelas, então ele segue a mesma lógica de criação/patch.
"""

from __future__ import annotations

import sys

def main() -> int:
    from db import criar_tabelas  # noqa
    criar_tabelas()
    print("OK: criar_tabelas() executado.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
