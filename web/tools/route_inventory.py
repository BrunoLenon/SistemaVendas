"""Gera inventário de rotas (baseline) para comparar antes/depois.

Uso:
  python -m web.tools.route_inventory
ou
  python web/tools/route_inventory.py
"""

from __future__ import annotations

import json

from app import app  # noqa: E402


def main():
    routes = []
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        if rule.endpoint == "static":
            continue
        routes.append(
            {
                "rule": rule.rule,
                "endpoint": rule.endpoint,
                "methods": sorted([m for m in rule.methods if m not in {"HEAD", "OPTIONS"}]),
            }
        )
    print(json.dumps(routes, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
