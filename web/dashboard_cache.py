"""Cache do dashboard.

Objetivo:
- Evitar recomputar agregações pesadas a cada acesso (principalmente no plano free).
- Após importação diária, recalcular os resumos por EMP/vendedor/mês/ano.

O cache fica no próprio Postgres (Supabase), não no filesystem do servidor.
"""

from __future__ import annotations

import json
from datetime import date
from typing import Dict, List, Optional, Tuple

from sqlalchemy import case, func

from db import SessionLocal, Venda, DashboardCache


DS_CA = ("DS", "CA")


def month_bounds(ano: int, mes: int) -> Tuple[date, date]:
    """Retorna (inicio_inclusivo, fim_exclusivo) do mês."""
    mes = max(1, min(12, int(mes)))
    ano = int(ano)
    start = date(ano, mes, 1)
    if mes == 12:
        end = date(ano + 1, 1, 1)
    else:
        end = date(ano, mes + 1, 1)
    return start, end


def _signed_value():
    return case((Venda.mov_tipo_movto.in_(DS_CA), -Venda.valor_total), else_=Venda.valor_total)


def refresh_dashboard_cache(emp: str, ano: int, mes: int) -> Dict[str, int]:
    """Recalcula cache de um EMP para um mês/ano.

    Retorna um resumo {"vendedores": N, "linhas_cache": N}.
    """
    emp = str(emp).strip()
    start, end = month_bounds(ano, mes)

    with SessionLocal() as db:
        # Agregado principal por vendedor
        q = (
            db.query(
                Venda.vendedor.label("vendedor"),
                func.coalesce(func.sum(case((~Venda.mov_tipo_movto.in_(DS_CA), Venda.valor_total), else_=0.0)), 0.0).label("valor_bruto"),
                func.coalesce(func.sum(case((Venda.mov_tipo_movto == "DS", Venda.valor_total), else_=0.0)), 0.0).label("devolucoes"),
                func.coalesce(func.sum(case((Venda.mov_tipo_movto == "CA", Venda.valor_total), else_=0.0)), 0.0).label("cancelamentos"),
                func.coalesce(func.sum(_signed_value()), 0.0).label("valor_liquido"),
                func.count(func.distinct(case((~Venda.mov_tipo_movto.in_(DS_CA), Venda.mestre), else_=None))).label("mix_produtos"),
                func.count(func.distinct(case((~Venda.mov_tipo_movto.in_(DS_CA), Venda.marca), else_=None))).label("mix_marcas"),
            )
            .filter(Venda.emp == emp)
            .filter(Venda.movimento >= start)
            .filter(Venda.movimento < end)
            .group_by(Venda.vendedor)
        )

        rows = q.all()

        # Ranking por marca (líquido/assinado) por vendedor
        q_rank = (
            db.query(
                Venda.vendedor.label("vendedor"),
                Venda.marca.label("marca"),
                func.coalesce(func.sum(_signed_value()), 0.0).label("valor"),
            )
            .filter(Venda.emp == emp)
            .filter(Venda.movimento >= start)
            .filter(Venda.movimento < end)
            .group_by(Venda.vendedor, Venda.marca)
        )

        rank_rows = q_rank.all()
        rank_map: Dict[str, List[dict]] = {}
        totals: Dict[str, float] = {}
        for r in rank_rows:
            v = (r.vendedor or "").strip().upper()
            m = (r.marca or "").strip()
            val = float(r.valor or 0.0)
            rank_map.setdefault(v, []).append({"marca": m, "valor": val})
            totals[v] = totals.get(v, 0.0) + val

        # Upsert cache
        vendedores_count = 0
        cache_rows = 0
        for r in rows:
            vendedor = (r.vendedor or "").strip().upper()
            if not vendedor:
                continue
            vendedores_count += 1

            bruto = float(r.valor_bruto or 0.0)
            devol = float(r.devolucoes or 0.0)
            canc = float(r.cancelamentos or 0.0)
            liquido = float(r.valor_liquido or 0.0)
            pct_dev = (devol / bruto * 100.0) if bruto else 0.0

            ranking_list = sorted(rank_map.get(vendedor, []), key=lambda x: x["valor"], reverse=True)
            total_periodo = float(totals.get(vendedor, 0.0))
            # adiciona percentuais e top15
            out_list = []
            for item in ranking_list:
                val = float(item["valor"])
                out_list.append({
                    "marca": item["marca"],
                    "valor": val,
                    "pct": (val / total_periodo * 100.0) if total_periodo else 0.0,
                })
            top15 = out_list[:15]

            # upsert manual (sem depender de on_conflict do SQLAlchemy core)
            obj = (
                db.query(DashboardCache)
                .filter(
                    DashboardCache.emp == emp,
                    DashboardCache.vendedor == vendedor,
                    DashboardCache.ano == int(ano),
                    DashboardCache.mes == int(mes),
                )
                .first()
            )
            if not obj:
                obj = DashboardCache(emp=emp, vendedor=vendedor, ano=int(ano), mes=int(mes))
                db.add(obj)

            obj.valor_bruto = bruto
            obj.valor_liquido = liquido
            obj.devolucoes = devol
            obj.cancelamentos = canc
            obj.pct_devolucao = pct_dev
            obj.mix_produtos = int(r.mix_produtos or 0)
            obj.mix_marcas = int(r.mix_marcas or 0)
            obj.ranking_json = json.dumps(out_list, ensure_ascii=False)
            obj.ranking_top15_json = json.dumps(top15, ensure_ascii=False)
            obj.total_liquido_periodo = total_periodo
            obj.atualizado_em = func.now()

            cache_rows += 1

        db.commit()

    return {"vendedores": vendedores_count, "linhas_cache": cache_rows}
