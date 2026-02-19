import json
from datetime import datetime
from sqlalchemy import and_

from db import (
    FinanceiroPagamento,
    FinanceiroAudit,
    CampanhaV2ResultadoNew,
    CampanhaV2MasterNew,
)


def sync_pagamentos_v2(db, ano: int, mes: int, actor: str = "") -> dict:
    """Cria/atualiza pagamentos do Financeiro com base em campanhas_v2_resultados (NEW schema).

    Regras:
    - Só cria pagamento quando premio > 0
    - Upsert pela chave uq_fin_pag_key (ano,mes,origem_tipo,origem_id,emp,vendedor)
    - Não altera status se já estiver A_PAGAR/PAGO (mantém status atual), só atualiza valores/nome.
    """
    actor = (actor or "").strip() or None

    # rows: (resultado, nome_campanha)
    rows = (
        db.query(CampanhaV2ResultadoNew, CampanhaV2MasterNew.nome)
        .join(CampanhaV2MasterNew, CampanhaV2MasterNew.id == CampanhaV2ResultadoNew.campanha_id)
        .filter(CampanhaV2ResultadoNew.ano == int(ano))
        .filter(CampanhaV2ResultadoNew.mes == int(mes))
        .all()
    )

    created = 0
    updated = 0
    skipped = 0

    for res, nome in rows:
        premio = float(getattr(res, "premio", 0.0) or 0.0)
        if premio <= 0:
            skipped += 1
            continue

        emp = getattr(res, "emp", None)
        vendedor = (getattr(res, "vendedor", "") or "").strip().upper()
        if not vendedor:
            skipped += 1
            continue

        origem_tipo = "V2"
        origem_id = int(getattr(res, "campanha_id"))
        campanha_nome = (nome or "").strip() or None

        existing = (
            db.query(FinanceiroPagamento)
            .filter(FinanceiroPagamento.ano == int(ano))
            .filter(FinanceiroPagamento.mes == int(mes))
            .filter(FinanceiroPagamento.origem_tipo == origem_tipo)
            .filter(FinanceiroPagamento.origem_id == origem_id)
            .filter(FinanceiroPagamento.vendedor == vendedor)
            .filter(FinanceiroPagamento.emp.is_(None) if emp is None else (FinanceiroPagamento.emp == int(emp)))
            .first()
        )

        if existing:
            # Atualiza valor e nome; preserva status se já avançado
            existing.valor_premio = premio
            if campanha_nome:
                existing.campanha_nome = campanha_nome
            if existing.status not in ("A_PAGAR", "PAGO"):
                existing.status = "PENDENTE"
            existing.atualizado_por = actor
            existing.atualizado_em = datetime.utcnow()
            updated += 1

            db.add(FinanceiroAudit(
                pagamento_id=existing.id,
                acao="UPSERT_V2",
                de_status=None,
                para_status=existing.status,
                usuario=actor,
                meta={"ano": int(ano), "mes": int(mes), "origem": "V2", "campanha_id": origem_id, "premio": premio},
            ))
        else:
            p = FinanceiroPagamento(
                ano=int(ano),
                mes=int(mes),
                origem_tipo=origem_tipo,
                origem_id=origem_id,
                campanha_nome=campanha_nome,
                emp=int(emp) if emp is not None else None,
                vendedor=vendedor,
                valor_premio=premio,
                status="PENDENTE",
                atualizado_por=actor,
                atualizado_em=datetime.utcnow(),
                criado_em=datetime.utcnow(),
            )
            db.add(p)
            db.flush()
            created += 1

            db.add(FinanceiroAudit(
                pagamento_id=p.id,
                acao="CREATE_FROM_V2",
                de_status=None,
                para_status="PENDENTE",
                usuario=actor,
                meta={"ano": int(ano), "mes": int(mes), "origem": "V2", "campanha_id": origem_id, "premio": premio},
            ))

    return {"created": created, "updated": updated, "skipped": skipped, "total": len(rows)}


def atualizar_status_pagamentos(db, pagamento_ids: list[int], novo_status: str, actor: str = "") -> int:
    novo_status = (novo_status or "").strip().upper()
    if novo_status not in ("PENDENTE", "A_PAGAR", "PAGO"):
        raise ValueError("Status inválido.")
    actor = (actor or "").strip() or None

    count = 0
    for pid in pagamento_ids:
        p = db.query(FinanceiroPagamento).filter(FinanceiroPagamento.id == int(pid)).first()
        if not p:
            continue
        de = p.status
        if de == novo_status:
            continue

        p.status = novo_status
        p.atualizado_por = actor
        p.atualizado_em = datetime.utcnow()
        db.add(p)

        db.add(FinanceiroAudit(
            pagamento_id=p.id,
            acao="STATUS_CHANGE",
            de_status=de,
            para_status=novo_status,
            usuario=actor,
            meta={"ids": pagamento_ids[:50], "novo_status": novo_status},
        ))
        count += 1
    return count
