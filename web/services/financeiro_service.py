import json
from datetime import datetime

from sqlalchemy import and_

from db import (
    SessionLocal,
    FinanceiroPagamento,
    FinanceiroAudit,
    CampanhaV2MasterNew,
    CampanhaV2ResultadoNew,
)


VALID_STATUS = {"PENDENTE", "A_PAGAR", "PAGO"}


def sync_pagamentos_v2(ano: int, mes: int, actor: str | None = None, keep_status: bool = True) -> dict:
    """Sincroniza a tabela financeiro_pagamentos com os resultados V2 (new schema).

    - Cria pagamentos ausentes.
    - Atualiza valor_premio e campanha_nome.
    - Por padrão NÃO rebaixa status (mantém A_PAGAR/PAGO) quando keep_status=True.

    Retorna um dict com contadores.
    """
    actor = (actor or "").strip() or None
    created = 0
    updated = 0

    db = SessionLocal()
    try:
        # Carrega nomes das campanhas (para export/tela)
        masters = {
            m.id: m.nome
            for m in db.query(CampanhaV2MasterNew).all()
        }

        rows = (
            db.query(CampanhaV2ResultadoNew)
            .filter(and_(CampanhaV2ResultadoNew.ano == int(ano), CampanhaV2ResultadoNew.mes == int(mes)))
            .all()
        )

        for r in rows:
            key_filter = and_(
                FinanceiroPagamento.ano == int(ano),
                FinanceiroPagamento.mes == int(mes),
                FinanceiroPagamento.origem_tipo == "V2",
                FinanceiroPagamento.origem_id == int(r.campanha_id),
                FinanceiroPagamento.emp.is_(None) if r.emp is None else (FinanceiroPagamento.emp == int(r.emp)),
                FinanceiroPagamento.vendedor == str(r.vendedor),
            )

            existing = db.query(FinanceiroPagamento).filter(key_filter).first()

            campanha_nome = masters.get(int(r.campanha_id))
            premio = float(r.premio or 0.0)

            if existing is None:
                p = FinanceiroPagamento(
                    ano=int(ano),
                    mes=int(mes),
                    origem_tipo="V2",
                    origem_id=int(r.campanha_id),
                    campanha_nome=campanha_nome,
                    emp=(int(r.emp) if r.emp is not None else None),
                    vendedor=str(r.vendedor),
                    valor_premio=premio,
                    status="PENDENTE",
                    atualizado_por=actor,
                    atualizado_em=datetime.utcnow(),
                )
                db.add(p)
                db.flush()  # para obter id

                db.add(
                    FinanceiroAudit(
                        pagamento_id=p.id,
                        acao="UPSERT",
                        de_status=None,
                        para_status="PENDENTE",
                        usuario=actor,
                        meta=json.dumps({"origem": "V2", "campanha_id": int(r.campanha_id)}),
                    )
                )
                created += 1
            else:
                # Atualiza valores mas preserva status se keep_status=True
                existing.valor_premio = premio
                existing.campanha_nome = campanha_nome
                existing.atualizado_por = actor
                existing.atualizado_em = datetime.utcnow()
                updated += 1

        db.commit()
        return {"created": created, "updated": updated, "total_v2_rows": len(rows)}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def atualizar_status_pagamento(pagamento_id: int, novo_status: str, actor: str | None = None) -> None:
    """Atualiza status do pagamento e grava auditoria."""
    actor = (actor or "").strip() or None
    novo_status = (novo_status or "").strip().upper()
    if novo_status not in VALID_STATUS:
        raise ValueError(f"Status inválido: {novo_status}")

    db = SessionLocal()
    try:
        p = db.query(FinanceiroPagamento).filter(FinanceiroPagamento.id == int(pagamento_id)).first()
        if not p:
            raise ValueError("Pagamento não encontrado")

        de = p.status
        if de == novo_status:
            return

        p.status = novo_status
        p.atualizado_por = actor
        p.atualizado_em = datetime.utcnow()

        db.add(
            FinanceiroAudit(
                pagamento_id=p.id,
                acao="STATUS_CHANGE",
                de_status=de,
                para_status=novo_status,
                usuario=actor,
                meta=json.dumps({"origem_tipo": p.origem_tipo, "origem_id": p.origem_id}),
            )
        )

        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
