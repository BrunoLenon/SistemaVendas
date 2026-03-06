from __future__ import annotations

from datetime import date
from typing import Callable, Any

from flask import request, session, render_template


def register_ranking_marca_routes(
    app,
    *,
    admin_required_fn: Callable[[Callable[..., Any]], Callable[..., Any]],
    login_required_fn: Callable[[Callable[..., Any]], Callable[..., Any]],
    role_fn: Callable[[], str],
    allowed_emps_fn: Callable[[], list],
) -> None:
    """Registra rotas de Ranking por Marca (Admin + Usuário).

    Refatoração pura: mantém URLs e endpoints originais.
    """

    def admin_campanhas_ranking_marca():
        from services.ranking_marca_v2_new import (
            list_campaigns_for_admin,
            get_scope_emps,
            create_or_update_campaign,
            delete_campaign,
            recalc_ranking_marca,
            _to_float,
            _parse_date,
            _to_int,
        )
        from db import Emp, SessionLocal

        db = SessionLocal()
        erro = None
        ok = None

        try:
            # competência para recalcular (default mês atual)
            hoje = date.today()
            ano = _to_int(request.args.get("ano"), hoje.year)
            mes = _to_int(request.args.get("mes"), hoje.month)

            anos = list(range(hoje.year - 2, hoje.year + 2 + 1))

            # options de EMPs (cadastro)
            emps_rows = db.query(Emp).order_by(Emp.codigo.asc()).all()
            emps_opts = [{"value": int(e.codigo), "label": f"{int(e.codigo)} — {e.nome}"} for e in emps_rows]

            if request.method == "POST":
                acao = (request.form.get("acao") or "").strip().lower()

                # helper para ler emps do multiselect (pode vir como vários inputs "emps")
                emps_vals = request.form.getlist("emps")
                if not emps_vals:
                    # fallback: "101,1001"
                    raw = (request.form.get("emps") or "").strip()
                    if raw:
                        emps_vals = [x.strip() for x in raw.split(",") if x.strip()]

                emps: list[int] = []
                for v in emps_vals:
                    try:
                        emps.append(int(v))
                    except Exception:
                        pass

                if acao in ("criar", "editar"):
                    campanha_id = request.form.get("id") if acao == "editar" else None

                    nome = (request.form.get("nome") or "").strip()
                    marca_alvo = (request.form.get("marca_alvo") or "").strip()

                    vig_ini = _parse_date(request.form.get("vigencia_inicio"))
                    vig_fim = _parse_date(request.form.get("vigencia_fim"))

                    scope_mode = (request.form.get("scope_mode") or "GLOBAL").strip()

                    minimo = _to_float(request.form.get("base_minima_valor"), 0.0)

                    p1 = _to_float(request.form.get("premio_top1"), 0.0)
                    p2 = _to_float(request.form.get("premio_top2"), 0.0)
                    p3 = _to_float(request.form.get("premio_top3"), 0.0)

                    ativo = (request.form.get("ativo") or "1") == "1"

                    create_or_update_campaign(
                        db,
                        campanha_id=int(campanha_id) if campanha_id else None,
                        nome=nome,
                        marca_alvo=marca_alvo,
                        vigencia_inicio=vig_ini,
                        vigencia_fim=vig_fim,
                        scope_mode=scope_mode,
                        emps=emps,
                        base_minima_valor=minimo,
                        premio_top1=p1,
                        premio_top2=p2,
                        premio_top3=p3,
                        ativo=ativo,
                    )
                    db.commit()
                    ok = "Campanha salva com sucesso."

                elif acao == "remover":
                    cid = int(request.form.get("id") or 0)
                    delete_campaign(db, cid)
                    db.commit()
                    ok = f"Campanha #{cid} removida."

                elif acao == "recalcular":
                    cid = int(request.form.get("id") or 0)
                    ano_p = _to_int(request.form.get("ano"), ano)
                    mes_p = _to_int(request.form.get("mes"), mes)
                    actor = (session.get("username") or session.get("nome") or session.get("user") or "admin")

                    try:
                        # Compatibilidade: algumas versões do service não aceitam periodo_ini/periodo_fim
                        import inspect as _inspect

                        _kwargs = dict(campanha_id=cid, ano=ano_p, mes=mes_p, actor=str(actor))
                        periodo_ini = (request.form.get("periodo_ini") or "").strip()
                        periodo_fim = (request.form.get("periodo_fim") or "").strip()
                        try:
                            _sig = _inspect.signature(recalc_ranking_marca)
                            if "periodo_ini" in _sig.parameters and periodo_ini:
                                _kwargs["periodo_ini"] = periodo_ini
                            if "periodo_fim" in _sig.parameters and periodo_fim:
                                _kwargs["periodo_fim"] = periodo_fim
                        except Exception:
                            pass

                        res = recalc_ranking_marca(db, **_kwargs)
                        db.commit()

                        if res.get("rows", 0) > 0:
                            ok = f"✅ Snapshot recalculado: {res.get('rows', 0)} vendedores qualificados ({mes_p:02d}/{ano_p})."
                        else:
                            motivo = res.get("motivo") or "Nenhum vendedor atingiu o mínimo"
                            ok = f"⚠️ Recálculo concluído: {motivo} ({mes_p:02d}/{ano_p})."
                    except Exception as e:
                        try:
                            db.rollback()
                        except Exception:
                            pass
                        erro = str(e)

            # listagem
            campanhas = list_campaigns_for_admin(db)

            # mapa de emps por campanha
            emps_map = {}
            for c in campanhas:
                try:
                    emps_map[int(c.get("id"))] = get_scope_emps(db, int(c.get("id")))
                except Exception:
                    pass

            return render_template(
                "admin_campanhas_ranking_marca.html",
                role=role_fn(),
                emp=session.get("emp"),
                campanhas=campanhas,
                emps_map=emps_map,
                emps_opts=emps_opts,
                erro=erro,
                ok=ok,
                ano=ano,
                mes=mes,
                anos=anos,
            )

        except Exception as e:
            try:
                db.rollback()
            except Exception:
                pass
            erro = str(e)
            # fallback para render mesmo em erro
            try:
                campanhas = list_campaigns_for_admin(db)
            except Exception:
                campanhas = []
            return render_template(
                "admin_campanhas_ranking_marca.html",
                role=role_fn(),
                emp=session.get("emp"),
                campanhas=campanhas,
                emps_map={},
                emps_opts=[],
                erro=erro,
                ok=None,
                ano=date.today().year,
                mes=date.today().month,
                anos=list(range(date.today().year - 2, date.today().year + 3)),
            )

        finally:
            try:
                db.close()
            except Exception:
                pass

    def campanhas_ranking_marca():
        from services.ranking_marca_v2_new import list_campaigns_for_user, get_scope_emps, _to_int
        from db import SessionLocal, CampanhaV2MasterNewSchema as CampanhaV2MasterNew, CampanhaV2ResultadoNewSchema as CampanhaV2ResultadoNew

        db = SessionLocal()
        erro = None
        info = None

        try:
            hoje = date.today()
            ano = _to_int(request.args.get("ano"), hoje.year)
            mes = _to_int(request.args.get("mes"), hoje.month)

            anos = list(range(hoje.year - 2, hoje.year + 2 + 1))

            role = (role_fn() or "").lower()
            allowed_emps = allowed_emps_fn()  # [] = todas (admin_all_emps)
            campanhas = list_campaigns_for_user(db, role=role, allowed_emps=allowed_emps)

            campanha_id = request.args.get("campanha_id")
            campanha = None
            resultados = []
            scope_emps = []

            if campanha_id:
                try:
                    cid = int(campanha_id)
                except Exception:
                    cid = 0

                campanha = db.query(CampanhaV2MasterNew).filter(CampanhaV2MasterNew.id == cid).first()
                if not campanha:
                    info = "Campanha não encontrada."
                    campanha = None
                else:
                    # regra de visibilidade para POR_EMP
                    if (campanha.scope_mode or "GLOBAL").upper() == "POR_EMP" and role != "admin":
                        scope_emps = get_scope_emps(db, cid)
                        if allowed_emps:
                            allowed_set = {int(e) for e in allowed_emps if str(e).isdigit()}
                            scope_set = {int(e) for e in scope_emps}
                            if not scope_set.intersection(allowed_set):
                                campanha = None
                                info = "Você não tem acesso a esta campanha."
                        else:
                            # allowed_emps vazio => treat as all
                            pass
                    else:
                        scope_emps = get_scope_emps(db, cid)

                    if campanha:
                        resultados = (
                            db.query(CampanhaV2ResultadoNew)
                            .filter(CampanhaV2ResultadoNew.campanha_id == cid)
                            .filter(CampanhaV2ResultadoNew.ano == int(ano))
                            .filter(CampanhaV2ResultadoNew.mes == int(mes))
                            .order_by(CampanhaV2ResultadoNew.posicao.asc().nullslast())
                            .all()
                        )

            me = (session.get("nome") or session.get("username") or session.get("vendedor") or "").strip().upper()

            return render_template(
                "campanhas_ranking_marca.html",
                role=role_fn(),
                emp=session.get("emp"),
                campanhas=campanhas,
                campanha_id=int(campanha_id) if campanha_id and str(campanha_id).isdigit() else None,
                campanha=campanha,
                resultados=resultados,
                scope_emps=scope_emps,
                ano=ano,
                mes=mes,
                anos=anos,
                me=me,
                erro=erro,
                info=info,
            )

        except Exception as e:
            erro = str(e)
            return render_template(
                "campanhas_ranking_marca.html",
                role=role_fn(),
                emp=session.get("emp"),
                campanhas=[],
                campanha_id=None,
                campanha=None,
                resultados=[],
                scope_emps=[],
                ano=date.today().year,
                mes=date.today().month,
                anos=list(range(date.today().year - 2, date.today().year + 3)),
                me="",
                erro=erro,
                info=None,
            )
        finally:
            try:
                db.close()
            except Exception:
                pass

    # endpoints originais
    app.add_url_rule(
        "/admin/campanhas/ranking-marca",
        endpoint="admin_campanhas_ranking_marca",
        view_func=admin_required_fn(admin_campanhas_ranking_marca),
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/campanhas/ranking-marca",
        endpoint="campanhas_ranking_marca",
        view_func=login_required_fn(campanhas_ranking_marca),
        methods=["GET"],
    )
