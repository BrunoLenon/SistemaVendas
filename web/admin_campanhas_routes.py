# -*- coding: utf-8 -*-
"""
Rotas do Admin: Campanhas (Qtd) - legado (/admin/campanhas)

Refatoração pura: extraído do app.py sem alterar comportamento externo.
"""
from __future__ import annotations

from calendar import monthrange
from datetime import date, datetime
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Callable

from flask import redirect, render_template, request
from sqlalchemy import func, or_


def register_admin_campanhas_routes(
    app,
    *,
    SessionLocal,
    CampanhaQtd,
    CampanhaQtdResultado,
    login_required_fn: Callable[[], Any],
    admin_required_fn: Callable[[], Any],
    competencia_fechada_fn: Callable[[Any, str, int, int], bool],
    usuario_logado_fn: Callable[[], Any],
) -> None:
    """
    Registra rotas de cadastro/administração de campanhas de recompensa por quantidade.

    Mantém endpoint compatível: "admin_campanhas_qtd".
    """

    def _to_dec(raw: str, *, field_label: str = "Número") -> Decimal:
        value = (raw or "").strip().replace(".", "").replace(",", ".") if "," in (raw or "") else (raw or "").strip().replace(",", ".")
        try:
            return Decimal(value)
        except Exception:
            raise ValueError(f"{field_label} inválido.")

    def _get_selected_emps(form) -> list[str]:
        """Lê EMPs selecionadas no cadastro em lote, mantendo compatibilidade com o campo legado `emp`."""
        values: list[str] = []

        def add_raw(raw: Any) -> None:
            text = str(raw or "").strip()
            if not text:
                return
            # Aceita valores vindos de checkboxes, campo legado ou digitação manual: "101, 102;103".
            normalized = text.replace(";", ",").replace("\n", ",").replace("\t", ",")
            for part in normalized.split(","):
                emp_code = str(part or "").strip()
                if emp_code:
                    values.append(emp_code)

        for key in ("emps", "emp", "emp_manual"):
            try:
                for raw in form.getlist(key):
                    add_raw(raw)
            except Exception:
                add_raw(form.get(key))

        seen: set[str] = set()
        result: list[str] = []
        for emp_code in values:
            key = emp_code.upper()
            if key in seen:
                continue
            seen.add(key)
            result.append(emp_code)
        return result

    def _parse_common_payload(form, *, current_obj=None) -> dict[str, Any]:
        """Valida e normaliza os dados comuns da campanha (escopo/vigência)."""
        selected_emps = _get_selected_emps(form)
        emp = (selected_emps[0] if selected_emps else (form.get("emp") or "")).strip()
        vendedor = (form.get("vendedor") or "").strip().upper() or None
        titulo = (form.get("titulo") or "").strip() or None
        campanha_tipo = (form.get("campanha_tipo") or "VENDEDOR").strip().upper()
        if campanha_tipo not in {"VENDEDOR", "GERENTE"}:
            campanha_tipo = "VENDEDOR"
        if campanha_tipo == "GERENTE":
            vendedor = None
        if not emp:
            raise ValueError("Informe a EMP.")

        data_ini_raw = (form.get("data_inicio") or "").strip()
        data_fim_raw = (form.get("data_fim") or "").strip()
        if not data_ini_raw or not data_fim_raw:
            raise ValueError("Informe data início e fim.")
        data_inicio = datetime.strptime(data_ini_raw, "%Y-%m-%d").date()
        data_fim = datetime.strptime(data_fim_raw, "%Y-%m-%d").date()
        if data_fim < data_inicio:
            raise ValueError("Data fim não pode ser menor que data início.")

        payload = {
            "emp": str(emp),
            "campanha_tipo": campanha_tipo,
            "vendedor": vendedor,
            "titulo": titulo,
            "data_inicio": data_inicio,
            "data_fim": data_fim,
        }
        return payload

    def _get_list_value(form, name: str, idx: int | None, *, fallback_name: str | None = None) -> str:
        """Lê campo simples ou campo de regra em lista, mantendo compatibilidade com o formulário antigo."""
        if idx is not None:
            values = form.getlist(name)
            if idx < len(values):
                return str(values[idx] or "")
            return ""
        return str(form.get(fallback_name or name) or "")

    def _parse_rule_payload(
        form,
        *,
        base_payload: dict[str, Any],
        idx: int | None = None,
        current_obj=None,
    ) -> dict[str, Any]:
        """Valida uma regra/item da campanha.

        Cada regra vira uma linha em campanhas_qtd. Isso mantém o motor atual seguro:
        1 campanha por EMP + produto/descrição + critérios opcionais.
        """
        prefix = "regra_" if idx is not None else ""

        campo_match = (_get_list_value(form, prefix + "campo_match", idx, fallback_name="campo_match") or "codigo").strip().lower()
        if campo_match not in {"codigo", "descricao"}:
            campo_match = "codigo"

        produto_prefixo = _get_list_value(form, prefix + "produto_prefixo", idx, fallback_name="produto_prefixo").strip()
        descricao_prefixo = _get_list_value(form, prefix + "descricao_prefixo", idx, fallback_name="descricao_prefixo").strip()
        marca = _get_list_value(form, prefix + "marca", idx, fallback_name="marca").strip()

        recompensa_raw = _get_list_value(form, prefix + "recompensa_unit", idx, fallback_name="recompensa_unit").strip()
        qtd_min_raw = _get_list_value(form, prefix + "qtd_minima", idx, fallback_name="qtd_minima").strip()
        valor_min_raw = _get_list_value(form, prefix + "valor_minimo", idx, fallback_name="valor_minimo").strip()

        # Faturamento mínimo pode ser por item/regra; se vier em branco, usa o campo global legado.
        fat_min_emp_raw = _get_list_value(form, prefix + "faturamento_minimo_emp", idx, fallback_name="faturamento_minimo_emp").strip()
        if idx is not None and not fat_min_emp_raw:
            fat_min_emp_raw = (form.get("faturamento_minimo_emp") or "").strip()

        if campo_match == "descricao":
            if not descricao_prefixo:
                raise ValueError("Informe a descrição/início em todas as regras por descrição.")
            # Mantém produto_prefixo preenchido para compatibilidade com coluna NOT NULL e relatórios antigos.
            if not produto_prefixo:
                produto_prefixo = descricao_prefixo
        else:
            if not produto_prefixo:
                raise ValueError("Informe o código/prefixo em todas as regras por código.")
            descricao_prefixo = ""

        if not recompensa_raw:
            raise ValueError("Informe a recompensa (R$/un) em todas as regras.")

        recompensa_unit = _to_dec(recompensa_raw, field_label="Recompensa")
        if recompensa_unit < 0:
            raise ValueError("Recompensa não pode ser negativa.")

        qtd_minima = _to_dec(qtd_min_raw, field_label="Quantidade mínima") if qtd_min_raw else None
        if qtd_minima is not None and qtd_minima < 0:
            raise ValueError("Quantidade mínima não pode ser negativa.")

        valor_minimo = _to_dec(valor_min_raw, field_label="Valor mínimo") if valor_min_raw else None
        if valor_minimo is not None and valor_minimo < 0:
            raise ValueError("Valor mínimo não pode ser negativo.")

        faturamento_minimo_emp = None
        if fat_min_emp_raw:
            faturamento_minimo_emp = _to_dec(fat_min_emp_raw, field_label="Faturamento mínimo da EMP")
            if faturamento_minimo_emp < 0:
                raise ValueError("Faturamento mínimo da EMP não pode ser negativo.")
        elif current_obj is not None and hasattr(current_obj, "faturamento_minimo_emp"):
            faturamento_minimo_emp = getattr(current_obj, "faturamento_minimo_emp", None)

        payload = dict(base_payload)
        payload.update({
            "produto_prefixo": (produto_prefixo or "").upper(),
            "descricao_prefixo": (descricao_prefixo or "").strip(),
            "campo_match": campo_match,
            # Marca em branco significa: considerar TODAS as marcas.
            "marca": (marca or "").upper(),
            "recompensa_unit": float(recompensa_unit.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)),
            "qtd_minima": float(qtd_minima) if qtd_minima is not None else None,
            "valor_minimo": float(valor_minimo) if valor_minimo is not None else None,
        })
        if hasattr(CampanhaQtd, "faturamento_minimo_emp"):
            payload["faturamento_minimo_emp"] = float(faturamento_minimo_emp) if faturamento_minimo_emp not in (None, "") else None
        return payload

    def _rule_has_content(form, idx: int) -> bool:
        names = [
            "regra_produto_prefixo",
            "regra_descricao_prefixo",
            "regra_marca",
            "regra_recompensa_unit",
            "regra_qtd_minima",
            "regra_valor_minimo",
            "regra_faturamento_minimo_emp",
        ]
        for name in names:
            vals = form.getlist(name)
            if idx < len(vals) and str(vals[idx] or "").strip():
                return True
        return False

    def _parse_campaign_payload(form, *, current_obj=None) -> dict[str, Any]:
        """Compatibilidade: valida uma única regra/campanha."""
        base_payload = _parse_common_payload(form, current_obj=current_obj)
        return _parse_rule_payload(form, base_payload=base_payload, current_obj=current_obj)

    def _parse_campaign_payloads(form, *, current_obj=None) -> list[dict[str, Any]]:
        """Valida uma ou várias regras no cadastro.

        Quando o formulário envia arrays `regra_*`, cada item preenchido vira uma campanha.
        Se não houver arrays, mantém o comportamento antigo de uma única campanha.
        """
        rule_lengths = [len(form.getlist(name)) for name in (
            "regra_campo_match",
            "regra_produto_prefixo",
            "regra_descricao_prefixo",
            "regra_marca",
            "regra_recompensa_unit",
        )]
        total_rules = max(rule_lengths or [0])
        if total_rules <= 0:
            return [_parse_campaign_payload(form, current_obj=current_obj)]

        base_payload = _parse_common_payload(form, current_obj=current_obj)
        payloads: list[dict[str, Any]] = []
        for idx in range(total_rules):
            if not _rule_has_content(form, idx):
                continue
            payloads.append(_parse_rule_payload(form, base_payload=base_payload, idx=idx, current_obj=current_obj))
        if not payloads:
            raise ValueError("Inclua ao menos uma regra/item da campanha.")
        return payloads

    def _prefixes_overlap(a: Any, b: Any) -> bool:
        """Retorna True quando dois prefixos podem alcançar o mesmo item.

        Ex.: 30015 conflita com 300157; BLOCO conflita com BLOCO TITAN.
        """
        aa = _safe_upper(a)
        bb = _safe_upper(b)
        if not aa or not bb:
            return False
        return aa.startswith(bb) or bb.startswith(aa)

    def _payloads_overlap(a: dict[str, Any], b: dict[str, Any]) -> bool:
        """Confere duplicidade dentro do mesmo lote antes de gravar.

        Marca em branco é curinga e conflita com qualquer marca na mesma regra.
        """
        if str(a.get("emp") or "") != str(b.get("emp") or ""):
            return False
        if _safe_upper(a.get("campanha_tipo") or "VENDEDOR") != _safe_upper(b.get("campanha_tipo") or "VENDEDOR"):
            return False
        if (a.get("campo_match") or "codigo") != (b.get("campo_match") or "codigo"):
            return False
        if (a.get("data_inicio") or date.min) > (b.get("data_fim") or date.max):
            return False
        if (a.get("data_fim") or date.max) < (b.get("data_inicio") or date.min):
            return False

        tipo = _safe_upper(a.get("campanha_tipo") or "VENDEDOR")
        if tipo != "GERENTE":
            if _safe_upper(a.get("vendedor")) != _safe_upper(b.get("vendedor")):
                return False

        if (a.get("campo_match") or "codigo") == "descricao":
            if not _prefixes_overlap(a.get("descricao_prefixo"), b.get("descricao_prefixo")):
                return False
        else:
            if not _prefixes_overlap(a.get("produto_prefixo"), b.get("produto_prefixo")):
                return False

        ma = _safe_upper(a.get("marca"))
        mb = _safe_upper(b.get("marca"))
        return (not ma) or (not mb) or ma == mb

    def _find_batch_duplicates(payloads: list[dict[str, Any]]) -> list[tuple[str, int, int]]:
        conflicts: list[tuple[str, int, int]] = []
        for i in range(len(payloads)):
            for j in range(i + 1, len(payloads)):
                if _payloads_overlap(payloads[i], payloads[j]):
                    conflicts.append((str(payloads[i].get("emp") or ""), i + 1, j + 1))
        return conflicts

    def _apply_campaign_payload(obj, payload: dict[str, Any]) -> None:
        for key, value in payload.items():
            if hasattr(obj, key):
                setattr(obj, key, value)
        if hasattr(obj, "updated_at"):
            obj.updated_at = datetime.utcnow()

    def _find_duplicate_campaign(db, payload: dict[str, Any], *, exclude_id: int | None = None):
        """Localiza campanha QTD duplicada/concorrente com vigência sobreposta.

        Marca em branco significa "todas as marcas". Por isso:
        - nova campanha sem marca conflita com qualquer marca existente na mesma regra;
        - nova campanha com marca conflita com campanha da mesma marca ou campanha sem marca.
        """
        emp = str(payload.get("emp") or "").strip()
        marca = _safe_upper(payload.get("marca"))
        tipo = _safe_upper(payload.get("campanha_tipo") or "VENDEDOR") or "VENDEDOR"
        campo_match = str(payload.get("campo_match") or "codigo").strip().lower()
        data_inicio = payload.get("data_inicio")
        data_fim = payload.get("data_fim")

        if not emp or not data_inicio or not data_fim:
            return None

        q = (
            db.query(CampanhaQtd)
            .filter(CampanhaQtd.emp == emp)
            .filter(func.upper(func.coalesce(CampanhaQtd.campanha_tipo, "VENDEDOR")) == tipo)
            .filter(func.lower(func.coalesce(CampanhaQtd.campo_match, "codigo")) == campo_match)
            .filter(CampanhaQtd.data_inicio <= data_fim)
            .filter(CampanhaQtd.data_fim >= data_inicio)
        )
        if exclude_id:
            q = q.filter(CampanhaQtd.id != int(exclude_id))

        # Trava de marca: marca vazia é curinga.
        if marca:
            q = q.filter(or_(
                func.upper(func.coalesce(CampanhaQtd.marca, "")) == marca,
                func.coalesce(CampanhaQtd.marca, "") == "",
            ))
        # se marca está vazia, não filtra marca: conflita com qualquer marca na mesma regra.

        if tipo == "GERENTE":
            q = q.filter(or_(CampanhaQtd.vendedor.is_(None), CampanhaQtd.vendedor == ""))
        else:
            vendedor = _safe_upper(payload.get("vendedor"))
            if vendedor:
                q = q.filter(func.upper(func.coalesce(CampanhaQtd.vendedor, "")) == vendedor)
            else:
                q = q.filter(or_(CampanhaQtd.vendedor.is_(None), CampanhaQtd.vendedor == ""))

        if campo_match == "descricao":
            alvo = _safe_upper(payload.get("descricao_prefixo"))
            if not alvo:
                return None
        else:
            alvo = _safe_upper(payload.get("produto_prefixo"))
            if not alvo:
                return None

        # Prefixo sempre é regra "começa com". Portanto 30015 conflita com 300157
        # e BLOCO conflita com BLOCO TITAN. Filtramos candidatos leves e confirmamos em Python.
        for cand in q.order_by(CampanhaQtd.id.asc()).limit(1000).all():
            if campo_match == "descricao":
                cand_regra = getattr(cand, "descricao_prefixo", None) or getattr(cand, "produto_prefixo", None)
            else:
                cand_regra = getattr(cand, "produto_prefixo", None)
            if _prefixes_overlap(alvo, cand_regra):
                return cand
        return None

    def _format_duplicate_message(duplicates: list[tuple[str, Any]]) -> str:
        details = []
        for emp_code, dup in duplicates[:8]:
            details.append(f"EMP {emp_code}: já existe a campanha #{getattr(dup, 'id', '?')} ({getattr(dup, 'titulo', '') or 'sem título'}).")
        extra = ""
        if len(duplicates) > 8:
            extra = f" + {len(duplicates) - 8} outra(s)."
        return "Campanha duplicada bloqueada. Nenhuma campanha foi criada/alterada. " + " ".join(details) + extra

    def _get_campaign_id_from_form(form) -> int:
        raw = form.get("campanha_id") or form.get("id") or ""
        raw_s = str(raw or "").strip()
        try:
            cid = int(raw_s)
        except Exception:
            raise ValueError(f"ID da campanha inválido ou não enviado pelo formulário: {raw_s!r}")
        if cid <= 0:
            raise ValueError("ID da campanha não enviado pelo formulário.")
        return cid


    def _safe_upper(value: Any) -> str:
        return str(value or "").strip().upper()

    def _load_assisted_options(db) -> dict[str, Any]:
        """Carrega listas de apoio para reduzir erro de digitação no cadastro.

        Conservador por desenho: qualquer falha em tabela auxiliar não bloqueia a tela.
        """
        options: dict[str, Any] = {
            "emps": [],
            "vendedores": [],
            "marcas": [],
            "has_faturamento_minimo_emp": hasattr(CampanhaQtd, "faturamento_minimo_emp"),
        }

        try:
            from db import Emp, Usuario, UsuarioEmp, Venda  # type: ignore
        except Exception:
            Emp = Usuario = UsuarioEmp = Venda = None  # type: ignore

        emp_map: dict[str, dict[str, Any]] = {}

        def add_emp(codigo: Any, *, nome: Any = None, cidade: Any = None, uf: Any = None, ativo: Any = True) -> None:
            cod = str(codigo or "").strip()
            if not cod:
                return
            current = emp_map.get(cod) or {"codigo": cod, "nome": "", "cidade": "", "uf": "", "ativo": True}
            if nome and not current.get("nome"):
                current["nome"] = str(nome or "").strip()
            if cidade and not current.get("cidade"):
                current["cidade"] = str(cidade or "").strip()
            if uf and not current.get("uf"):
                current["uf"] = str(uf or "").strip().upper()
            current["ativo"] = bool(ativo)
            emp_map[cod] = current

        # EMPs oficiais cadastradas.
        if Emp is not None:
            try:
                for e in db.query(Emp).order_by(Emp.ativo.desc(), Emp.codigo.asc()).all():
                    add_emp(getattr(e, "codigo", None), nome=getattr(e, "nome", None), cidade=getattr(e, "cidade", None), uf=getattr(e, "uf", None), ativo=getattr(e, "ativo", True))
            except Exception:
                pass

        # Fallback/complemento: EMPs que já aparecem em campanhas.
        try:
            rows = (
                db.query(CampanhaQtd.emp)
                .filter(CampanhaQtd.emp.isnot(None))
                .distinct()
                .order_by(CampanhaQtd.emp.asc())
                .limit(250)
                .all()
            )
            for row in rows:
                add_emp(row[0])
        except Exception:
            pass

        # Fallback/complemento: EMPs que já aparecem nas vendas.
        if Venda is not None:
            try:
                rows = (
                    db.query(Venda.emp)
                    .filter(Venda.emp.isnot(None))
                    .filter(Venda.emp != "")
                    .distinct()
                    .order_by(Venda.emp.asc())
                    .limit(300)
                    .all()
                )
                for row in rows:
                    add_emp(row[0])
            except Exception:
                pass

        options["emps"] = sorted(emp_map.values(), key=lambda x: str(x.get("codigo") or ""))

        vendedor_map: dict[str, set[str]] = {}

        def add_vendedor(nome: Any, emp: Any = None) -> None:
            vend = str(nome or "").strip().upper()
            if not vend:
                return
            vendedor_map.setdefault(vend, set())
            emp_code = str(emp or "").strip()
            if emp_code:
                vendedor_map[vend].add(emp_code)

        # Vendedores oficiais por usuário e vínculo multi-EMP.
        if Usuario is not None:
            try:
                for u in db.query(Usuario).filter(func.lower(Usuario.role) == "vendedor").order_by(Usuario.username.asc()).limit(500).all():
                    add_vendedor(getattr(u, "username", None), getattr(u, "emp", None))
            except Exception:
                pass

        if Usuario is not None and UsuarioEmp is not None:
            try:
                rows = (
                    db.query(Usuario.username, UsuarioEmp.emp)
                    .join(UsuarioEmp, UsuarioEmp.usuario_id == Usuario.id)
                    .filter(func.lower(Usuario.role) == "vendedor")
                    .filter(UsuarioEmp.ativo.is_(True))
                    .order_by(UsuarioEmp.emp.asc(), Usuario.username.asc())
                    .limit(1200)
                    .all()
                )
                for username, emp in rows:
                    add_vendedor(username, emp)
            except Exception:
                pass

        # Vendedores reais das vendas importadas. Importante porque campanha precisa bater com Venda.vendedor.
        if Venda is not None:
            try:
                rows = (
                    db.query(Venda.emp, Venda.vendedor)
                    .filter(Venda.vendedor.isnot(None))
                    .filter(Venda.vendedor != "")
                    .distinct()
                    .order_by(Venda.emp.asc(), Venda.vendedor.asc())
                    .limit(1800)
                    .all()
                )
                for emp, vendedor in rows:
                    add_vendedor(vendedor, emp)
            except Exception:
                pass

        options["vendedores"] = [
            {"nome": nome, "emps": sorted(emps)}
            for nome, emps in sorted(vendedor_map.items(), key=lambda item: item[0])
        ]

        marcas: set[str] = set()

        def add_marca(value: Any) -> None:
            marca = str(value or "").strip().upper()
            if marca:
                marcas.add(marca)

        try:
            rows = (
                db.query(CampanhaQtd.marca)
                .filter(CampanhaQtd.marca.isnot(None))
                .distinct()
                .order_by(CampanhaQtd.marca.asc())
                .limit(300)
                .all()
            )
            for row in rows:
                add_marca(row[0])
        except Exception:
            pass

        if Venda is not None:
            try:
                rows = (
                    db.query(Venda.marca)
                    .filter(Venda.marca.isnot(None))
                    .filter(Venda.marca != "")
                    .distinct()
                    .order_by(Venda.marca.asc())
                    .limit(500)
                    .all()
                )
                for row in rows:
                    add_marca(row[0])
            except Exception:
                pass

        options["marcas"] = sorted(marcas)
        return options

    def admin_campanhas_qtd():
        """Cadastro e administração de campanhas de recompensa por quantidade."""
        red = login_required_fn()
        if red:
            return red
        red = admin_required_fn()
        if red:
            return red

        erro = None
        ok = None

        hoje = date.today()
        try:
            mes = int(request.values.get("mes") or hoje.month)
        except Exception:
            mes = hoje.month
        try:
            ano = int(request.values.get("ano") or hoje.year)
        except Exception:
            ano = hoje.year
        if mes < 1 or mes > 12:
            mes = hoje.month
        if ano < 2000 or ano > 2100:
            ano = hoje.year

        # Lista gerencial: por padrão mostra somente campanhas com vigência cruzando
        # a competência selecionada. Mantém opção de consulta histórica com escopo=todas.
        lista_escopo = (request.values.get("escopo") or "periodo").strip().lower()
        if lista_escopo not in {"periodo", "todas"}:
            lista_escopo = "periodo"
        periodo_inicio = date(int(ano), int(mes), 1)
        periodo_fim = date(int(ano), int(mes), monthrange(int(ano), int(mes))[1])

        with SessionLocal() as db:
            if request.method == "POST":
                acao = (request.form.get("acao") or "").strip().lower()

                # Se a competência estiver FECHADA, bloqueia alterações de campanhas (mantém integridade do fechamento).
                try:
                    emps_post: list[str] = []
                    if acao == "criar":
                        emps_post = _get_selected_emps(request.form)
                    else:
                        emp_post = (request.form.get("emp") or "").strip()
                        if not emp_post:
                            cid_check = _get_campaign_id_from_form(request.form)
                            if cid_check:
                                obj_check = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid_check).first()
                                if obj_check:
                                    emp_post = (obj_check.emp or "").strip()
                        if emp_post:
                            emps_post = [emp_post]
                    for emp_post in emps_post:
                        if emp_post and competencia_fechada_fn(db, emp_post, ano, mes):
                            return redirect('/admin/fechamento' + f'?emp={emp_post}&mes={mes}&ano={ano}')
                except Exception:
                    pass

                try:
                    if acao == "criar":
                        selected_emps = _get_selected_emps(request.form)
                        if not selected_emps:
                            raise ValueError("Selecione ao menos uma EMP para a campanha.")

                        base_rules = _parse_campaign_payloads(request.form)
                        payloads: list[dict[str, Any]] = []
                        duplicates: list[tuple[str, Any]] = []

                        for emp_code in selected_emps:
                            for rule_payload in base_rules:
                                payload = dict(rule_payload)
                                payload["emp"] = str(emp_code).strip()
                                dup = _find_duplicate_campaign(db, payload)
                                if dup:
                                    duplicates.append((payload["emp"], dup))
                                payloads.append(payload)

                        batch_conflicts = _find_batch_duplicates(payloads)
                        if batch_conflicts:
                            exemplos = ", ".join([f"EMP {emp} regras {a}/{b}" for emp, a, b in batch_conflicts[:6]])
                            raise ValueError("Há regras duplicadas/conflitantes no próprio lote. Ajuste antes de salvar: " + exemplos)

                        if duplicates:
                            raise ValueError(_format_duplicate_message(duplicates))

                        for payload in payloads:
                            db.add(CampanhaQtd(**payload, ativo=1))
                        db.commit()
                        if len(payloads) == 1:
                            ok = "Campanha cadastrada com sucesso."
                        else:
                            qtd_emps = len(selected_emps)
                            qtd_regras = len(base_rules)
                            ok = f"Campanha cadastrada com sucesso: {qtd_regras} regra(s) aplicada(s) em {qtd_emps} EMP(s), total de {len(payloads)} cadastro(s)."

                    elif acao == "editar":
                        cid = _get_campaign_id_from_form(request.form)
                        c = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                        if not c:
                            app.logger.warning("Campanha QTD não encontrada para editar cid=%s form=%s", cid, dict(request.form))
                            raise ValueError(f"Campanha não encontrada para o ID {cid}.")
                        payload = _parse_campaign_payload(request.form, current_obj=c)
                        dup = _find_duplicate_campaign(db, payload, exclude_id=cid)
                        if dup:
                            raise ValueError(_format_duplicate_message([(payload.get("emp"), dup)]))
                        _apply_campaign_payload(c, payload)
                        db.commit()
                        ok = "Campanha atualizada com sucesso."

                    elif acao == "duplicar":
                        cid = _get_campaign_id_from_form(request.form)
                        c = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                        if not c:
                            app.logger.warning("Campanha QTD não encontrada para duplicar cid=%s form=%s", cid, dict(request.form))
                            raise ValueError(f"Campanha não encontrada para o ID {cid}.")

                        clone_title = (request.form.get("titulo") or "").strip()
                        if not clone_title:
                            base_title = c.titulo or f"Campanha #{c.id}"
                            clone_title = f"Cópia — {base_title}"[:120]

                        data_inicio_raw = (request.form.get("data_inicio") or "").strip()
                        data_fim_raw = (request.form.get("data_fim") or "").strip()
                        data_inicio = datetime.strptime(data_inicio_raw, "%Y-%m-%d").date() if data_inicio_raw else c.data_inicio
                        data_fim = datetime.strptime(data_fim_raw, "%Y-%m-%d").date() if data_fim_raw else c.data_fim
                        if data_fim < data_inicio:
                            raise ValueError("Data fim não pode ser menor que data início.")

                        payload = {
                            "emp": c.emp,
                            "campanha_tipo": c.campanha_tipo or "VENDEDOR",
                            "vendedor": None if (c.campanha_tipo or "VENDEDOR") == "GERENTE" else c.vendedor,
                            "titulo": clone_title,
                            "produto_prefixo": c.produto_prefixo,
                            "descricao_prefixo": c.descricao_prefixo,
                            "campo_match": c.campo_match or "codigo",
                            "marca": c.marca,
                            "recompensa_unit": c.recompensa_unit or 0,
                            "qtd_minima": c.qtd_minima,
                            "valor_minimo": c.valor_minimo,
                            "data_inicio": data_inicio,
                            "data_fim": data_fim,
                        }
                        if hasattr(CampanhaQtd, "faturamento_minimo_emp"):
                            payload["faturamento_minimo_emp"] = getattr(c, "faturamento_minimo_emp", None)

                        dup = _find_duplicate_campaign(db, payload)
                        if dup:
                            raise ValueError(_format_duplicate_message([(payload.get("emp"), dup)]))

                        # Segurança: cópia nasce inativa para evitar pagamento/cálculo duplicado sem revisão.
                        db.add(CampanhaQtd(**payload, ativo=0))
                        db.commit()
                        ok = "Campanha duplicada como inativa. Revise e ative quando estiver correta."

                    elif acao == "toggle":
                        cid = _get_campaign_id_from_form(request.form)
                        c = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                        if not c:
                            app.logger.warning("Campanha QTD não encontrada para toggle cid=%s form=%s", cid, dict(request.form))
                            raise ValueError(f"Campanha não encontrada para o ID {cid}.")
                        c.ativo = 0 if int(c.ativo or 0) == 1 else 1
                        if hasattr(c, "updated_at"):
                            c.updated_at = datetime.utcnow()
                        db.commit()
                        ok = "Status da campanha atualizado."

                    elif acao == "remover":
                        cid = _get_campaign_id_from_form(request.form)
                        c = db.query(CampanhaQtd).filter(CampanhaQtd.id == cid).first()
                        if not c:
                            app.logger.warning("Campanha QTD não encontrada para remover cid=%s form=%s", cid, dict(request.form))
                            raise ValueError(f"Campanha não encontrada para o ID {cid}.")

                        # Remove também o histórico/snapshot mensal dessa campanha.
                        db.query(CampanhaQtdResultado).filter(CampanhaQtdResultado.campanha_id == cid).delete(synchronize_session=False)

                        db.delete(c)
                        db.commit()
                        ok = "Campanha removida."

                    elif acao == "pagar":
                        rid = int(request.form.get("resultado_id") or 0)
                        r = db.query(CampanhaQtdResultado).filter(CampanhaQtdResultado.id == rid).first()
                        if not r:
                            raise ValueError("Resultado não encontrado.")
                        if (r.status_pagamento or "PENDENTE") == "PAGO":
                            r.status_pagamento = "PENDENTE"
                            r.pago_em = None
                        else:
                            r.status_pagamento = "PAGO"
                            r.pago_em = datetime.utcnow()
                        if hasattr(r, "updated_at"):
                            r.updated_at = datetime.utcnow()
                        db.commit()
                        ok = "Status de pagamento atualizado."

                    else:
                        raise ValueError("Ação inválida.")

                except Exception as e:
                    db.rollback()
                    erro = str(e)
                    app.logger.exception("Erro ao gerenciar campanhas")

            campanhas_total_geral = 0
            try:
                campanhas_total_geral = db.query(func.count(CampanhaQtd.id)).scalar() or 0
            except Exception:
                campanhas_total_geral = 0

            campanhas_query = db.query(CampanhaQtd)
            if lista_escopo == "periodo":
                campanhas_query = campanhas_query.filter(
                    CampanhaQtd.data_inicio <= periodo_fim,
                    CampanhaQtd.data_fim >= periodo_inicio,
                )

            campanhas = campanhas_query.order_by(CampanhaQtd.emp.asc(), CampanhaQtd.data_inicio.desc()).all()
            resultados = (
                db.query(CampanhaQtdResultado)
                .filter(
                    CampanhaQtdResultado.competencia_ano == int(ano),
                    CampanhaQtdResultado.competencia_mes == int(mes),
                )
                .order_by(CampanhaQtdResultado.valor_recompensa.desc())
                .all()
            )

            assisted_options = _load_assisted_options(db)

        campanhas_total_geral = int(campanhas_total_geral or 0)

        # UX: agrupa por competência (mês/ano) na lista.
        try:
            for c in (campanhas or []):
                di = getattr(c, "data_inicio", None)
                if di:
                    setattr(c, "competencia_label", f"{int(di.month):02d}/{int(di.year)}")
                else:
                    setattr(c, "competencia_label", "")
        except Exception:
            pass

        return render_template(
            "admin_campanhas_qtd.html",
            usuario=usuario_logado_fn(),
            campanhas=campanhas,
            resultados=resultados,
            ano=ano,
            mes=mes,
            erro=erro,
            ok=ok,
            assisted_options=assisted_options,
            lista_escopo=lista_escopo,
            periodo_inicio=periodo_inicio,
            periodo_fim=periodo_fim,
            campanhas_total_geral=campanhas_total_geral,
        )

    app.add_url_rule(
        "/admin/campanhas",
        endpoint="admin_campanhas_qtd",
        view_func=admin_campanhas_qtd,
        methods=["GET", "POST"],
    )
