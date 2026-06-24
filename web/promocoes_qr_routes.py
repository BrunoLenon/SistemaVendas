from __future__ import annotations

import random
import secrets
import string
from datetime import date, datetime
from urllib.parse import quote_plus

from flask import redirect, render_template, request, url_for
from sqlalchemy import bindparam, text

from admin_config_routes import _read_upload, _store_branding_upload, _ALLOWED_LOGO_EXT, _MAX_LOGO_UPLOAD_BYTES
from auth_helpers import _admin_required
from db import SessionLocal

_MAX_LAYOUT_UPLOAD_BYTES = 8_000_000
_MAX_CODIGOS_POR_LOTE = 500
_MAX_LISTAGEM_CODIGOS = 500


# -----------------------------------------------------------------------------
# Schema / helpers
# -----------------------------------------------------------------------------
def _ensure_schema(db) -> None:
    db.execute(text("""
        CREATE TABLE IF NOT EXISTS promocoes_qr_campanhas (
            id SERIAL PRIMARY KEY,
            slug VARCHAR(80) NOT NULL UNIQUE,
            nome VARCHAR(160) NOT NULL,
            titulo VARCHAR(180),
            subtitulo TEXT,
            premio VARCHAR(180),
            regulamento TEXT,
            logo_url TEXT,
            layout_url TEXT,
            cor_primaria VARCHAR(20) NOT NULL DEFAULT '#ff8c00',
            cor_secundaria VARCHAR(20) NOT NULL DEFAULT '#111111',
            inicio_em DATE,
            fim_em DATE,
            ativo BOOLEAN NOT NULL DEFAULT FALSE,
            criado_em TIMESTAMP NOT NULL DEFAULT NOW(),
            atualizado_em TIMESTAMP
        );
    """))
    db.execute(text("""
        CREATE TABLE IF NOT EXISTS promocoes_qr_codigos (
            id SERIAL PRIMARY KEY,
            campanha_id INTEGER NOT NULL REFERENCES promocoes_qr_campanhas(id) ON DELETE CASCADE,
            codigo VARCHAR(80) NOT NULL UNIQUE,
            lote VARCHAR(100),
            info_qr TEXT,
            usado BOOLEAN NOT NULL DEFAULT FALSE,
            usado_em TIMESTAMP,
            nome_cliente VARCHAR(160),
            telefone VARCHAR(40),
            cpf VARCHAR(40),
            observacao TEXT,
            premiado BOOLEAN NOT NULL DEFAULT FALSE,
            premio_descricao VARCHAR(220),
            premio_valor NUMERIC(12,2),
            mensagem_resultado TEXT,
            whatsapp_resgate VARCHAR(30),
            mensagem_whatsapp TEXT,
            criado_em TIMESTAMP NOT NULL DEFAULT NOW(),
            excluido_em TIMESTAMP,
            excluido_motivo TEXT
        );
    """))

    # Migrações idempotentes para instalações existentes.
    db.execute(text("ALTER TABLE promocoes_qr_campanhas ALTER COLUMN ativo SET DEFAULT FALSE;"))

    db.execute(text("ALTER TABLE promocoes_qr_codigos ADD COLUMN IF NOT EXISTS premiado BOOLEAN NOT NULL DEFAULT FALSE;"))
    db.execute(text("ALTER TABLE promocoes_qr_codigos ADD COLUMN IF NOT EXISTS premio_descricao VARCHAR(220);"))
    db.execute(text("ALTER TABLE promocoes_qr_codigos ADD COLUMN IF NOT EXISTS premio_valor NUMERIC(12,2);"))
    db.execute(text("ALTER TABLE promocoes_qr_codigos ADD COLUMN IF NOT EXISTS mensagem_resultado TEXT;"))
    db.execute(text("ALTER TABLE promocoes_qr_codigos ADD COLUMN IF NOT EXISTS whatsapp_resgate VARCHAR(30);"))
    db.execute(text("ALTER TABLE promocoes_qr_codigos ADD COLUMN IF NOT EXISTS mensagem_whatsapp TEXT;"))
    db.execute(text("ALTER TABLE promocoes_qr_codigos ADD COLUMN IF NOT EXISTS excluido_em TIMESTAMP;"))
    db.execute(text("ALTER TABLE promocoes_qr_codigos ADD COLUMN IF NOT EXISTS excluido_motivo TEXT;"))

    db.execute(text("CREATE INDEX IF NOT EXISTS ix_promocoes_qr_codigos_campanha ON promocoes_qr_codigos(campanha_id);"))
    db.execute(text("CREATE INDEX IF NOT EXISTS ix_promocoes_qr_codigos_usado ON promocoes_qr_codigos(usado);"))
    db.execute(text("CREATE INDEX IF NOT EXISTS ix_promocoes_qr_codigos_premiado ON promocoes_qr_codigos(premiado);"))
    db.execute(text("CREATE INDEX IF NOT EXISTS ix_promocoes_qr_codigos_lote ON promocoes_qr_codigos(campanha_id, lote);"))
    db.execute(text("CREATE INDEX IF NOT EXISTS ix_promocoes_qr_codigos_ativos ON promocoes_qr_codigos(campanha_id, usado, premiado) WHERE excluido_em IS NULL;"))


def _slugify(value: str) -> str:
    value = (value or '').strip().lower()
    repl = str.maketrans('áàãâäéèêëíìîïóòõôöúùûüçñ', 'aaaaaeeeeiiiiooooouuuucn')
    value = value.translate(repl)
    out: list[str] = []
    last_dash = False
    for ch in value:
        if ch.isalnum():
            out.append(ch)
            last_dash = False
        elif not last_dash:
            out.append('-')
            last_dash = True
    return ''.join(out).strip('-')[:80] or 'promocao'


def _parse_bool(v: str | None) -> bool:
    return (v or '').strip().lower() in {'1', 'on', 'true', 'sim', 'ativo', 'yes'}


def _only_digits(value: str | None) -> str:
    return ''.join(ch for ch in (value or '') if ch.isdigit())


def _parse_date(value: str | None):
    value = (value or '').strip()
    if not value:
        return None
    return datetime.fromisoformat(value).date()


def _validate_campanha_periodo(*, ativo: bool, inicio_em, fim_em) -> None:
    """Validação defensiva para evitar ativar campanha vencida.

    A campanha pode ser cadastrada como rascunho sem datas. Para ficar ativa,
    exige data final válida e não vencida. Isso evita o caso operacional de
    reativar/copiar uma campanha antiga com validade vencida.
    """
    hoje = date.today()
    if inicio_em and fim_em and inicio_em > fim_em:
        raise ValueError('A data de início não pode ser maior que a data final da campanha.')
    if ativo:
        if not fim_em:
            raise ValueError('Para ativar a campanha, informe a data final/validade.')
        if fim_em < hoje:
            raise ValueError('Não é permitido ativar campanha com data final vencida.')




def _campanha_status(row) -> dict:
    """Retorna status operacional seguro para exibição no admin."""
    hoje = date.today()
    ativo = bool(row.get('ativo')) if hasattr(row, 'get') else bool(row['ativo'])
    inicio_em = row.get('inicio_em') if hasattr(row, 'get') else row['inicio_em']
    fim_em = row.get('fim_em') if hasattr(row, 'get') else row['fim_em']

    if fim_em and fim_em < hoje:
        return {'key': 'expirada', 'label': 'Expirada', 'chip': 'qr-chip-danger'}
    if inicio_em and inicio_em > hoje:
        return {'key': 'agendada', 'label': 'Agendada', 'chip': 'qr-chip-warn'}
    if ativo:
        return {'key': 'ativa', 'label': 'Ativa', 'chip': 'qr-chip-ok'}
    return {'key': 'rascunho', 'label': 'Rascunho', 'chip': 'qr-chip-warn'}


def _normalize_hex_color(value: str | None, fallback: str) -> str:
    value = (value or '').strip()
    if not value:
        return fallback
    if not value.startswith('#'):
        value = '#' + value
    if len(value) not in (4, 7):
        return fallback
    valid = set('0123456789abcdefABCDEF')
    if any(ch not in valid for ch in value[1:]):
        return fallback
    return value


def _validate_slug_available(db, slug: str, campanha_id: int | None = None) -> None:
    if campanha_id:
        row = db.execute(text("""
            SELECT id, nome
              FROM promocoes_qr_campanhas
             WHERE slug=:slug
               AND id <> :id
             LIMIT 1
        """), {'slug': slug, 'id': campanha_id}).mappings().first()
    else:
        row = db.execute(text("""
            SELECT id, nome
              FROM promocoes_qr_campanhas
             WHERE slug=:slug
             LIMIT 1
        """), {'slug': slug}).mappings().first()
    if row:
        raise ValueError(f'O slug público "{slug}" já está em uso pela campanha "{row["nome"]}". Informe outro slug.')


def _unique_slug(db, base_slug: str) -> str:
    base_slug = _slugify(base_slug)
    slug = base_slug
    for i in range(2, 200):
        exists = db.execute(text('SELECT 1 FROM promocoes_qr_campanhas WHERE slug=:slug LIMIT 1'), {'slug': slug}).first()
        if not exists:
            return slug
        slug = _slugify(f'{base_slug}-{i}')
    return _slugify(f'{base_slug}-{secrets.token_hex(3)}')

def _new_code(prefix: str = '') -> str:
    alphabet = string.ascii_uppercase + string.digits
    core = ''.join(secrets.choice(alphabet) for _ in range(10))
    prefix = ''.join(ch for ch in (prefix or '').upper() if ch.isalnum())[:8]
    return f"{prefix}{core}" if prefix else core


def _public_url(campanha_slug: str, codigo: str) -> str:
    # Rota curta para ir impressa no QR Code.
    return url_for('promocao_qr_ler', slug=campanha_slug, codigo=codigo, _external=True)


def _parse_premios_lote(raw: str, total: int, mensagem_nao_premiado: str) -> list[dict]:
    """Formato por linha: quantidade|descrição|valor opcional."""
    premios: list[dict] = []
    for line in (raw or '').splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split('|')]
        try:
            qtd = int(parts[0])
        except Exception:
            raise ValueError('Formato de prêmio inválido. Use: quantidade|descrição|valor opcional')
        if qtd <= 0:
            continue
        desc = parts[1] if len(parts) > 1 and parts[1] else 'Prêmio'
        valor = None
        if len(parts) > 2 and parts[2]:
            valor = float(parts[2].replace('.', '').replace(',', '.'))
        for _ in range(qtd):
            premios.append({
                'premiado': True,
                'premio_descricao': desc,
                'premio_valor': valor,
                'mensagem_resultado': f'Parabéns! Você ganhou: {desc}',
            })
    if len(premios) > total:
        raise ValueError('A quantidade de prêmios é maior que a quantidade total de QR Codes.')
    while len(premios) < total:
        premios.append({
            'premiado': False,
            'premio_descricao': None,
            'premio_valor': None,
            'mensagem_resultado': mensagem_nao_premiado or 'Não foi dessa vez, mas não desista!',
        })
    random.SystemRandom().shuffle(premios)
    return premios


def _safe_int_list(values) -> list[int]:
    ids: list[int] = []
    for value in values or []:
        try:
            item = int(value)
        except Exception:
            continue
        if item > 0:
            ids.append(item)
    # Remove duplicados preservando ordem.
    return list(dict.fromkeys(ids))


def _get_codigo_filters(source) -> dict:
    status = (source.get('status') or 'todos').strip().lower()
    if status not in {'todos', 'disponiveis', 'lidos'}:
        status = 'todos'

    premio = (source.get('premio') or 'todos').strip().lower()
    if premio not in {'todos', 'premiados', 'nao_premiados'}:
        premio = 'todos'

    try:
        per_page = int(source.get('per_page') or 200)
    except Exception:
        per_page = 200
    per_page = max(50, min(per_page, _MAX_LISTAGEM_CODIGOS))

    return {
        'status': status,
        'premio': premio,
        'lote': (source.get('lote') or '').strip(),
        'busca': (source.get('busca') or '').strip(),
        'per_page': per_page,
    }


def _codigos_where(campanha_id: int, filters: dict, *, bloquear_lidos: bool = False) -> tuple[str, dict]:
    params = {'campanha_id': campanha_id}
    where = ['campanha_id=:campanha_id', 'excluido_em IS NULL']

    status = filters.get('status') or 'todos'
    if status == 'disponiveis':
        where.append('usado=FALSE')
    elif status == 'lidos':
        where.append('usado=TRUE')

    if bloquear_lidos:
        where.append('usado=FALSE')

    premio = filters.get('premio') or 'todos'
    if premio == 'premiados':
        where.append('premiado=TRUE')
    elif premio == 'nao_premiados':
        where.append('premiado=FALSE')

    lote = (filters.get('lote') or '').strip()
    if lote:
        where.append("COALESCE(lote, '') = :lote")
        params['lote'] = lote

    busca = (filters.get('busca') or '').strip()
    if busca:
        where.append("""
            (
                codigo ILIKE :busca OR
                COALESCE(info_qr, '') ILIKE :busca OR
                COALESCE(nome_cliente, '') ILIKE :busca OR
                COALESCE(telefone, '') ILIKE :busca OR
                COALESCE(premio_descricao, '') ILIKE :busca
            )
        """)
        params['busca'] = f'%{busca}%'

    return ' AND '.join(where), params


def _redirect_admin_qr(campanha_id: int | str | None, *, msg: str = '', source=None):
    args: dict = {}
    if campanha_id:
        args['campanha_id'] = campanha_id
    src = source or request.form
    for key in ('status', 'premio', 'lote', 'busca', 'per_page'):
        value = src.get(key)
        if value not in (None, ''):
            args[key] = value
    if msg:
        args['msg'] = msg[:260]
    return redirect(url_for('admin_promocoes_qr', **args))


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
def register_promocoes_qr_routes(app):
    @app.route('/admin/promocoes-qr', methods=['GET', 'POST'], endpoint='admin_promocoes_qr')
    def admin_promocoes_qr():
        red = _admin_required()
        if red:
            return red

        with SessionLocal() as db:
            _ensure_schema(db)
            msgs: list[str] = []
            if request.args.get('msg'):
                msgs.append(request.args.get('msg'))

            if request.method == 'POST':
                acao = (request.form.get('acao') or '').strip()
                try:
                    if acao in {'salvar_campanha', 'nova_campanha'}:
                        campanha_id = request.form.get('campanha_id')
                        nome = (request.form.get('nome') or '').strip()
                        if not nome:
                            raise ValueError('Informe o nome da campanha.')
                        slug = _slugify(request.form.get('slug') or nome)
                        campanha_id_int = int(campanha_id) if campanha_id else None
                        _validate_slug_available(db, slug, campanha_id_int)
                        logo_url = (request.form.get('logo_url_atual') or '').strip()
                        layout_url = (request.form.get('layout_url_atual') or '').strip()

                        logo = _read_upload(
                            request.files.get('logo'),
                            label='Logo da campanha',
                            max_bytes=_MAX_LOGO_UPLOAD_BYTES,
                            allowed_ext=_ALLOWED_LOGO_EXT,
                        )
                        layout = _read_upload(
                            request.files.get('layout'),
                            label='Imagem/layout de fundo',
                            max_bytes=_MAX_LAYOUT_UPLOAD_BYTES,
                            allowed_ext=_ALLOWED_LOGO_EXT,
                        )
                        if logo:
                            logo_url, _ = _store_branding_upload(logo, folder='promocoes-qr/logos')
                        if layout:
                            layout_url, _ = _store_branding_upload(layout, folder='promocoes-qr/layouts')

                        inicio_em = _parse_date(request.form.get('inicio_em'))
                        fim_em = _parse_date(request.form.get('fim_em'))
                        ativo = _parse_bool(request.form.get('ativo'))
                        _validate_campanha_periodo(ativo=ativo, inicio_em=inicio_em, fim_em=fim_em)

                        params = {
                            'slug': slug,
                            'nome': nome,
                            'titulo': (request.form.get('titulo') or '').strip(),
                            'subtitulo': (request.form.get('subtitulo') or '').strip(),
                            'premio': (request.form.get('premio') or '').strip(),
                            'regulamento': (request.form.get('regulamento') or '').strip(),
                            'logo_url': logo_url,
                            'layout_url': layout_url,
                            'cor_primaria': _normalize_hex_color(request.form.get('cor_primaria'), '#ff8c00'),
                            'cor_secundaria': _normalize_hex_color(request.form.get('cor_secundaria'), '#111111'),
                            'inicio_em': inicio_em,
                            'fim_em': fim_em,
                            'ativo': ativo,
                        }

                        if campanha_id:
                            params['id'] = int(campanha_id)
                            db.execute(text("""
                                UPDATE promocoes_qr_campanhas
                                   SET slug=:slug, nome=:nome, titulo=:titulo, subtitulo=:subtitulo, premio=:premio,
                                       regulamento=:regulamento, logo_url=:logo_url, layout_url=:layout_url,
                                       cor_primaria=:cor_primaria, cor_secundaria=:cor_secundaria,
                                       inicio_em=:inicio_em, fim_em=:fim_em, ativo=:ativo, atualizado_em=NOW()
                                 WHERE id=:id
                            """), params)
                            msg = 'Campanha atualizada com sucesso.'
                        else:
                            row = db.execute(text("""
                                INSERT INTO promocoes_qr_campanhas
                                    (slug,nome,titulo,subtitulo,premio,regulamento,logo_url,layout_url,cor_primaria,cor_secundaria,inicio_em,fim_em,ativo)
                                VALUES
                                    (:slug,:nome,:titulo,:subtitulo,:premio,:regulamento,:logo_url,:layout_url,:cor_primaria,:cor_secundaria,:inicio_em,:fim_em,:ativo)
                                RETURNING id
                            """), params).first()
                            campanha_id = row[0]
                            msg = 'Campanha criada com sucesso.'
                        db.commit()
                        return _redirect_admin_qr(campanha_id, msg=msg)

                    elif acao == 'duplicar_campanha':
                        campanha_id = int(request.form.get('campanha_id') or 0)
                        origem = db.execute(text("""
                            SELECT *
                              FROM promocoes_qr_campanhas
                             WHERE id=:id
                             LIMIT 1
                        """), {'id': campanha_id}).mappings().first()
                        if not origem:
                            raise ValueError('Campanha de origem não localizada para duplicar.')

                        novo_nome = f"{origem['nome']} - cópia"
                        novo_slug = _unique_slug(db, f"{origem['slug']}-copia")
                        row = db.execute(text("""
                            INSERT INTO promocoes_qr_campanhas
                                (slug,nome,titulo,subtitulo,premio,regulamento,logo_url,layout_url,cor_primaria,cor_secundaria,inicio_em,fim_em,ativo)
                            VALUES
                                (:slug,:nome,:titulo,:subtitulo,:premio,:regulamento,:logo_url,:layout_url,:cor_primaria,:cor_secundaria,NULL,NULL,FALSE)
                            RETURNING id
                        """), {
                            'slug': novo_slug,
                            'nome': novo_nome,
                            'titulo': origem.get('titulo') or '',
                            'subtitulo': origem.get('subtitulo') or '',
                            'premio': origem.get('premio') or '',
                            'regulamento': origem.get('regulamento') or '',
                            'logo_url': origem.get('logo_url') or '',
                            'layout_url': origem.get('layout_url') or '',
                            'cor_primaria': origem.get('cor_primaria') or '#ff8c00',
                            'cor_secundaria': origem.get('cor_secundaria') or '#111111',
                        }).first()
                        db.commit()
                        return _redirect_admin_qr(row[0], msg='Campanha duplicada como rascunho. Revise datas e publique quando estiver pronta.')

                    elif acao == 'gerar_codigos':
                        campanha_id = int(request.form.get('campanha_id') or 0)

                        campanha_validacao = db.execute(text('''
                            SELECT ativo, inicio_em, fim_em
                              FROM promocoes_qr_campanhas
                             WHERE id=:id
                             LIMIT 1
                        '''), {'id': campanha_id}).mappings().first()
                        if not campanha_validacao:
                            raise ValueError('Campanha não localizada.')
                        if campanha_validacao.get('inicio_em') and campanha_validacao.get('fim_em') and campanha_validacao['inicio_em'] > campanha_validacao['fim_em']:
                            raise ValueError('A data de início da campanha é maior que a data final. Corrija antes de gerar QR Codes.')
                        if campanha_validacao.get('fim_em') and campanha_validacao['fim_em'] < date.today():
                            raise ValueError('Esta campanha está com validade vencida. Atualize a data antes de gerar novos QR Codes.')

                        quantidade_raw = (request.form.get('quantidade') or '').strip()
                        if not quantidade_raw:
                            raise ValueError('Informe a quantidade de QR Codes que deseja gerar.')
                        qtd = max(1, min(int(quantidade_raw), _MAX_CODIGOS_POR_LOTE))
                        prefixo = request.form.get('prefixo') or ''
                        lote = (request.form.get('lote') or '').strip()
                        info_qr = (request.form.get('info_qr') or '').strip()
                        mensagem_nao_premiado = (request.form.get('mensagem_nao_premiado') or 'Não foi dessa vez, mas não desista!').strip()
                        whatsapp_resgate = _only_digits(request.form.get('whatsapp_resgate'))
                        mensagem_whatsapp = (request.form.get('mensagem_whatsapp') or '').strip()
                        premios_lote = _parse_premios_lote(request.form.get('premios_lote') or '', qtd, mensagem_nao_premiado)
                        for premio_cfg in premios_lote:
                            for _tentativa in range(8):
                                codigo = _new_code(prefixo)
                                try:
                                    db.execute(text("""
                                        INSERT INTO promocoes_qr_codigos
                                            (campanha_id,codigo,lote,info_qr,premiado,premio_descricao,premio_valor,mensagem_resultado,whatsapp_resgate,mensagem_whatsapp)
                                        VALUES
                                            (:campanha_id,:codigo,:lote,:info_qr,:premiado,:premio_descricao,:premio_valor,:mensagem_resultado,:whatsapp_resgate,:mensagem_whatsapp)
                                    """), {
                                        'campanha_id': campanha_id,
                                        'codigo': codigo,
                                        'lote': lote,
                                        'info_qr': info_qr,
                                        'whatsapp_resgate': whatsapp_resgate,
                                        'mensagem_whatsapp': mensagem_whatsapp,
                                        **premio_cfg,
                                    })
                                    break
                                except Exception:
                                    db.rollback()
                                    _ensure_schema(db)
                            else:
                                raise RuntimeError('Não foi possível gerar código único.')
                        db.commit()
                        return _redirect_admin_qr(campanha_id, msg=f'{qtd} QR Codes gerados com sucesso.')

                    elif acao == 'excluir_codigo':
                        codigo_id = int(request.form.get('codigo_id') or 0)
                        campanha_id = request.form.get('campanha_id')
                        result = db.execute(text("""
                            UPDATE promocoes_qr_codigos
                               SET excluido_em=NOW(), excluido_motivo='Exclusão individual pelo admin'
                             WHERE id=:id AND campanha_id=:campanha_id AND excluido_em IS NULL
                        """), {'id': codigo_id, 'campanha_id': int(campanha_id or 0)})
                        db.commit()
                        msg = 'Código excluído.' if getattr(result, 'rowcount', 0) else 'Nenhum código foi excluído.'
                        return _redirect_admin_qr(campanha_id, msg=msg, source=request.form)

                    elif acao == 'excluir_codigos_selecionados':
                        campanha_id = int(request.form.get('campanha_id') or 0)
                        ids = _safe_int_list(request.form.getlist('codigo_ids'))
                        if not ids:
                            raise ValueError('Selecione ao menos um código para excluir.')

                        incluir_lidos = _parse_bool(request.form.get('incluir_lidos'))
                        sql_extra = '' if incluir_lidos else ' AND usado=FALSE'
                        stmt = text(f"""
                            UPDATE promocoes_qr_codigos
                               SET excluido_em=NOW(), excluido_motivo=:motivo
                             WHERE campanha_id=:campanha_id
                               AND id IN :ids
                               AND excluido_em IS NULL
                               {sql_extra}
                        """).bindparams(bindparam('ids', expanding=True))
                        result = db.execute(stmt, {
                            'campanha_id': campanha_id,
                            'ids': ids,
                            'motivo': 'Exclusão em massa de códigos selecionados pelo admin',
                        })
                        db.commit()
                        total = int(getattr(result, 'rowcount', 0) or 0)
                        ignorados = max(0, len(ids) - total)
                        msg = f'{total} código(s) excluído(s).'
                        if ignorados:
                            msg += f' {ignorados} ignorado(s) por já estarem lidos/usados ou inválidos.'
                        return _redirect_admin_qr(campanha_id, msg=msg, source=request.form)

                    elif acao == 'excluir_filtrados':
                        campanha_id = int(request.form.get('campanha_id') or 0)
                        confirmacao = (request.form.get('confirmacao_exclusao') or '').strip().upper()
                        if confirmacao != 'EXCLUIR':
                            raise ValueError('Digite EXCLUIR para confirmar a exclusão em massa filtrada.')

                        incluir_lidos = _parse_bool(request.form.get('incluir_lidos_filtrados'))
                        filters = _get_codigo_filters(request.form)
                        where_sql, params = _codigos_where(campanha_id, filters, bloquear_lidos=not incluir_lidos)
                        result = db.execute(text(f"""
                            UPDATE promocoes_qr_codigos
                               SET excluido_em=NOW(), excluido_motivo=:motivo
                             WHERE {where_sql}
                        """), {
                            **params,
                            'motivo': 'Exclusão em massa por filtro pelo admin',
                        })
                        db.commit()
                        total = int(getattr(result, 'rowcount', 0) or 0)
                        msg = f'{total} código(s) excluído(s) pelos filtros atuais.'
                        if not incluir_lidos:
                            msg += ' Códigos já lidos/usados foram preservados.'
                        return _redirect_admin_qr(campanha_id, msg=msg, source=request.form)

                except Exception as exc:
                    db.rollback()
                    msgs.append(f'Falha ao salvar: {exc}')

            campanhas = db.execute(text("""
                SELECT c.*,
                       COALESCE(x.total,0) AS total_codigos,
                       COALESCE(x.usados,0) AS codigos_usados,
                       COALESCE(x.excluidos,0) AS codigos_excluidos
                  FROM promocoes_qr_campanhas c
             LEFT JOIN (
                    SELECT campanha_id,
                           SUM(CASE WHEN excluido_em IS NULL THEN 1 ELSE 0 END) total,
                           SUM(CASE WHEN excluido_em IS NULL AND usado THEN 1 ELSE 0 END) usados,
                           SUM(CASE WHEN excluido_em IS NOT NULL THEN 1 ELSE 0 END) excluidos
                      FROM promocoes_qr_codigos
                     GROUP BY campanha_id
                  ) x ON x.campanha_id = c.id
                 ORDER BY c.criado_em DESC, c.id DESC
            """)).mappings().all()

            campanhas = [dict(c, **{
                'status_key': _campanha_status(c)['key'],
                'status_label': _campanha_status(c)['label'],
                'status_chip': _campanha_status(c)['chip'],
            }) for c in campanhas]

            criando_nova = (request.args.get('novo') or '').strip().lower() in {'1', 'true', 'sim', 'novo'}
            campanha_id = None if criando_nova else (request.args.get('campanha_id') or (campanhas[0]['id'] if campanhas else None))
            campanha = None
            campanha_status = None
            codigos = []
            lotes = []
            codigo_stats = {
                'total': 0,
                'usados': 0,
                'disponiveis': 0,
                'premiados': 0,
                'nao_premiados': 0,
                'total_lotes': 0,
                'excluidos': 0,
            }
            filtros_codigos = _get_codigo_filters(request.args)
            codigos_filtrados_total = 0

            if campanha_id:
                campanha = db.execute(text('SELECT * FROM promocoes_qr_campanhas WHERE id=:id'), {'id': int(campanha_id)}).mappings().first()
                if campanha:
                    campanha = dict(campanha)
                    campanha_status = _campanha_status(campanha)
                    codigo_stats = db.execute(text("""
                        SELECT
                            COALESCE(SUM(CASE WHEN excluido_em IS NULL THEN 1 ELSE 0 END),0) AS total,
                            COALESCE(SUM(CASE WHEN excluido_em IS NULL AND usado THEN 1 ELSE 0 END),0) AS usados,
                            COALESCE(SUM(CASE WHEN excluido_em IS NULL AND NOT usado THEN 1 ELSE 0 END),0) AS disponiveis,
                            COALESCE(SUM(CASE WHEN excluido_em IS NULL AND premiado THEN 1 ELSE 0 END),0) AS premiados,
                            COALESCE(SUM(CASE WHEN excluido_em IS NULL AND NOT premiado THEN 1 ELSE 0 END),0) AS nao_premiados,
                            COALESCE(COUNT(DISTINCT CASE WHEN excluido_em IS NULL AND COALESCE(lote,'') <> '' THEN lote END),0) AS total_lotes,
                            COALESCE(SUM(CASE WHEN excluido_em IS NOT NULL THEN 1 ELSE 0 END),0) AS excluidos
                          FROM promocoes_qr_codigos
                         WHERE campanha_id=:id
                    """), {'id': campanha['id']}).mappings().first() or codigo_stats

                    lotes = db.execute(text("""
                        SELECT lote, COUNT(*) AS total
                          FROM promocoes_qr_codigos
                         WHERE campanha_id=:id
                           AND excluido_em IS NULL
                           AND COALESCE(lote,'') <> ''
                         GROUP BY lote
                         ORDER BY MAX(criado_em) DESC, lote ASC
                         LIMIT 80
                    """), {'id': campanha['id']}).mappings().all()

                    where_sql, params = _codigos_where(int(campanha['id']), filtros_codigos)
                    codigos_filtrados_total = int((db.execute(text(f"""
                        SELECT COUNT(*) FROM promocoes_qr_codigos WHERE {where_sql}
                    """), params).scalar() or 0))

                    codigos = db.execute(text(f"""
                        SELECT * FROM promocoes_qr_codigos
                         WHERE {where_sql}
                         ORDER BY criado_em DESC, id DESC
                         LIMIT :limit
                    """), {**params, 'limit': filtros_codigos['per_page']}).mappings().all()

            return render_template(
                'admin_promocoes_qr.html',
                campanhas=campanhas,
                campanha=campanha,
                campanha_status=campanha_status,
                criando_nova=criando_nova,
                codigos=codigos,
                lotes=lotes,
                codigo_stats=codigo_stats,
                filtros_codigos=filtros_codigos,
                codigos_filtrados_total=codigos_filtrados_total,
                msgs=msgs,
                public_url_fn=_public_url,
                qr_img_fn=lambda url: 'https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=' + quote_plus(url),
                today_iso=date.today().isoformat(),
                demo_public_url=_public_url(campanha['slug'] if campanha else 'preview', 'PREVIEW123'),
            )

    @app.route('/admin/promocoes-qr/<int:campanha_id>/imprimir', methods=['GET'], endpoint='admin_promocoes_qr_imprimir')
    def admin_promocoes_qr_imprimir(campanha_id: int):
        red = _admin_required()
        if red:
            return red
        with SessionLocal() as db:
            _ensure_schema(db)
            campanha = db.execute(text('SELECT * FROM promocoes_qr_campanhas WHERE id=:id'), {'id': campanha_id}).mappings().first()
            if not campanha:
                return redirect(url_for('admin_promocoes_qr'))
            somente = (request.args.get('somente') or 'todos').strip()
            where_extra = ''
            if somente == 'disponiveis':
                where_extra = ' AND usado=FALSE'
            codigos = db.execute(text(f'''
                SELECT * FROM promocoes_qr_codigos
                 WHERE campanha_id=:id
                   AND excluido_em IS NULL
                   {where_extra}
                 ORDER BY criado_em DESC, id DESC
                 LIMIT 1000
            '''), {'id': campanha_id}).mappings().all()
            return render_template(
                'admin_promocoes_qr_imprimir.html',
                campanha=campanha,
                codigos=codigos,
                public_url_fn=_public_url,
                qr_img_fn=lambda url: 'https://api.qrserver.com/v1/create-qr-code/?size=260x260&data=' + quote_plus(url),
            )

    @app.route('/p/<slug>/<codigo>', methods=['GET', 'POST'], endpoint='promocao_qr_ler')
    def promocao_qr_ler(slug: str, codigo: str):
        with SessionLocal() as db:
            _ensure_schema(db)
            row = db.execute(text("""
                SELECT q.*, c.slug, c.nome, c.titulo, c.subtitulo, c.premio, c.regulamento,
                       c.logo_url, c.layout_url, c.cor_primaria, c.cor_secundaria,
                       c.inicio_em, c.fim_em, c.ativo
                  FROM promocoes_qr_codigos q
                  JOIN promocoes_qr_campanhas c ON c.id = q.campanha_id
                 WHERE c.slug=:slug
                   AND q.codigo=:codigo
                   AND q.excluido_em IS NULL
                 LIMIT 1
            """), {'slug': slug, 'codigo': codigo}).mappings().first()

            status = 'invalido'
            mensagem = 'Código inválido ou não localizado.'
            today = date.today()

            if row:
                expirado = (row['fim_em'] and row['fim_em'] < today) or (row['inicio_em'] and row['inicio_em'] > today) or (not row['ativo'])
                if expirado:
                    status = 'expirado'
                    mensagem = 'Este QR Code está expirado ou a campanha não está ativa.'
                elif row['usado']:
                    status = 'usado'
                    mensagem = 'Este QR Code já foi lido anteriormente.'
                else:
                    upd = db.execute(text("""
                        UPDATE promocoes_qr_codigos
                           SET usado=TRUE, usado_em=NOW()
                         WHERE id=:id AND usado=FALSE AND excluido_em IS NULL
                    """), {'id': row['id']})
                    db.commit()
                    if getattr(upd, 'rowcount', 0) != 1:
                        status = 'usado'
                        mensagem = 'Este QR Code já foi lido anteriormente.'
                    else:
                        status = 'premiado' if row.get('premiado') else 'nao_premiado'
                        mensagem = row.get('mensagem_resultado') or ('Parabéns! Você ganhou!' if row.get('premiado') else 'Não foi dessa vez, mas não desista!')
                        row = dict(row)
                        row['usado'] = True

            return render_template('promocao_qr_resgate.html', item=row, status=status, mensagem=mensagem)
