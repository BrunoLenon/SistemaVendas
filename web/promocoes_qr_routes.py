from __future__ import annotations

import secrets
import string
import random
from datetime import date, datetime
from urllib.parse import quote_plus

from flask import flash, redirect, render_template, request, url_for
from sqlalchemy import text

from admin_config_routes import _read_upload, _store_branding_upload, _ALLOWED_LOGO_EXT, _MAX_LOGO_UPLOAD_BYTES
from auth_helpers import _admin_required
from db import SessionLocal

_MAX_LAYOUT_UPLOAD_BYTES = 8_000_000


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
            ativo BOOLEAN NOT NULL DEFAULT TRUE,
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
            criado_em TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """))
    db.execute(text("CREATE INDEX IF NOT EXISTS ix_promocoes_qr_codigos_campanha ON promocoes_qr_codigos(campanha_id);"))
    # Migração leve/idempotente para instalações que já criaram a tabela antes desta versão.
    db.execute(text("ALTER TABLE promocoes_qr_codigos ADD COLUMN IF NOT EXISTS premiado BOOLEAN NOT NULL DEFAULT FALSE;"))
    db.execute(text("ALTER TABLE promocoes_qr_codigos ADD COLUMN IF NOT EXISTS premio_descricao VARCHAR(220);"))
    db.execute(text("ALTER TABLE promocoes_qr_codigos ADD COLUMN IF NOT EXISTS premio_valor NUMERIC(12,2);"))
    db.execute(text("ALTER TABLE promocoes_qr_codigos ADD COLUMN IF NOT EXISTS mensagem_resultado TEXT;
    db.execute(text("ALTER TABLE promocoes_qr_codigos ADD COLUMN IF NOT EXISTS whatsapp_resgate VARCHAR(30);"))
    db.execute(text("ALTER TABLE promocoes_qr_codigos ADD COLUMN IF NOT EXISTS mensagem_whatsapp TEXT;"))"))
    db.execute(text("CREATE INDEX IF NOT EXISTS ix_promocoes_qr_codigos_usado ON promocoes_qr_codigos(usado);"))
    db.execute(text("CREATE INDEX IF NOT EXISTS ix_promocoes_qr_codigos_premiado ON promocoes_qr_codigos(premiado);"))


def _slugify(value: str) -> str:
    value = (value or '').strip().lower()
    repl = str.maketrans('áàãâäéèêëíìîïóòõôöúùûüçñ', 'aaaaaeeeeiiiiooooouuuucn')
    value = value.translate(repl)
    out = []
    last_dash = False
    for ch in value:
        if ch.isalnum():
            out.append(ch); last_dash = False
        elif not last_dash:
            out.append('-'); last_dash = True
    return ''.join(out).strip('-')[:80] or 'promocao'


def _parse_bool(v: str | None) -> bool:
    return (v or '').strip().lower() in {'1','on','true','sim','ativo','yes'}


def _parse_date(value: str | None):
    value = (value or '').strip()
    if not value:
        return None
    return datetime.fromisoformat(value).date()


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


def register_promocoes_qr_routes(app):
    @app.route('/admin/promocoes-qr', methods=['GET', 'POST'], endpoint='admin_promocoes_qr')
    def admin_promocoes_qr():
        red = _admin_required()
        if red:
            return red

        with SessionLocal() as db:
            _ensure_schema(db)
            msgs: list[str] = []

            if request.method == 'POST':
                acao = (request.form.get('acao') or '').strip()
                try:
                    if acao in {'salvar_campanha', 'nova_campanha'}:
                        campanha_id = request.form.get('campanha_id')
                        nome = (request.form.get('nome') or '').strip()
                        if not nome:
                            raise ValueError('Informe o nome da campanha.')
                        slug = _slugify(request.form.get('slug') or nome)
                        logo_url = (request.form.get('logo_url_atual') or '').strip()
                        layout_url = (request.form.get('layout_url_atual') or '').strip()

                        logo = _read_upload(request.files.get('logo'), label='Logo da campanha', max_bytes=_MAX_LOGO_UPLOAD_BYTES, allowed_ext=_ALLOWED_LOGO_EXT)
                        layout = _read_upload(request.files.get('layout'), label='Imagem/layout de fundo', max_bytes=_MAX_LAYOUT_UPLOAD_BYTES, allowed_ext=_ALLOWED_LOGO_EXT)
                        if logo:
                            logo_url, _ = _store_branding_upload(logo, folder='promocoes-qr/logos')
                        if layout:
                            layout_url, _ = _store_branding_upload(layout, folder='promocoes-qr/layouts')

                        params = {
                            'slug': slug,
                            'nome': nome,
                            'titulo': (request.form.get('titulo') or '').strip(),
                            'subtitulo': (request.form.get('subtitulo') or '').strip(),
                            'premio': (request.form.get('premio') or '').strip(),
                            'regulamento': (request.form.get('regulamento') or '').strip(),
                            'logo_url': logo_url,
                            'layout_url': layout_url,
                            'cor_primaria': (request.form.get('cor_primaria') or '#ff8c00').strip(),
                            'cor_secundaria': (request.form.get('cor_secundaria') or '#111111').strip(),
                            'inicio_em': _parse_date(request.form.get('inicio_em')),
                            'fim_em': _parse_date(request.form.get('fim_em')),
                            'ativo': _parse_bool(request.form.get('ativo')),
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
                            msgs.append('Campanha atualizada com sucesso.')
                        else:
                            row = db.execute(text("""
                                INSERT INTO promocoes_qr_campanhas
                                    (slug,nome,titulo,subtitulo,premio,regulamento,logo_url,layout_url,cor_primaria,cor_secundaria,inicio_em,fim_em,ativo)
                                VALUES
                                    (:slug,:nome,:titulo,:subtitulo,:premio,:regulamento,:logo_url,:layout_url,:cor_primaria,:cor_secundaria,:inicio_em,:fim_em,:ativo)
                                RETURNING id
                            """), params).first()
                            campanha_id = row[0]
                            msgs.append('Campanha criada com sucesso.')
                        db.commit()
                        return redirect(url_for('admin_promocoes_qr', campanha_id=campanha_id))

                    elif acao == 'gerar_codigos':
                        campanha_id = int(request.form.get('campanha_id') or 0)
                        qtd = max(1, min(int(request.form.get('quantidade') or 1), 500))
                        prefixo = request.form.get('prefixo') or ''
                        lote = (request.form.get('lote') or '').strip()
                        info_qr = (request.form.get('info_qr') or '').strip()
                        mensagem_nao_premiado = (request.form.get('mensagem_nao_premiado') or 'Não foi dessa vez, mas não desista!').strip()
                        premios_lote = _parse_premios_lote(request.form.get('premios_lote') or '', qtd, mensagem_nao_premiado)
                        for premio_cfg in premios_lote:
                            for _tentativa in range(8):
                                codigo = _new_code(prefixo)
                                try:
                                    db.execute(text("""
                                        INSERT INTO promocoes_qr_codigos
                                            (campanha_id,codigo,lote,info_qr,premiado,premio_descricao,premio_valor,mensagem_resultado)
                                        VALUES
                                            (:campanha_id,:codigo,:lote,:info_qr,:premiado,:premio_descricao,:premio_valor,:mensagem_resultado)
                                    """), {
                                        'campanha_id': campanha_id,
                                        'codigo': codigo,
                                        'lote': lote,
                                        'info_qr': info_qr,
                                        **premio_cfg,
                                    })
                                    break
                                except Exception:
                                    db.rollback()
                                    _ensure_schema(db)
                            else:
                                raise RuntimeError('Não foi possível gerar código único.')
                        db.commit()
                        return redirect(url_for('admin_promocoes_qr', campanha_id=campanha_id))

                    elif acao == 'excluir_codigo':
                        codigo_id = int(request.form.get('codigo_id') or 0)
                        campanha_id = request.form.get('campanha_id')
                        db.execute(text('DELETE FROM promocoes_qr_codigos WHERE id=:id'), {'id': codigo_id})
                        db.commit()
                        return redirect(url_for('admin_promocoes_qr', campanha_id=campanha_id))

                except Exception as exc:
                    db.rollback()
                    msgs.append(f'Falha ao salvar: {exc}')

            campanhas = db.execute(text("""
                SELECT c.*, 
                       COALESCE(x.total,0) AS total_codigos,
                       COALESCE(x.usados,0) AS codigos_usados
                  FROM promocoes_qr_campanhas c
             LEFT JOIN (
                    SELECT campanha_id, COUNT(*) total, SUM(CASE WHEN usado THEN 1 ELSE 0 END) usados
                      FROM promocoes_qr_codigos GROUP BY campanha_id
                  ) x ON x.campanha_id = c.id
                 ORDER BY c.criado_em DESC, c.id DESC
            """)).mappings().all()

            campanha_id = request.args.get('campanha_id') or (campanhas[0]['id'] if campanhas else None)
            campanha = None
            codigos = []
            if campanha_id:
                campanha = db.execute(text('SELECT * FROM promocoes_qr_campanhas WHERE id=:id'), {'id': int(campanha_id)}).mappings().first()
                if campanha:
                    codigos = db.execute(text("""
                        SELECT * FROM promocoes_qr_codigos
                         WHERE campanha_id=:id
                         ORDER BY criado_em DESC, id DESC
                         LIMIT 200
                    """), {'id': campanha['id']}).mappings().all()

            return render_template(
                'admin_promocoes_qr.html',
                campanhas=campanhas,
                campanha=campanha,
                codigos=codigos,
                msgs=msgs,
                public_url_fn=_public_url,
                qr_img_fn=lambda url: 'https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=' + quote_plus(url),
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
                 WHERE campanha_id=:id {where_extra}
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
                 WHERE c.slug=:slug AND q.codigo=:codigo
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
                         WHERE id=:id AND usado=FALSE
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
