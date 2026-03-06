from __future__ import annotations

import os
import re
import mimetypes
from datetime import date, datetime

import requests
from flask import request, render_template

from auth_helpers import _admin_required
from branding import _get_setting, _set_setting, _current_branding
from db import SessionLocal, BrandingTheme, Usuario


def _supabase_storage_upload(filename: str, content: bytes, content_type: str, folder: str) -> str:
    """Faz upload no Supabase Storage e retorna URL pública.
    Requer SUPABASE_URL e uma key (preferencialmente service role).
    """
    supa_url = (os.getenv("SUPABASE_URL") or "").rstrip("/")
    key = (
        os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        or os.getenv("SUPABASE_SERVICE_KEY")
        or os.getenv("SUPABASE_KEY")
        or os.getenv("SUPABASE_ANON_KEY")
        or ""
    )
    if not supa_url or not key:
        raise RuntimeError("SUPABASE_URL/SUPABASE_KEY não configurados no ambiente.")

    bucket = os.getenv("SUPABASE_STORAGE_BUCKET", "branding")
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    path = f"{folder}/{ts}_{safe_name}"
    endpoint = f"{supa_url}/storage/v1/object/{bucket}/{path}"

    headers = {
        "Authorization": f"Bearer {key}",
        "apikey": key,
        "Content-Type": content_type or "application/octet-stream",
        "x-upsert": "true",
    }
    r = requests.put(endpoint, headers=headers, data=content, timeout=30)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Falha upload storage: {r.status_code} {r.text[:200]}")
    public_url = f"{supa_url}/storage/v1/object/public/{bucket}/{path}"
    return public_url


def register_admin_config_routes(app):
    """Registra as rotas de /admin/configuracoes sem alterar endpoints/contratos."""

    def admin_configuracoes():
        red = _admin_required()
        if red:
            return red

        msgs: list[str] = []
        today = date.today()

        with SessionLocal() as db:

            # Modo manutenção (admin-only)
            maintenance_mode = (_get_setting(db, "maintenance_mode", "off") or "off").strip().lower()

            if request.method == "POST":
                acao = (request.form.get("acao") or "").strip()

                if acao in ("toggle_maintenance", "maintenance_on", "maintenance_off"):
                    try:
                        if acao == "maintenance_on":
                            new_val = "on"
                        elif acao == "maintenance_off":
                            new_val = "off"
                        else:
                            # toggle on/off (compatibilidade)
                            new_val = (request.form.get("maintenance_mode") or "").strip().lower()
                            if new_val not in ("on", "off"):
                                new_val = "off"

                        _set_setting(db, "maintenance_mode", new_val)
                        db.commit()
                        maintenance_mode = new_val
                        msgs.append(f"Modo manutenção {'ativado' if new_val == 'on' else 'desativado'}.")

                    except Exception:
                        db.rollback()
                        msgs.append("Falha ao atualizar modo manutenção.")

            # Upload padrão (sempre disponível)
            if request.method == "POST" and (request.form.get("acao") or "") == "upload_default":
                try:
                    logo_file = request.files.get("default_logo")
                    fav_file = request.files.get("default_favicon")

                    def _read_file(f, max_bytes: int, allowed_ext: set[str]):
                        if not f or not getattr(f, "filename", ""):
                            return None
                        filename = f.filename
                        ext = (os.path.splitext(filename)[1] or "").lower()
                        if ext and ext not in allowed_ext:
                            raise ValueError(f"Arquivo inválido ({ext}). Permitidos: {', '.join(sorted(allowed_ext))}")
                        data = f.read()
                        if len(data) > max_bytes:
                            raise ValueError("Arquivo muito grande.")
                        ctype = f.mimetype or mimetypes.guess_type(filename)[0] or "application/octet-stream"
                        return filename, data, ctype

                    logo = _read_file(logo_file, max_bytes=2_000_000, allowed_ext={".png", ".jpg", ".jpeg", ".webp", ".svg"})
                    fav = _read_file(fav_file, max_bytes=400_000, allowed_ext={".png", ".ico", ".jpg", ".jpeg", ".webp", ".svg"})

                    if not logo and not fav:
                        raise ValueError("Envie uma logo e/ou um favicon.")

                    if logo:
                        url = _supabase_storage_upload(logo[0], logo[1], logo[2], folder="default")
                        _set_setting(db, "branding.default_logo_url", url)
                    if fav:
                        url = _supabase_storage_upload(fav[0], fav[1], fav[2], folder="default")
                        _set_setting(db, "branding.default_favicon_url", url)

                    # bump version para cache bust
                    _set_setting(db, "branding.default_version", datetime.utcnow().isoformat())
                    db.commit()
                    msgs.append("Arquivos padrão atualizados com sucesso.")

                except Exception as e:
                    db.rollback()
                    msgs.append(f"Erro ao salvar: {e}")

            # Criar tema sazonal
            if request.method == "POST" and (request.form.get("acao") or "") == "create_theme":
                try:
                    name = (request.form.get("name") or "").strip()
                    sd = request.form.get("start_date")
                    ed = request.form.get("end_date")
                    if not name or not sd or not ed:
                        raise ValueError("Informe nome, data início e data fim.")
                    start_date = datetime.fromisoformat(sd).date()
                    end_date = datetime.fromisoformat(ed).date()
                    if end_date < start_date:
                        raise ValueError("Data fim precisa ser >= data início.")

                    logo_file = request.files.get("theme_logo")
                    fav_file = request.files.get("theme_favicon")
                    logo_url = None
                    fav_url = None
                    if logo_file and logo_file.filename:
                        data = logo_file.read()
                        if len(data) > 2_000_000:
                            raise ValueError("Logo do tema muito grande.")
                        ctype = logo_file.mimetype or mimetypes.guess_type(logo_file.filename)[0] or "application/octet-stream"
                        logo_url = _supabase_storage_upload(logo_file.filename, data, ctype, folder="themes")
                    if fav_file and fav_file.filename:
                        data = fav_file.read()
                        if len(data) > 400_000:
                            raise ValueError("Favicon do tema muito grande.")
                        ctype = fav_file.mimetype or mimetypes.guess_type(fav_file.filename)[0] or "application/octet-stream"
                        fav_url = _supabase_storage_upload(fav_file.filename, data, ctype, folder="themes")

                    t = BrandingTheme(
                        name=name,
                        start_date=start_date,
                        end_date=end_date,
                        logo_url=logo_url,
                        favicon_url=fav_url,
                        is_active=True,
                    )
                    db.add(t)
                    db.commit()
                    msgs.append("Tema criado com sucesso.")

                except Exception as e:
                    db.rollback()
                    msgs.append(f"Erro ao criar tema: {e}")

            # Ações em tema existente
            if request.method == "POST" and (request.form.get("acao") or "").startswith("theme_"):
                try:
                    theme_id = int(request.form.get("theme_id") or "0")
                    t = db.query(BrandingTheme).filter(BrandingTheme.id == theme_id).first()
                    if not t:
                        raise ValueError("Tema não encontrado.")
                    acao = request.form.get("acao")

                    if acao == "theme_toggle":
                        t.is_active = not bool(t.is_active)
                        db.commit()
                        msgs.append("Status do tema atualizado.")

                    elif acao == "theme_update":
                        name = (request.form.get("name") or "").strip()
                        sd = request.form.get("start_date")
                        ed = request.form.get("end_date")
                        if name:
                            t.name = name
                        if sd:
                            t.start_date = datetime.fromisoformat(sd).date()
                        if ed:
                            t.end_date = datetime.fromisoformat(ed).date()
                        if t.end_date < t.start_date:
                            raise ValueError("Data fim precisa ser >= data início.")

                        logo_file = request.files.get("theme_logo")
                        fav_file = request.files.get("theme_favicon")
                        if logo_file and logo_file.filename:
                            data = logo_file.read()
                            if len(data) > 2_000_000:
                                raise ValueError("Logo do tema muito grande.")
                            ctype = logo_file.mimetype or mimetypes.guess_type(logo_file.filename)[0] or "application/octet-stream"
                            t.logo_url = _supabase_storage_upload(logo_file.filename, data, ctype, folder="themes")
                        if fav_file and fav_file.filename:
                            data = fav_file.read()
                            if len(data) > 400_000:
                                raise ValueError("Favicon do tema muito grande.")
                            ctype = fav_file.mimetype or mimetypes.guess_type(fav_file.filename)[0] or "application/octet-stream"
                            t.favicon_url = _supabase_storage_upload(fav_file.filename, data, ctype, folder="themes")

                        db.commit()
                        msgs.append("Tema atualizado com sucesso.")

                    elif acao == "theme_delete":
                        db.delete(t)
                        db.commit()
                        msgs.append("Tema removido.")

                    elif acao == "alterar_emp":
                        # Atualiza o campo EMP "legado/padrão" do usuário (util para supervisor e como EMP padrão para multi-EMP)
                        alvo = (request.form.get("alvo") or "").strip().upper()
                        emp_novo = (request.form.get("emp_novo") or "").strip()
                        if not alvo:
                            raise ValueError("Informe o usuário para alterar EMP.")
                        u = db.query(Usuario).filter(Usuario.username == alvo).first()
                        if not u:
                            raise ValueError("Usuário não encontrado.")
                        # Admin pode alterar EMP de qualquer role (inclusive limpar)
                        if emp_novo == "":
                            setattr(u, "emp", None)
                            db.commit()
                            ok = f"EMP do usuário {alvo} removida."
                        else:
                            setattr(u, "emp", str(emp_novo))
                            db.commit()
                            ok = f"EMP do usuário {alvo} atualizada para {emp_novo}."
                    else:
                        raise ValueError("Ação inválida.")

                except Exception as e:
                    db.rollback()
                    msgs.append(f"Erro: {e}")

            # Dados para tela
            branding = _current_branding(db)
            default_logo = _get_setting(db, "branding.default_logo_url")
            default_favicon = _get_setting(db, "branding.default_favicon_url")
            themes = db.query(BrandingTheme).order_by(BrandingTheme.start_date.desc(), BrandingTheme.id.desc()).all()

        return render_template(
            "admin_configuracoes.html",
            msgs=msgs,
            branding=branding,
            default_logo=default_logo,
            default_favicon=default_favicon,
            themes=themes,
            today=today.isoformat(),
        )

    app.add_url_rule(
        "/admin/configuracoes",
        endpoint="admin_configuracoes",
        view_func=admin_configuracoes,
        methods=["GET", "POST"],
    )
