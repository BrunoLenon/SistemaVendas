from __future__ import annotations

import base64
import mimetypes
import os
import re
from datetime import date, datetime
from typing import Iterable

import requests
from flask import render_template, request

from auth_helpers import _admin_required
from branding import _current_branding, _get_setting, _set_setting, clear_branding_cache
from db import BrandingTheme, SessionLocal, Usuario


_ALLOWED_LOGO_EXT = {".png", ".jpg", ".jpeg", ".webp", ".svg"}
_ALLOWED_FAVICON_EXT = {".png", ".ico", ".jpg", ".jpeg", ".webp", ".svg"}
_TRUTHY = {"1", "true", "on", "yes", "y", "sim", "ativo"}
_FALSEY = {"0", "false", "off", "no", "n", "nao", "não", "desativado"}


def _normalize_flag(value: str | None, default: str = "off") -> str:
    v = (value or "").strip().lower()
    if v in _TRUTHY:
        return "on"
    if v in _FALSEY:
        return "off"
    return default


def _storage_credentials() -> tuple[str, str, str]:
    supa_url = (os.getenv("SUPABASE_URL") or "").rstrip("/")
    key = (
        os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        or os.getenv("SUPABASE_SERVICE_KEY")
        or os.getenv("SUPABASE_KEY")
        or os.getenv("SUPABASE_ANON_KEY")
        or ""
    )
    bucket = os.getenv("SUPABASE_STORAGE_BUCKET", "branding")
    return supa_url, key, bucket


def _supabase_storage_upload(filename: str, content: bytes, content_type: str, folder: str) -> str:
    """Faz upload no Supabase Storage e retorna a URL pública esperada.

    Importante: não bloqueamos o salvamento no banco por uma checagem HTTP da URL
    pública logo após o upload. Em produção o Supabase pode levar alguns instantes para
    propagar o arquivo ou a requisição externa da Render pode falhar momentaneamente.
    O problema anterior era: o arquivo subia para o bucket, mas uma validação posterior
    lançava erro e impedia o commit do AppSetting.
    """
    supa_url, key, bucket = _storage_credentials()
    if not supa_url or not key:
        raise RuntimeError("SUPABASE_URL/SUPABASE_KEY não configurados no ambiente.")

    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
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

    return f"{supa_url}/storage/v1/object/public/{bucket}/{path}"


def _to_data_uri(content: bytes, content_type: str) -> str:
    ctype = content_type or "application/octet-stream"
    encoded = base64.b64encode(content).decode("ascii")
    return f"data:{ctype};base64,{encoded}"


def _read_upload(file_obj, *, label: str, max_bytes: int, allowed_ext: Iterable[str]) -> tuple[str, bytes, str] | None:
    if not file_obj or not getattr(file_obj, "filename", ""):
        return None

    filename = str(file_obj.filename or "").strip()
    ext = (os.path.splitext(filename)[1] or "").lower()
    allowed = set(allowed_ext)
    if not ext or ext not in allowed:
        raise ValueError(f"{label}: arquivo inválido. Permitidos: {', '.join(sorted(allowed))}.")

    data = file_obj.read()
    if not data:
        raise ValueError(f"{label}: arquivo vazio.")
    if len(data) > max_bytes:
        limite_mb = max_bytes / 1_000_000
        raise ValueError(f"{label}: arquivo muito grande. Limite: {limite_mb:.1f}MB.")

    ctype = file_obj.mimetype or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    if ext == ".svg" and ctype == "application/octet-stream":
        ctype = "image/svg+xml"
    elif ext == ".ico" and ctype == "application/octet-stream":
        ctype = "image/x-icon"

    if not (ctype.startswith("image/") or ctype in {"image/svg+xml", "image/x-icon"}):
        raise ValueError(f"{label}: o arquivo precisa ser uma imagem válida.")

    return filename, data, ctype


def _store_branding_upload(upload: tuple[str, bytes, str], *, folder: str) -> tuple[str, str]:
    """Salva imagem no Supabase Storage quando possível; usa DB/data URI como fallback.

    Mesmo que a Render esteja configurada para usar storage, não deixamos a tela sem
    salvar a configuração visual. Se o Storage falhar, o fallback em base64 é gravado
    no AppSetting. Para forçar erro em vez de fallback, use BRANDING_UPLOAD_MODE=strict_storage.
    """
    filename, data, ctype = upload
    mode = (os.getenv("BRANDING_UPLOAD_MODE") or "auto").strip().lower()

    if mode in {"storage", "supabase", "auto", "strict_storage"}:
        try:
            return _supabase_storage_upload(filename, data, ctype, folder=folder), "storage"
        except Exception:
            if mode == "strict_storage":
                raise

    return _to_data_uri(data, ctype), "db"




def _verify_saved_settings(db, saved: list[tuple[str, str]]) -> list[str]:
    """Confirma após o commit se os AppSettings foram realmente persistidos."""
    missing: list[str] = []
    if not saved:
        return missing
    try:
        db.expire_all()
        for label, key in saved:
            value = _get_setting(db, key)
            if value is None or str(value).strip() == "":
                missing.append(label)
    except Exception:
        # Não derruba a tela; a operação principal já foi executada.
        return []
    return missing

def _parse_date(value: str | None, label: str) -> date:
    if not value:
        raise ValueError(f"Informe {label}.")
    try:
        return datetime.fromisoformat(value).date()
    except Exception:
        raise ValueError(f"{label} inválida.")


def _maintenance_snapshot(db) -> dict:
    db_mode = _normalize_flag(_get_setting(db, "maintenance_mode", "off"), "off")
    env_raw = (os.getenv("MAINTENANCE_MODE") or "").strip()
    env_mode = _normalize_flag(env_raw, "") if env_raw else ""
    effective = env_mode or db_mode
    return {
        "db_mode": db_mode,
        "env_raw": env_raw,
        "env_mode": env_mode,
        "effective": effective,
        "forced_by_env": bool(env_raw),
    }


def register_admin_config_routes(app):
    """Registra as rotas de /admin/configuracoes sem alterar endpoint."""

    def admin_configuracoes():
        red = _admin_required()
        if red:
            return red

        msgs: list[str] = []
        today_obj = date.today()
        today_iso = today_obj.isoformat()

        with SessionLocal() as db:
            maintenance = _maintenance_snapshot(db)

            if request.method == "POST":
                acao = (request.form.get("acao") or "").strip()

                # Modo manutenção
                if acao in ("toggle_maintenance", "maintenance_on", "maintenance_off"):
                    try:
                        if acao == "maintenance_on":
                            new_val = "on"
                        elif acao == "maintenance_off":
                            new_val = "off"
                        else:
                            new_val = _normalize_flag(request.form.get("maintenance_mode"), "off")

                        _set_setting(db, "maintenance_mode", new_val)
                        db.commit()
                        maintenance = _maintenance_snapshot(db)
                        msgs.append(f"Modo manutenção salvo como {'ativado' if new_val == 'on' else 'desativado'}.")
                        if maintenance["forced_by_env"]:
                            msgs.append("Atenção: a variável MAINTENANCE_MODE da Render está com prioridade sobre o valor salvo no banco.")

                    except Exception as e:
                        db.rollback()
                        msgs.append(f"Falha ao atualizar modo manutenção: {e}")

                # Upload padrão
                elif acao == "upload_default":
                    storage_modes: list[str] = []
                    saved_settings: list[tuple[str, str]] = []
                    try:
                        logo = _read_upload(
                            request.files.get("default_logo"),
                            label="Logo principal",
                            max_bytes=2_000_000,
                            allowed_ext=_ALLOWED_LOGO_EXT,
                        )
                        fav = _read_upload(
                            request.files.get("default_favicon"),
                            label="Favicon",
                            max_bytes=400_000,
                            allowed_ext=_ALLOWED_FAVICON_EXT,
                        )
                        login_logo_left = _read_upload(
                            request.files.get("login_logo_left"),
                            label="Logo do login — lado esquerdo",
                            max_bytes=2_000_000,
                            allowed_ext=_ALLOWED_LOGO_EXT,
                        )
                        login_logo_right = _read_upload(
                            request.files.get("login_logo_right"),
                            label="Logo do login — lado direito",
                            max_bytes=2_000_000,
                            allowed_ext=_ALLOWED_LOGO_EXT,
                        )

                        if not logo and not fav and not login_logo_left and not login_logo_right:
                            raise ValueError("Envie ao menos uma logo e/ou um favicon.")

                        if logo:
                            url, mode = _store_branding_upload(logo, folder="default")
                            storage_modes.append(mode)
                            _set_setting(db, "branding.default_logo_url", url)
                            saved_settings.append(("Logo principal", "branding.default_logo_url"))
                        if fav:
                            url, mode = _store_branding_upload(fav, folder="default")
                            storage_modes.append(mode)
                            _set_setting(db, "branding.default_favicon_url", url)
                            saved_settings.append(("Favicon", "branding.default_favicon_url"))
                        if login_logo_left:
                            url, mode = _store_branding_upload(login_logo_left, folder="login-left")
                            storage_modes.append(mode)
                            _set_setting(db, "branding.login_logo_left_url", url)
                            saved_settings.append(("Logo do login — lado esquerdo", "branding.login_logo_left_url"))
                        if login_logo_right:
                            url, mode = _store_branding_upload(login_logo_right, folder="login-right")
                            storage_modes.append(mode)
                            _set_setting(db, "branding.login_logo_right_url", url)
                            saved_settings.append(("Logo do login — lado direito", "branding.login_logo_right_url"))

                        _set_setting(db, "branding.default_version", datetime.utcnow().isoformat())
                        db.commit()
                        missing = _verify_saved_settings(db, saved_settings)
                        clear_branding_cache()
                        if missing:
                            msgs.append("Atenção: o upload foi processado, mas estes itens não apareceram gravados no banco: " + ", ".join(missing) + ".")
                        elif "db" in storage_modes:
                            msgs.append("Branding salvo com sucesso. Um ou mais arquivos foram gravados direto no banco como fallback seguro.")
                        else:
                            msgs.append("Branding salvo com sucesso no Storage e registrado no banco.")

                    except Exception as e:
                        db.rollback()
                        msgs.append(f"Erro ao salvar branding: {e}")

                # Criar tema sazonal
                elif acao == "create_theme":
                    storage_modes: list[str] = []
                    try:
                        name = (request.form.get("name") or "").strip()
                        if not name:
                            raise ValueError("Informe o nome do tema.")
                        start_date = _parse_date(request.form.get("start_date"), "data início")
                        end_date = _parse_date(request.form.get("end_date"), "data fim")
                        if end_date < start_date:
                            raise ValueError("Data fim precisa ser maior ou igual à data início.")

                        logo = _read_upload(
                            request.files.get("theme_logo"),
                            label="Logo do tema",
                            max_bytes=2_000_000,
                            allowed_ext=_ALLOWED_LOGO_EXT,
                        )
                        fav = _read_upload(
                            request.files.get("theme_favicon"),
                            label="Favicon do tema",
                            max_bytes=400_000,
                            allowed_ext=_ALLOWED_FAVICON_EXT,
                        )
                        logo_url = None
                        fav_url = None
                        if logo:
                            logo_url, mode = _store_branding_upload(logo, folder="themes")
                            storage_modes.append(mode)
                        if fav:
                            fav_url, mode = _store_branding_upload(fav, folder="themes")
                            storage_modes.append(mode)

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
                        clear_branding_cache()
                        if start_date <= today_obj <= end_date:
                            msgs.append("Tema criado com sucesso e já está dentro da vigência atual.")
                        else:
                            msgs.append("Tema criado com sucesso. Ele será aplicado automaticamente dentro da vigência cadastrada.")
                        if "db" in storage_modes:
                            msgs.append("Observação: arquivo do tema salvo no banco como fallback porque o Storage público não respondeu corretamente.")

                    except Exception as e:
                        db.rollback()
                        msgs.append(f"Erro ao criar tema: {e}")

                # Ações em tema existente
                elif acao in {"theme_toggle", "theme_update", "theme_delete"}:
                    try:
                        theme_id = int(request.form.get("theme_id") or "0")
                        t = db.query(BrandingTheme).filter(BrandingTheme.id == theme_id).first()
                        if not t:
                            raise ValueError("Tema não encontrado.")

                        if acao == "theme_toggle":
                            t.is_active = not bool(t.is_active)
                            db.commit()
                            clear_branding_cache()
                            msgs.append("Status do tema atualizado.")

                        elif acao == "theme_update":
                            storage_modes: list[str] = []
                            name = (request.form.get("name") or "").strip()
                            if name:
                                t.name = name
                            if request.form.get("start_date"):
                                t.start_date = _parse_date(request.form.get("start_date"), "data início")
                            if request.form.get("end_date"):
                                t.end_date = _parse_date(request.form.get("end_date"), "data fim")
                            if t.end_date < t.start_date:
                                raise ValueError("Data fim precisa ser maior ou igual à data início.")

                            logo = _read_upload(
                                request.files.get("theme_logo"),
                                label="Logo do tema",
                                max_bytes=2_000_000,
                                allowed_ext=_ALLOWED_LOGO_EXT,
                            )
                            fav = _read_upload(
                                request.files.get("theme_favicon"),
                                label="Favicon do tema",
                                max_bytes=400_000,
                                allowed_ext=_ALLOWED_FAVICON_EXT,
                            )
                            if logo:
                                t.logo_url, mode = _store_branding_upload(logo, folder="themes")
                                storage_modes.append(mode)
                            if fav:
                                t.favicon_url, mode = _store_branding_upload(fav, folder="themes")
                                storage_modes.append(mode)

                            db.commit()
                            clear_branding_cache()
                            msgs.append("Tema atualizado com sucesso.")
                            if "db" in storage_modes:
                                msgs.append("Observação: arquivo do tema salvo no banco como fallback porque o Storage público não respondeu corretamente.")

                        elif acao == "theme_delete":
                            db.delete(t)
                            db.commit()
                            clear_branding_cache()
                            msgs.append("Tema removido.")

                    except Exception as e:
                        db.rollback()
                        msgs.append(f"Erro no tema sazonal: {e}")

                # Compatibilidade: ação antiga eventualmente enviada por formulário legado.
                elif acao == "alterar_emp":
                    try:
                        alvo = (request.form.get("alvo") or "").strip().upper()
                        emp_novo = (request.form.get("emp_novo") or "").strip()
                        if not alvo:
                            raise ValueError("Informe o usuário para alterar EMP.")
                        u = db.query(Usuario).filter(Usuario.username == alvo).first()
                        if not u:
                            raise ValueError("Usuário não encontrado.")
                        setattr(u, "emp", str(emp_novo) if emp_novo else None)
                        db.commit()
                        msgs.append(f"EMP do usuário {alvo} {'atualizada para ' + emp_novo if emp_novo else 'removida'}.")
                    except Exception as e:
                        db.rollback()
                        msgs.append(f"Erro: {e}")

            # Dados para tela
            maintenance = _maintenance_snapshot(db)
            branding = _current_branding(db)
            default_logo = _get_setting(db, "branding.default_logo_url")
            default_favicon = _get_setting(db, "branding.default_favicon_url")
            login_logo_left = _get_setting(db, "branding.login_logo_left_url")
            login_logo_right = _get_setting(db, "branding.login_logo_right_url")
            themes = db.query(BrandingTheme).order_by(BrandingTheme.start_date.desc(), BrandingTheme.id.desc()).all()
            active_theme_id = branding.get("theme_id") if isinstance(branding, dict) else None
            storage_url, storage_key, storage_bucket = _storage_credentials()

        return render_template(
            "admin_configuracoes.html",
            msgs=msgs,
            branding=branding,
            default_logo=default_logo,
            default_favicon=default_favicon,
            login_logo_left=login_logo_left,
            login_logo_right=login_logo_right,
            themes=themes,
            today=today_iso,
            active_theme_id=active_theme_id,
            maintenance_mode=maintenance["effective"],
            maintenance_db_mode=maintenance["db_mode"],
            maintenance_env_mode=maintenance["env_mode"],
            maintenance_env_raw=maintenance["env_raw"],
            maintenance_forced_by_env=maintenance["forced_by_env"],
            storage_configured=bool(storage_url and storage_key),
            storage_bucket=storage_bucket,
        )

    app.add_url_rule(
        "/admin/configuracoes",
        endpoint="admin_configuracoes",
        view_func=admin_configuracoes,
        methods=["GET", "POST"],
    )
