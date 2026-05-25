from __future__ import annotations

import asyncio
import logging
import secrets
import shutil
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .config import load_settings
from .db import Database, isoformat, utcnow
from .pki import PKIError, PKIManager
from .pushover import send_notification
from .security import (
    SimpleRateLimiter,
    common_name,
    ensure_csrf_token,
    get_client_ip,
    is_admin,
    require_admin,
    validate_csrf,
    validate_device_type,
    validate_duration,
    validate_identifier,
    validate_p12_password,
)


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("simplewebpki")


BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))
SETTINGS = load_settings()


def _redirect(location: str) -> RedirectResponse:
    return RedirectResponse(url=location, status_code=status.HTTP_303_SEE_OTHER)


def _safe_next(value: str | None) -> str:
    if value and value.startswith("/") and not value.startswith("//"):
        return value
    return "/admin"


def _dt_format(value: str | None) -> str:
    if not value:
        return "—"
    dt = datetime.fromisoformat(value)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _download_filename(fmt: str) -> str:
    return {
        "p12": "client.p12",
        "crt": "client.crt",
        "key": "client.key",
        "pem": "client-fullchain.pem",
        "ca": "ca.crt",
    }[fmt]


def _download_media_type(fmt: str) -> str:
    return {
        "p12": "application/x-pkcs12",
        "crt": "application/x-x509-ca-cert",
        "key": "application/x-pem-file",
        "pem": "application/x-pem-file",
        "ca": "application/x-x509-ca-cert",
    }[fmt]


def _flash(request: Request, message: str, category: str = "info") -> None:
    flashes = request.session.setdefault("flashes", [])
    flashes.append({"message": message, "category": category})
    request.session["flashes"] = flashes


def _pop_flashes(request: Request) -> list[dict[str, str]]:
    flashes = request.session.pop("flashes", [])
    return flashes if isinstance(flashes, list) else []


def _base_context(request: Request) -> dict[str, object]:
    csrf = ensure_csrf_token(request)
    return {
        "request": request,
        "csrf_token": csrf,
        "is_admin": is_admin(request),
        "flashes": _pop_flashes(request),
        "app_name": request.app.state.settings.app_name,
    }


def _has_invite_access(request: Request) -> bool:
    invite_token = request.query_params.get("token", "") or request.session.get("invite_token", "")
    configured = request.app.state.settings.invite_token
    if not configured:
        return False
    return secrets.compare_digest(invite_token, configured)


def _enroll_access_allowed(request: Request) -> bool:
    return is_admin(request) or _has_invite_access(request)


def _ensure_enroll_access_or_redirect(request: Request) -> RedirectResponse | None:
    if _enroll_access_allowed(request):
        if _has_invite_access(request):
            request.session["invite_token"] = request.query_params.get("token", "")
        return None
    if request.app.state.settings.invite_token:
        return _redirect("/login?next=/enroll")
    return _redirect("/login?next=/enroll")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = SETTINGS
    db = Database(settings.database_url)
    pki = PKIManager(settings)
    rate_limiter = SimpleRateLimiter(settings.enroll_rate_limit_max, settings.enroll_rate_limit_window_seconds)

    app.state.settings = settings
    app.state.db = db
    app.state.pki = pki
    app.state.rate_limiter = rate_limiter
    app.state.cleanup_task = None

    try:
        pki.ensure_ca()
    except PKIError as exc:
        logger.error("%s", exc)
        raise

    db.init_schema()
    await asyncio.to_thread(_initial_cleanup, app)
    app.state.cleanup_task = asyncio.create_task(_cleanup_loop(app))
    try:
        yield
    finally:
        task = app.state.cleanup_task
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


def _initial_cleanup(app: FastAPI) -> None:
    _cleanup_artifacts(app)


def _cleanup_artifacts(app: FastAPI) -> None:
    records = [
        {
            "temp_dir": row.temp_dir,
            "download_expires_at": row.download_expires_at,
            "downloaded_at": row.downloaded_at,
        }
        for row in app.state.db.all_for_cleanup()
    ]
    app.state.pki.cleanup_expired_artifacts(records)
    known_dirs = {Path(row["temp_dir"]).resolve() for row in records}
    for candidate in app.state.settings.temp_root.iterdir():
        if not candidate.is_dir():
            continue
        if candidate.resolve() in known_dirs:
            continue
        shutil.rmtree(candidate, ignore_errors=True)


async def _cleanup_loop(app: FastAPI) -> None:
    while True:
        try:
            await asyncio.sleep(60)
            await asyncio.to_thread(_cleanup_artifacts, app)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Erreur pendant le nettoyage périodique")


def create_app() -> FastAPI:
    app = FastAPI(title="SimpleWebPKI", lifespan=lifespan)
    app.add_middleware(
        SessionMiddleware,
        secret_key=SETTINGS.secret_key,
        same_site="lax",
        https_only=SETTINGS.session_cookie_secure,
        max_age=60 * 60 * 12,
    )
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return TEMPLATES.TemplateResponse(
            "index.html",
            {
                **_base_context(request),
                "invite_enabled": bool(request.app.state.settings.invite_token),
            },
        )

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, next: str | None = None):
        return TEMPLATES.TemplateResponse(
            "login.html",
            {
                **_base_context(request),
                "next_path": _safe_next(next),
            },
        )

    @app.post("/login")
    async def login_post(
        request: Request,
        username: str = Form("admin"),
        password: str = Form(...),
        next_path: str = Form("/admin"),
        csrf_token: str = Form(...),
    ):
        validate_csrf(request, csrf_token)
        next_url = _safe_next(next_path)
        admin_password = request.app.state.settings.admin_password or "admin"
        if username.strip() != "admin" or password != admin_password:
            _flash(request, "Identifiants invalides.", "error")
            return _redirect("/login?next=" + next_url)
        request.session.clear()
        ensure_csrf_token(request)
        request.session["is_admin"] = True
        _flash(request, "Connexion administrateur réussie.", "success")
        return _redirect(next_url)

    @app.post("/logout")
    async def logout_post(request: Request, csrf_token: str = Form(...)):
        validate_csrf(request, csrf_token)
        request.session.clear()
        _flash(request, "Déconnexion effectuée.", "success")
        return _redirect("/")

    @app.get("/enroll", response_class=HTMLResponse)
    async def enroll_page(request: Request):
        redirect = _ensure_enroll_access_or_redirect(request)
        if redirect:
            return redirect
        return TEMPLATES.TemplateResponse(
            "enroll.html",
            {
                **_base_context(request),
                "duration_options": [90, 180, 365],
                "device_types": ["iphone", "android", "macos", "windows", "linux", "other"],
                "invite_token": request.query_params.get("token", "") or request.session.get("invite_token", ""),
                "defaults": {
                    "username": "",
                    "device_name": "",
                    "device_type": "iphone",
                    "certificate_duration_days": "90",
                },
            },
        )

    @app.post("/enroll", response_class=HTMLResponse)
    async def enroll_post(
        request: Request,
        background_tasks: BackgroundTasks,
        username: str = Form(...),
        device_name: str = Form(...),
        device_type: str = Form(...),
        certificate_duration_days: str = Form(...),
        p12_password: str = Form(...),
        csrf_token: str = Form(...),
        invite_token: str = Form(""),
    ):
        validate_csrf(request, csrf_token)
        if not _enroll_access_allowed(request):
            if not request.app.state.settings.invite_token:
                return _redirect("/login?next=/enroll")
            if not secrets.compare_digest(invite_token, request.app.state.settings.invite_token):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invitation invalide")
        elif request.app.state.settings.invite_token and invite_token and not secrets.compare_digest(invite_token, request.app.state.settings.invite_token):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invitation invalide")

        source_ip = get_client_ip(request)
        rate = request.app.state.rate_limiter.allow(source_ip)
        if not rate.allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Trop de tentatives. Réessayez plus tard.",
                headers={"Retry-After": str(rate.retry_after_seconds or 60)},
            )

        errors: list[str] = []
        try:
            username_clean = validate_identifier(username, "username")
            device_name_clean = validate_identifier(device_name, "device_name")
            device_type_clean = validate_device_type(device_type)
            duration_days = validate_duration(certificate_duration_days, request.app.state.settings.cert_max_days)
            password_clean = validate_p12_password(p12_password)
        except HTTPException as exc:
            errors.append(str(exc.detail))
            return TEMPLATES.TemplateResponse(
                "enroll.html",
                {
                    **_base_context(request),
                    "errors": errors,
                    "duration_options": [90, 180, 365],
                    "device_types": ["iphone", "android", "macos", "windows", "linux", "other"],
                    "invite_token": invite_token,
                    "defaults": {
                        "username": username,
                        "device_name": device_name,
                        "device_type": device_type,
                        "certificate_duration_days": certificate_duration_days,
                    },
                },
                status_code=400,
            )

        cn = common_name(username_clean, device_name_clean)
        download_token = secrets.token_urlsafe(32)
        try:
            artifacts = await asyncio.to_thread(
                request.app.state.pki.generate_certificate,
                token=download_token,
                username=username_clean,
                device_name=device_name_clean,
                common_name=cn,
                device_type=device_type_clean,
                duration_days=duration_days,
                p12_password=password_clean,
            )
        except PKIError as exc:
            logger.exception("Échec de génération du certificat pour %s", cn)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

        issued_at = isoformat(artifacts.issued_at)
        expires_at = isoformat(artifacts.expires_at)
        download_expires_at = isoformat(artifacts.issued_at + timedelta(seconds=request.app.state.settings.download_ttl_seconds))
        record_id = request.app.state.db.insert_certificate(
            {
                "username": username_clean,
                "device_name": device_name_clean,
                "device_type": device_type_clean,
                "common_name": cn,
                "serial_number": artifacts.serial_number,
                "certificate_fingerprint_sha256": artifacts.fingerprint_sha256,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "downloaded_at": None,
                "revoked_at": None,
                "source_ip": source_ip,
                "user_agent": request.headers.get("user-agent", "unknown"),
                "download_token": download_token,
                "temp_dir": str(artifacts.temp_dir),
                "download_expires_at": download_expires_at,
            }
        )

        pushover_message = (
            f"User: {username_clean}\n"
            f"Device: {device_name_clean}\n"
            f"Type: {device_type_clean}\n"
            f"CN: {cn}\n"
            f"Serial: {artifacts.serial_number}\n"
            f"Expires: {_dt_format(expires_at)}\n"
            f"Source IP: {source_ip}"
        )
        background_tasks.add_task(
            send_notification,
            enabled=request.app.state.settings.pushover_enabled,
            user_key=request.app.state.settings.pushover_user_key,
            api_token=request.app.state.settings.pushover_api_token,
            title="Nouveau certificat mTLS généré",
            message=pushover_message,
        )

        cert_row = request.app.state.db.get_by_id(record_id)
        return TEMPLATES.TemplateResponse(
            "download.html",
            {
                **_base_context(request),
                "record": cert_row,
                "artifacts": {
                    "p12": _download_filename("p12"),
                    "crt": _download_filename("crt"),
                    "key": _download_filename("key"),
                    "pem": _download_filename("pem"),
                    "ca": _download_filename("ca"),
                },
                "download_token": download_token,
                "download_ttl_seconds": request.app.state.settings.download_ttl_seconds,
                "expires_at_human": _dt_format(download_expires_at),
                "common_name": cn,
                "device_type": device_type_clean,
            },
        )

    @app.get("/download/{token}/{fmt}")
    async def download_file(request: Request, token: str, fmt: str):
        if fmt not in {"p12", "crt", "key", "pem", "ca"}:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        row = request.app.state.db.get_by_token(token)
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

        expires = datetime.fromisoformat(row.download_expires_at)
        if utcnow() > expires:
            shutil.rmtree(Path(row.temp_dir), ignore_errors=True)
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="Le lien a expiré")

        file_map = {
            "p12": Path(row.temp_dir) / "client.p12",
            "crt": Path(row.temp_dir) / "client.crt",
            "key": Path(row.temp_dir) / "client.key",
            "pem": Path(row.temp_dir) / "client-fullchain.pem",
            "ca": Path(row.temp_dir) / "ca.crt",
        }
        file_path = file_map[fmt]
        if not file_path.exists():
            shutil.rmtree(Path(row.temp_dir), ignore_errors=True)
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="Fichier indisponible")

        request.app.state.db.mark_downloaded(row.id)
        return FileResponse(
            path=str(file_path),
            filename=_download_filename(fmt),
            media_type=_download_media_type(fmt),
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/admin", response_class=HTMLResponse)
    async def admin_page(request: Request):
        if not is_admin(request):
            return _redirect("/login?next=/admin")
        records = request.app.state.db.list_certificates()
        return TEMPLATES.TemplateResponse(
            "admin.html",
            {
                **_base_context(request),
                "records": records,
                "settings": request.app.state.settings,
                "ca_cert_path": str(request.app.state.pki.ca_cert_path),
                "ca_key_path": str(request.app.state.pki.ca_key_path),
            },
        )

    @app.post("/admin/certs/{cert_id}/revoke")
    async def revoke_certificate(request: Request, cert_id: int, csrf_token: str = Form(...)):
        require_admin(request)
        validate_csrf(request, csrf_token)
        cert = request.app.state.db.get_by_id(cert_id)
        if not cert:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        request.app.state.db.mark_revoked(cert_id)
        _flash(request, f"Certificat {cert.common_name} marqué comme révoqué.", "success")
        return _redirect("/admin")

    @app.get("/admin/export.csv")
    async def export_csv(request: Request):
        require_admin(request)
        csv_content = request.app.state.db.export_csv()
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="certificates.csv"'},
        )

    @app.get("/healthz")
    async def healthz(request: Request):
        return JSONResponse(
            {
                "status": "ok",
                "ca_loaded": bool(request.app.state.pki.ca_cert_path.exists() and request.app.state.pki.ca_key_path.exists()),
                "database": str(request.app.state.db.path),
            }
        )

    return app


app = create_app()
