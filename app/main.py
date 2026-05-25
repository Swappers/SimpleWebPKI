from __future__ import annotations

import asyncio
import logging
import secrets
import shutil
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
import segno

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
DISPLAY_TZ = timezone(timedelta(hours=2))

I18N = {
    "fr": {
        "nav_enroll": "Enrôlement",
        "nav_admin": "Administration",
        "nav_logout": "Déconnexion",
        "nav_language": "English",
        "index_kicker": "PKI client mTLS self-hosted",
        "index_title": "SimpleWebPKI",
        "index_lead": "Générez et distribuez des certificats client mTLS depuis votre LAN ou VPN, avec un flux public pensé pour iPhone.",
        "index_cta_enroll": "Démarrer l’enrôlement",
        "index_cta_admin": "Ouvrir l’administration",
        "index_card1_title": "Usage simple",
        "index_card1_body": "Créez un certificat client, téléchargez les formats utiles, puis installez le .p12 sur iPhone, macOS, Windows ou Android.",
        "index_card2_title": "Temporaire et propre",
        "index_card2_body": "Les fichiers sensibles vivent uniquement dans un répertoire temporaire et expirent automatiquement après 10 minutes.",
        "index_card3_title": "Administration",
        "index_card3_body": "Surveillez l’inventaire, exportez en CSV et marquez les certificats comme révoqués dans SQLite.",
        "index_notice_label": "Accès",
        "index_notice": "L’enrôlement est public, l’administration reste réservée au compte admin.",
        "login_eyebrow": "Accès administrateur",
        "login_title": "Connexion admin",
        "login_lead": "Cette page sert uniquement à l’administration. Pour générer un certificat, allez directement sur",
        "login_username": "Nom d’utilisateur",
        "login_password": "Mot de passe",
        "login_submit": "Se connecter",
        "login_nav_hint": "Administration",
        "enroll_eyebrow": "Enrôlement",
        "enroll_title": "Générer un certificat client",
        "enroll_lead": "Remplissez le formulaire depuis votre iPhone ou votre ordinateur. Le lien de téléchargement expire rapidement.",
        "enroll_warning": "Le fichier .p12 contient une clé privée. Ne le partagez pas. Le lien expire rapidement.",
        "enroll_username": "Nom d’utilisateur",
        "enroll_device_name": "Nom de l’appareil",
        "enroll_device_type": "Type d’appareil",
        "enroll_duration": "Durée du certificat",
        "enroll_p12_password": "Mot de passe du .p12 (optionnel)",
        "enroll_p12_placeholder": "Laisser vide pour ne pas en définir",
        "enroll_submit": "Générer le certificat",
        "download_eyebrow": "Téléchargements prêts",
        "download_lead": "Le certificat a été généré. Les liens expirent à {expires}.",
        "download_warning": "Le fichier .p12 contient une clé privée. Ne le partagez pas. Le lien expire rapidement.",
        "download_qr_title": "Partager via QR code",
        "download_qr_desc": "Scannez ce QR code pour ouvrir directement le lien de téléchargement du .p12 sur un autre appareil.",
        "download_qr_button": "Télécharger .p12",
        "download_crt": "Télécharger .crt",
        "download_key": "Télécharger .key",
        "download_pem": "Télécharger .pem",
        "download_ca": "Télécharger CA .crt",
        "download_iphone_title": "Installation iPhone",
        "download_step1": "Téléchargez le fichier .p12.",
        "download_step2": "Ouvrez le fichier depuis Safari ou Fichiers.",
        "download_step3": "Allez dans Réglages > Profil téléchargé.",
        "download_step4": "Installez le profil.",
        "download_step5": "Entrez le mot de passe du .p12 si vous en avez défini un.",
        "download_step6": "Testez ensuite le domaine protégé.",
        "download_summary_title": "Résumé",
        "download_summary_cn": "CN",
        "download_summary_type": "Type",
        "download_summary_expiration": "Expiration des liens",
        "admin_eyebrow": "Administration",
        "admin_title": "Inventaire des certificats",
        "admin_ca_loaded": "CA chargée",
        "admin_ca_cert": "Chemin CA cert",
        "admin_ca_key": "Chemin CA key",
        "admin_pushover": "Pushover",
        "admin_export": "Exporter CSV",
        "admin_device": "Appareil",
        "admin_serial": "Numéro de série",
        "admin_fingerprint": "Empreinte SHA256",
        "admin_issued": "Émis",
        "admin_expires": "Expire",
        "admin_downloaded": "Téléchargé",
        "admin_revoked": "Révoqué",
        "admin_source_ip": "IP source",
        "admin_user_agent": "Agent utilisateur",
        "admin_revoke": "Mark revoked",
        "admin_empty": "Aucun certificat généré pour le moment.",
        "admin_status_revoked": "Révoqué",
        "admin_status_downloaded": "Téléchargé",
        "admin_status_pending": "En attente",
        "admin_not_configured": "Non configuré",
        "admin_configured": "Configuré",
        "common_yes": "Oui",
        "common_no": "Non",
        "validation_csrf": "CSRF invalide",
        "validation_username": "{field} invalide. Lettres, chiffres, tirets et underscores uniquement.",
        "validation_device_type": "Type d'appareil invalide",
        "validation_duration": "Durée non autorisée",
        "validation_duration_limit": "Durée supérieure à la limite autorisée",
        "validation_password": "Le mot de passe du .p12 doit contenir au moins 12 caractères, ou être laissé vide",
        "flash_login_ok": "Connexion administrateur réussie.",
        "flash_login_fail": "Identifiants invalides.",
        "flash_logout_ok": "Déconnexion effectuée.",
        "flash_revoke_ok": "Certificat {cn} marqué comme révoqué.",
        "revoke_notification_title": "Certificat mTLS révoqué",
        "revoke_notification_template": (
            "User: {username}\n"
            "Device: {device_name}\n"
            "Type: {device_type}\n"
            "CN: {common_name}\n"
            "Serial: {serial_number}\n"
            "Revoked At: {revoked_at}\n"
            "Source IP: {source_ip}"
        ),
        "flash_rate_limit": "Trop de tentatives. Réessayez plus tard.",
        "download_ttl_label": "UTC+2",
    },
    "en": {
        "nav_enroll": "Enroll",
        "nav_admin": "Admin",
        "nav_logout": "Logout",
        "nav_language": "Français",
        "index_kicker": "Self-hosted mTLS client PKI",
        "index_title": "SimpleWebPKI",
        "index_lead": "Generate and distribute mTLS client certificates from your LAN or VPN, with a public flow designed for iPhone.",
        "index_cta_enroll": "Start enrollment",
        "index_cta_admin": "Open administration",
        "index_card1_title": "Simple workflow",
        "index_card1_body": "Create a client certificate, download the useful formats, then install the .p12 on iPhone, macOS, Windows, or Android.",
        "index_card2_title": "Temporary and clean",
        "index_card2_body": "Sensitive files live only in a temporary directory and expire automatically after 10 minutes.",
        "index_card3_title": "Administration",
        "index_card3_body": "Monitor the inventory, export CSV, and mark certificates as revoked in SQLite.",
        "index_notice_label": "Access",
        "index_notice": "Enrollment is public, administration remains reserved for the admin account.",
        "login_eyebrow": "Administrator access",
        "login_title": "Admin login",
        "login_lead": "This page is only for administration. To generate a certificate, go directly to",
        "login_username": "Username",
        "login_password": "Password",
        "login_submit": "Sign in",
        "login_nav_hint": "Administration",
        "enroll_eyebrow": "Enrollment",
        "enroll_title": "Generate a client certificate",
        "enroll_lead": "Fill out the form from your iPhone or computer. The download link expires quickly.",
        "enroll_warning": "The .p12 file contains a private key. Do not share it. The link expires quickly.",
        "enroll_username": "Username",
        "enroll_device_name": "Device name",
        "enroll_device_type": "Device type",
        "enroll_duration": "Certificate duration",
        "enroll_p12_password": "P12 password (optional)",
        "enroll_p12_placeholder": "Leave blank for no password",
        "enroll_submit": "Generate certificate",
        "download_eyebrow": "Downloads ready",
        "download_lead": "The certificate has been generated. Links expire at {expires}.",
        "download_warning": "The .p12 file contains a private key. Do not share it. The link expires quickly.",
        "download_qr_title": "Share via QR code",
        "download_qr_desc": "Scan this QR code to open the .p12 download link directly on another device.",
        "download_qr_button": "Download .p12",
        "download_crt": "Download .crt",
        "download_key": "Download .key",
        "download_pem": "Download .pem",
        "download_ca": "Download CA .crt",
        "download_iphone_title": "iPhone setup",
        "download_step1": "Download the .p12 file.",
        "download_step2": "Open the file from Safari or Files.",
        "download_step3": "Go to Settings > Profile Downloaded.",
        "download_step4": "Install the profile.",
        "download_step5": "Enter the .p12 password if you set one.",
        "download_step6": "Then test the protected domain.",
        "download_summary_title": "Summary",
        "download_summary_cn": "CN",
        "download_summary_type": "Type",
        "download_summary_expiration": "Link expiration",
        "admin_eyebrow": "Administration",
        "admin_title": "Certificate inventory",
        "admin_ca_loaded": "CA loaded",
        "admin_ca_cert": "CA cert path",
        "admin_ca_key": "CA key path",
        "admin_pushover": "Pushover",
        "admin_export": "Export CSV",
        "admin_device": "Device",
        "admin_serial": "Serial",
        "admin_fingerprint": "SHA256 fingerprint",
        "admin_issued": "Issued",
        "admin_expires": "Expires",
        "admin_downloaded": "Downloaded",
        "admin_revoked": "Revoked",
        "admin_source_ip": "Source IP",
        "admin_user_agent": "User agent",
        "admin_revoke": "Mark revoked",
        "admin_empty": "No certificates have been generated yet.",
        "admin_status_revoked": "Revoked",
        "admin_status_downloaded": "Downloaded",
        "admin_status_pending": "Pending",
        "admin_not_configured": "Not configured",
        "admin_configured": "Configured",
        "common_yes": "Yes",
        "common_no": "No",
        "validation_csrf": "Invalid CSRF token",
        "validation_username": "Invalid {field}. Letters, digits, hyphens and underscores only.",
        "validation_device_type": "Invalid device type",
        "validation_duration": "Duration not allowed",
        "validation_duration_limit": "Duration exceeds the allowed limit",
        "validation_password": "The .p12 password must be at least 12 characters, or left blank",
        "flash_login_ok": "Admin login successful.",
        "flash_login_fail": "Invalid credentials.",
        "flash_logout_ok": "Logged out.",
        "flash_revoke_ok": "Certificate {cn} marked as revoked.",
        "revoke_notification_title": "mTLS certificate revoked",
        "revoke_notification_template": (
            "User: {username}\n"
            "Device: {device_name}\n"
            "Type: {device_type}\n"
            "CN: {common_name}\n"
            "Serial: {serial_number}\n"
            "Revoked At: {revoked_at}\n"
            "Source IP: {source_ip}"
        ),
        "flash_rate_limit": "Too many attempts. Please try again later.",
        "download_ttl_label": "UTC+2",
    },
}


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
    return dt.astimezone(DISPLAY_TZ).strftime("%Y-%m-%d %H:%M UTC+2")


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


def get_lang(request: Request) -> str:
    lang = request.query_params.get("lang")
    if lang in {"en", "fr"}:
        request.session["lang"] = lang
        return lang
    session_lang = request.session.get("lang")
    if session_lang in {"en", "fr"}:
        return session_lang
    return "fr"


def ui_for(lang: str) -> dict[str, str]:
    return I18N.get(lang, I18N["fr"])


def duration_label(days: int, lang: str) -> str:
    if lang == "en":
        if days == 365:
            return "1 year"
        if days == 365 * 5:
            return "5 years"
        if days == 365 * 10:
            return "10 years"
        return f"{days} days"
    if days == 365:
        return "1 an"
    if days == 365 * 5:
        return "5 ans"
    if days == 365 * 10:
        return "10 ans"
    return f"{days} jours"


def lang_url(path: str, lang: str) -> str:
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}lang={lang}"


def _make_qr_svg(data: str) -> str:
    qr = segno.make(data, error="m")
    buffer = BytesIO()
    qr.save(buffer, kind="svg", xmldecl=False, svgns=True, scale=6, border=3)
    return buffer.getvalue().decode("utf-8")


def _duration_options() -> list[int]:
    return [90, 180, 365, 365 * 5, 365 * 10]


def _flash(request: Request, message: str, category: str = "info") -> None:
    flashes = request.session.setdefault("flashes", [])
    flashes.append({"message": message, "category": category})
    request.session["flashes"] = flashes


def _flash_key(request: Request, key: str, category: str = "info", **kwargs: object) -> None:
    lang = get_lang(request)
    message = ui_for(lang)[key].format(**kwargs)
    _flash(request, message, category)


def _pop_flashes(request: Request) -> list[dict[str, str]]:
    flashes = request.session.pop("flashes", [])
    return flashes if isinstance(flashes, list) else []


def _base_context(request: Request) -> dict[str, object]:
    lang = get_lang(request)
    ui = ui_for(lang)
    csrf = ensure_csrf_token(request)
    return {
        "request": request,
        "lang": lang,
        "ui": ui,
        "csrf_token": csrf,
        "is_admin": is_admin(request),
        "flashes": _pop_flashes(request),
        "app_name": request.app.state.settings.app_name,
        "lang_switch": "en" if lang == "fr" else "fr",
        "lang_url": lang_url,
        "duration_label": duration_label,
        "switch_lang_url": str(request.url.include_query_params(lang="en" if lang == "fr" else "fr")),
    }


TEMPLATES.env.filters["dtformat"] = _dt_format


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
        https_only=False,
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
        lang = get_lang(request)
        validate_csrf(request, csrf_token, lang)
        next_url = _safe_next(next_path)
        admin_password = request.app.state.settings.admin_password or "admin"
        if username.strip() != "admin" or password != admin_password:
            _flash_key(request, "flash_login_fail", "error")
            return _redirect(lang_url("/login?next=" + next_url, lang))
        request.session.clear()
        ensure_csrf_token(request)
        request.session["is_admin"] = True
        request.session["lang"] = lang
        _flash_key(request, "flash_login_ok", "success")
        return _redirect(lang_url(next_url, lang))

    @app.post("/logout")
    async def logout_post(request: Request, csrf_token: str = Form(...)):
        lang = get_lang(request)
        validate_csrf(request, csrf_token, lang)
        request.session.clear()
        request.session["lang"] = lang
        _flash_key(request, "flash_logout_ok", "success")
        return _redirect(lang_url("/", lang))

    @app.get("/enroll", response_class=HTMLResponse)
    async def enroll_page(request: Request):
        return TEMPLATES.TemplateResponse(
            "enroll.html",
            {
                **_base_context(request),
                "duration_options": _duration_options(),
                "device_types": [
                    ("iphone", "iPhone"),
                    ("android", "Android"),
                    ("macos", "macOS"),
                    ("windows", "Windows"),
                    ("linux", "Linux"),
                    ("other", "Other" if get_lang(request) == "en" else "Autre"),
                ],
                "defaults": {
                    "username": "",
                    "device_name": "",
                    "device_type": "iphone",
                    "certificate_duration_days": "365",
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
    ):
        lang = get_lang(request)
        validate_csrf(request, csrf_token, lang)

        source_ip = get_client_ip(request)
        rate = request.app.state.rate_limiter.allow(source_ip)
        if not rate.allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=ui_for(lang)["flash_rate_limit"],
                headers={"Retry-After": str(rate.retry_after_seconds or 60)},
            )

        errors: list[str] = []
        try:
            username_clean = validate_identifier(username, "username", lang)
            device_name_clean = validate_identifier(device_name, "device_name", lang)
            device_type_clean = validate_device_type(device_type, lang)
            duration_days = validate_duration(certificate_duration_days, request.app.state.settings.cert_max_days, lang)
            password_clean = validate_p12_password(p12_password, lang)
        except HTTPException as exc:
            errors.append(str(exc.detail))
            return TEMPLATES.TemplateResponse(
                "enroll.html",
                {
                    **_base_context(request),
                    "errors": errors,
                    "duration_options": _duration_options(),
                    "device_types": [
                        ("iphone", "iPhone"),
                        ("android", "Android"),
                        ("macos", "macOS"),
                        ("windows", "Windows"),
                        ("linux", "Linux"),
                        ("other", "Other" if lang == "en" else "Autre"),
                    ],
                    "defaults": {
                        "username": username,
                        "device_name": device_name,
                        "device_type": device_type,
                        "certificate_duration_days": certificate_duration_days or "365",
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
        p12_download_url = lang_url(str(request.url_for("download_file", token=download_token, fmt="p12")), lang)
        p12_qr_svg = _make_qr_svg(p12_download_url)
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
                "p12_download_url": p12_download_url,
                "p12_qr_svg": p12_qr_svg,
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
        lang = get_lang(request)
        if not is_admin(request):
            return _redirect(lang_url("/login?next=/admin", lang))
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
    async def revoke_certificate(
        request: Request,
        background_tasks: BackgroundTasks,
        cert_id: int,
        csrf_token: str = Form(...),
    ):
        lang = get_lang(request)
        require_admin(request, lang)
        validate_csrf(request, csrf_token, lang)
        cert = request.app.state.db.get_by_id(cert_id)
        if not cert:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        revoked_at = utcnow()
        request.app.state.db.mark_revoked(cert_id, revoked_at)
        background_tasks.add_task(
            send_notification,
            enabled=request.app.state.settings.pushover_enabled,
            user_key=request.app.state.settings.pushover_user_key,
            api_token=request.app.state.settings.pushover_api_token,
            title=ui_for(lang)["revoke_notification_title"],
            message=ui_for(lang)["revoke_notification_template"].format(
                username=cert.username,
                device_name=cert.device_name,
                device_type=cert.device_type,
                common_name=cert.common_name,
                serial_number=cert.serial_number,
                revoked_at=_dt_format(isoformat(revoked_at)),
                source_ip=cert.source_ip,
            ),
        )
        _flash_key(request, "flash_revoke_ok", "success", cn=cert.common_name)
        return _redirect(lang_url("/admin", lang))

    @app.get("/admin/export.csv")
    async def export_csv(request: Request):
        lang = get_lang(request)
        require_admin(request, lang)
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
