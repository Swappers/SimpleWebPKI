from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _default_secret_key() -> str:
    return secrets.token_hex(32)


@dataclass
class Settings:
    app_name: str = "SimpleWebPKI"
    admin_password: str = os.getenv("ADMIN_PASSWORD", "").strip()
    secret_key: str = os.getenv("SECRET_KEY", "").strip()
    database_url: str = os.getenv("DATABASE_URL", "sqlite:////data/certportal.db").strip()
    ca_cert_path: Path = Path(os.getenv("CA_CERT_PATH", "/pki/ca.crt")).expanduser()
    ca_key_path: Path = Path(os.getenv("CA_KEY_PATH", "/pki/ca.key")).expanduser()
    cert_max_days: int = _env_int("CERT_MAX_DAYS", 365)
    download_ttl_seconds: int = _env_int("DOWNLOAD_TTL_SECONDS", 600)
    pushover_enabled: bool = _env_bool("PUSHOVER_ENABLED", False)
    pushover_user_key: str = os.getenv("PUSHOVER_USER_KEY", "").strip()
    pushover_api_token: str = os.getenv("PUSHOVER_API_TOKEN", "").strip()
    dev_ca: bool = _env_bool("CERTPORTAL_DEV_CA", False)
    invite_token: str = os.getenv("INVITE_TOKEN", "").strip()
    session_cookie_secure: bool = _env_bool("SESSION_COOKIE_SECURE", False)
    data_dir: Path = Path(os.getenv("DATA_DIR", "/data")).expanduser()
    temp_root: Path = Path(os.getenv("CERT_TEMP_ROOT", "/tmp/certportal")).expanduser()
    enroll_rate_limit_max: int = _env_int("ENROLL_RATE_LIMIT_MAX", 5)
    enroll_rate_limit_window_seconds: int = _env_int("ENROLL_RATE_LIMIT_WINDOW_SECONDS", 600)

    def __post_init__(self) -> None:
        if not self.secret_key:
            self.secret_key = _default_secret_key()
        if self.cert_max_days < 1:
            self.cert_max_days = 365
        if self.download_ttl_seconds < 60:
            self.download_ttl_seconds = 600
        self.temp_root.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    @property
    def ca_loaded(self) -> bool:
        return self.ca_cert_path.exists() and self.ca_key_path.exists()

    @property
    def pushover_configured(self) -> bool:
        return self.pushover_enabled and bool(self.pushover_user_key) and bool(self.pushover_api_token)


def load_settings() -> Settings:
    return Settings()

