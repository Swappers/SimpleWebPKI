from __future__ import annotations

import hmac
import ipaddress
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque

from fastapi import HTTPException, Request, status


NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
DEVICE_TYPES = {"iphone", "android", "macos", "windows", "linux", "other"}


def ensure_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def validate_csrf(request: Request, token: str | None) -> None:
    expected = request.session.get("csrf_token")
    if not expected or not token or not hmac.compare_digest(expected, token):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CSRF invalide")


def is_admin(request: Request) -> bool:
    return bool(request.session.get("is_admin"))


def require_admin(request: Request) -> None:
    if not is_admin(request):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès refusé")


def validate_identifier(value: str, field_name: str) -> str:
    cleaned = value.strip()
    if not cleaned or len(cleaned) > 64 or not NAME_RE.fullmatch(cleaned):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} invalide. Lettres, chiffres, tirets et underscores uniquement.",
        )
    return cleaned


def validate_device_type(value: str) -> str:
    cleaned = value.strip().lower()
    if cleaned not in DEVICE_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Type d'appareil invalide")
    return cleaned


def validate_duration(days: str, max_days: int) -> int:
    try:
        parsed = int(days)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Durée invalide") from exc
    if parsed not in {90, 180, 365}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Durée non autorisée")
    if parsed > max_days:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Durée supérieure à la limite autorisée")
    return parsed


def validate_p12_password(password: str) -> str:
    if len(password) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le mot de passe du .p12 doit contenir au moins 12 caractères",
        )
    return password


def common_name(username: str, device_name: str) -> str:
    return f"{username}-{device_name}"


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        candidate = forwarded.split(",")[0].strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


@dataclass
class RateLimitResult:
    allowed: bool
    retry_after_seconds: int | None = None


class SimpleRateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._hits: dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> RateLimitResult:
        now = time.time()
        with self._lock:
            hits = self._hits[key]
            while hits and hits[0] <= now - self.window_seconds:
                hits.popleft()
            if len(hits) >= self.max_attempts:
                retry_after = int(max(1, (hits[0] + self.window_seconds) - now))
                return RateLimitResult(allowed=False, retry_after_seconds=retry_after)
            hits.append(now)
            return RateLimitResult(allowed=True)

