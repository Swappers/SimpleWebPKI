from __future__ import annotations

import csv
import io
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


def _sqlite_path(database_url: str) -> Path:
    parsed = urlparse(database_url)
    if parsed.scheme != "sqlite":
        raise ValueError("DATABASE_URL must use sqlite://")
    if database_url.startswith("sqlite:////"):
        return Path(database_url.replace("sqlite:////", "/", 1))
    if database_url.startswith("sqlite:///"):
        return Path(database_url.replace("sqlite:///", "", 1))
    raise ValueError("Unsupported sqlite URL format")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat()


@dataclass
class CertificateRow:
    id: int
    username: str
    device_name: str
    device_type: str
    common_name: str
    serial_number: str
    certificate_fingerprint_sha256: str
    issued_at: str
    expires_at: str
    downloaded_at: str | None
    revoked_at: str | None
    source_ip: str
    user_agent: str
    download_token: str
    temp_dir: str
    download_expires_at: str


class Database:
    def __init__(self, database_url: str) -> None:
        self.path = _sqlite_path(database_url)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    device_name TEXT NOT NULL,
                    device_type TEXT NOT NULL,
                    common_name TEXT NOT NULL,
                    serial_number TEXT NOT NULL,
                    certificate_fingerprint_sha256 TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    downloaded_at TEXT,
                    revoked_at TEXT,
                    source_ip TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    download_token TEXT NOT NULL UNIQUE,
                    temp_dir TEXT NOT NULL,
                    download_expires_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_certificates_common_name ON certificates(common_name);
                CREATE INDEX IF NOT EXISTS idx_certificates_download_expires_at ON certificates(download_expires_at);
                """
            )

    def insert_certificate(self, row: dict[str, object]) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO certificates (
                    username, device_name, device_type, common_name, serial_number,
                    certificate_fingerprint_sha256, issued_at, expires_at, downloaded_at,
                    revoked_at, source_ip, user_agent, download_token, temp_dir, download_expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["username"],
                    row["device_name"],
                    row["device_type"],
                    row["common_name"],
                    row["serial_number"],
                    row["certificate_fingerprint_sha256"],
                    row["issued_at"],
                    row["expires_at"],
                    row.get("downloaded_at"),
                    row.get("revoked_at"),
                    row["source_ip"],
                    row["user_agent"],
                    row["download_token"],
                    row["temp_dir"],
                    row["download_expires_at"],
                ),
            )
            return int(cur.lastrowid)

    def get_by_token(self, token: str) -> CertificateRow | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM certificates WHERE download_token = ?", (token,)).fetchone()
            return CertificateRow(**dict(row)) if row else None

    def get_by_id(self, cert_id: int) -> CertificateRow | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM certificates WHERE id = ?", (cert_id,)).fetchone()
            return CertificateRow(**dict(row)) if row else None

    def list_certificates(self) -> list[CertificateRow]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM certificates ORDER BY issued_at DESC, id DESC").fetchall()
            return [CertificateRow(**dict(row)) for row in rows]

    def mark_downloaded(self, cert_id: int, when: datetime | None = None) -> None:
        timestamp = isoformat(when or utcnow())
        with self._connect() as conn:
            conn.execute(
                "UPDATE certificates SET downloaded_at = COALESCE(downloaded_at, ?) WHERE id = ?",
                (timestamp, cert_id),
            )

    def mark_revoked(self, cert_id: int, when: datetime | None = None) -> None:
        timestamp = isoformat(when or utcnow())
        with self._connect() as conn:
            conn.execute("UPDATE certificates SET revoked_at = ? WHERE id = ?", (timestamp, cert_id))

    def all_for_cleanup(self) -> list[CertificateRow]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM certificates").fetchall()
            return [CertificateRow(**dict(row)) for row in rows]

    def export_csv(self) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "id",
                "username",
                "device_name",
                "device_type",
                "common_name",
                "serial_number",
                "certificate_fingerprint_sha256",
                "issued_at",
                "expires_at",
                "downloaded_at",
                "revoked_at",
                "source_ip",
                "user_agent",
            ]
        )
        for row in self.list_certificates():
            writer.writerow(
                [
                    row.id,
                    row.username,
                    row.device_name,
                    row.device_type,
                    row.common_name,
                    row.serial_number,
                    row.certificate_fingerprint_sha256,
                    row.issued_at,
                    row.expires_at,
                    row.downloaded_at or "",
                    row.revoked_at or "",
                    row.source_ip,
                    row.user_agent,
                ]
            )
        return buffer.getvalue()

