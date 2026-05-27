from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import Settings


logger = logging.getLogger("simplewebpki.pki")


class PKIError(RuntimeError):
    pass


@dataclass
class GeneratedArtifacts:
    token: str
    temp_dir: Path
    client_crt: Path
    client_key: Path
    client_pem: Path
    ca_crt: Path
    client_p12: Path
    serial_number: str
    fingerprint_sha256: str
    issued_at: datetime
    expires_at: datetime
    common_name: str


class PKIManager:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.ca_cert_path = settings.ca_cert_path
        self.ca_key_path = settings.ca_key_path

    def _run(self, args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        try:
            proc = subprocess.run(
                args,
                cwd=str(cwd) if cwd else None,
                check=True,
                capture_output=True,
                text=True,
            )
            return proc
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else "unknown error"
            raise PKIError(f"OpenSSL a échoué: {stderr}") from exc

    def ensure_ca(self) -> None:
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            return
        if not self.settings.generate_self_signed_ca:
            raise PKIError(
                f"CA manquante: {self.ca_cert_path} / {self.ca_key_path}. "
                "Refus de démarrer hors mode dev."
            )

        dev_ca_dir = self.settings.data_dir / "dev-ca"
        dev_ca_dir.mkdir(parents=True, exist_ok=True)
        self.ca_cert_path = dev_ca_dir / "ca.crt"
        self.ca_key_path = dev_ca_dir / "ca.key"
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            return

        ca_name = self.settings.self_signed_ca_name or "SimpleWebPKI CA"
        ca_org = self.settings.self_signed_ca_org or "SimpleWebPKI"
        logger.warning("GENERATE_SELF_SIGNED_CA activé: génération d'une CA locale dans %s", dev_ca_dir)
        self._run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:4096",
                "-sha256",
                "-days",
                "3650",
                "-nodes",
                "-addext",
                "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-addext",
                "subjectKeyIdentifier=hash",
                "-subj",
                f"/CN={ca_name}/O={ca_org}",
                "-keyout",
                str(self.ca_key_path),
                "-out",
                str(self.ca_cert_path),
            ]
        )
        os.chmod(self.ca_key_path, 0o600)

    def _ensure_temp_dir(self, token: str) -> Path:
        temp_dir = self.settings.temp_root / token
        temp_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(temp_dir, 0o700)
        return temp_dir

    def generate_certificate(
        self,
        *,
        token: str,
        username: str,
        device_name: str,
        common_name: str,
        device_type: str,
        duration_days: int,
        p12_password: str,
    ) -> GeneratedArtifacts:
        self.ensure_ca()
        temp_dir = self._ensure_temp_dir(token)
        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + timedelta(days=duration_days)

        client_key = temp_dir / "client.key"
        client_csr = temp_dir / "client.csr"
        client_crt = temp_dir / "client.crt"
        client_pem = temp_dir / "client-fullchain.pem"
        ca_crt = temp_dir / "ca.crt"
        client_p12 = temp_dir / "client.p12"
        p12_password_file = temp_dir / "p12.pass"
        ext_file = temp_dir / "client.ext"

        try:
            self._run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:4096",
                    "-out",
                    str(client_key),
                ]
            )
            os.chmod(client_key, 0o600)

            self._run(
                [
                    "openssl",
                    "req",
                    "-new",
                    "-key",
                    str(client_key),
                    "-subj",
                    f"/CN={common_name}",
                    "-out",
                    str(client_csr),
                ]
            )

            ext_file.write_text(
                "\n".join(
                    [
                        "[v3_req]",
                        "basicConstraints=CA:FALSE",
                        "keyUsage=critical,digitalSignature,keyEncipherment",
                        "extendedKeyUsage=clientAuth",
                        "subjectKeyIdentifier=hash",
                        "authorityKeyIdentifier=keyid,issuer",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            self._run(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    str(client_csr),
                    "-CA",
                    str(self.ca_cert_path),
                    "-CAkey",
                    str(self.ca_key_path),
                    "-CAcreateserial",
                    "-out",
                    str(client_crt),
                    "-days",
                    str(duration_days),
                    "-sha256",
                    "-extfile",
                    str(ext_file),
                    "-extensions",
                    "v3_req",
                ]
            )

            shutil.copy2(self.ca_cert_path, ca_crt)
            client_pem.write_text(client_crt.read_text(encoding="utf-8") + ca_crt.read_text(encoding="utf-8"), encoding="utf-8")

            pkcs12_cmd = [
                "openssl",
                "pkcs12",
                "-export",
                "-name",
                f"SimpleWebPKI {common_name}",
                "-caname",
                "SimpleWebPKI Root CA",
                "-inkey",
                str(client_key),
                "-in",
                str(client_crt),
                "-certfile",
                str(ca_crt),
                "-out",
                str(client_p12),
            ]
            if p12_password:
                p12_password_file.write_text(p12_password, encoding="utf-8")
                os.chmod(p12_password_file, 0o600)
                pkcs12_cmd.extend(["-passout", f"file:{p12_password_file}"])
            else:
                pkcs12_cmd.extend(["-passout", "pass:"])

            self._run(pkcs12_cmd)
            os.chmod(client_p12, 0o600)
            p12_password_file.unlink(missing_ok=True)

            self._run(
                [
                    "openssl",
                    "verify",
                    "-CAfile",
                    str(self.ca_cert_path),
                    str(client_crt),
                ]
            )

            meta = self._run(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(client_crt),
                    "-noout",
                    "-serial",
                    "-fingerprint",
                    "-sha256",
                ]
            )
            serial_number = ""
            fingerprint = ""
            for line in meta.stdout.splitlines():
                if line.startswith("serial="):
                    serial_number = line.split("=", 1)[1].strip().upper()
                elif "Fingerprint=" in line:
                    fingerprint = line.split("=", 1)[1].strip().replace(":", "").upper()
            if not serial_number or not fingerprint:
                raise PKIError("Impossible de lire le numéro de série ou l'empreinte du certificat")

            return GeneratedArtifacts(
                token=token,
                temp_dir=temp_dir,
                client_crt=client_crt,
                client_key=client_key,
                client_pem=client_pem,
                ca_crt=ca_crt,
                client_p12=client_p12,
                serial_number=serial_number,
                fingerprint_sha256=fingerprint,
                issued_at=issued_at,
                expires_at=expires_at,
                common_name=common_name,
            )
        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    def cleanup_expired_artifacts(self, records: list[dict[str, str]], *, now: datetime | None = None) -> None:
        current = now or datetime.now(timezone.utc)
        for record in records:
            expires = datetime.fromisoformat(record["download_expires_at"])
            temp_dir = Path(record["temp_dir"])
            if expires <= current:
                shutil.rmtree(temp_dir, ignore_errors=True)
                continue
            if record.get("downloaded_at"):
                # Keep the bundle alive until the TTL expires so the user can still fetch the remaining formats.
                continue
            if not temp_dir.exists():
                continue
