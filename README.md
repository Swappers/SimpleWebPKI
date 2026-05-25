# SimpleWebPKI

SimpleWebPKI is a self-hosted web application for generating and distributing client mTLS certificates. It is designed for LAN/VPN use, with a mobile-first interface that is easy to use from an iPhone.

## Features

- Client certificate generation with RSA 4096-bit keys and `clientAuth` EKU
- Exports:
  - `.p12` for iPhone, macOS, and Windows
  - client `.crt`
  - private `.key`
  - `.pem` bundle containing certificate + CA
  - public `ca.crt`
- SQLite storage for metadata only
- Automatic cleanup of temporary files
- Pushover notifications on every certificate generation
- Admin dashboard for inventory, logical revocation, and CSV export
- CSRF protection and simple rate limiting on `/enroll`
- QR code on the download page for sharing the short-lived `.p12` link
- Built-in French/English UI switcher in the header

## Requirements

- Docker and Docker Compose
- An existing CA mounted into the container, unless running in dev mode
- An `ADMIN_PASSWORD` value
- A `SECRET_KEY` value

## Configuration

Set the values directly in the `environment:` block of `docker-compose.yml`. The file ships with `change-me` placeholders for the required secrets.

Important variables:

- `ADMIN_PASSWORD`: password for the `admin` account
- `SECRET_KEY`: FastAPI session secret
- `DATABASE_URL`: SQLite database URL, default `sqlite:////data/certportal.db`
- `CA_CERT_PATH`: read-only CA certificate path
- `CA_KEY_PATH`: read-only CA private key path
- `CERT_MAX_DAYS`: maximum allowed duration, default `3650`
- `DOWNLOAD_TTL_SECONDS`: lifetime of download links
- `PUSHOVER_ENABLED`: enable or disable Pushover
- `GENERATE_SELF_SIGNED_CA=true`: auto-generate a development CA only if CA files are missing

## Create a Test CA with OpenSSL

Example:

```bash
mkdir -p pki
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -subj "/CN=SimpleWebPKI Test CA/O=SimpleWebPKI" \
  -keyout pki/ca.key \
  -out pki/ca.crt
chmod 600 pki/ca.key
```

Then start the app with `GENERATE_SELF_SIGNED_CA=false` in `docker-compose.yml`.

## Mount an OPNsense CA Export

From OPNsense, export:

- the public CA certificate as `ca.crt`
- the private CA key as `ca.key`

Place them in `./pki/` on the host. The container reads them read-only through:

- `/pki/ca.crt`
- `/pki/ca.key`

If the CA is missing in production, the application refuses to start.

## Start the App

```bash
docker compose up -d
```

The application pulls the image from GitHub Container Registry (`ghcr.io/swappers/simplewebpki:latest`) and listens on `127.0.0.1:8080` by default in this compose setup. If you use SWAG/nginx as a reverse proxy, keep access limited to LAN/VPN only.

## Reverse Proxy with SWAG/nginx

Example nginx block:

```nginx
location /simplewebpki/ {
    proxy_pass http://127.0.0.1:8080/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Best practices:

- restrict access to LAN/VPN IPs
- expose the app only through SWAG/nginx
- keep TLS termination at the proxy

If SWAG runs in Docker too, place both services on a shared Docker network and adjust `proxy_pass` to the service name.

## Import the Public CA into Cloudflare BYOCA

Cloudflare expects the public CA certificate to validate client mTLS certificates.

1. Log in to Cloudflare.
2. Open the mTLS / BYOCA certificate management section.
3. Import `ca.crt`.
4. Keep the private key `ca.key` out of Cloudflare.
5. Use this CA for services protected by mTLS.

## Usage

1. Open `/enroll`.
2. Fill in:
   - `username`
   - `device_name`
   - `device_type`
   - `certificate_duration_days` (`90`, `180`, `365`, `1825`, `3650`)
   - `p12_password` (optional)
3. Download the `.p12` first for iPhone.

The Common Name is generated automatically as:

`username-device_name`

## Install the `.p12` on iPhone

1. Download the `.p12` file from Safari or Files.
2. Open the file.
3. Go to `Settings > Profile Downloaded`.
4. Install the profile.
5. Enter the `.p12` password if you set one.
6. Test access to the protected domain.

Important warning for users:

> The `.p12` file contains a private key. Do not share it. The link expires quickly.

For the smoothest iPhone experience, keep the `.p12` format. Leaving the password empty gives the simplest install flow, while setting one adds transport protection.

## Revocation

The `Mark revoked` button marks the certificate as revoked in SQLite for internal inventory tracking.

## Development

To auto-generate a development CA when the CA is missing:

```bash
export GENERATE_SELF_SIGNED_CA=true
docker compose up -d
```

This option is intended only for demo/dev use.

## Health

The `/healthz` endpoint returns a simple status JSON.
