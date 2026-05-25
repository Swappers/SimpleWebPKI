from __future__ import annotations

import logging
from urllib import parse, request as urllib_request


logger = logging.getLogger("simplewebpki.pushover")


def send_notification(
    *,
    enabled: bool,
    user_key: str,
    api_token: str,
    title: str,
    message: str,
) -> None:
    if not enabled or not user_key or not api_token:
        return

    payload = parse.urlencode(
        {
            "token": api_token,
            "user": user_key,
            "title": title,
            "message": message,
        }
    ).encode("utf-8")
    req = urllib_request.Request(
        "https://api.pushover.net/1/messages.json",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib_request.urlopen(req, timeout=5) as response:
            response.read()
    except Exception as exc:  # pragma: no cover - network errors are environment-dependent
        logger.warning("Pushover notification failed: %s", exc)

