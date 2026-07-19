"""Request-authentication and input helpers shared by both Lambda handlers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any, Mapping


MAX_BODY_BYTES = 64 * 1024
SIGNATURE_TOLERANCE_SECONDS = 300
INCIDENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ROLE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,64}$")


class RequestError(ValueError):
    """Raised when an inbound request cannot be safely processed."""


def normalized_headers(event: Mapping[str, Any]) -> dict[str, str]:
    headers = event.get("headers") or {}
    if not isinstance(headers, Mapping):
        raise RequestError("headers must be an object")
    return {str(key).lower(): str(value) for key, value in headers.items()}


def raw_request_body(event: Mapping[str, Any]) -> bytes:
    body = event.get("body", "")
    if body is None:
        body = ""
    if not isinstance(body, (str, bytes)):
        raise RequestError("body must be text")

    if event.get("isBase64Encoded"):
        try:
            raw = base64.b64decode(body, validate=True)
        except (ValueError, TypeError) as exc:
            raise RequestError("body is not valid base64") from exc
    else:
        raw = body.encode("utf-8") if isinstance(body, str) else body

    if len(raw) > MAX_BODY_BYTES:
        raise RequestError("request body is too large")
    return raw


def _validated_timestamp(value: str, now: int | None = None) -> str:
    try:
        timestamp = int(value)
    except (TypeError, ValueError) as exc:
        raise RequestError("invalid request timestamp") from exc

    current = int(time.time()) if now is None else int(now)
    if abs(current - timestamp) > SIGNATURE_TOLERANCE_SECONDS:
        raise RequestError("request timestamp is outside the replay window")
    return str(timestamp)


def verify_alert_signature(
    raw_body: bytes,
    headers: Mapping[str, str],
    secret: str,
    *,
    now: int | None = None,
) -> None:
    """Verify the Aegis alert HMAC: v1=HMAC(secret, ``v1:timestamp:body``)."""

    timestamp = _validated_timestamp(headers.get("x-aegis-timestamp", ""), now)
    provided = headers.get("x-aegis-signature", "")
    signed = b"v1:" + timestamp.encode("ascii") + b":" + raw_body
    expected = "v1=" + hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, provided):
        raise RequestError("invalid alert signature")


def verify_slack_signature(
    raw_body: bytes,
    headers: Mapping[str, str],
    signing_secret: str,
    *,
    now: int | None = None,
) -> None:
    """Verify Slack's documented ``v0`` request signature and replay window."""

    timestamp = _validated_timestamp(headers.get("x-slack-request-timestamp", ""), now)
    provided = headers.get("x-slack-signature", "")
    signed = b"v0:" + timestamp.encode("ascii") + b":" + raw_body
    expected = "v0=" + hmac.new(
        signing_secret.encode("utf-8"), signed, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, provided):
        raise RequestError("invalid Slack signature")


def parse_allowed_roles(value: str) -> frozenset[str]:
    try:
        roles = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RuntimeError("ALLOWED_TARGET_ROLES must be JSON") from exc

    if not isinstance(roles, list) or not roles:
        raise RuntimeError("ALLOWED_TARGET_ROLES must contain at least one role")
    if any(not isinstance(role, str) or not ROLE_NAME_PATTERN.fullmatch(role) for role in roles):
        raise RuntimeError("ALLOWED_TARGET_ROLES contains an invalid role name")
    return frozenset(roles)


def validate_incident_id(value: Any) -> str:
    if not isinstance(value, str) or not INCIDENT_ID_PATTERN.fullmatch(value):
        raise RequestError("event_id is missing or invalid")
    return value


def validate_short_text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RequestError(f"{field} is missing or invalid")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise RequestError(f"{field} is too long")
    return normalized


def slack_escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
