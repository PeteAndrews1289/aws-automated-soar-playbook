"""Authenticated alert intake for the AegisSOAR reference workflow."""

from __future__ import annotations

import datetime as dt
import functools
import hashlib
import json
import os
import urllib.parse
import urllib.request
from typing import Any

try:
    from .security import (
        RequestError,
        normalized_headers,
        parse_allowed_roles,
        raw_request_body,
        slack_escape,
        validate_incident_id,
        validate_short_text,
        verify_alert_signature,
    )
except ImportError:  # Lambda imports the handler as a top-level module.
    from security import (  # type: ignore[no-redef]
        RequestError,
        normalized_headers,
        parse_allowed_roles,
        raw_request_body,
        slack_escape,
        validate_incident_id,
        validate_short_text,
        verify_alert_signature,
    )


ALERT_RECEIVED = "ALERT_RECEIVED"
PENDING_APPROVAL = "PENDING_APPROVAL"
NOTIFICATION_FAILED = "NOTIFICATION_FAILED"


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _boto3():
    import boto3

    return boto3


@functools.lru_cache(maxsize=8)
def _secret_value(secret_arn: str) -> str:
    response = _boto3().client("secretsmanager").get_secret_value(SecretId=secret_arn)
    value = response.get("SecretString")
    if not value:
        raise RuntimeError("configured secret has no SecretString")
    return value


def _incident_table():
    return _boto3().resource("dynamodb").Table(os.environ["INCIDENT_TABLE_NAME"])


def _conditional_check_failed(exc: Exception) -> bool:
    response = getattr(exc, "response", {})
    return response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _parse_alert(raw_body: bytes, allowed_roles: frozenset[str]) -> dict[str, str]:
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RequestError("body must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise RequestError("body must be a JSON object")

    result = payload.get("result")
    if not isinstance(result, dict):
        raise RequestError("result must be an object")

    role = validate_short_text(result.get("iam_role"), "result.iam_role", 64)
    if role not in allowed_roles:
        raise RequestError("target role is not allowlisted")

    return {
        "incident_id": validate_incident_id(payload.get("event_id")),
        "alert_name": validate_short_text(payload.get("search_name"), "search_name", 120),
        "attacker_ip": validate_short_text(result.get("clientip"), "result.clientip", 64),
        "affected_asset": validate_short_text(result.get("host"), "result.host", 160),
        "target_role": role,
    }


def _deterministic_narrative(alert: dict[str, str]) -> str:
    return (
        f"{alert['alert_name']} reported source {alert['attacker_ip']} targeting "
        f"{alert['affected_asset']}. Requested containment of role "
        f"{alert['target_role']} is awaiting analyst approval; this alert alone is not "
        "proof of compromise."
    )


def generate_threat_narrative(alert: dict[str, str]) -> tuple[str, str]:
    """Return an optional model narrative, with a deterministic safe fallback."""

    secret_arn = os.environ.get("OPENAI_API_KEY_SECRET_ARN", "").strip()
    model = os.environ.get("OPENAI_MODEL", "").strip()
    if not secret_arn or not model:
        return _deterministic_narrative(alert), "deterministic"

    try:
        prompt = (
            "Write a concise two-sentence SOC triage summary using only these untrusted "
            "alert fields. Do not declare a compromise as fact. The containment decision "
            "belongs to a human analyst.\n"
            + json.dumps(alert, sort_keys=True)
        )
        request_body = json.dumps(
            {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=request_body,
            headers={
                "Authorization": f"Bearer {_secret_value(secret_arn)}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            result = json.loads(response.read())
        narrative = result["choices"][0]["message"]["content"]
        if not isinstance(narrative, str) or not narrative.strip():
            raise ValueError("model returned an empty narrative")
        return narrative.strip()[:1200], "model"
    except Exception as exc:
        print(json.dumps({"event": "narrative_fallback", "error_type": type(exc).__name__}))
        return _deterministic_narrative(alert), "deterministic_fallback"


def _validated_webhook_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in {"hooks.slack.com", "hooks.slack-gov.com"}:
        raise RuntimeError("Slack webhook secret does not contain an allowed HTTPS URL")
    return url


def send_slack_alert(alert: dict[str, str], narrative: str) -> None:
    webhook_url = _validated_webhook_url(
        _secret_value(os.environ["SLACK_WEBHOOK_URL_SECRET_ARN"])
    )
    incident_id = alert["incident_id"]
    fields = {
        "incident": slack_escape(incident_id),
        "alert": slack_escape(alert["alert_name"]),
        "source": slack_escape(alert["attacker_ip"]),
        "asset": slack_escape(alert["affected_asset"]),
        "role": slack_escape(alert["target_role"]),
        "narrative": slack_escape(narrative),
    }
    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"SOAR review: {fields['alert']}"},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Incident:* `{fields['incident']}`\n*Source:* `{fields['source']}`\n"
                        f"*Asset:* `{fields['asset']}`\n*Allowlisted role:* `{fields['role']}`\n\n"
                        f"*Triage context:*\n{fields['narrative']}"
                    ),
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve role containment"},
                        "style": "primary",
                        "value": incident_id,
                        "action_id": "approve_role_containment",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Mark false positive"},
                        "style": "danger",
                        "value": incident_id,
                        "action_id": "mark_false_positive",
                    },
                ],
            },
        ]
    }
    request = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        if response.status >= 300:
            raise RuntimeError(f"Slack webhook returned HTTP {response.status}")


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    try:
        raw_body = raw_request_body(event)
        headers = normalized_headers(event)
        alert_secret = _secret_value(os.environ["ALERT_WEBHOOK_SECRET_ARN"])
        verify_alert_signature(raw_body, headers, alert_secret)
        allowed_roles = parse_allowed_roles(os.environ["ALLOWED_TARGET_ROLES"])
        alert = _parse_alert(raw_body, allowed_roles)
    except RequestError as exc:
        return _response(401 if "signature" in str(exc) or "timestamp" in str(exc) else 400, {"error": str(exc)})

    narrative = _deterministic_narrative(alert)
    narrative_source = "deterministic"
    payload_sha256 = hashlib.sha256(raw_body).hexdigest()
    now = _utc_now()
    item = {
        "incident_id": alert["incident_id"],
        "external_event_id": alert["incident_id"],
        "payload_sha256": payload_sha256,
        "created_at": now,
        "updated_at": now,
        "alert_name": alert["alert_name"],
        "attacker_ip": alert["attacker_ip"],
        "affected_asset": alert["affected_asset"],
        "target_role": alert["target_role"],
        "narrative": narrative,
        "narrative_source": narrative_source,
        "status": ALERT_RECEIVED,
    }
    table = _incident_table()
    try:
        table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(incident_id)",
        )
    except Exception as exc:
        if not _conditional_check_failed(exc):
            raise
        existing = table.get_item(
            Key={"incident_id": alert["incident_id"]}, ConsistentRead=True
        ).get("Item", {})
        if existing.get("payload_sha256") != payload_sha256:
            return _response(
                409,
                {
                    "error": "event_id already belongs to a different payload",
                    "incident_id": alert["incident_id"],
                },
            )
        return _response(
            200,
            {
                "incident_id": alert["incident_id"],
                "status": existing.get("status", "UNKNOWN"),
                "duplicate": True,
            },
        )

    try:
        narrative, narrative_source = generate_threat_narrative(alert)
        table.update_item(
            Key={"incident_id": alert["incident_id"]},
            UpdateExpression=(
                "SET narrative = :narrative, narrative_source = :source, updated_at = :updated"
            ),
            ConditionExpression="#status = :received",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":narrative": narrative,
                ":source": narrative_source,
                ":updated": _utc_now(),
                ":received": ALERT_RECEIVED,
            },
        )
        send_slack_alert(alert, narrative)
        table.update_item(
            Key={"incident_id": alert["incident_id"]},
            UpdateExpression="SET #status = :pending, updated_at = :updated",
            ConditionExpression="#status = :received",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":pending": PENDING_APPROVAL,
                ":received": ALERT_RECEIVED,
                ":updated": _utc_now(),
            },
        )
    except Exception as exc:
        print(json.dumps({"event": "notification_failed", "error_type": type(exc).__name__}))
        table.update_item(
            Key={"incident_id": alert["incident_id"]},
            UpdateExpression="SET #status = :failed, updated_at = :updated, notification_error_type = :error",
            ConditionExpression="#status = :received",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":failed": NOTIFICATION_FAILED,
                ":received": ALERT_RECEIVED,
                ":updated": _utc_now(),
                ":error": type(exc).__name__[:80],
            },
        )
        return _response(
            502,
            {"incident_id": alert["incident_id"], "status": NOTIFICATION_FAILED},
        )

    return _response(
        202,
        {"incident_id": alert["incident_id"], "status": PENDING_APPROVAL},
    )
