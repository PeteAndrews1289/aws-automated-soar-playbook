"""Authenticated Slack decision receiver with truth-preserving containment states."""

from __future__ import annotations

import datetime as dt
import functools
import json
import os
import re
import urllib.parse
from typing import Any

try:
    from .security import (
        RequestError,
        normalized_headers,
        parse_allowed_roles,
        raw_request_body,
        slack_escape,
        validate_incident_id,
        verify_slack_signature,
    )
except ImportError:  # Lambda imports the handler as a top-level module.
    from security import (  # type: ignore[no-redef]
        RequestError,
        normalized_headers,
        parse_allowed_roles,
        raw_request_body,
        slack_escape,
        validate_incident_id,
        verify_slack_signature,
    )


PENDING_APPROVAL = "PENDING_APPROVAL"
CONTAINMENT_IN_PROGRESS = "CONTAINMENT_IN_PROGRESS"
CONTAINED_BY_HUMAN = "CONTAINED_BY_HUMAN"
CONTAINMENT_FAILED = "CONTAINMENT_FAILED"
FALSE_POSITIVE = "FALSE_POSITIVE"
SLACK_USER_ID_PATTERN = re.compile(r"^[A-Z][A-Z0-9]{1,31}$")


class PolicyAttachmentNotVerified(RuntimeError):
    """The expected managed policy was not visible after attachment."""


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _boto3():
    import boto3

    return boto3


@functools.lru_cache(maxsize=4)
def _secret_value(secret_arn: str) -> str:
    response = _boto3().client("secretsmanager").get_secret_value(SecretId=secret_arn)
    value = response.get("SecretString")
    if not value:
        raise RuntimeError("configured secret has no SecretString")
    return value


def _incident_table():
    return _boto3().resource("dynamodb").Table(os.environ["INCIDENT_TABLE_NAME"])


def _iam_client():
    return _boto3().client("iam")


def _conditional_check_failed(exc: Exception) -> bool:
    response = getattr(exc, "response", {})
    return response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


def _aws_error_code(exc: Exception) -> str:
    response = getattr(exc, "response", {})
    code = response.get("Error", {}).get("Code")
    return str(code or type(exc).__name__)[:80]


def _response(status_code: int, body: dict[str, Any] | str) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _parse_slack_payload(raw_body: bytes) -> tuple[dict[str, Any], str, str, str]:
    try:
        form = urllib.parse.parse_qs(
            raw_body.decode("utf-8"), strict_parsing=True, max_num_fields=8
        )
        encoded_payload = form["payload"][0]
        payload = json.loads(encoded_payload)
    except (UnicodeDecodeError, ValueError, KeyError, IndexError, json.JSONDecodeError) as exc:
        raise RequestError("invalid Slack interaction payload") from exc
    if not isinstance(payload, dict):
        raise RequestError("invalid Slack interaction payload")

    actions = payload.get("actions")
    if not isinstance(actions, list) or len(actions) != 1 or not isinstance(actions[0], dict):
        raise RequestError("exactly one Slack action is required")
    action_id = actions[0].get("action_id")
    if action_id not in {"approve_role_containment", "mark_false_positive"}:
        raise RequestError("unsupported Slack action")
    incident_id = validate_incident_id(actions[0].get("value"))

    user = payload.get("user")
    user_id = user.get("id") if isinstance(user, dict) else None
    if not isinstance(user_id, str) or not SLACK_USER_ID_PATTERN.fullmatch(user_id):
        raise RequestError("Slack user ID is missing or invalid")
    return payload, action_id, incident_id, user_id


def _slack_result(original_blocks: Any, text: str) -> dict[str, Any]:
    safe_blocks = original_blocks[:2] if isinstance(original_blocks, list) else []
    safe_blocks.append(
        {"type": "section", "text": {"type": "mrkdwn", "text": text}}
    )
    return {"replace_original": True, "text": text, "blocks": safe_blocks}


def _mark_containment_failed(table: Any, incident_id: str, error_code: str) -> None:
    table.update_item(
        Key={"incident_id": incident_id},
        UpdateExpression=(
            "SET #status = :failed, updated_at = :updated, "
            "containment_error_code = :error"
        ),
        ConditionExpression="#status = :in_progress",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":failed": CONTAINMENT_FAILED,
            ":in_progress": CONTAINMENT_IN_PROGRESS,
            ":updated": _utc_now(),
            ":error": error_code,
        },
    )


def _begin_containment(table: Any, incident_id: str, user_id: str) -> bool:
    try:
        table.update_item(
            Key={"incident_id": incident_id},
            UpdateExpression=(
                "SET #status = :in_progress, updated_at = :updated, "
                "decision_by = :user, decision = :decision"
            ),
            ConditionExpression="#status = :pending",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":in_progress": CONTAINMENT_IN_PROGRESS,
                ":pending": PENDING_APPROVAL,
                ":updated": _utc_now(),
                ":user": user_id,
                ":decision": "APPROVE_CONTAINMENT",
            },
        )
        return True
    except Exception as exc:
        if _conditional_check_failed(exc):
            return False
        raise


def _approve_containment(
    table: Any,
    iam: Any,
    incident: dict[str, Any],
    user_id: str,
    allowed_roles: frozenset[str],
) -> tuple[str, str]:
    incident_id = incident["incident_id"]
    if not _begin_containment(table, incident_id, user_id):
        current = table.get_item(
            Key={"incident_id": incident_id}, ConsistentRead=True
        ).get("Item", {})
        return str(current.get("status", "UNKNOWN")), "This incident was already processed."

    target_role = incident.get("target_role")
    if not isinstance(target_role, str) or target_role not in allowed_roles:
        _mark_containment_failed(table, incident_id, "TargetRoleNotAllowlisted")
        return CONTAINMENT_FAILED, "Containment failed: the stored role is not allowlisted."

    policy_arn = os.environ["QUARANTINE_POLICY_ARN"]
    try:
        iam.attach_role_policy(RoleName=target_role, PolicyArn=policy_arn)
        attached = iam.list_attached_role_policies(RoleName=target_role).get(
            "AttachedPolicies", []
        )
        verified = any(policy.get("PolicyArn") == policy_arn for policy in attached)
        if not verified:
            raise PolicyAttachmentNotVerified()
    except Exception as exc:
        error_code = _aws_error_code(exc)
        print(
            json.dumps(
                {
                    "event": "containment_failed",
                    "incident_id": incident_id,
                    "error_code": error_code,
                }
            )
        )
        _mark_containment_failed(table, incident_id, error_code)
        return (
            CONTAINMENT_FAILED,
            f"Containment failed for `{slack_escape(target_role)}`; no contained state was recorded.",
        )

    table.update_item(
        Key={"incident_id": incident_id},
        UpdateExpression=(
            "SET #status = :contained, updated_at = :updated, "
            "containment_verified_at = :verified, containment_policy_arn = :policy"
        ),
        ConditionExpression="#status = :in_progress",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={
            ":contained": CONTAINED_BY_HUMAN,
            ":in_progress": CONTAINMENT_IN_PROGRESS,
            ":updated": _utc_now(),
            ":verified": _utc_now(),
            ":policy": policy_arn,
        },
    )
    return (
        CONTAINED_BY_HUMAN,
        f"Containment attachment verified for `{slack_escape(target_role)}` by <@{slack_escape(user_id)}>.",
    )


def _mark_false_positive(table: Any, incident_id: str, user_id: str) -> tuple[str, str]:
    try:
        table.update_item(
            Key={"incident_id": incident_id},
            UpdateExpression=(
                "SET #status = :false_positive, updated_at = :updated, "
                "decision_by = :user, decision = :decision"
            ),
            ConditionExpression="#status = :pending",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":false_positive": FALSE_POSITIVE,
                ":pending": PENDING_APPROVAL,
                ":updated": _utc_now(),
                ":user": user_id,
                ":decision": "FALSE_POSITIVE",
            },
        )
        return FALSE_POSITIVE, f"Marked false positive by <@{slack_escape(user_id)}>; no containment attempted."
    except Exception as exc:
        if not _conditional_check_failed(exc):
            raise
        current = table.get_item(
            Key={"incident_id": incident_id}, ConsistentRead=True
        ).get("Item", {})
        return str(current.get("status", "UNKNOWN")), "This incident was already processed."


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    try:
        raw_body = raw_request_body(event)
        headers = normalized_headers(event)
        signing_secret = _secret_value(os.environ["SLACK_SIGNING_SECRET_ARN"])
        verify_slack_signature(raw_body, headers, signing_secret)
        payload, action_id, incident_id, user_id = _parse_slack_payload(raw_body)
        allowed_roles = parse_allowed_roles(os.environ["ALLOWED_TARGET_ROLES"])
    except RequestError as exc:
        return _response(401 if "signature" in str(exc) or "timestamp" in str(exc) else 400, {"error": str(exc)})

    table = _incident_table()
    incident = table.get_item(
        Key={"incident_id": incident_id}, ConsistentRead=True
    ).get("Item")
    if not isinstance(incident, dict):
        return _response(404, {"error": "incident not found"})

    if action_id == "approve_role_containment":
        status, text = _approve_containment(
            table, _iam_client(), incident, user_id, allowed_roles
        )
    else:
        status, text = _mark_false_positive(table, incident_id, user_id)

    print(json.dumps({"event": "decision_processed", "incident_id": incident_id, "status": status}))
    original_blocks = payload.get("message", {}).get("blocks", [])
    return _response(200, _slack_result(original_blocks, text))
