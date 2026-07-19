import hashlib
import hmac
import json
import os
import time
import unittest
from unittest.mock import patch

from lambda_soar import soar_playbook
from tests.fakes import MemoryTable


ALERT_SECRET = "test-alert-secret"


def signed_event(payload):
    raw = json.dumps(payload, separators=(",", ":"))
    timestamp = str(int(time.time()))
    digest = hmac.new(
        ALERT_SECRET.encode(), f"v1:{timestamp}:{raw}".encode(), hashlib.sha256
    ).hexdigest()
    return {
        "body": raw,
        "headers": {
            "X-Aegis-Timestamp": timestamp,
            "X-Aegis-Signature": f"v1={digest}",
        },
    }


def valid_payload(event_id="evt-001", role="lab-response-role"):
    return {
        "event_id": event_id,
        "search_name": "Suspicious IAM policy change",
        "result": {
            "clientip": "192.0.2.44",
            "host": "lab-workload",
            "iam_role": role,
        },
    }


class AlertIntakeTests(unittest.TestCase):
    def setUp(self):
        soar_playbook._secret_value.cache_clear()
        self.table = MemoryTable()
        self.environment = patch.dict(
            os.environ,
            {
                "INCIDENT_TABLE_NAME": "incidents",
                "ALERT_WEBHOOK_SECRET_ARN": "alert-secret-arn",
                "SLACK_WEBHOOK_URL_SECRET_ARN": "slack-url-arn",
                "ALLOWED_TARGET_ROLES": '["lab-response-role"]',
            },
            clear=True,
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_valid_alert_persists_allowlisted_role_and_waits_for_approval(self):
        with (
            patch.object(soar_playbook, "_incident_table", return_value=self.table),
            patch.object(soar_playbook, "_secret_value", return_value=ALERT_SECRET),
            patch.object(soar_playbook, "send_slack_alert") as send,
        ):
            response = soar_playbook.lambda_handler(signed_event(valid_payload()), None)

        self.assertEqual(response["statusCode"], 202)
        self.assertEqual(self.table.items["evt-001"]["status"], "PENDING_APPROVAL")
        self.assertEqual(self.table.items["evt-001"]["target_role"], "lab-response-role")
        send.assert_called_once()

    def test_replayed_event_is_idempotent_and_does_not_send_again(self):
        event = signed_event(valid_payload())
        with (
            patch.object(soar_playbook, "_incident_table", return_value=self.table),
            patch.object(soar_playbook, "_secret_value", return_value=ALERT_SECRET),
            patch.object(soar_playbook, "send_slack_alert") as send,
        ):
            first = soar_playbook.lambda_handler(event, None)
            second = soar_playbook.lambda_handler(event, None)

        self.assertEqual(first["statusCode"], 202)
        self.assertTrue(json.loads(second["body"])["duplicate"])
        self.assertEqual(send.call_count, 1)

    def test_reused_event_id_with_different_payload_is_rejected(self):
        first_event = signed_event(valid_payload())
        changed_payload = valid_payload()
        changed_payload["search_name"] = "Different alert using the same event ID"
        second_event = signed_event(changed_payload)
        with (
            patch.object(soar_playbook, "_incident_table", return_value=self.table),
            patch.object(soar_playbook, "_secret_value", return_value=ALERT_SECRET),
            patch.object(soar_playbook, "send_slack_alert") as send,
        ):
            soar_playbook.lambda_handler(first_event, None)
            response = soar_playbook.lambda_handler(second_event, None)

        self.assertEqual(response["statusCode"], 409)
        self.assertEqual(send.call_count, 1)

    def test_disallowed_role_is_rejected_before_persistence(self):
        with (
            patch.object(soar_playbook, "_incident_table", return_value=self.table),
            patch.object(soar_playbook, "_secret_value", return_value=ALERT_SECRET),
        ):
            response = soar_playbook.lambda_handler(
                signed_event(valid_payload(role="unapproved-role")), None
            )

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(self.table.items, {})

    def test_slack_delivery_failure_is_not_left_pending(self):
        with (
            patch.object(soar_playbook, "_incident_table", return_value=self.table),
            patch.object(soar_playbook, "_secret_value", return_value=ALERT_SECRET),
            patch.object(
                soar_playbook, "send_slack_alert", side_effect=RuntimeError("delivery failed")
            ),
        ):
            response = soar_playbook.lambda_handler(signed_event(valid_payload()), None)

        self.assertEqual(response["statusCode"], 502)
        self.assertEqual(self.table.items["evt-001"]["status"], "NOTIFICATION_FAILED")

    def test_invalid_signature_is_rejected(self):
        event = signed_event(valid_payload())
        event["headers"]["X-Aegis-Signature"] = "v1=bad"
        with patch.object(soar_playbook, "_secret_value", return_value=ALERT_SECRET):
            response = soar_playbook.lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 401)


if __name__ == "__main__":
    unittest.main()
