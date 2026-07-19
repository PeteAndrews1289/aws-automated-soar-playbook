import hashlib
import hmac
import json
import os
import time
import unittest
import urllib.parse
from unittest.mock import patch

from lambda_soar import slack_action_receiver as receiver
from tests.fakes import FakeIam, MemoryTable


SLACK_SECRET = "test-slack-secret"
POLICY_ARN = "arn:aws:iam::111122223333:policy/aegis-quarantine"


def slack_event(action_id="approve_role_containment", incident_id="evt-001"):
    payload = {
        "actions": [{"action_id": action_id, "value": incident_id}],
        "user": {"id": "U12345"},
        "message": {"blocks": [{"type": "header"}, {"type": "section"}]},
    }
    raw = urllib.parse.urlencode(
        {"payload": json.dumps(payload, separators=(",", ":"))}
    )
    timestamp = str(int(time.time()))
    digest = hmac.new(
        SLACK_SECRET.encode(), f"v0:{timestamp}:{raw}".encode(), hashlib.sha256
    ).hexdigest()
    return {
        "body": raw,
        "headers": {
            "X-Slack-Request-Timestamp": timestamp,
            "X-Slack-Signature": f"v0={digest}",
        },
    }


def pending_item():
    return {
        "evt-001": {
            "incident_id": "evt-001",
            "status": "PENDING_APPROVAL",
            "target_role": "lab-response-role",
        }
    }


class SlackDecisionTests(unittest.TestCase):
    def setUp(self):
        receiver._secret_value.cache_clear()
        self.environment = patch.dict(
            os.environ,
            {
                "INCIDENT_TABLE_NAME": "incidents",
                "SLACK_SIGNING_SECRET_ARN": "slack-secret-arn",
                "ALLOWED_TARGET_ROLES": '["lab-response-role"]',
                "QUARANTINE_POLICY_ARN": POLICY_ARN,
            },
            clear=True,
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def call(self, table, iam, event=None):
        with (
            patch.object(receiver, "_incident_table", return_value=table),
            patch.object(receiver, "_iam_client", return_value=iam),
            patch.object(receiver, "_secret_value", return_value=SLACK_SECRET),
        ):
            return receiver.lambda_handler(event or slack_event(), None)

    def test_success_is_recorded_only_after_policy_attachment_is_visible(self):
        table = MemoryTable(pending_item())
        iam = FakeIam()
        response = self.call(table, iam)

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(table.items["evt-001"]["status"], "CONTAINED_BY_HUMAN")
        self.assertEqual(iam.attach_calls, [("lab-response-role", POLICY_ARN)])
        self.assertIn("attachment verified", response["body"])

    def test_access_denied_becomes_containment_failed(self):
        table = MemoryTable(pending_item())
        response = self.call(table, FakeIam(fail_attach=True))

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(table.items["evt-001"]["status"], "CONTAINMENT_FAILED")
        self.assertEqual(table.items["evt-001"]["containment_error_code"], "AccessDenied")
        self.assertIn("no contained state was recorded", response["body"])

    def test_unverified_attachment_becomes_containment_failed(self):
        table = MemoryTable(pending_item())
        self.call(table, FakeIam(visible=False))
        self.assertEqual(table.items["evt-001"]["status"], "CONTAINMENT_FAILED")

    def test_replayed_approval_does_not_attach_twice(self):
        table = MemoryTable(pending_item())
        iam = FakeIam()
        event = slack_event()
        first = self.call(table, iam, event)
        second = self.call(table, iam, event)

        self.assertEqual(first["statusCode"], 200)
        self.assertEqual(second["statusCode"], 200)
        self.assertEqual(len(iam.attach_calls), 1)
        self.assertIn("already processed", second["body"])

    def test_false_positive_does_not_call_iam(self):
        table = MemoryTable(pending_item())
        iam = FakeIam()
        response = self.call(table, iam, slack_event("mark_false_positive"))

        self.assertEqual(response["statusCode"], 200)
        self.assertEqual(table.items["evt-001"]["status"], "FALSE_POSITIVE")
        self.assertEqual(iam.attach_calls, [])

    def test_invalid_slack_signature_is_rejected(self):
        event = slack_event()
        event["headers"]["X-Slack-Signature"] = "v0=bad"
        table = MemoryTable(pending_item())
        response = self.call(table, FakeIam(), event)
        self.assertEqual(response["statusCode"], 401)


if __name__ == "__main__":
    unittest.main()
