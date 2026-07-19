import os
import unittest
from unittest.mock import patch

from lambda_soar import slack_action_receiver, soar_playbook
from tests.fakes import FakeIam, MemoryTable
from tests.test_slack_action_receiver import SLACK_SECRET, slack_event
from tests.test_soar_playbook import ALERT_SECRET, signed_event, valid_payload


class WorkflowIntegrationTests(unittest.TestCase):
    def test_persisted_alert_role_is_retrieved_for_verified_containment(self):
        table = MemoryTable()
        environment = {
            "ALERT_WEBHOOK_SECRET_ARN": "alert-secret-arn",
            "ALLOWED_TARGET_ROLES": '["lab-response-role"]',
            "INCIDENT_TABLE_NAME": "incidents",
            "QUARANTINE_POLICY_ARN": "arn:aws:iam::111122223333:policy/aegis-quarantine",
            "SLACK_SIGNING_SECRET_ARN": "slack-secret-arn",
            "SLACK_WEBHOOK_URL_SECRET_ARN": "slack-url-arn",
        }

        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(soar_playbook, "_incident_table", return_value=table),
            patch.object(soar_playbook, "_secret_value", return_value=ALERT_SECRET),
            patch.object(soar_playbook, "send_slack_alert"),
        ):
            intake = soar_playbook.lambda_handler(signed_event(valid_payload()), None)

        iam = FakeIam()
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(slack_action_receiver, "_incident_table", return_value=table),
            patch.object(slack_action_receiver, "_iam_client", return_value=iam),
            patch.object(
                slack_action_receiver, "_secret_value", return_value=SLACK_SECRET
            ),
        ):
            decision = slack_action_receiver.lambda_handler(slack_event(), None)

        self.assertEqual(intake["statusCode"], 202)
        self.assertEqual(decision["statusCode"], 200)
        self.assertEqual(table.items["evt-001"]["status"], "CONTAINED_BY_HUMAN")
        self.assertEqual(
            iam.attach_calls,
            [
                (
                    "lab-response-role",
                    "arn:aws:iam::111122223333:policy/aegis-quarantine",
                )
            ],
        )


if __name__ == "__main__":
    unittest.main()
