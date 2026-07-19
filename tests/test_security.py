import base64
import hashlib
import hmac
import unittest

from lambda_soar.security import (
    RequestError,
    raw_request_body,
    verify_alert_signature,
    verify_slack_signature,
)


class RequestSecurityTests(unittest.TestCase):
    def test_alert_signature_is_verified(self):
        body = b'{"event_id":"evt-1"}'
        timestamp = "1000"
        digest = hmac.new(
            b"alert-secret", b"v1:" + timestamp.encode() + b":" + body, hashlib.sha256
        ).hexdigest()

        verify_alert_signature(
            body,
            {"x-aegis-timestamp": timestamp, "x-aegis-signature": f"v1={digest}"},
            "alert-secret",
            now=1000,
        )

    def test_stale_slack_request_is_rejected(self):
        with self.assertRaisesRegex(RequestError, "replay window"):
            verify_slack_signature(
                b"payload=x",
                {"x-slack-request-timestamp": "1000", "x-slack-signature": "v0=bad"},
                "slack-secret",
                now=1301,
            )

    def test_base64_body_is_decoded_before_verification(self):
        self.assertEqual(
            raw_request_body(
                {"body": base64.b64encode(b"payload=x").decode(), "isBase64Encoded": True}
            ),
            b"payload=x",
        )


if __name__ == "__main__":
    unittest.main()
