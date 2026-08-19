"""Security tests for request authentication and input validation.

This module is the trust boundary of the whole workflow: everything downstream
assumes a request that reached it was signed by the expected sender, arrived
inside the replay window, and carried values within declared bounds. These tests
try to break each of those assumptions individually.
"""

import base64
import hashlib
import hmac
import unittest

from lambda_soar.security import (
    MAX_BODY_BYTES,
    SIGNATURE_TOLERANCE_SECONDS,
    RequestError,
    normalized_headers,
    parse_allowed_roles,
    raw_request_body,
    slack_escape,
    validate_incident_id,
    validate_short_text,
    verify_alert_signature,
    verify_slack_signature,
)

ALERT_SECRET = "alert-secret"
SLACK_SECRET = "slack-secret"
NOW = 1_700_000_000


def alert_headers(body: bytes, *, secret: str = ALERT_SECRET, timestamp: int = NOW) -> dict:
    signed = b"v1:" + str(timestamp).encode() + b":" + body
    digest = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return {"x-aegis-timestamp": str(timestamp), "x-aegis-signature": f"v1={digest}"}


def slack_headers(body: bytes, *, secret: str = SLACK_SECRET, timestamp: int = NOW) -> dict:
    signed = b"v0:" + str(timestamp).encode() + b":" + body
    digest = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return {"x-slack-request-timestamp": str(timestamp), "x-slack-signature": f"v0={digest}"}


class AlertSignatureTests(unittest.TestCase):
    BODY = b'{"event_id":"evt-1"}'

    def test_a_correctly_signed_request_is_accepted(self):
        verify_alert_signature(self.BODY, alert_headers(self.BODY), ALERT_SECRET, now=NOW)

    def test_a_modified_body_is_rejected(self):
        headers = alert_headers(self.BODY)
        with self.assertRaisesRegex(RequestError, "invalid alert signature"):
            verify_alert_signature(b'{"event_id":"evt-2"}', headers, ALERT_SECRET, now=NOW)

    def test_a_single_flipped_byte_is_rejected(self):
        headers = alert_headers(self.BODY)
        tampered = bytearray(self.BODY)
        tampered[-2] ^= 0x01
        with self.assertRaises(RequestError):
            verify_alert_signature(bytes(tampered), headers, ALERT_SECRET, now=NOW)

    def test_the_wrong_secret_is_rejected(self):
        headers = alert_headers(self.BODY, secret="not-the-secret")
        with self.assertRaises(RequestError):
            verify_alert_signature(self.BODY, headers, ALERT_SECRET, now=NOW)

    def test_a_reused_signature_with_a_new_timestamp_is_rejected(self):
        """The timestamp is inside the signed payload, so it cannot be swapped."""
        headers = alert_headers(self.BODY)
        headers["x-aegis-timestamp"] = str(NOW + 1)
        with self.assertRaises(RequestError):
            verify_alert_signature(self.BODY, headers, ALERT_SECRET, now=NOW + 1)

    def test_a_missing_signature_header_is_rejected(self):
        headers = alert_headers(self.BODY)
        del headers["x-aegis-signature"]
        with self.assertRaises(RequestError):
            verify_alert_signature(self.BODY, headers, ALERT_SECRET, now=NOW)

    def test_a_missing_timestamp_header_is_rejected(self):
        headers = alert_headers(self.BODY)
        del headers["x-aegis-timestamp"]
        with self.assertRaisesRegex(RequestError, "invalid request timestamp"):
            verify_alert_signature(self.BODY, headers, ALERT_SECRET, now=NOW)

    def test_a_non_numeric_timestamp_is_rejected(self):
        headers = alert_headers(self.BODY)
        headers["x-aegis-timestamp"] = "not-a-number"
        with self.assertRaisesRegex(RequestError, "invalid request timestamp"):
            verify_alert_signature(self.BODY, headers, ALERT_SECRET, now=NOW)

    def test_an_empty_signature_is_rejected(self):
        headers = alert_headers(self.BODY)
        headers["x-aegis-signature"] = ""
        with self.assertRaises(RequestError):
            verify_alert_signature(self.BODY, headers, ALERT_SECRET, now=NOW)

    def test_a_signature_without_its_version_prefix_is_rejected(self):
        headers = alert_headers(self.BODY)
        headers["x-aegis-signature"] = headers["x-aegis-signature"].removeprefix("v1=")
        with self.assertRaises(RequestError):
            verify_alert_signature(self.BODY, headers, ALERT_SECRET, now=NOW)

    def test_an_empty_body_is_still_authenticated(self):
        verify_alert_signature(b"", alert_headers(b""), ALERT_SECRET, now=NOW)


class ReplayWindowTests(unittest.TestCase):
    BODY = b'{"event_id":"evt-1"}'

    def test_a_request_at_the_tolerance_boundary_is_accepted(self):
        timestamp = NOW - SIGNATURE_TOLERANCE_SECONDS
        verify_alert_signature(
            self.BODY, alert_headers(self.BODY, timestamp=timestamp), ALERT_SECRET, now=NOW
        )

    def test_a_request_one_second_past_the_boundary_is_rejected(self):
        timestamp = NOW - SIGNATURE_TOLERANCE_SECONDS - 1
        with self.assertRaisesRegex(RequestError, "replay window"):
            verify_alert_signature(
                self.BODY, alert_headers(self.BODY, timestamp=timestamp), ALERT_SECRET, now=NOW
            )

    def test_a_far_future_timestamp_is_rejected(self):
        """Clock skew is bounded in both directions, not just the past."""
        timestamp = NOW + SIGNATURE_TOLERANCE_SECONDS + 1
        with self.assertRaisesRegex(RequestError, "replay window"):
            verify_alert_signature(
                self.BODY, alert_headers(self.BODY, timestamp=timestamp), ALERT_SECRET, now=NOW
            )

    def test_the_window_is_checked_before_the_signature(self):
        """A stale request should be cheap to reject."""
        with self.assertRaisesRegex(RequestError, "replay window"):
            verify_slack_signature(
                b"payload=x",
                {"x-slack-request-timestamp": "1000", "x-slack-signature": "v0=bad"},
                SLACK_SECRET,
                now=1301,
            )


class SlackSignatureTests(unittest.TestCase):
    BODY = b"payload=%7B%22type%22%3A%22block_actions%22%7D"

    def test_a_correctly_signed_slack_request_is_accepted(self):
        verify_slack_signature(self.BODY, slack_headers(self.BODY), SLACK_SECRET, now=NOW)

    def test_a_modified_slack_body_is_rejected(self):
        headers = slack_headers(self.BODY)
        with self.assertRaises(RequestError):
            verify_slack_signature(b"payload=tampered", headers, SLACK_SECRET, now=NOW)

    def test_an_alert_signature_cannot_authenticate_a_slack_request(self):
        """The version prefix is inside the signed payload, so v1 and v0 differ."""
        headers = alert_headers(self.BODY)
        with self.assertRaises(RequestError):
            verify_slack_signature(
                self.BODY,
                {
                    "x-slack-request-timestamp": headers["x-aegis-timestamp"],
                    "x-slack-signature": headers["x-aegis-signature"].replace("v1=", "v0="),
                },
                ALERT_SECRET,
                now=NOW,
            )

    def test_the_slack_secret_does_not_authenticate_alert_webhooks(self):
        with self.assertRaises(RequestError):
            verify_alert_signature(
                self.BODY, alert_headers(self.BODY, secret=SLACK_SECRET), ALERT_SECRET, now=NOW
            )


class RequestBodyTests(unittest.TestCase):
    def test_base64_body_is_decoded_before_verification(self):
        self.assertEqual(
            raw_request_body(
                {"body": base64.b64encode(b"payload=x").decode(), "isBase64Encoded": True}
            ),
            b"payload=x",
        )

    def test_a_plain_body_is_encoded_as_utf8(self):
        self.assertEqual(raw_request_body({"body": "payload=x"}), b"payload=x")

    def test_a_missing_body_becomes_empty_bytes(self):
        self.assertEqual(raw_request_body({}), b"")
        self.assertEqual(raw_request_body({"body": None}), b"")

    def test_invalid_base64_is_rejected(self):
        with self.assertRaisesRegex(RequestError, "valid base64"):
            raw_request_body({"body": "not base64!!", "isBase64Encoded": True})

    def test_non_canonical_base64_is_rejected(self):
        """validate=True refuses padding tricks that decode to the same bytes."""
        with self.assertRaises(RequestError):
            raw_request_body({"body": "cGF5bG9hZD14\n\n", "isBase64Encoded": True})

    def test_a_non_text_body_is_rejected(self):
        with self.assertRaisesRegex(RequestError, "body must be text"):
            raw_request_body({"body": {"not": "text"}})

    def test_a_body_at_the_size_limit_is_accepted(self):
        payload = "a" * MAX_BODY_BYTES
        self.assertEqual(len(raw_request_body({"body": payload})), MAX_BODY_BYTES)

    def test_a_body_over_the_size_limit_is_rejected(self):
        with self.assertRaisesRegex(RequestError, "too large"):
            raw_request_body({"body": "a" * (MAX_BODY_BYTES + 1)})

    def test_the_size_limit_applies_after_base64_decoding(self):
        """A small encoded body must not expand past the cap unchecked."""
        oversized = base64.b64encode(b"a" * (MAX_BODY_BYTES + 1)).decode()
        with self.assertRaisesRegex(RequestError, "too large"):
            raw_request_body({"body": oversized, "isBase64Encoded": True})


class HeaderTests(unittest.TestCase):
    def test_headers_are_lowercased_for_lookup(self):
        headers = normalized_headers({"headers": {"X-Aegis-Signature": "v1=abc"}})
        self.assertEqual(headers["x-aegis-signature"], "v1=abc")

    def test_missing_headers_become_an_empty_mapping(self):
        self.assertEqual(normalized_headers({}), {})
        self.assertEqual(normalized_headers({"headers": None}), {})

    def test_a_non_object_headers_field_is_rejected(self):
        with self.assertRaisesRegex(RequestError, "headers must be an object"):
            normalized_headers({"headers": ["not", "an", "object"]})

    def test_header_values_are_coerced_to_strings(self):
        self.assertEqual(normalized_headers({"headers": {"x-count": 5}})["x-count"], "5")


class InputValidationTests(unittest.TestCase):
    def test_a_valid_incident_id_is_accepted(self):
        self.assertEqual(validate_incident_id("evt-2026-01_A:1"), "evt-2026-01_A:1")

    def test_incident_ids_reject_injection_characters(self):
        for value in ["evt 1", "evt/1", "evt;drop", "../evt", "evt\n1", "evt$1", "<evt>"]:
            with self.subTest(value=value), self.assertRaises(RequestError):
                validate_incident_id(value)

    def test_an_empty_or_oversized_incident_id_is_rejected(self):
        with self.assertRaises(RequestError):
            validate_incident_id("")
        with self.assertRaises(RequestError):
            validate_incident_id("a" * 129)

    def test_a_non_string_incident_id_is_rejected(self):
        for value in [None, 5, ["evt"], {"id": "evt"}]:
            with self.subTest(value=value), self.assertRaises(RequestError):
                validate_incident_id(value)

    def test_short_text_is_trimmed_and_bounded(self):
        self.assertEqual(validate_short_text("  hello  ", "title", 32), "hello")
        with self.assertRaisesRegex(RequestError, "too long"):
            validate_short_text("a" * 33, "title", 32)
        with self.assertRaises(RequestError):
            validate_short_text("   ", "title", 32)
        with self.assertRaises(RequestError):
            validate_short_text(None, "title", 32)

    def test_allowed_roles_must_be_a_non_empty_json_list_of_valid_names(self):
        self.assertEqual(parse_allowed_roles('["QuarantineRole"]'), frozenset({"QuarantineRole"}))
        for value in ["[]", "{}", '"QuarantineRole"', "not-json", '["bad role"]', "[5]"]:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                parse_allowed_roles(value)

    def test_allowed_roles_reject_a_name_over_the_iam_limit(self):
        with self.assertRaises(RuntimeError):
            parse_allowed_roles('["%s"]' % ("a" * 65))

    def test_slack_escaping_neutralises_control_characters(self):
        self.assertEqual(slack_escape("<a & b>"), "&lt;a &amp; b&gt;")

    def test_slack_escaping_orders_ampersand_first(self):
        """Escaping & after < would double-encode the entity it produced."""
        self.assertEqual(slack_escape("&lt;"), "&amp;lt;")


if __name__ == "__main__":
    unittest.main()
