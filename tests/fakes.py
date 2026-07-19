"""Small in-memory AWS fakes used by the workflow tests."""

from __future__ import annotations

from copy import deepcopy


class ConditionalCheckFailed(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class AccessDenied(Exception):
    response = {"Error": {"Code": "AccessDenied"}}


class MemoryTable:
    def __init__(self, items=None):
        self.items = deepcopy(items or {})

    def put_item(self, *, Item, ConditionExpression=None):
        incident_id = Item["incident_id"]
        if ConditionExpression and incident_id in self.items:
            raise ConditionalCheckFailed()
        self.items[incident_id] = deepcopy(Item)
        return {}

    def get_item(self, *, Key, ConsistentRead=False):
        del ConsistentRead
        item = self.items.get(Key["incident_id"])
        return {"Item": deepcopy(item)} if item is not None else {}

    def update_item(self, **kwargs):
        incident_id = kwargs["Key"]["incident_id"]
        item = self.items[incident_id]
        values = kwargs.get("ExpressionAttributeValues", {})
        expected = next(
            (
                values[key]
                for key in (":received", ":pending", ":in_progress")
                if key in values and key in kwargs.get("ConditionExpression", "")
            ),
            None,
        )
        if expected is not None and item.get("status") != expected:
            raise ConditionalCheckFailed()

        for token in (
            ":pending",
            ":failed",
            ":in_progress",
            ":contained",
            ":false_positive",
        ):
            if token in values and f"#status = {token}" in kwargs["UpdateExpression"]:
                item["status"] = values[token]
        mappings = {
            ":updated": "updated_at",
            ":error": "containment_error_code",
            ":user": "decision_by",
            ":decision": "decision",
            ":verified": "containment_verified_at",
            ":policy": "containment_policy_arn",
        }
        for token, field in mappings.items():
            if token in values and field in kwargs["UpdateExpression"]:
                item[field] = values[token]
        if "notification_error_type" in kwargs["UpdateExpression"]:
            item["notification_error_type"] = values[":error"]
        return {}


class FakeIam:
    def __init__(self, *, fail_attach=False, visible=True):
        self.fail_attach = fail_attach
        self.visible = visible
        self.attach_calls = []

    def attach_role_policy(self, *, RoleName, PolicyArn):
        self.attach_calls.append((RoleName, PolicyArn))
        if self.fail_attach:
            raise AccessDenied()

    def list_attached_role_policies(self, *, RoleName):
        if not self.attach_calls or not self.visible:
            return {"AttachedPolicies": []}
        _, policy_arn = self.attach_calls[-1]
        return {"AttachedPolicies": [{"PolicyName": "quarantine", "PolicyArn": policy_arn}]}
