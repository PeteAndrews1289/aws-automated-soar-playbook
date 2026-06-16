# Incident Workflow

This document describes the human-in-the-loop SOAR flow implemented by AegisSOAR.

## 1. Alert Intake

Splunk sends alert telemetry to the API Gateway `/incident` route. The expected payload includes:

- `search_name`
- `clientip`
- `host`
- `iam_role`

## 2. Incident Creation

The SOAR Lambda generates a unique incident ID and stores a record in DynamoDB.

Initial state:

- `PENDING_APPROVAL`

Stored context:

- Alert name
- Attacker IP
- Affected asset
- AI-generated summary
- Timestamp

## 3. AI Narrative

The Lambda sends selected alert fields to the OpenAI API to generate a short SOC-style narrative.

Design intent:

- Help the analyst understand the alert faster.
- Keep the raw alert fields visible.
- Avoid letting the model make the containment decision.

## 4. Slack Analyst Decision

Slack receives an interactive Block Kit message with two analyst actions:

- Approve quarantine
- Mark false positive

The workflow pauses until a human chooses an action.

## 5. Containment Action

If quarantine is approved, the Slack receiver Lambda attaches an AWS deny policy to the target IAM role.

Resulting state:

- `CONTAINED_BY_HUMAN`

If the alert is rejected, the incident is marked:

- `FALSE_POSITIVE`

## 6. Evidence to Review

- DynamoDB incident record
- Slack message and final action state
- Lambda logs
- IAM role policy attachment
- Splunk alert payload

## Security Notes

- The lab demonstrates the workflow pattern, not production-ready SOAR governance.
- Production use would require narrow IAM permissions, authentication on public endpoints, approval audit logs, rollback, and change-control integration.
