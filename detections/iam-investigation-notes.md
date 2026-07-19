# IAM investigation notes and migration map

This file preserves the unique, supportable query ideas from the decommissioned `aws-iam-abuse-detection-lab` before that standalone repository is archived. The original repository contained setup screenshots and manual SPL notes, but no sanitized CloudTrail corpus, Splunk result captures, automated tests, or CI. The searches below are therefore **unvalidated investigation starters**, not detections with measured performance.

## Where the tested IAM work lives

The replacement [Detection Engineering Lab](https://github.com/PeteAndrews1289/detection-engineering-lab) converts the strongest overlapping hypotheses into structured, fixture-tested artifacts:

- [`AWS-IAM-001`](https://github.com/PeteAndrews1289/detection-engineering-lab/blob/main/detections/aws/iam_privilege_change.json) covers `AttachUserPolicy`, `AttachRolePolicy`, `PutUserPolicy`, `PutRolePolicy`, `CreatePolicyVersion`, and `SetDefaultPolicyVersion` with malicious and benign synthetic fixtures.
- [`AWS-ROOT-001`](https://github.com/PeteAndrews1289/detection-engineering-lab/blob/main/detections/aws/root_account_usage.json) covers root-account API activity with synthetic positive and negative cases.

Those fixture results prove deterministic behavior against the checked-in synthetic cases only. They do not establish operational precision, recall, or production tuning.

## Material retained here

### Nested CloudTrail parser

Use this only when CloudTrail files were indexed as a JSON object containing a top-level `Records` array. Environments using the Splunk AWS add-on commonly expose already-extracted events and should not need this preamble.

```spl
index=<configured-index> sourcetype=<configured-cloudtrail-json>
| spath path=Records{} output=record
| mvexpand record
| spath input=record
```

### IAM user lifecycle

```spl
index=<configured-index> sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com
eventName IN ("CreateUser", "DeleteUser")
| table _time recipientAccountId awsRegion eventName userIdentity.arn sourceIPAddress requestParameters.userName errorCode
| sort -_time
```

Triage: confirm the actor, change record, target name, subsequent credential or policy creation, and whether a deletion interrupted access or followed suspicious activity. User creation may be onboarding or persistence; deletion may be cleanup or disruption. Neither API name proves intent.

### Role assumption

```spl
index=<configured-index> sourcetype=aws:cloudtrail eventSource=sts.amazonaws.com eventName=AssumeRole
| table _time recipientAccountId awsRegion userIdentity.arn sourceIPAddress requestParameters.roleArn responseElements.assumedRoleUser.arn errorCode
| sort -_time
```

Triage: establish the source principal, trust-policy path, session name, MFA/external-ID conditions, source network, and subsequent actions under the assumed-role session. `AssumeRole` is a privilege-context change, but it is also routine in well-designed AWS environments.

### Failed API calls

```spl
index=<configured-index> sourcetype=aws:cloudtrail errorCode=*
| table _time recipientAccountId awsRegion eventSource eventName errorCode errorMessage userIdentity.arn sourceIPAddress userAgent
| sort -_time
```

Triage: correlate the failure with repeated enumeration, privilege-changing calls, the actor's normal responsibilities, and later successful activity. The historical SOAR `AccessDenied` result is itself an example of why a failed call must be recorded accurately; it is not automatically adversary evidence.

### Identity enumeration

```spl
index=<configured-index> sourcetype=aws:cloudtrail
eventName IN ("ListUsers", "ListRoles", "ListPolicies", "GetCallerIdentity")
| stats count values(eventName) as actions values(sourceIPAddress) as source_ips by userIdentity.arn
| sort -count
```

Triage: baseline deployment, inventory, and administrative tooling before setting a threshold. Look for a new actor or source that enumerates identities and then attempts role assumption, credential creation, or a permission change.

## Archive checklist for the former IAM repository

| Former material | Disposition |
| --- | --- |
| Policy-attachment hypothesis | Replaced by tested `AWS-IAM-001` in Detection Engineering Lab |
| Failed-call and broad reconnaissance ideas | Overlap with the six upstream CloudTrail starter searches; limitations retained there |
| CreateUser/DeleteUser, AssumeRole, identity enumeration | Preserved above as explicitly unvalidated investigation notes |
| General IAM findings | Consolidated into the triage guidance above; unsupported claims removed |
| AWS console screenshots | Not migrated: they showed resource setup, not Splunk detection results, and included account/credential identifiers |
| Phase setup notes | Not duplicated: they described manual actions but provided no replayable telemetry or test result |

No successful alerting, correlation, or detection-rate result is inferred from the former lab. This migration was reviewed against Detection Engineering Lab commit `5be0666654ec627e1c51910bc18d8c887ae206cb`.
