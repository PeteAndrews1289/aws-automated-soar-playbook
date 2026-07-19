# CloudTrail starter searches

These six searches came from the upstream CloudTrail-to-Splunk exercise. They are hypotheses, not validated detections. Replace `index=<configured-index>`, confirm field extraction, and add a schedule, threshold, suppression, synthetic malicious and benign fixtures, expected results, and false-positive tests before alerting.

## Failed API calls

```spl
index=<configured-index> sourcetype=aws:cloudtrail errorCode=*
| table _time eventSource eventName errorCode errorMessage userIdentity.arn sourceIPAddress userAgent
| sort -_time
```

Failed calls can indicate permission probing, ordinary misconfiguration, or unavailable features. A failure alone is not evidence of malicious activity.

## IAM privilege changes

```spl
index=<configured-index> sourcetype=aws:cloudtrail
eventName IN ("AttachUserPolicy","AttachRolePolicy","PutUserPolicy","PutRolePolicy","CreatePolicy","CreatePolicyVersion","SetDefaultPolicyVersion")
| table _time eventName userIdentity.arn sourceIPAddress requestParameters.userName requestParameters.roleName requestParameters.policyArn
| sort -_time
```

Starting point: ATT&CK T1098.003 only when the observed change actually adds cloud permissions. Approved identity administration is a common benign cause.

## Root-account usage

```spl
index=<configured-index> sourcetype=aws:cloudtrail userIdentity.type=Root
| table _time eventSource eventName sourceIPAddress userAgent errorCode
| sort -_time
```

Starting point: ATT&CK T1078.004 only when evidence supports account abuse. Review break-glass administration before escalation.

## Reconnaissance activity

```spl
index=<configured-index> sourcetype=aws:cloudtrail
| search eventName="List*" OR eventName="Describe*" OR eventName="Get*"
| stats count values(eventName) as actions values(eventSource) as services by userIdentity.arn sourceIPAddress
| sort -count
```

Starting point: ATT&CK T1580 when the sequence indicates cloud-infrastructure discovery. Inventory tooling can look similar.

## Security-group changes

```spl
index=<configured-index> sourcetype=aws:cloudtrail
eventName IN ("AuthorizeSecurityGroupIngress","AuthorizeSecurityGroupEgress","RevokeSecurityGroupIngress","RevokeSecurityGroupEgress","CreateSecurityGroup","DeleteSecurityGroup")
| table _time eventName userIdentity.arn sourceIPAddress requestParameters.groupId requestParameters.groupName errorCode
| sort -_time
```

Starting point: ATT&CK T1562.007 only when a change weakens a cloud firewall. Approved network changes are expected noise.

## S3 policy or ACL changes

```spl
index=<configured-index> sourcetype=aws:cloudtrail
eventName IN ("PutBucketPolicy","DeleteBucketPolicy","PutBucketAcl","PutPublicAccessBlock","DeletePublicAccessBlock")
| table _time eventName userIdentity.arn sourceIPAddress requestParameters.bucketName errorCode
| sort -_time
```

A storage permission change alone is not evidence of collection or exfiltration; confirm its effect and intent.

## Triage checklist

- Establish the actor, source, event, error, account, region, and trail.
- Compare the action with approved changes and the identity's normal responsibilities.
- Correlate enumeration with later write activity rather than treating one API call as proof.
- Record why activity was expected or suspicious and what independent evidence supports the decision.
