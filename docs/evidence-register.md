# Evidence register

| Claim | Evidence retained from the completed labs | Public representation |
| --- | --- | --- |
| CloudTrail reached Splunk | One Splunk search showed 647 events | Bounded count in the sanitized SVG; raw rows removed |
| Splunk polled the SQS input | Input configuration showed a 600-second interval | Configuration value retained; no latency claim |
| Detection work was drafted | Six SPL searches exist | Queries retained with validation and false-positive caveats |
| Analyst approval UI existed | Slack screenshots showed interactive buttons | Architecture and code retained; workspace capture removed |
| IAM containment failed | CloudWatch showed `AccessDenied` on `AttachRolePolicy` | Failure disclosed as the principal negative result |
| Kubernetes policy text was generated | CloudWatch and a YAML artifact showed manifest generation | YAML retained as a sample; no apply/isolation claim |

## Removed source captures

The screenshots mixed useful evidence with an AWS account ID, a public endpoint, resource identifiers, and contradictory status text. They were removed from the proposed current tree. The underlying exercises and credentials were dismantled, but responsible portfolio presentation still avoids publishing operational identifiers and false success signals.

The removal is not a claim of permanent erasure: historic blobs remain recoverable through Git history unless the repository history is rewritten.

## Upstream CloudTrail/Splunk interpretation limits

- **647 events** is one observed search result, not ingest capacity or coverage.
- **600 seconds** is the configured poll interval, not measured end-to-end latency.
- Standard and FIFO resources appeared during the exercise; retained evidence does not establish one reproducible final queue configuration.
- No public raw-event corpus remains, so the six searches cannot be replayed here.
- That upstream lab was manually configured and later dismantled. It did not implement AI, infrastructure as code, or automated response.

## SOAR interpretation limits

- Historical containment was not successful; the only retained result is `AccessDenied`.
- The revised code is tested locally and through CI, but a new deployed end-to-end containment run is not claimed.
- IAM attachment visibility is narrower than session revocation or workload isolation.
- Slack and alert HMACs authenticate shared-secret holders; production deployments also need secret rotation, monitoring, and a documented recovery path.
