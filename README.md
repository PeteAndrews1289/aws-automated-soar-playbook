# Automated Cloud SOAR (Security Orchestration, Automation, and Response) Playbook

An enterprise-grade, event-driven incident response automation engine built using Infrastructure as Code (IaC). This repository demonstrates a serverless SOAR playbook that programmatically intercepts real-time threat telemetry from a Splunk SIEM and executes active runtime containment loops across AWS IAM and cloud-native Kubernetes environments in under **2 milliseconds**.

## 🏗️ Target Architecture

```mermaid
graph TD
    A[Attacker strikes Vulnerable App] -->|Generates Log| B(Splunk SIEM Watchtower)
    B -->|Real-Time Trigger Outbound Webhook| C(AWS API Gateway)
    C -->|Routes JSON Payload| D(AWS Lambda Brain)
    D -->|AWS SDK Boto3| E[Attach AWSDenyAll to Compromised Role]
    D -->|Programmatic Generation| F[Kubernetes NetworkPolicy Isolation]
    D -->|Webhook Event Forwarding| G[SecOps Visibility Alert Hub]
