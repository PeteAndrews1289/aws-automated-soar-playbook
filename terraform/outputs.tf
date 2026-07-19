output "alert_intake_url" {
  description = "Signed alert endpoint. Treat the URL as public and authenticate every request."
  value       = "${aws_apigatewayv2_api.alerts.api_endpoint}/incident"
  sensitive   = true
}

output "slack_interactivity_url" {
  description = "Public Slack callback URL protected by Slack request-signature verification."
  value       = aws_lambda_function_url.slack.function_url
  sensitive   = true
}

output "quarantine_policy_arn" {
  description = "Lab quarantine policy that the receiver may attach to allowlisted roles."
  value       = aws_iam_policy.quarantine.arn
}
