data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  allowed_target_roles = sort(tolist(var.allowed_target_role_names))
  target_role_arns = [
    for role_name in local.allowed_target_roles :
    "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${role_name}"
  ]
  brain_secret_arns = compact([
    var.alert_webhook_secret_arn,
    var.slack_webhook_url_secret_arn,
    var.openai_api_key_secret_arn,
  ])
}

data "archive_file" "lambda_bundle" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda_soar"
  output_path = "${path.module}/.build/aegis-soar.zip"
  excludes    = ["__pycache__", "*.pyc", "*.pyo"]
}

resource "aws_dynamodb_table" "incidents" {
  name         = "${var.name_prefix}-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }
}

resource "aws_iam_policy" "quarantine" {
  name_prefix = "${var.name_prefix}-quarantine-"
  description = "Explicit deny policy attached only to allowlisted lab roles after approval."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "QuarantineDeny"
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "brain" {
  name_prefix = "${var.name_prefix}-brain-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role" "receiver" {
  name_prefix = "${var.name_prefix}-receiver-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRole"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_cloudwatch_log_group" "brain" {
  name              = "/aws/lambda/${var.name_prefix}-brain"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "receiver" {
  name              = "/aws/lambda/${var.name_prefix}-slack-receiver"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role_policy" "brain" {
  name = "${var.name_prefix}-brain"
  role = aws_iam_role.brain.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IncidentIntake"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
        ]
        Resource = aws_dynamodb_table.incidents.arn
      },
      {
        Sid      = "ReadConfiguredSecrets"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = local.brain_secret_arns
      },
      {
        Sid    = "WriteFunctionLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.brain.arn}:*"
      },
    ]
  })
}

resource "aws_iam_role_policy" "receiver" {
  name = "${var.name_prefix}-receiver"
  role = aws_iam_role.receiver.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadAndTransitionIncidents"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
        ]
        Resource = aws_dynamodb_table.incidents.arn
      },
      {
        Sid      = "ReadSlackSigningSecret"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = var.slack_signing_secret_arn
      },
      {
        Sid      = "AttachOnlyQuarantinePolicy"
        Effect   = "Allow"
        Action   = "iam:AttachRolePolicy"
        Resource = local.target_role_arns
        Condition = {
          ArnEquals = {
            "iam:PolicyARN" = aws_iam_policy.quarantine.arn
          }
        }
      },
      {
        Sid      = "VerifyQuarantineAttachment"
        Effect   = "Allow"
        Action   = "iam:ListAttachedRolePolicies"
        Resource = local.target_role_arns
      },
      {
        Sid    = "WriteFunctionLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.receiver.arn}:*"
      },
    ]
  })
}

resource "aws_lambda_function" "brain" {
  filename         = data.archive_file.lambda_bundle.output_path
  function_name    = "${var.name_prefix}-brain"
  role             = aws_iam_role.brain.arn
  handler          = "soar_playbook.lambda_handler"
  runtime          = "python3.10"
  timeout          = 15
  memory_size      = 256
  source_code_hash = data.archive_file.lambda_bundle.output_base64sha256

  environment {
    variables = {
      ALERT_WEBHOOK_SECRET_ARN     = var.alert_webhook_secret_arn
      ALLOWED_TARGET_ROLES         = jsonencode(local.allowed_target_roles)
      INCIDENT_TABLE_NAME          = aws_dynamodb_table.incidents.name
      OPENAI_API_KEY_SECRET_ARN    = var.openai_api_key_secret_arn == null ? "" : var.openai_api_key_secret_arn
      OPENAI_MODEL                 = var.openai_model == null ? "" : var.openai_model
      SLACK_WEBHOOK_URL_SECRET_ARN = var.slack_webhook_url_secret_arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.brain, aws_iam_role_policy.brain]
}

resource "aws_lambda_function" "receiver" {
  filename         = data.archive_file.lambda_bundle.output_path
  function_name    = "${var.name_prefix}-slack-receiver"
  role             = aws_iam_role.receiver.arn
  handler          = "slack_action_receiver.lambda_handler"
  runtime          = "python3.10"
  timeout          = 10
  memory_size      = 256
  source_code_hash = data.archive_file.lambda_bundle.output_base64sha256

  environment {
    variables = {
      ALLOWED_TARGET_ROLES     = jsonencode(local.allowed_target_roles)
      INCIDENT_TABLE_NAME      = aws_dynamodb_table.incidents.name
      QUARANTINE_POLICY_ARN    = aws_iam_policy.quarantine.arn
      SLACK_SIGNING_SECRET_ARN = var.slack_signing_secret_arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.receiver, aws_iam_role_policy.receiver]
}

resource "aws_apigatewayv2_api" "alerts" {
  name          = "${var.name_prefix}-alert-intake"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "alerts" {
  api_id                 = aws_apigatewayv2_api.alerts.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.brain.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "incident" {
  api_id    = aws_apigatewayv2_api.alerts.id
  route_key = "POST /incident"
  target    = "integrations/${aws_apigatewayv2_integration.alerts.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.alerts.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowIncidentRoute"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.brain.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.alerts.execution_arn}/*/POST/incident"
}

resource "aws_lambda_function_url" "slack" {
  function_name      = aws_lambda_function.receiver.function_name
  authorization_type = "NONE"
}

resource "aws_lambda_permission" "slack_function_url" {
  statement_id           = "AllowSignedSlackFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.receiver.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "slack_function_invoke" {
  statement_id             = "AllowSignedSlackFunctionInvoke"
  action                   = "lambda:InvokeFunction"
  function_name            = aws_lambda_function.receiver.function_name
  principal                = "*"
  invoked_via_function_url = true
}
