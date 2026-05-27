variable "openai_api_key" {
  description = "OpenAI API Key for SOC Narrative Generation"
  type        = string
  sensitive   = true 
}

# 1. Automatically zip the playbook function files
data "archive_file" "soar_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda_soar"
  output_path = "${path.module}/soar_function_payload.zip"
}

# 2. Build the secure IAM execution role for Lambda
resource "aws_iam_role" "soar_lambda_role" {
  name = "soar_incident_response_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# Attach standard managed policy for execution logging logs
resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.soar_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# 3. Create the AWS Lambda Function
resource "aws_lambda_function" "soar_brain_lambda" {
  filename         = "soar_function_payload.zip"
  function_name    = "automated_cloud_soar_playbook"
  role             = aws_iam_role.soar_lambda_role.arn
  handler          = "soar_playbook.lambda_handler"
  runtime          = "python3.10"
  timeout          = 15
  source_code_hash = data.archive_file.soar_zip.output_base64sha256

  environment {
    variables = {
      OPENAI_API_KEY = var.openai_api_key
    }
  }
}

# 4. Provision the Public API Gateway
resource "aws_apigatewayv2_api" "soar_gateway" {
  name          = "soar-incident-receiver"
  protocol_type = "HTTP"
}

# Link API Gateway endpoint to execute the Lambda function
resource "aws_apigatewayv2_integration" "gateway_lambda_link" {
  api_id           = aws_apigatewayv2_api.soar_gateway.id
  integration_type = "AWS_PROXY"
  integration_uri  = aws_lambda_function.soar_brain_lambda.invoke_arn
}

# Create a dedicated route for the inbound webhook traffic
resource "aws_apigatewayv2_route" "gateway_route" {
  api_id    = aws_apigatewayv2_api.soar_gateway.id
  route_key = "POST /incident"
  target    = "integrations/${aws_apigatewayv2_integration.gateway_lambda_link.id}"
}

# Stand up the default stage and auto-deploy changes
resource "aws_apigatewayv2_stage" "gateway_stage" {
  api_id      = aws_apigatewayv2_api.soar_gateway.id
  name        = "$default"
  auto_deploy = true
}

# Explicitly grant API Gateway permission to trigger the Lambda container
resource "aws_lambda_permission" "allow_api_gateway" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.soar_brain_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.soar_gateway.execution_arn}/*/*"
}

# Output the endpoint URL to use in our Splunk Webhook alert settings
output "soar_endpoint_url" {
  value = "${aws_apigatewayv2_api.soar_gateway.api_endpoint}/incident"
}

# --- PHASE 1: DYNAMODB PERSISTENCE LAYER ---

resource "aws_dynamodb_table" "incident_database" {
  name           = "aegis_soar_incidents"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "incident_id"

  attribute {
    name = "incident_id"
    type = "S" # "S" stands for String
  }
}

# Define the policy allowing Lambda to write to the DynamoDB table
resource "aws_iam_policy" "dynamodb_write_policy" {
  name        = "soar_dynamodb_write_access"
  description = "Allows SOAR playbook to log incidents into DynamoDB."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.incident_database.arn
      }
    ]
  })
}

# Attach this specific policy to the existing Lambda execution role
resource "aws_iam_role_policy_attachment" "soar_attach_dynamodb" {
  role       = aws_iam_role.soar_lambda_role.name
  policy_arn = aws_iam_policy.dynamodb_write_policy.arn
}

# Grant the SOAR Lambda permission to attach quarantine policies to compromised roles
resource "aws_iam_role_policy" "soar_iam_quarantine_access" {
  name = "soar_iam_quarantine_policy"
  role = "soar_incident_response_execution_role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "iam:AttachRolePolicy"
        Resource = "*"
      }
    ]
  })
}