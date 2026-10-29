# EventBridge Rule & Lambda Runtime Pod Quarantine Mesh

data "archive_file" "lambda_falco_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_falco_quarantine.zip"

  source {
    content  = file("${path.module}/../src/lambda_falco_quarantine.py")
    filename = "lambda_falco_quarantine.py"
  }
}

resource "aws_iam_role" "lambda_quarantine_role" {
  name = "${local.name_prefix}-falco-remediation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "lambda_quarantine_policy" {
  name = "${local.name_prefix}-quarantine-policy"
  role = aws_iam_role.lambda_quarantine_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogsAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Sid    = "EKSClusterDescribeAccess"
        Effect = "Allow"
        Action = [
          "eks:DescribeCluster",
          "eks:ListClusters"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "falco_pod_quarantine" {
  filename         = data.archive_file.lambda_falco_zip.output_path
  source_code_hash = data.archive_file.lambda_falco_zip.output_base64sha256
  function_name    = "${local.name_prefix}-falco-pod-quarantine"
  role             = aws_iam_role.lambda_quarantine_role.arn
  handler          = "lambda_falco_quarantine.lambda_handler"
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      ENVIRONMENT  = var.environment
      CLUSTER_NAME = var.cluster_name
      DRY_RUN      = "false"
    }
  }

  tags = merge(local.common_tags, {
    Function = "AutomatedRuntimePodQuarantine"
  })
}

resource "aws_cloudwatch_event_rule" "falco_threat_rule" {
  name        = "${local.name_prefix}-falco-threat-rule"
  description = "Captures high/critical severity container runtime alerts from Falco and triggers automated pod quarantine"

  event_pattern = jsonencode({
    source      = ["custom.falco.security"]
    detail-type = ["Falco Alert Event"]
    detail = {
      priority = ["CRITICAL", "HIGH"]
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "quarantine_lambda_target" {
  rule      = aws_cloudwatch_event_rule.falco_threat_rule.name
  target_id = "TriggerPodQuarantine"
  arn       = aws_lambda_function.falco_pod_quarantine.arn
}

resource "aws_lambda_permission" "allow_eventbridge_to_quarantine_lambda" {
  statement_id  = "AllowExecutionFromEventBridgeFalco"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.falco_pod_quarantine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.falco_threat_rule.arn
}
