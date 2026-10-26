# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# SGEA sample tenant app: deploys onto an exported enclave.
#
#   - Cognito user pool + app client: a TEST identity provider issuing the JWT the enclave's
#     runtime authorizer requires (production: the organization IdP).
#   - Tool Lambda (terraform-aws-modules/lambda) registered as an AgentCore Gateway target.
#   - Agent execution role (least privilege: this model, this guardrail, this memory, this gateway).
#   - The agent runtime, created with SGEA's own agentcore-runtime wrapper (VPC-only, JWT inbound
#     auth, idle timeout, account-scoped resource policy) from ./.sgea-modules (symlink to
#     build/<profile-id>/terraform/modules — see ../README.md).
terraform {
  required_version = ">= 1.11"
  backend "local" {} # path set at init: -backend-config=path=...
  required_providers {
    aws   = { source = "hashicorp/aws", version = ">= 6.29" }
    awscc = { source = "hashicorp/awscc", version = ">= 1.100" }
  }
}

provider "aws" {
  region = var.enclave.region
  default_tags { tags = { "sgea:tenant" = "sample-agent", "sgea:profile" = var.enclave.profile } }
}
provider "awscc" { region = var.enclave.region }

data "aws_caller_identity" "this" {}
data "aws_partition" "this" {}

locals {
  account = data.aws_caller_identity.this.account_id
  arn     = data.aws_partition.this.partition
  region  = var.enclave.region
  name    = "sgea-${var.enclave.env}-sample"
  # Inference profile "us.<model>" -> underlying foundation model id
  base_model = join(".", slice(split(".", var.model_id), 1, length(split(".", var.model_id))))
}

check "model_is_authorized" {
  assert {
    condition     = contains(var.enclave.authorized_model_ids, local.base_model)
    error_message = "${local.base_model} is not on the enclave's authorized model list for ${var.enclave.profile}."
  }
}

# ----- test identity provider -----
resource "aws_cognito_user_pool" "test_idp" {
  name                     = "${local.name}-test-idp"
  deletion_protection      = "INACTIVE"
  mfa_configuration        = "OPTIONAL"
  auto_verified_attributes = []
  password_policy {
    minimum_length    = 14
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }
  software_token_mfa_configuration { enabled = true }
}

resource "aws_cognito_user_pool_client" "agent" {
  name                  = "${local.name}-client"
  user_pool_id          = aws_cognito_user_pool.test_idp.id
  generate_secret       = false
  explicit_auth_flows   = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
  access_token_validity = 60
  id_token_validity     = 60
  token_validity_units {
    access_token = "minutes"
    id_token     = "minutes"
  }
}

# ----- tool behind the enclave gateway -----
module "tool" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "8.12.0"

  function_name                  = "${local.name}-enclave-facts"
  handler                        = "handler.handler"
  runtime                        = "python3.12"
  source_path                    = "${path.module}/../tool"
  timeout                        = 10
  reserved_concurrent_executions = 20
  kms_key_arn                    = var.enclave.kms_key_arn
  tracing_mode                   = "Active"
  vpc_subnet_ids                 = var.network.agent_subnet_ids
  vpc_security_group_ids         = var.network.agent_security_group_ids
  dead_letter_target_arn         = aws_sqs_queue.tool_dlq.arn # lambda-dlq-check
  # Same rules as the enclave's own functions: no inline policies (iam-no-inline-policy-check).
  attach_cloudwatch_logs_policy = false
  attach_tracing_policy         = false
  attach_network_policy         = false
  attach_dead_letter_policy     = false
  attach_policies               = true
  number_of_policies            = 3
  policies = [
    aws_iam_policy.tool.arn,
    "arn:${local.arn}:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
    "arn:${local.arn}:iam::aws:policy/AWSXRayDaemonWriteAccess",
  ]
  cloudwatch_logs_retention_in_days = var.enclave.log_retention_days
  cloudwatch_logs_kms_key_id        = var.enclave.kms_key_arn
  environment_variables = {
    SGEA_PROFILE      = var.enclave.profile
    SGEA_GUARDRAIL_ID = var.enclave.guardrail_id
  }
}

# Customer-managed policy + attachment (iam-no-inline-policy-check applies to tenant roles too).
resource "aws_sqs_queue" "tool_dlq" {
  name                      = "${local.name}-enclave-facts-dlq"
  kms_master_key_id         = var.enclave.kms_key_arn
  message_retention_seconds = 1209600
}

resource "aws_iam_policy" "tool" {
  name = "${local.name}-enclave-facts-function"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "EnclaveKey", Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = var.enclave.kms_key_arn },
      { Sid = "DeadLetter", Effect = "Allow", Action = "sqs:SendMessage", Resource = aws_sqs_queue.tool_dlq.arn },
    ]
  })
}

resource "aws_iam_policy" "gateway_invokes_tool" {
  name = "${local.name}-gateway-invokes-tool"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "lambda:InvokeFunction", Resource = module.tool.lambda_function_arn }]
  })
}

resource "aws_iam_role_policy_attachment" "gateway_invokes_tool" {
  role       = var.enclave.gateway_role_name
  policy_arn = aws_iam_policy.gateway_invokes_tool.arn
}

resource "aws_bedrockagentcore_gateway_target" "facts" {
  gateway_identifier = var.enclave.gateway_id
  name               = "facts"
  description        = "Enclave facts (SGEA sample tool)"
  credential_provider_configuration {
    gateway_iam_role {}
  }
  target_configuration {
    mcp {
      lambda {
        lambda_arn = module.tool.lambda_function_arn
        tool_schema {
          inline_payload {
            name        = "enclave_facts"
            description = "Facts about the governed enclave this agent runs in (profile, region, guardrail, controls)."
            input_schema {
              type = "object"
              property {
                name        = "topic"
                type        = "string"
                description = "What the user wants to know about the enclave"
              }
            }
          }
        }
      }
    }
  }
  depends_on = [aws_iam_role_policy_attachment.gateway_invokes_tool]
}

# The enclave gateway is default-deny (gateway_tool_path: policy engine in ENFORCE mode). The tenant
# permits exactly its own tool, for exactly its own agent role. In GovCloud the enclave's interceptor
# Lambda enforces instead — add the rule to the enclave's tool_policy there.
resource "awscc_bedrockagentcore_policy" "permit_facts_tool" {
  count            = var.enclave.policy_engine_id == null ? 0 : 1
  policy_engine_id = var.enclave.policy_engine_id
  name             = "${replace(local.name, "-", "_")}_permit_facts"
  description      = "Sample tenant: allow the agent to call facts___enclave_facts"
  validation_mode  = "FAIL_ON_ANY_FINDINGS"
  definition = {
    cedar = {
      # Exactly this tenant's agent role (Cedar IamEntity id = assumed-role ARN, AWS docs: policy-conditions);
      # a bare `principal is AgentCore::IamEntity` is rejected by AgentCore as overly permissive.
      statement = "permit(principal == AgentCore::IamEntity::\"arn:${local.arn}:sts::${local.account}:assumed-role/${aws_iam_role.agent.name}\", action == AgentCore::Action::\"facts___enclave_facts\", resource == AgentCore::Gateway::\"${var.enclave.gateway_arn}\");"
    }
  }
  depends_on = [aws_bedrockagentcore_gateway_target.facts]
}

# ----- agent execution role (least privilege) -----
resource "aws_iam_role" "agent" {
  name = "${local.name}-agent"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock-agentcore.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account }
        ArnLike      = { "aws:SourceArn" = "arn:${local.arn}:bedrock-agentcore:${local.region}:${local.account}:*" }
      }
    }]
  })
}

# Customer-managed policy + attachment (iam-no-inline-policy-check applies to tenant roles too).
resource "aws_iam_policy" "agent" {
  name = "${local.name}-agent"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "PullImage", Effect = "Allow", Action = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
      Resource = "arn:${local.arn}:ecr:${local.region}:${local.account}:repository/${split("/", var.enclave.agents_repository_url)[1]}" },
      # AgentCore Runtime pulls the agent image with this role; the action has no resource-level scoping (AWS docs).
      { Sid = "EcrAuth", Effect = "Allow", Action = "ecr:GetAuthorizationToken", Resource = "*" }, # nosemgrep: terraform.lang.security.iam.no-iam-creds-exposure.no-iam-creds-exposure
      { Sid = "Logs", Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
      Resource = "arn:${local.arn}:logs:${local.region}:${local.account}:log-group:/aws/bedrock-agentcore/runtimes/*" },
      { Sid = "Metrics", Effect = "Allow", Action = "cloudwatch:PutMetricData", Resource = "*",
      Condition = { StringEquals = { "cloudwatch:namespace" = "bedrock-agentcore" } } },
      { Sid = "Tracing", Effect = "Allow", Action = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"], Resource = "*" },
      { Sid = "InvokeAuthorizedModel", Effect = "Allow", Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
        Resource = ["arn:${local.arn}:bedrock:*:${local.account}:inference-profile/${var.model_id}",
      "arn:${local.arn}:bedrock:*::foundation-model/${local.base_model}"] },
      { Sid = "EnclaveGuardrail", Effect = "Allow", Action = "bedrock:ApplyGuardrail",
      Resource = "arn:${local.arn}:bedrock:${local.region}:${local.account}:guardrail/${var.enclave.guardrail_id}" },
      { Sid = "EnclaveMemory", Effect = "Allow", Action = ["bedrock-agentcore:CreateEvent", "bedrock-agentcore:ListEvents", "bedrock-agentcore:GetEvent"],
      Resource = "arn:${local.arn}:bedrock-agentcore:${local.region}:${local.account}:memory/${var.enclave.memory_id}" },
      { Sid = "EnclaveGateway", Effect = "Allow", Action = "bedrock-agentcore:InvokeGateway",
      Resource = "arn:${local.arn}:bedrock-agentcore:${local.region}:${local.account}:gateway/${var.enclave.gateway_id}" },
      { Sid = "EnclaveKey", Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = var.enclave.kms_key_arn },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "agent" {
  role       = aws_iam_role.agent.id
  policy_arn = aws_iam_policy.agent.arn
}

# ----- the agent runtime, via SGEA's own wrapper -----
module "runtime" {
  source = "./.sgea-modules/agentcore-runtime"

  name                = replace("${local.name}_agent", "-", "_")
  execution_role_arn  = aws_iam_role.agent.arn
  container_uri       = var.image_uri
  subnet_ids          = var.network.agent_subnet_ids
  security_group_ids  = var.network.agent_security_group_ids
  jwt_discovery_url   = "https://cognito-idp.${local.region}.amazonaws.com/${aws_cognito_user_pool.test_idp.id}/.well-known/openid-configuration"
  jwt_allowed_clients = [aws_cognito_user_pool_client.agent.id]
  # The caller's (runtime-validated) JWT reaches the agent so it can attribute token usage per user.
  request_header_allowlist = ["Authorization"]
  environment = {
    SGEA_MODEL_ID          = var.model_id
    SGEA_GUARDRAIL_ID      = var.enclave.guardrail_id
    SGEA_GUARDRAIL_VERSION = var.enclave.guardrail_version
    SGEA_MEMORY_ID         = var.enclave.memory_id
    SGEA_GATEWAY_URL       = var.enclave.gateway_url
  }
  depends_on = [aws_iam_role_policy_attachment.agent, aws_bedrockagentcore_gateway_target.facts, awscc_bedrockagentcore_policy.permit_facts_tool]
}

# AgentCore creates the runtime's log group itself when the runtime is created, so it cannot be
# pre-created (verified in sandbox: ResourceAlreadyExistsException). Apply the enclave controls to
# it afterwards (cloudwatch-log-group-encrypted, cw-loggroup-retention-period-check).
resource "terraform_data" "runtime_log_controls" {
  triggers_replace = [module.runtime.agent_runtime_id, var.enclave.kms_key_arn]
  provisioner "local-exec" {
    command = <<-EOT
      set -e
      G="/aws/bedrock-agentcore/runtimes/${module.runtime.agent_runtime_id}-DEFAULT"
      for i in $(seq 1 30); do aws logs describe-log-groups --region ${local.region} --log-group-name-prefix "$G" --query 'logGroups[0].logGroupName' --output text | grep -q "$G" && break; sleep 5; done
      aws logs associate-kms-key --region ${local.region} --log-group-name "$G" --kms-key-id "${var.enclave.kms_key_arn}"
      aws logs put-retention-policy --region ${local.region} --log-group-name "$G" --retention-in-days ${var.enclave.log_retention_days}
    EOT
  }
}
