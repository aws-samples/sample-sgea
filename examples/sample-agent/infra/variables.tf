variable "enclave" {
  description = "Enclave facts: `terraform output -json enclave` from build/<profile-id>/terraform."
  type = object({
    env                   = string
    profile               = string
    partition             = string
    region                = string
    kms_key_arn           = string
    guardrail_id          = string
    guardrail_version     = string
    authorized_model_ids  = list(string)
    gateway_id            = string
    gateway_url           = string
    gateway_arn           = string
    policy_engine_id      = optional(string) # null where the policy engine is unavailable (GovCloud: interceptor)
    gateway_role_name     = string
    memory_id             = string
    agents_repository_url = string
    token_ledger_table    = optional(string)
    token_timezone        = optional(string, "UTC")
    token_per_user_daily  = optional(number, 0)
    log_retention_days    = optional(number, 365) # the enclave's CloudWatch retention (pack-derived)
  })
}

variable "network" {
  description = "Network ids: `terraform output -json enclave_inputs` from examples/sandbox-network."
  type = object({
    agent_subnet_ids         = list(string)
    agent_security_group_ids = list(string)
  })
}

variable "image_uri" {
  description = "Agent image in the enclave ECR repo (scripts/build_push.sh prints it). Immutable tag."
  type        = string
}

variable "model_id" {
  description = "Inference profile id; its foundation model must be on the enclave's authorized list."
  type        = string
  default     = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
}
