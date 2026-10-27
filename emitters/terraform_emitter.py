# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
SGEA Terraform emitter — wrapper-seam design (ADR 0001).

Translates a RESOLVED profile into a root Terraform stack that calls a set of
thin WRAPPER MODULES, each keyed on the SGEA resolved-config shape. Two kinds
of seam:

  * resource-layer seam  -> pass-through to an OFFICIAL provider resource
      (aws_bedrock_guardrail, awscc_bedrock_knowledge_base [RDS/Aurora],
       awscc_bedrockagentcore_runtime). The wrapper only maps resolved-config
       inputs onto the official resource; it adds no resource logic.
  * governance-layer seam -> raw OFFICIAL provider resources where nothing
      official exists (org SCP/RCP via aws_organizations_policy; the per-user
      token-control layer via DynamoDB + Lambda). The wrapper is the single
      place to later point at an official module if one ships.

The wrapper INTERFACE is the resolved-config shape, never the shape of what is
behind it (ADR 0001). Callers (this root stack) depend only on that interface,
so swapping a wrapper's internals is a one-file change.

Honesty: wrapper bodies are structurally valid HCL and wire the resolved
control values. The EXACT official-resource attribute names must be confirmed
against the provider schema the first time `sgea verify` runs
`terraform validate` with network access — that is precisely what verify is
for. Each wrapper README says so.
"""
import json, os, shutil, subprocess

try:
    from .license_header import with_header
    from .guardrail_map import PII_ENTITIES, PHI_ENTITIES, CONTEXTUAL_ENTITIES, INPUT_ONLY_FILTERS, FILTER_ORDER
    from . import policy_library
    from .derived import (cw_retention, data_event_types, endpoint_services, backup_policy,
                          pack_resource_name, replica_region, policy_engine_available,
                          authorized_model_ids, scca_required, account_baseline, pack_template,
                          log_retention_days)
except ImportError:  # in-repo fallback import (sgea._load_emitters)
    from license_header import with_header
    from guardrail_map import PII_ENTITIES, PHI_ENTITIES, CONTEXTUAL_ENTITIES, INPUT_ONLY_FILTERS, FILTER_ORDER
    import policy_library
    from derived import (cw_retention, data_event_types, endpoint_services, backup_policy,
                         pack_resource_name, replica_region, policy_engine_available,
                         authorized_model_ids, scca_required, account_baseline, pack_template,
                         log_retention_days)

SEAM_OFFICIAL = "official-passthrough"
SEAM_RAW = "raw-governance-adapter"


def _w(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(with_header(path, content))   # MIT-0 header on generated .tf / .ts / .py / .sh
    return path


def _versions_tf(partition, use_awscc):
    prov = ['    aws = { source = "hashicorp/aws", version = ">= 6.0" }']
    if use_awscc:
        prov.append('    awscc = { source = "hashicorp/awscc", version = ">= 1.100" }')
    return ("terraform {\n  required_version = \">= 1.11\"\n  required_providers {\n"
            + "\n".join(prov) + "\n  }\n}\n")


def _seam_header(name, kind, official, swap):
    return ("# SGEA WRAPPER MODULE (seam) — " + name + "\n"
            "# seam-kind: " + kind + "\n"
            "# official-target: " + official + "\n"
            "# swap-later: " + swap + "\n"
            "# Interface = SGEA resolved-config shape. Do NOT change the variable\n"
            "# surface to match the resource behind it — that is what keeps the swap cheap.\n\n")


# -------------------- resource-layer wrapper modules --------------------
def _mod_bedrock_guardrail(partition):
    v = _seam_header("bedrock-guardrail", SEAM_OFFICIAL, "aws_bedrock_guardrail",
                     "replace the awscc resource with an official guardrail module if one ships")
    variables = (v +
        'variable "name" { type = string }\n'
        'variable "guardrail" {\n  description = "SGEA resolved-config guardrails block."\n  type = any\n}\n'
        'variable "kms_key_arn" {\n  type = string\n  default = null\n}\n'
        'variable "enforce_account_wide" {\n  description = "SGEA L2_account_baseline: enforce this guardrail on every model invocation in the account."\n  type = bool\n  default = false\n}\n'
        'variable "inference_profile_geo" {\n  description = "Geo for the STANDARD-tier guardrail profile (us, us-gov, eu, ...)."\n  type = string\n}\n'
        'variable "tags" {\n  type = map(string)\n  default = {}\n}\n')
    main = (_seam_header("bedrock-guardrail", SEAM_OFFICIAL, "aws_bedrock_guardrail", "swap internals only") +
        'locals {\n'
        '  # Entity sets come from emitters/guardrail_map.py (shared with the CDK emitter).\n'
        '  pii_entities = ' + json.dumps(PII_ENTITIES) + '\n'
        '  phi_entities = ' + json.dumps(PHI_ENTITIES) + '\n'
        '  contextual_entities = ' + json.dumps(CONTEXTUAL_ENTITIES) + '\n'
        '  input_only_filters = ' + json.dumps(INPUT_ONLY_FILTERS) + '\n\n'
        '  pii_mode   = try(var.guardrail.pii.mode, "off")\n'
        '  pii_action = try(var.guardrail.pii.action, "BLOCK")\n'
        '  ctx_action = try(var.guardrail.pii.contextual_action, local.pii_action)\n'
        '  pii_types  = local.pii_mode == "off" ? [] : concat(local.pii_entities,\n'
        '    try(var.guardrail.pii.phi_entities, false) ? local.phi_entities : [])\n\n'
        '  # API order (emitters/guardrail_map.FILTER_ORDER), then any other classes: no perpetual list diff.\n'
        '  filter_order = ' + json.dumps(FILTER_ORDER) + '\n'
        '  filter_types = concat([for c in local.filter_order : c if contains(keys(try(var.guardrail.content_filters, {})), c)],\n'
        '    [for c in keys(try(var.guardrail.content_filters, {})) : c if !contains(local.filter_order, c)])\n'
        '  filters = [for cls in local.filter_types : {\n'
        '    type            = cls\n'
        '    input_strength  = var.guardrail.content_filters[cls]\n'
        '    output_strength = contains(local.input_only_filters, cls) ? "NONE" : var.guardrail.content_filters[cls]\n'
        '  }]\n'
        '  pii    = [for t in local.pii_types : { type = t, action = contains(local.contextual_entities, t) ? local.ctx_action : local.pii_action }]\n'
        '  topics = [for t in try(var.guardrail.denied_topics, []) : { name = t, definition = t, type = "DENY" }]\n\n'
        '  # SGEA tier -> Bedrock tier. standard = CLASSIC (in-region); standard-plus = STANDARD,\n'
        '  # which routes through a same-geo guardrail profile (cross-region within the geo).\n'
        '  tier        = try(var.guardrail.tier, "standard") == "standard-plus" ? "STANDARD" : "CLASSIC"\n'
        '  profile_arn = "arn:${data.aws_partition.this.partition}:bedrock:${data.aws_region.this.region}:${data.aws_caller_identity.this.account_id}:guardrail-profile/${var.inference_profile_geo}.guardrail.v1:0"\n'
        '}\n\n'
        'data "aws_partition" "this" {}\n'
        'data "aws_region" "this" {}\n'
        'data "aws_caller_identity" "this" {}\n\n'
        '# OFFICIAL resource (hashicorp/aws, Bedrock API directly). Not awscc: Cloud Control applies\n'
        '# updates as a patch over the live model, which reports RegexesConfig = [] and then fails its\n'
        '# own minItems validation, so every in-place guardrail change failed (sandbox, 2026-10-15).\n'
        'resource "aws_bedrock_guardrail" "this" {\n'
        '  name                      = var.name\n'
        '  blocked_input_messaging   = "Blocked by enclave guardrail."\n'
        '  blocked_outputs_messaging = "Blocked by enclave guardrail."\n'
        '  kms_key_arn               = var.kms_key_arn\n'
        '  content_policy_config {\n'
        '    dynamic "filters_config" {\n'
        '      for_each = local.filters\n'
        '      content {\n'
        '        type            = filters_config.value.type\n'
        '        input_strength  = filters_config.value.input_strength\n'
        '        output_strength = filters_config.value.output_strength\n'
        '      }\n'
        '    }\n'
        '    tier_config {\n'
        '      tier_name = local.tier\n'
        '    }\n'
        '  }\n'
        '  dynamic "cross_region_config" {\n'
        '    for_each = local.tier == "STANDARD" ? [1] : []\n'
        '    content {\n'
        '      guardrail_profile_identifier = local.profile_arn\n'
        '    }\n'
        '  }\n'
        '  dynamic "sensitive_information_policy_config" {\n'
        '    for_each = length(local.pii) == 0 ? [] : [1]\n'
        '    content {\n'
        '      dynamic "pii_entities_config" {\n'
        '        for_each = local.pii\n'
        '        content {\n'
        '          type   = pii_entities_config.value.type\n'
        '          action = pii_entities_config.value.action\n'
        '        }\n'
        '      }\n'
        '    }\n'
        '  }\n'
        '  dynamic "topic_policy_config" {\n'
        '    for_each = length(local.topics) == 0 ? [] : [1]\n'
        '    content {\n'
        '      dynamic "topics_config" {\n'
        '        for_each = local.topics\n'
        '        content {\n'
        '          name       = topics_config.value.name\n'
        '          definition = topics_config.value.definition\n'
        '          type       = topics_config.value.type\n'
        '          examples   = []\n'
        '        }\n'
        '      }\n'
        '      tier_config {\n'
        '        tier_name = local.tier\n'
        '      }\n'
        '    }\n'
        '  }\n'
        '  tags = var.tags\n'
        '}\n\n'
        '# Immutable numbered version (enforcement references versions, not DRAFT);\n'
        '# re-cut whenever the guardrail definition changes.\n'
        'resource "awscc_bedrock_guardrail_version" "this" {\n'
        '  guardrail_identifier = aws_bedrock_guardrail.this.guardrail_id\n'
        '  description          = "SGEA ${var.name}"\n'
        '  lifecycle {\n'
        '    replace_triggered_by  = [aws_bedrock_guardrail.this]\n'
        '    create_before_destroy = true # enforced config moves to the new version before the old is deleted\n'
        '  }\n'
        '}\n\n'
        '# SGEA-BR-03: L2 account-baseline level = account-enforced guardrail on every invocation.\n'
        'resource "awscc_bedrock_enforced_guardrail_configuration" "this" {\n'
        '  count                = var.enforce_account_wide ? 1 : 0\n'
        '  guardrail_identifier = aws_bedrock_guardrail.this.guardrail_id # API stores the id (an ARN here diffs forever)\n'
        '  guardrail_version    = awscc_bedrock_guardrail_version.this.version\n'
        '  # SGEA-BR-03a: every user message / tool result is guarded regardless of guardContent tags;\n'
        '  # the developer-authored system prompt only where tagged (whole-prompt evaluation trips PROMPT_ATTACK).\n'
        '  selective_content_guarding = {\n'
        '    messages = "COMPREHENSIVE"\n'
        '    system   = "SELECTIVE"\n'
        '  }\n'
        '}\n')
    outputs = ('output "guardrail_id" { value = aws_bedrock_guardrail.this.guardrail_id }\n'
               'output "guardrail_arn" { value = aws_bedrock_guardrail.this.guardrail_arn }\n'
               'output "guardrail_version" { value = awscc_bedrock_guardrail_version.this.version }\n')
    readme = ("# bedrock-guardrail (SGEA wrapper seam)\n\n"
              "**Seam kind:** official pass-through -> `aws_bedrock_guardrail` "
              "(Bedrock API; CDK uses CloudFormation `AWS::Bedrock::Guardrail`). Not awscc: Cloud Control guardrail updates fail on an empty RegexesConfig.\n\n"
              "Maps the SGEA resolved-config `guardrails` block (content-filter strengths, PII/PHI "
              "entities) onto the official resource. No resource logic lives here.\n\n"
              "**Swap later:** if AWS publishes an official guardrail module, change this file only; "
              "the module's input surface (the resolved-config shape) stays the same, so the root "
              "stack is untouched.\n\n"
              "> Attribute names are confirmed on first `sgea verify` (`terraform validate`).\n")
    return {"versions.tf": _versions_tf(partition, True), "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme}


def _mod_bedrock_kb(partition):
    variables = (_seam_header("bedrock-knowledge-base", SEAM_OFFICIAL, "awscc_bedrock_knowledge_base (RDS/Aurora)",
                              "slot an official module behind this wrapper if one supports Aurora without OpenSearch") +
        'variable "name" { type = string }\n'
        'variable "role_arn" { type = string }\n'
        'variable "embedding_model_arn" { type = string }\n'
        'variable "aurora" {\n  description = "Aurora/pgvector storage inputs (cluster ARN, secret ARN, db, table, columns)."\n  type = object({\n'
        '    resource_arn        = string\n    credentials_secret_arn = string\n    database_name       = string\n    table_name          = string\n    primary_key_field   = string\n    vector_field        = string\n    text_field          = string\n    metadata_field      = string\n  })\n}\n'
        'variable "tags" {\n  type = map(string)\n  default = {}\n}\n')
    main = (_seam_header("bedrock-knowledge-base", SEAM_OFFICIAL, "awscc_bedrock_knowledge_base", "swap internals only") +
        '# OFFICIAL resource (CFN AWS::Bedrock::KnowledgeBase via awscc), RDS/Aurora storage.\n'
        '# Aurora PostgreSQL/pgvector is a first-class Bedrock KB vector store (RDS Data API),\n'
        '# so the enclave Aurora-only decision is met WITHOUT OpenSearch Serverless or S3 Vectors.\n'
        'resource "awscc_bedrock_knowledge_base" "this" {\n'
        '  name     = var.name\n'
        '  role_arn = var.role_arn\n'
        '  knowledge_base_configuration = {\n'
        '    type = "VECTOR"\n'
        '    vector_knowledge_base_configuration = { embedding_model_arn = var.embedding_model_arn }\n'
        '  }\n'
        '  storage_configuration = {\n'
        '    type = "RDS"\n'
        '    rds_configuration = {\n'
        '      resource_arn           = var.aurora.resource_arn\n'
        '      credentials_secret_arn = var.aurora.credentials_secret_arn\n'
        '      database_name          = var.aurora.database_name\n'
        '      table_name             = var.aurora.table_name\n'
        '      field_mapping = {\n'
        '        primary_key_field = var.aurora.primary_key_field\n'
        '        vector_field      = var.aurora.vector_field\n'
        '        text_field        = var.aurora.text_field\n'
        '        metadata_field    = var.aurora.metadata_field\n'
        '      }\n'
        '    }\n'
        '  }\n'
        '  tags = var.tags\n'
        '}\n')
    outputs = ('output "knowledge_base_id" { value = awscc_bedrock_knowledge_base.this.knowledge_base_id }\n')
    readme = ("# bedrock-knowledge-base (SGEA wrapper seam)\n\n"
              "**Seam kind:** official pass-through -> `awscc_bedrock_knowledge_base` with an **RDS "
              "(Aurora PostgreSQL/pgvector)** storage configuration.\n\n"
              "This is how the enclave's Aurora-only vector-store decision is honored *with* an "
              "official resource: Bedrock Knowledge Bases support Aurora via the RDS Data API, so no "
              "OpenSearch Serverless / S3 Vectors dependency is needed. `aws-ia/bedrock` is "
              "deliberately NOT used here because it depends on OpenSearch (ADR 0001).\n\n"
              "**Swap later:** if an official module supports Aurora KBs cleanly, point this wrapper "
              "at it; the root stack keeps passing the same `aurora` object.\n")
    return {"versions.tf": _versions_tf(partition, True), "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme}


def _mod_agentcore_runtime(partition):
    variables = (_seam_header("agentcore-runtime", SEAM_OFFICIAL, "awscc_bedrockagentcore_runtime",
                              "swap to an official AgentCore module when aws-ia publishes one") + """\
variable "name" { type = string }
variable "execution_role_arn" { type = string }
variable "container_uri" { type = string }
# SGEA-AC-RT-01..03: runtimes always run inside the enclave VPC (no PUBLIC mode).
variable "subnet_ids" {
  type = list(string)
  validation {
    condition     = length(var.subnet_ids) > 0
    error_message = "SGEA-AC-RT-02: VPC network mode requires private enclave subnets."
  }
}
variable "security_group_ids" {
  type = list(string)
  validation {
    condition     = length(var.security_group_ids) > 0
    error_message = "SGEA-AC-RT-03: VPC network mode requires security groups."
  }
}
# SGEA-AC-RT-04: inbound calls authenticate end users against the organization IdP.
variable "jwt_discovery_url" { type = string }
variable "jwt_allowed_clients" {
  type    = list(string)
  default = []
}
variable "jwt_allowed_audience" {
  type    = list(string)
  default = []
}
# SGEA-AC-RT-06: FedRAMP SC-10 bounds idle user sessions at 15 minutes.
variable "idle_session_timeout_seconds" {
  type    = number
  default = 900
  validation {
    condition     = var.idle_session_timeout_seconds <= 900
    error_message = "SGEA-AC-RT-06: idle_runtime_session_timeout must be <= 900 seconds."
  }
}
variable "max_lifetime_seconds" {
  type    = number
  default = 28800
}
# SGEA-AC-ID-04: enclave AgentCore VPC endpoint id(s) callers must come through.
variable "allowed_source_vpce_ids" {
  description = "bedrock-agentcore interface endpoint ids. Empty = no network restriction (SGEA-AC-ID-04 unmet)."
  type        = list(string)
  default     = []
}
# SGEA-AC-RT-07: forward only allow-listed request headers into agent code.
variable "request_header_allowlist" {
  type    = list(string)
  default = []
}
variable "environment" {
  type    = map(string)
  default = {}
}
variable "tags" {
  type    = map(string)
  default = {}
}
""")
    main = (_seam_header("agentcore-runtime", SEAM_OFFICIAL, "awscc_bedrockagentcore_runtime", "swap internals only") + """\
# OFFICIAL resource (CFN AWS::BedrockAgentCore::Runtime via awscc). awscc is the official
# Terraform path for AgentCore — generated from the CFN registry, available commercial + GovCloud.
resource "awscc_bedrockagentcore_runtime" "this" {
  agent_runtime_name = var.name
  role_arn           = var.execution_role_arn
  agent_runtime_artifact = {
    container_configuration = { container_uri = var.container_uri }
  }
  network_configuration = {
    network_mode = "VPC"
    network_mode_config = {
      subnets         = var.subnet_ids
      security_groups = var.security_group_ids
    }
  }
  authorizer_configuration = {
    custom_jwt_authorizer = {
      discovery_url    = var.jwt_discovery_url
      allowed_clients  = length(var.jwt_allowed_clients) > 0 ? var.jwt_allowed_clients : null
      allowed_audience = length(var.jwt_allowed_audience) > 0 ? var.jwt_allowed_audience : null
    }
  }
  lifecycle_configuration = {
    idle_runtime_session_timeout = var.idle_session_timeout_seconds
    max_lifetime                 = var.max_lifetime_seconds
  }
  request_header_configuration = length(var.request_header_allowlist) == 0 ? null : {
    request_header_allowlist = var.request_header_allowlist
  }
  environment_variables = var.environment
  tags                  = var.tags
}

# SGEA-AC-ID-04: network-restrict invocation. The runtime uses OAuth (custom JWT) inbound auth, for
# which AWS requires a wildcard principal and recommends network conditions (aws:SourceVpce) —
# account conditions do not apply to JWT callers (AWS docs: resource-based-policies; verified in sandbox).
# Without endpoint ids NO resource policy is emitted (never an unconditioned wildcard Allow); the JWT
# authorizer still gates every call and `sgea check` reports SGEA-AC-ID-04 unmet.
resource "awscc_bedrockagentcore_resource_policy" "this" {
  count        = length(var.allowed_source_vpce_ids) > 0 ? 1 : 0
  resource_arn = awscc_bedrockagentcore_runtime.this.agent_runtime_arn
  policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Sid       = "AllowOnlyThroughEnclaveEndpoints"
    Effect    = "Allow"
    Principal = "*"
    Action    = "bedrock-agentcore:InvokeAgentRuntime"
    Resource  = awscc_bedrockagentcore_runtime.this.agent_runtime_arn
    Condition = { StringEquals = { "aws:SourceVpce" = var.allowed_source_vpce_ids } }
  }] })
}
""")
    outputs = ('output "agent_runtime_arn" { value = awscc_bedrockagentcore_runtime.this.agent_runtime_arn }\n'
               'output "agent_runtime_id" { value = awscc_bedrockagentcore_runtime.this.agent_runtime_id }\n')
    readme = ("# agentcore-runtime (SGEA wrapper seam)\n\n"
              "**Seam kind:** official pass-through -> `awscc_bedrockagentcore_runtime` "
              "(CloudFormation `AWS::BedrockAgentCore::Runtime`).\n\n"
              "Enforces the SGEA-inferred runtime controls (`sources/inferred/service-controls.yaml`): "
              "VPC-only networking (RT-01..03), custom JWT inbound auth (RT-04), idle session <= 900 s "
              "(RT-06), request-header allow-list (RT-07). `PUBLIC` mode is not exposed.\n\n"
              "**Swap later:** replace with an `aws-ia` AgentCore module if/when one is published; "
              "callers keep the same resolved-config inputs.\n")
    return {"versions.tf": _versions_tf(partition, True), "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme}


# -------------------- enclave foundation wrapper modules --------------------
def _mod_enclave_kms(partition):
    variables = (_seam_header("enclave-kms", SEAM_RAW, "raw aws_kms_key", "point at an official KMS module") + """\
variable "env" { type = string }
variable "config_service_role_arn" {
  description = "AWS Config service-linked role ARN (root stack). null = the role already exists (landing zone)."
  type        = string
  default     = null
}
variable "tags" {
  type    = map(string)
  default = {}
}
""")
    main = (_seam_header("enclave-kms", SEAM_OFFICIAL, "terraform-aws-modules/kms/aws 4.2.2", "swap internals only") + """\
# Enclave customer-managed key (kms-cmk-not-scheduled-for-deletion, *-encrypted-kms,
# SGEA-*-KMS) via terraform-aws-modules/kms. Created only when kms_key_arn is not supplied.
data "aws_caller_identity" "this" {}
data "aws_partition" "this" {}
data "aws_region" "this" {}

locals {
  account = data.aws_caller_identity.this.account_id
  arn     = data.aws_partition.this.partition
  region  = data.aws_region.this.region
}

module "kms" {
  source  = "terraform-aws-modules/kms/aws"
  version = "4.2.2"

  description             = "SGEA enclave CMK (${var.env})"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  aliases                 = ["sgea-${var.env}"]
  enable_default_policy   = true # account root administers the key

  key_statements = [
    {
      sid        = "CloudWatchLogs"
      actions    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
      resources  = ["*"]
      principals = [{ type = "Service", identifiers = ["logs.${local.region}.amazonaws.com"] }]
      condition  = [{ test = "ArnLike", variable = "kms:EncryptionContext:aws:logs:arn", values = ["arn:${local.arn}:logs:${local.region}:${local.account}:*"] }]
    },
    {
      sid        = "CloudTrail"
      actions    = ["kms:GenerateDataKey*", "kms:DescribeKey"]
      resources  = ["*"]
      principals = [{ type = "Service", identifiers = ["cloudtrail.amazonaws.com"] }]
      condition  = [{ test = "StringLike", variable = "kms:EncryptionContext:aws:cloudtrail:arn", values = ["arn:${local.arn}:cloudtrail:*:${local.account}:trail/*"] }]
    },
    {
      # AWS Config's service-linked role delivering to the SSE-KMS stores. Named directly (no wildcard
      # principal, CKV_AWS_33): the root stack creates the role before this key.
      sid        = "ConfigDelivery"
      actions    = ["kms:GenerateDataKey*", "kms:Decrypt"]
      resources  = ["*"]
      principals = [{ type = "AWS", identifiers = [coalesce(var.config_service_role_arn, "arn:${local.arn}:iam::${local.account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig")] }]
    },
    {
      # AWS Config's delivery-channel writability check runs as the service principal (verified in sandbox).
      sid        = "ConfigServicePrincipal"
      actions    = ["kms:Decrypt", "kms:GenerateDataKey"]
      resources  = ["*"]
      principals = [{ type = "Service", identifiers = ["config.amazonaws.com"] }]
      condition  = [{ test = "StringEquals", variable = "aws:SourceAccount", values = [local.account] }]
    },
    {
      sid        = "BedrockInvocationLogDelivery"
      actions    = ["kms:GenerateDataKey*", "kms:Decrypt"]
      resources  = ["*"]
      principals = [{ type = "Service", identifiers = ["bedrock.amazonaws.com"] }]
      condition  = [{ test = "StringEquals", variable = "aws:SourceAccount", values = [local.account] }]
    },
    {
      # S3 event notifications publish to the CMK-encrypted log-store-events topic.
      sid        = "S3EventNotificationsToEncryptedSns"
      actions    = ["kms:GenerateDataKey*", "kms:Decrypt"]
      resources  = ["*"]
      principals = [{ type = "Service", identifiers = ["s3.amazonaws.com"] }]
      condition  = [{ test = "StringEquals", variable = "aws:SourceAccount", values = [local.account] }]
    },
    {
      # CloudWatch alarms publish to the CMK-encrypted security-alarm topic (sns-encrypted-kms).
      sid        = "CloudWatchAlarmsToEncryptedSns"
      actions    = ["kms:GenerateDataKey*", "kms:Decrypt"]
      resources  = ["*"]
      principals = [{ type = "Service", identifiers = ["cloudwatch.amazonaws.com"] }]
      condition  = [{ test = "StringEquals", variable = "aws:SourceAccount", values = [local.account] }]
    },
    {
      # ADR 0002: EventBridge rules, AWS Budgets and Cost Anomaly Detection publish to the CMK-encrypted
      # security-alarm topic.
      sid        = "EventDeliveryToEncryptedSns"
      actions    = ["kms:GenerateDataKey*", "kms:Decrypt"]
      resources  = ["*"]
      # AWS Budgets / Cost Anomaly Detection do not run in AWS GovCloud (US): named only in the commercial partition.
      principals = [{ type = "Service", identifiers = local.arn == "aws-us-gov" ? ["events.amazonaws.com"] : ["events.amazonaws.com", "budgets.amazonaws.com", "costalerts.amazonaws.com"] }]
      condition  = [{ test = "StringEquals", variable = "aws:SourceAccount", values = [local.account] }]
    },
  ]
  tags = var.tags
}
""")
    outputs = 'output "key_arn" { value = module.kms.key_arn }\n'
    readme = ("# enclave-kms (SGEA wrapper seam)\n\n"
              "Enclave CMK with annual rotation and a 30-day deletion window; key policy admits "
              "CloudWatch Logs, CloudTrail and Bedrock invocation-log delivery for this account only. "
              "Instantiated by the root stack only when `kms_key_arn` is not supplied.\n")
    return {"versions.tf": _versions_tf(partition, False), "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme}


def _mod_enclave_logging(partition):
    variables = (_seam_header("enclave-logging", SEAM_RAW, "raw S3 / CloudWatch / CloudTrail / Bedrock logging",
                              "point at an official logging module") + """\
variable "env" { type = string }
variable "kms_key_arn" { type = string }
variable "config_service_role_arn" {
  description = "AWS Config service-linked role ARN (root stack). null = the role already exists (landing zone)."
  type        = string
  default     = null
}
variable "logging" {
  description = "SGEA resolved-config logging block (retention_days pre-rounded to a CloudWatch value)."
  type        = any
}
variable "cloudwatch_retention_days" { type = number }
variable "replica_region" {
  description = "Second allowed region for the log-store replica (inside regions.allowed)."
  type        = string
}
variable "data_event_resource_types" {
  description = "CloudTrail data-event resources.type values derived from logging.cloudtrail_data_events."
  type        = list(string)
  default     = []
}
variable "event_publishers" {
  description = "ADR 0002 M1: EventBridge rules sgea-<env>-evt-* publish to the security-alarm topic (topic policy)."
  type        = bool
  default     = false
}
variable "cost_publishers" {
  description = "ADR 0002 M4: AWS Budgets / Cost Anomaly Detection publish to the security-alarm topic (topic policy)."
  type        = bool
  default     = false
}
variable "tags" {
  type    = map(string)
  default = {}
}
""")
    main = (_seam_header("enclave-logging", SEAM_RAW, "raw S3 / CloudWatch / CloudTrail / Bedrock logging",
                         "swap internals only") + """\
data "aws_caller_identity" "this" {}
data "aws_partition" "this" {}
data "aws_region" "this" {}

locals {
  account   = data.aws_caller_identity.this.account_id
  arn       = data.aws_partition.this.partition
  region    = data.aws_region.this.region
  retention = var.logging.retention_days
  lock      = try(var.logging.most_sensitive_store, false)
  trail     = "sgea-${var.env}"
}

# ----- log storage: most-sensitive store + access-log sink + cross-region replica -----
locals {
  log_store_name = "sgea-${var.env}-logs-${local.account}-${local.region}"
  access_name    = "sgea-${var.env}-access-logs-${local.account}-${local.region}"
  replica_name   = "sgea-${var.env}-logs-replica-${local.account}-${var.replica_region}"
  replica_access = "sgea-${var.env}-access-logs-${local.account}-${var.replica_region}"
  log_store_arn  = "arn:${local.arn}:s3:::${local.log_store_name}"
  config_name    = "sgea-${var.env}-config-${local.account}-${local.region}"
  config_arn     = "arn:${local.arn}:s3:::${local.config_name}"
  trail_arn      = "arn:${local.arn}:cloudtrail:${local.region}:${local.account}:trail/${local.trail}"
}

module "log_store" {
  source            = "./bucket"
  name              = local.log_store_name
  kms_key_arn       = var.kms_key_arn
  object_lock       = local.lock
  retention_days    = local.retention
  access_logging    = true
  log_target_bucket = module.access_logs.name
  role              = "log-store"
  notify                 = true
  notification_topic_arn = aws_sns_topic_policy.log_store_events.arn # via the policy: S3 validates the destination
  replication = {
    role = aws_iam_role.replication.arn
    rules = [{
      id                        = "replicate-all"
      status                    = "Enabled"
      priority                  = 1
      filter                    = { prefix = "" }
      delete_marker_replication = false
      source_selection_criteria = { sse_kms_encrypted_objects = { enabled = true } }
      destination = {
        bucket             = module.replica.arn
        storage_class      = "STANDARD"
        replica_kms_key_id = aws_kms_key.replica.arn
      }
    }]
  }
  tags              = var.tags
  extra_statements = [
    {
      Sid       = "CloudTrailAclCheck"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:GetBucketAcl"
      Resource  = local.log_store_arn
      Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
    },
    {
      Sid       = "CloudTrailWrite"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${local.log_store_arn}/cloudtrail/AWSLogs/${local.account}/*"
      Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
    },
    {
      Sid       = "BedrockInvocationLogWrite"
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${local.log_store_arn}/bedrock/*"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account }
        ArnLike      = { "aws:SourceArn" = "arn:${local.arn}:bedrock:${local.region}:${local.account}:*" }
      }
    },
  ]
}

# AWS Config delivery bucket. Same hardening as the log store minus Object Lock: S3 requires a
# checksum header on writes to Object Lock buckets and the AWS Config writer does not send one
# (verified in sandbox: InsufficientDeliveryPolicyException). Tagged sgea:role=config-delivery.
module "config_store" {
  source            = "./bucket"
  name              = local.config_name
  kms_key_arn       = var.kms_key_arn
  object_lock       = false
  retention_days    = local.retention
  access_logging    = true
  log_target_bucket = module.access_logs.name
  role              = "config-delivery"
  notify                 = true
  notification_topic_arn = aws_sns_topic_policy.log_store_events.arn # via the policy: S3 validates the destination
  tags              = var.tags
  extra_statements = [
    {
      Sid       = "ConfigBucketCheck"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
      Resource  = local.config_arn
      Condition = { StringEquals = { "AWS:SourceAccount" = local.account } }
    },
    {
      Sid       = "ConfigDelivery"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${local.config_arn}/config/AWSLogs/${local.account}/Config/*"
      Condition = { StringEquals = { "AWS:SourceAccount" = local.account, "s3:x-amz-acl" = "bucket-owner-full-control" } }
    },
    {
      Sid       = "ConfigServiceLinkedRole"
      Effect    = "Allow"
      Principal = { AWS = coalesce(var.config_service_role_arn, "arn:${local.arn}:iam::${local.account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig") }
      Action    = ["s3:GetBucketAcl", "s3:ListBucket", "s3:PutObject"]
      Resource  = [local.config_arn, "${local.config_arn}/config/AWSLogs/${local.account}/Config/*"]
    },
  ]
}

# Server-access-log sink (s3-bucket-logging-enabled target). Tagged sgea:role=access-log-sink:
# a sink cannot log to itself, so it is the documented exemption for that rule.
module "access_logs" {
  source                 = "./bucket"
  name                   = local.access_name
  kms_key_arn            = var.kms_key_arn
  sse_algorithm          = "AES256" # S3 server access logging delivery does not support SSE-KMS targets
  object_lock            = false
  retention_days         = local.retention
  role                   = "access-log-sink" # module attaches the S3 server-access-log delivery policy
  notify                 = true
  notification_topic_arn = aws_sns_topic_policy.log_store_events.arn # via the policy: S3 validates the destination
  tags                   = var.tags
}

# ----- cross-region replica (s3-bucket-replication-enabled, CP-9 / CP-6) -----
resource "aws_kms_key" "replica" {
  provider                = aws.replica
  description             = "SGEA log replica CMK (${var.env})"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountAdministration"
      Effect    = "Allow"
      Principal = { AWS = "arn:${local.arn}:iam::${local.account}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
  tags = var.tags
}

module "replica" {
  source            = "./bucket"
  providers         = { aws = aws.replica }
  name              = local.replica_name
  kms_key_arn       = aws_kms_key.replica.arn
  object_lock       = local.lock
  retention_days    = local.retention
  access_logging    = true
  log_target_bucket = module.replica_access_logs.name
  role              = "replica"
  tags              = merge(var.tags, { "sgea:region" = "replica" }) # not evaluated by the primary-region packs
}

# Access-log sink in the replica region (log delivery targets must be same-region).
module "replica_access_logs" {
  source         = "./bucket"
  providers      = { aws = aws.replica }
  name           = local.replica_access
  kms_key_arn    = aws_kms_key.replica.arn
  sse_algorithm  = "AES256"
  object_lock    = false
  retention_days = local.retention
  role           = "access-log-sink" # module attaches the S3 server-access-log delivery policy
  tags           = merge(var.tags, { "sgea:region" = "replica" }) # not evaluated by the primary-region packs
}

resource "aws_iam_role" "replication" {
  name = "sgea-${var.env}-log-replication"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "s3.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}

# iam-no-inline-policy-check: customer-managed policy + attachment (no inline role policies).
resource "aws_iam_policy" "replication" {
  name = "sgea-${var.env}-replication"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetReplicationConfiguration", "s3:ListBucket"], Resource = local.log_store_arn },
      { Effect = "Allow", Action = ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging", "s3:GetObjectRetention", "s3:GetObjectLegalHold"], Resource = "${local.log_store_arn}/*" },
      { Effect = "Allow", Action = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"], Resource = "${module.replica.arn}/*" }, # same-account replica: no ObjectOwnerOverrideToBucketOwner
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = var.kms_key_arn },
      { Effect = "Allow", Action = ["kms:Encrypt", "kms:GenerateDataKey"], Resource = aws_kms_key.replica.arn },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "replication" {
  role       = aws_iam_role.replication.id
  policy_arn = aws_iam_policy.replication.arn
}

# ----- log-store event notifications (s3-event-notifications-enabled): object removals -> SNS (CMK) -----
resource "aws_sns_topic" "log_store_events" {
  name              = "sgea-${var.env}-log-store-events"
  kms_master_key_id = var.kms_key_arn
  tags              = var.tags
}

resource "aws_sns_topic_policy" "log_store_events" {
  arn = aws_sns_topic.log_store_events.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "S3EventNotifications"
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.log_store_events.arn
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account }
        ArnLike      = { "aws:SourceArn" = "arn:${local.arn}:s3:::sgea-${var.env}-*" }
      }
    }]
  })
}

# ----- enclave security alarms topic (cloudwatch-alarm-action-check, sns-encrypted-kms) -----
resource "aws_sns_topic" "security_alarms" {
  name              = "sgea-${var.env}-security-alarms"
  kms_master_key_id = var.kms_key_arn
  tags              = var.tags
}

# ADR 0002: service publishers of the monitoring layer. Written only when the layer is on; it replaces
# the default topic policy, so it keeps owner access and the CloudWatch-alarm publisher explicitly.
resource "aws_sns_topic_policy" "security_alarms" {
  count = var.event_publishers || var.cost_publishers ? 1 : 0
  arn   = aws_sns_topic.security_alarms.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "OwnerAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.arn}:iam::${local.account}:root" }
        Action    = ["sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:AddPermission", "sns:RemovePermission", "sns:DeleteTopic", "sns:Subscribe", "sns:ListSubscriptionsByTopic", "sns:Publish"]
        Resource  = aws_sns_topic.security_alarms.arn
      },
      {
        Sid       = "CloudWatchAlarms"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.security_alarms.arn
        Condition = { StringEquals = { "aws:SourceAccount" = local.account } }
      },
      ], var.event_publishers ? [{
        Sid       = "EventBridgeRules"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.security_alarms.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account }
          ArnLike      = { "aws:SourceArn" = "arn:${local.arn}:events:${local.region}:${local.account}:rule/sgea-${var.env}-evt-*" }
        }
      }] : [], var.cost_publishers ? [
      {
        Sid       = "Budgets"
        Effect    = "Allow"
        Principal = { Service = "budgets.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.security_alarms.arn
        Condition = { StringEquals = { "aws:SourceAccount" = local.account } }
      },
      {
        Sid       = "CostAnomalyDetection"
        Effect    = "Allow"
        Principal = { Service = "costalerts.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.security_alarms.arn
        Condition = { StringEquals = { "aws:SourceAccount" = local.account } }
      },
    ] : [])
  })
}

# ----- CloudWatch log groups (cw-loggroup-retention-period-check, cloudwatch-log-group-encrypted) -----
module "log_group" {
  source   = "terraform-aws-modules/cloudwatch/aws//modules/log-group"
  version  = "5.7.3"
  for_each = { bedrock_invocations = "bedrock/model-invocations", agentcore = "agentcore", cloudtrail = "cloudtrail" }

  name              = "/sgea/${var.env}/${each.value}"
  retention_in_days = var.cloudwatch_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

# ----- Bedrock model-invocation logging (SGEA-BR-01/02) -----
resource "aws_iam_role" "bedrock_logging" {
  count = var.logging.model_invocation_logging ? 1 : 0
  name  = "sgea-${var.env}-bedrock-invocation-logging"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = local.account }
        ArnLike      = { "aws:SourceArn" = "arn:${local.arn}:bedrock:${local.region}:${local.account}:*" }
      }
    }]
  })
  tags = var.tags
}

# iam-no-inline-policy-check: customer-managed policy + attachment (no inline role policies).
resource "aws_iam_policy" "bedrock_logging" {
  count = var.logging.model_invocation_logging ? 1 : 0
  name = "sgea-${var.env}-bedrock-logging"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${module.log_group["bedrock_invocations"].cloudwatch_log_group_arn}:*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "bedrock_logging" {
  count = var.logging.model_invocation_logging ? 1 : 0
  role       = aws_iam_role.bedrock_logging[0].id
  policy_arn = aws_iam_policy.bedrock_logging[0].arn
}

resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  count = var.logging.model_invocation_logging ? 1 : 0
  logging_config {
    text_data_delivery_enabled      = true
    image_data_delivery_enabled     = true
    embedding_data_delivery_enabled = true
    video_data_delivery_enabled     = true
    cloudwatch_config {
      log_group_name = module.log_group["bedrock_invocations"].cloudwatch_log_group_name
      role_arn       = aws_iam_role.bedrock_logging[0].arn
      large_data_delivery_s3_config {
        bucket_name = module.log_store.name
        key_prefix  = "bedrock/large-data"
      }
    }
    s3_config {
      bucket_name = module.log_store.name
      key_prefix  = "bedrock/invocations"
    }
  }
  depends_on = [module.log_store, aws_iam_role_policy_attachment.bedrock_logging]
}

# ----- CloudTrail (cloudtrail-enabled, multi-region, log-file validation, encrypted, CW integration) -----
resource "aws_iam_role" "cloudtrail" {
  name = "sgea-${var.env}-cloudtrail-to-cloudwatch"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

# iam-no-inline-policy-check: customer-managed policy + attachment (no inline role policies).
resource "aws_iam_policy" "cloudtrail" {
  name = "sgea-${var.env}-cloudtrail"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${module.log_group["cloudtrail"].cloudwatch_log_group_arn}:*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cloudtrail" {
  role       = aws_iam_role.cloudtrail.id
  policy_arn = aws_iam_policy.cloudtrail.arn
}

resource "aws_cloudtrail" "this" {
  name                          = local.trail
  s3_bucket_name                = module.log_store.name
  s3_key_prefix                 = "cloudtrail"
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = var.kms_key_arn
  cloud_watch_logs_group_arn    = "${module.log_group["cloudtrail"].cloudwatch_log_group_arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail.arn

  advanced_event_selector {
    name = "management-events"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  # SGEA-AC-LOG-03: data events for the enclave's AI / data services.
  dynamic "advanced_event_selector" {
    for_each = toset(var.data_event_resource_types)
    content {
      name = "data-events-${advanced_event_selector.value}"
      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }
      field_selector {
        field  = "resources.type"
        equals = [advanced_event_selector.value]
      }
      # Never log the trail's own deliveries to the log store (AWS best practice).
      dynamic "field_selector" {
        for_each = advanced_event_selector.value == "AWS::S3::Object" ? [1] : []
        content {
          field           = "resources.ARN"
          not_starts_with = ["${local.log_store_arn}/"]
        }
      }
    }
  }

  tags       = var.tags
  depends_on = [module.log_store, aws_iam_role_policy_attachment.cloudtrail]
}
""")
    outputs = ('output "log_bucket" { value = module.log_store.name }\n'
               'output "agentcore_log_group" { value = module.log_group["agentcore"].cloudwatch_log_group_name }\n'
               'output "invocation_log_group" { value = module.log_group["bedrock_invocations"].cloudwatch_log_group_name }\n'
               'output "config_bucket" { value = module.config_store.name }\n'
               'output "log_bucket_arn" { value = module.log_store.arn }\n'
               'output "alarm_topic_arn" { value = aws_sns_topic.security_alarms.arn }\n'
               '# Same topic, available only once its publisher policy exists (Budgets validates it at create).\n'
               'output "monitoring_topic_arn" {\n  value      = aws_sns_topic.security_alarms.arn\n  depends_on = [aws_sns_topic_policy.security_alarms]\n}\n'
               'output "cloudtrail_log_group" { value = module.log_group["cloudtrail"].cloudwatch_log_group_name }\n'
               'output "config_bucket_arn" { value = module.config_store.arn }\n'
               'output "trail_arn" { value = aws_cloudtrail.this.arn }\n')
    versions = ("terraform {\n  required_version = \">= 1.11\"\n  required_providers {\n"
                '    aws = {\n      source                = "hashicorp/aws"\n      version               = ">= 6.0"\n'
                '      configuration_aliases = [aws.replica]\n    }\n  }\n}\n')
    readme = ("# enclave-logging (SGEA wrapper seam)\n\n"
              "Driven by the resolved-config `logging` block:\n\n"
              "- **Most-sensitive store** — S3, ACLs disabled, public access blocked, versioned, SSE-KMS "
              "(enclave CMK), TLS-only policy, Object Lock (GOVERNANCE) when `most_sensitive_store`, "
              "expiry at `retention_days`.\n"
              "- **CloudWatch log groups** for Bedrock invocations, AgentCore and CloudTrail at "
              "`retention_days` (rounded up to a value CloudWatch accepts), KMS-encrypted.\n"
              "- **Bedrock model-invocation logging** to S3 + CloudWatch when `model_invocation_logging`.\n"
              "- **CloudTrail** — multi-region, log-file validation, KMS, CloudWatch integration, data "
              "events per `cloudtrail_data_events`.\n\n"
              "- **Access-log sink** for S3 server access logs (exempt from logging itself, tagged "
              "`sgea:role=access-log-sink`) and a **cross-region replica** in `replica_region` with its "
              "own CMK; every bucket is built by `./bucket` (same hardening, EventBridge notifications).\n\n"
              "> CloudTrail `resources.type` values for Bedrock / AgentCore data events are validated by "
              "the service at apply time, not by `terraform validate`; confirm on first sandbox apply.\n")
    return {"versions.tf": versions, "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme,
            "bucket/versions.tf": _versions_tf(partition, False), "bucket/variables.tf": _BUCKET_VARS,
            "bucket/main.tf": _BUCKET_MAIN, "bucket/outputs.tf": _BUCKET_OUTPUTS}


# Hardened S3 bucket used for every enclave log bucket (one definition, same controls):
# s3-bucket-versioning-enabled, s3-default-encryption-kms, s3-bucket-level-public-access-prohibited,
# s3-bucket-acl-prohibited, s3-bucket-ssl-requests-only, s3-bucket-default-lock-enabled,
# s3-bucket-logging-enabled, s3-event-notifications-enabled, s3-version-lifecycle-policy-check.
_BUCKET_VARS = """\
variable "name" { type = string }
variable "kms_key_arn" { type = string }
variable "sse_algorithm" {
  type    = string
  default = "aws:kms"
}
variable "object_lock" { type = bool }
variable "retention_days" { type = number }
variable "access_logging" {
  description = "Deliver S3 server access logs to log_target_bucket."
  type        = bool
  default     = false
}
variable "log_target_bucket" {
  type    = string
  default = null
}
variable "role" {
  description = "sgea:role tag (log-store | access-log-sink | replica | config-delivery)."
  type        = string
}
variable "extra_statements" {
  description = "Additional bucket-policy statements (heterogeneous shapes, hence `any`)."
  type        = any
  default     = []
}
variable "notify" {
  description = "s3-event-notifications-enabled: send object-removal events to notification_topic_arn (primary-region stores)."
  type        = bool
  default     = false
}
variable "notification_topic_arn" {
  type    = string
  default = null
}
variable "replication" {
  description = "terraform-aws-modules/s3-bucket replication_configuration (log store only)."
  type        = any
  default     = {}
}
variable "tags" {
  type    = map(string)
  default = {}
}
"""

_BUCKET_MAIN = """\
# Every enclave log bucket = terraform-aws-modules/s3-bucket with the same controls:
# s3-bucket-versioning-enabled, s3-default-encryption-kms, s3-bucket-level-public-access-prohibited,
# s3-bucket-acl-prohibited, s3-bucket-ssl-requests-only, s3-bucket-default-lock-enabled,
# s3-bucket-logging-enabled, s3-event-notifications-enabled, s3-version-lifecycle-policy-check.
data "aws_caller_identity" "this" {}

module "bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "5.17.0"

  bucket              = var.name
  object_lock_enabled = var.object_lock
  object_lock_configuration = var.object_lock ? {
    rule = { default_retention = { mode = "GOVERNANCE", days = var.retention_days } }
  } : null

  versioning = { enabled = true }
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm     = var.sse_algorithm
        kms_master_key_id = var.sse_algorithm == "aws:kms" ? var.kms_key_arn : null
      }
      bucket_key_enabled = var.sse_algorithm == "aws:kms"
    }
  }

  block_public_acls        = true
  block_public_policy      = true
  ignore_public_acls       = true
  restrict_public_buckets  = true
  control_object_ownership = true
  object_ownership         = "BucketOwnerEnforced"

  lifecycle_rule = [{
    id                            = "retention"
    enabled                       = true
    filter                        = {}
    expiration                    = { days = var.retention_days }
    noncurrent_version_expiration = { noncurrent_days = 30 }
  }]

  logging = var.access_logging ? { target_bucket = var.log_target_bucket, target_prefix = "${var.name}/" } : null

  replication_configuration = var.replication

  attach_deny_insecure_transport_policy     = true
  attach_access_log_delivery_policy         = var.role == "access-log-sink"
  access_log_delivery_policy_source_accounts = var.role == "access-log-sink" ? [data.aws_caller_identity.this.account_id] : []
  attach_policy                             = length(var.extra_statements) > 0
  policy                                    = length(var.extra_statements) > 0 ? jsonencode({ Version = "2012-10-17", Statement = var.extra_statements }) : null

  tags = merge(var.tags, { "sgea:role" = var.role })
}

module "notification" {
  source  = "terraform-aws-modules/s3-bucket/aws//modules/notification"
  version = "5.17.0"

  bucket      = var.name # known at plan (module.bucket.s3_bucket_id is not)
  eventbridge = true
  # s3-event-notifications-enabled counts SNS / SQS / Lambda destinations (EventBridge alone fails it).
  # One topic policy for all stores lives in enclave-logging, so the module must not write its own.
  create_sns_policy = false
  sns_notifications = var.notify ? {
    removals = { topic_arn = var.notification_topic_arn, events = ["s3:ObjectRemoved:*"] }
  } : {}
  depends_on = [module.bucket]
}
"""

_BUCKET_OUTPUTS = """\
# Known at plan (deterministic name) so dependents and `sgea check` can link to it.
output "name" {
  value      = var.name
  depends_on = [module.bucket]
}
output "arn" { value = "arn:${data.aws_partition.this.partition}:s3:::${var.name}" }
data "aws_partition" "this" {}
"""


def _mod_config_conformance(partition):
    variables = (_seam_header("config-conformance", SEAM_OFFICIAL, "aws_config_conformance_pack",
                              "swap internals only") + """\
variable "packs" {
  description = "Conformance pack name -> template file under ./packs (AWS awslabs/aws-config-rules)."
  type        = map(string)
}
variable "create_config_recorder" {
  description = "Create the Config recorder + delivery channel. Leave false where Control Tower / LZA already runs one (one recorder per region)."
  type        = bool
  default     = false
}
variable "delivery_bucket" {
  type    = string
  default = null
}
variable "delivery_kms_key_arn" {
  description = "CMK of the delivery bucket (required by Config for SSE-KMS buckets)."
  type        = string
  default     = null
}
variable "env" { type = string }
""")
    main = (_seam_header("config-conformance", SEAM_OFFICIAL, "aws_config_conformance_pack", "swap internals only") + """\
# Detective coverage: one AWS-published conformance pack per composed baseline,
# templates pinned in sources/conformance-packs (see catalog/<baseline>.json).
data "aws_partition" "this" {}
data "aws_caller_identity" "this" {}

# The AWS Config service-linked role is created at the root (before the enclave CMK, whose key policy names it).
resource "aws_config_configuration_recorder" "this" {
  count    = var.create_config_recorder ? 1 : 0
  name     = "sgea-${var.env}"
  role_arn = "arn:${data.aws_partition.this.partition}:iam::${data.aws_caller_identity.this.account_id}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "this" {
  count          = var.create_config_recorder ? 1 : 0
  name           = "sgea-${var.env}"
  s3_bucket_name = var.delivery_bucket
  s3_key_prefix  = "config"
  s3_kms_key_arn = var.delivery_kms_key_arn
  depends_on     = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
  count      = var.create_config_recorder ? 1 : 0
  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
}

resource "aws_config_conformance_pack" "this" {
  for_each      = var.packs
  name          = each.key
  template_body = file("${path.module}/packs/${each.value}")
  depends_on    = [aws_config_configuration_recorder_status.this]
}
""")
    outputs = 'output "conformance_pack_arns" { value = { for k, p in aws_config_conformance_pack.this : k => p.arn } }\n'
    readme = ("# config-conformance (SGEA wrapper seam)\n\n"
              "Deploys the AWS Config conformance pack(s) named by the resolved config's "
              "`evidence.conformance_packs` — one per composed baseline (e.g. FedRAMP Moderate + "
              "HIPAA Security). Templates are copied from `sources/conformance-packs/` at the pinned "
              "awslabs/aws-config-rules commit; their parameter defaults are the framework values "
              "recorded in `catalog/<baseline>.json`.\n\n"
              "**Prerequisite:** an AWS Config recorder in the account/region. Set "
              "`create_config_recorder = true` only where Control Tower / LZA does not already run one.\n")
    return {"versions.tf": _versions_tf(partition, False), "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme}


def _mod_agentcore_platform(partition):
    variables = (_seam_header("agentcore-platform", SEAM_OFFICIAL, "awscc_bedrockagentcore_* (gateway, memory, policy engine)",
                              "swap to an official AgentCore module when aws-ia publishes one") + """\
variable "env" { type = string }
variable "kms_key_arn" { type = string }
variable "gateway_tool_path" {
  description = "SGEA guardrails.levels contains gateway_tool_path: enforce a policy engine on tool calls."
  type        = bool
}
variable "tool_policy_interceptor" {
  description = "Enforce gateway_tool_path with the SGEA REQUEST interceptor Lambda (where the AgentCore policy engine is unavailable, e.g. GovCloud)."
  type        = bool
  default     = false
}
variable "tool_policy" {
  description = "Interceptor rules (JSON list of {effect, tools[], claim?, values[]}). Default [] = deny every tools/call (fail closed)."
  type        = string
  default     = "[]"
}
variable "alarm_topic_arn" {
  description = "Enclave security-alarm SNS topic (cloudwatch-alarm-action-check)."
  type        = string
  default     = null
}
variable "alarms" {
  type    = bool
  default = true
}
variable "alarm_insufficient_data_action" {
  description = "cloudwatch-alarm-action-check insufficientDataActionRequired."
  type        = bool
  default     = true
}
variable "reserved_concurrency" {
  description = "lambda-concurrency-check: within the pack's [ConcurrencyLimitLow, ConcurrencyLimitHigh]."
  type        = number
  default     = 100
}
variable "token_budget_enforce" {
  description = "token_control.enabled: the interceptor denies tools/call past the per-user / per-team token budgets."
  type        = bool
  default     = false
}
variable "token_control" {
  description = "Resolved-config token_control block (budgets, timezone, fail_closed_hours, team_claim)."
  type        = any
  default     = {}
}
variable "token_ledger_table" {
  type    = string
  default = null
}
variable "token_ledger_arn" {
  type    = string
  default = null
}
variable "lambda_subnet_ids" {
  type    = list(string)
  default = []
}
variable "lambda_security_group_ids" {
  type    = list(string)
  default = []
}
variable "cloudwatch_retention_days" {
  type    = number
  default = 365
}
variable "jwt_discovery_url" {
  description = "Org IdP OIDC discovery URL. When null the gateway uses AWS_IAM (SigV4) auth."
  type        = string
  default     = null
}
variable "jwt_allowed_clients" {
  type    = list(string)
  default = []
}
# SGEA-AC-MEM-02: explicit expiry, no longer than the conversational-data retention schedule.
variable "memory_event_expiry_days" {
  type    = number
  default = 30
  validation {
    condition     = var.memory_event_expiry_days >= 7 && var.memory_event_expiry_days <= 365
    error_message = "memory_event_expiry_days must be 7..365."
  }
}
variable "tags" {
  type    = map(string)
  default = {}
}
""")
    main = (_seam_header("agentcore-platform", SEAM_OFFICIAL, "awscc_bedrockagentcore_*", "swap internals only") + """\
data "aws_caller_identity" "this" {}
data "aws_partition" "this" {}
data "aws_region" "this" {}

locals {
  account = data.aws_caller_identity.this.account_id
  arn     = data.aws_partition.this.partition
  region  = data.aws_region.this.region
  trust = jsonencode({
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

# ----- agent images: SGEA-AC-RT-08/09 -----
module "ecr" {
  source  = "terraform-aws-modules/ecr/aws"
  version = "3.2.0"

  repository_name                 = "sgea-${var.env}-agents"
  repository_image_tag_mutability = "IMMUTABLE"
  repository_image_scan_on_push   = true
  repository_encryption_type      = "KMS"
  repository_kms_key              = var.kms_key_arn
  create_repository_policy        = false
  attach_repository_policy        = false
  # ecr-private-lifecycle-policy-configured
  create_lifecycle_policy = true
  repository_lifecycle_policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after 14 days"
        selection    = { tagStatus = "untagged", countType = "sinceImagePushed", countUnit = "days", countNumber = 14 }
        action       = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep the most recent 100 images"
        selection    = { tagStatus = "any", countType = "imageCountMoreThan", countNumber = 100 }
        action       = { type = "expire" }
      },
    ]
  })
  tags = var.tags
}

# ----- outbound credential store: SGEA-AC-ID-01 -----
# Destroy is a no-op in hashicorp/aws (framework.WithNoOpDelete): `terraform destroy` leaves the
# vault on this CMK. Before the key is scheduled for deletion, reset the vault to the service-managed
# key (SetTokenVaultCMK keyType = ServiceManagedKey; OPERATIONS.md) or the account's token vault breaks.
resource "aws_bedrockagentcore_token_vault_cmk" "this" {
  kms_configuration {
    key_type    = "CustomerManagedKey"
    kms_key_arn = var.kms_key_arn
  }
}

# ----- tool path: SGEA-AC-GW-01..04 -----
resource "aws_iam_role" "gateway" {
  name               = "sgea-${var.env}-agentcore-gateway"
  assume_role_policy = local.trust
  tags               = var.tags
}

# AWS docs (AgentCore Gateway and Policy IAM permissions): the gateway role reads and evaluates
# its policy engine.
# iam-no-inline-policy-check: customer-managed policy + attachment (no inline role policies).
resource "aws_iam_policy" "gateway_policy_engine" {
  count = var.gateway_tool_path ? 1 : 0
  name = "sgea-${var.env}-gateway-policy-engine"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "PolicyEngineConfiguration", Effect = "Allow", Action = ["bedrock-agentcore:GetPolicyEngine"],
      Resource = ["arn:${local.arn}:bedrock-agentcore:${local.region}:${local.account}:policy-engine/*"] },
      { Sid = "PolicyEngineAuthorization", Effect = "Allow",
        Action = ["bedrock-agentcore:AuthorizeAction", "bedrock-agentcore:PartiallyAuthorizeActions"],
        Resource = ["arn:${local.arn}:bedrock-agentcore:${local.region}:${local.account}:policy-engine/*",
      "arn:${local.arn}:bedrock-agentcore:${local.region}:${local.account}:gateway/*"] },
      # Policy engine and gateway are encrypted with the enclave CMK (AWS docs: policy-encryption):
      # the caller of a CMK-encrypted policy engine needs the key. AgentCore reaches KMS on the role's
      # behalf without a regional kms:ViaService (verified in sandbox), so: only via an AWS service,
      # only from this account.
      { Sid = "EnclaveKeyViaAgentCore", Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
        Resource = var.kms_key_arn,
      Condition = { Bool = { "aws:ViaAWSService" = "true" }, StringEquals = { "kms:CallerAccount" = local.account } } },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "gateway_policy_engine" {
  count = var.gateway_tool_path ? 1 : 0
  role       = aws_iam_role.gateway.id
  policy_arn = aws_iam_policy.gateway_policy_engine[0].arn
}

# The gateway encrypts its own configuration by assuming this role directly (session
# GenesisMCPTargetTargetEncryption, verified in sandbox) — not via a service — so it needs the
# key without the ViaAWSService condition. Scoped to the enclave key; only AgentCore (this
# account's resources) can assume the role.
# iam-no-inline-policy-check: customer-managed policy + attachment (no inline role policies).
resource "aws_iam_policy" "gateway_encryption" {
  name = "sgea-${var.env}-gateway-encryption"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "GatewayConfigEncryption", Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = var.kms_key_arn },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "gateway_encryption" {
  role       = aws_iam_role.gateway.id
  policy_arn = aws_iam_policy.gateway_encryption.arn
}

resource "awscc_bedrockagentcore_policy_engine" "this" {
  count              = var.gateway_tool_path ? 1 : 0
  name               = "sgea_${var.env}_tool_policy"
  description        = "SGEA gateway_tool_path guardrail level: Cedar policies on tool invocations."
  encryption_key_arn = var.kms_key_arn
  tags               = length(var.tags) > 0 ? [for k, v in var.tags : { key = k, value = v }] : null
}

# ----- gateway REQUEST interceptor: tool-path policy-engine stand-in (SGEA-AC-GW-03) and
# token budgets (SGEA-TC-01) -----
locals {
  interceptor_name = "sgea-${var.env}-tool-policy"
  interceptor      = var.tool_policy_interceptor || var.token_budget_enforce
  interceptor_env = merge({ TOOL_POLICY = var.tool_policy, TOOL_POLICY_ENFORCE = tostring(var.tool_policy_interceptor) },
    var.token_budget_enforce ? {
      TOKEN_LEDGER_TABLE      = var.token_ledger_table
      PER_USER_DAILY_TOKENS   = tostring(try(var.token_control.per_user_daily_tokens, 0))
      PER_TEAM_MONTHLY_TOKENS = tostring(try(var.token_control.per_team_monthly_tokens, 0))
      FAIL_CLOSED_HOURS       = tostring(try(var.token_control.fail_closed_hours, 4))
      TOKEN_TIMEZONE          = try(var.token_control.default_timezone, "UTC")
      TEAM_CLAIM              = try(var.token_control.team_claim, "cognito:groups")
  } : {})
}

module "interceptor" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "8.12.0"
  create  = local.interceptor

  function_name                     = local.interceptor_name
  runtime                           = "python3.15"
  handler                           = "tool_policy_interceptor.handler"
  create_package                    = false
  local_existing_package            = "${path.module}/tool_policy_interceptor.zip"
  timeout                           = 5
  memory_size                       = 256
  reserved_concurrent_executions    = var.reserved_concurrency # lambda-concurrency-check
  kms_key_arn                       = var.kms_key_arn
  environment_variables             = local.interceptor_env
  tracing_mode                      = "Active"
  vpc_subnet_ids                    = length(var.lambda_subnet_ids) > 0 ? var.lambda_subnet_ids : null # lambda-inside-vpc
  vpc_security_group_ids            = length(var.lambda_subnet_ids) > 0 ? var.lambda_security_group_ids : null
  dead_letter_target_arn            = try(aws_sqs_queue.interceptor_dlq[0].arn, null) # lambda-dlq-check
  cloudwatch_logs_retention_in_days = var.cloudwatch_retention_days
  cloudwatch_logs_kms_key_id        = var.kms_key_arn
  # iam-no-inline-policy-check: no module inline policies; one customer-managed policy + AWS managed ones.
  attach_cloudwatch_logs_policy = false
  attach_tracing_policy         = false
  attach_network_policy         = false
  attach_dead_letter_policy     = false
  attach_policies               = true
  number_of_policies            = 3
  policies = [
    try(aws_iam_policy.interceptor[0].arn, ""),
    "arn:${local.arn}:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
    "arn:${local.arn}:iam::aws:policy/AWSXRayDaemonWriteAccess",
  ]
  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "interceptor_errors" {
  count                     = local.interceptor && var.alarms ? 1 : 0
  alarm_name                = "${local.interceptor_name}-errors"
  alarm_description         = "SGEA gateway interceptor errors: tool-path policy / token budgets fail closed."
  namespace                 = "AWS/Lambda"
  metric_name               = "Errors"
  dimensions                = { FunctionName = local.interceptor_name }
  statistic                 = "Sum"
  period                    = 300
  evaluation_periods        = 1
  threshold                 = 0
  comparison_operator       = "GreaterThanThreshold"
  treat_missing_data        = "notBreaching"
  alarm_actions             = [var.alarm_topic_arn]
  insufficient_data_actions = var.alarm_insufficient_data_action ? [var.alarm_topic_arn] : []
  tags                      = var.tags
}

resource "aws_sqs_queue" "interceptor_dlq" {
  count                     = local.interceptor ? 1 : 0
  name                      = "${local.interceptor_name}-dlq"
  kms_master_key_id         = var.kms_key_arn
  message_retention_seconds = 1209600
  tags                      = var.tags
}

resource "aws_iam_policy" "interceptor" {
  count = local.interceptor ? 1 : 0
  name  = "${local.interceptor_name}-function"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      { Sid = "EnclaveKey", Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = var.kms_key_arn },
      { Sid = "DeadLetter", Effect = "Allow", Action = "sqs:SendMessage", Resource = aws_sqs_queue.interceptor_dlq[0].arn },
      ], var.token_budget_enforce ? [
      { Sid = "TokenLedger", Effect = "Allow", Action = "dynamodb:GetItem", Resource = var.token_ledger_arn },
    ] : [])
  })
  tags = var.tags
}

# iam-no-inline-policy-check: customer-managed policy + attachment (no inline role policies).
resource "aws_iam_policy" "gateway_invoke_interceptor" {
  count = local.interceptor ? 1 : 0
  name = "sgea-${var.env}-gateway-invoke-interceptor"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "lambda:InvokeFunction", Resource = module.interceptor.lambda_function_arn }]
  })
}

resource "aws_iam_role_policy_attachment" "gateway_invoke_interceptor" {
  count = local.interceptor ? 1 : 0
  role       = aws_iam_role.gateway.id
  policy_arn = aws_iam_policy.gateway_invoke_interceptor[0].arn
}

resource "awscc_bedrockagentcore_gateway" "this" {
  name            = "sgea-${var.env}-gateway"
  role_arn        = aws_iam_role.gateway.arn
  protocol_type   = "MCP"
  authorizer_type = var.jwt_discovery_url == null ? "AWS_IAM" : "CUSTOM_JWT"
  authorizer_configuration = var.jwt_discovery_url == null ? null : {
    custom_jwt_authorizer = {
      discovery_url   = var.jwt_discovery_url
      allowed_clients = length(var.jwt_allowed_clients) > 0 ? var.jwt_allowed_clients : null
    }
  }
  kms_key_arn = var.kms_key_arn
  policy_engine_configuration = var.gateway_tool_path ? {
    arn  = awscc_bedrockagentcore_policy_engine.this[0].policy_engine_arn
    mode = "ENFORCE"
  } : null
  # Tokens are passed to the interceptor (claims for rules / budget identity); it never logs them.
  interceptor_configurations = local.interceptor ? [{
    interceptor         = { lambda = { arn = module.interceptor.lambda_function_arn } }
    interception_points = ["REQUEST"]
    input_configuration = { pass_request_headers = true }
  }] : null
  tags       = var.tags
  depends_on = [aws_iam_role_policy_attachment.gateway_invoke_interceptor, aws_iam_role_policy_attachment.gateway_policy_engine, time_sleep.iam_propagation]
}

# ----- agent memory: SGEA-AC-MEM-01..03 -----
resource "aws_iam_role" "memory" {
  name               = "sgea-${var.env}-agentcore-memory"
  assume_role_policy = local.trust
  tags               = var.tags
}

# iam-no-inline-policy-check: customer-managed policy + attachment (no inline role policies).
resource "aws_iam_policy" "memory" {
  name = "sgea-${var.env}-memory"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "InvokeModelsForMemoryStrategies"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = ["arn:${local.arn}:bedrock:*::foundation-model/*", "arn:${local.arn}:bedrock:*:${local.account}:inference-profile/*"]
      },
      {
        Sid      = "UseEnclaveKey"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource = var.kms_key_arn
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "memory" {
  role       = aws_iam_role.memory.id
  policy_arn = aws_iam_policy.memory.arn
}

# AgentCore validates execution roles at create time; new IAM roles are eventually consistent.
resource "time_sleep" "iam_propagation" {
  create_duration = "20s"
  # Re-wait whenever a role or its policy changes: AgentCore validates them at create/update time.
  triggers = {
    gateway        = aws_iam_role.gateway.arn
    memory         = aws_iam_role.memory.arn
    gateway_policy = sha256(jsonencode([aws_iam_policy.gateway_policy_engine[*].policy, aws_iam_policy.gateway_encryption.policy]))
    memory_policy  = sha256(aws_iam_policy.memory.policy)
  }
  depends_on = [aws_iam_role_policy_attachment.memory, aws_iam_role_policy_attachment.gateway_policy_engine, aws_iam_role_policy_attachment.gateway_encryption]
}

resource "awscc_bedrockagentcore_memory" "this" {
  name                      = "sgea_${var.env}_memory"
  description               = "SGEA enclave agent memory"
  event_expiry_duration     = var.memory_event_expiry_days
  encryption_key_arn        = var.kms_key_arn
  memory_execution_role_arn = aws_iam_role.memory.arn
  tags                      = var.tags
  depends_on                = [time_sleep.iam_propagation]
}
""")
    outputs = ('output "gateway_id" { value = awscc_bedrockagentcore_gateway.this.gateway_identifier }\n'
               'output "gateway_url" { value = awscc_bedrockagentcore_gateway.this.gateway_url }\n'
               'output "gateway_arn" { value = awscc_bedrockagentcore_gateway.this.gateway_arn }\n'
               'output "policy_engine_id" { value = one(awscc_bedrockagentcore_policy_engine.this[*].policy_engine_id) }\n'
               'output "gateway_role_name" { value = aws_iam_role.gateway.name }\n'
               'output "memory_id" { value = awscc_bedrockagentcore_memory.this.memory_id }\n'
               'output "agents_repository_url" { value = module.ecr.repository_url }\n')
    readme = ("# agentcore-platform (SGEA wrapper seam)\n\n"
              "Enclave-shared AgentCore resources, configured to the SGEA-inferred controls:\n\n"
              "- **Gateway** (tool path) — authenticated (`CUSTOM_JWT` with the org IdP, else `AWS_IAM`), "
              "enclave CMK, and a **policy engine** in `ENFORCE` mode when `gateway_tool_path` is a "
              "resolved guardrail level (GW-01..04).\n"
              "- **Memory** — enclave CMK, explicit event expiry, dedicated least-privilege role (MEM-01..03).\n"
              "- **Token vault** — customer-managed key for outbound OAuth tokens / API keys (ID-01).\n"
              "- **ECR** — agent images: immutable tags, scan on push, KMS (RT-08/09).\n\n"
              "> `policy_engine_configuration.mode = \"ENFORCE\"` is an API enum not checked by "
              "`terraform validate`; confirm on first sandbox apply.\n")
    versions = _versions_tf(partition, True).replace(
        '  }\n}\n', '    time = { source = "hashicorp/time", version = ">= 0.12" }\n  }\n}\n')
    return {"versions.tf": versions, "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme}


def _mod_enclave_network(partition):
    variables = (_seam_header("enclave-network", SEAM_RAW, "raw aws_vpc_endpoint", "point at an official VPC-endpoint module") + """\
variable "env" { type = string }
variable "vpc_id" { type = string }
variable "subnet_ids" { type = list(string) }
variable "security_group_ids" { type = list(string) }
variable "route_table_ids" {
  description = "Route tables for the S3 and DynamoDB gateway endpoints."
  type        = list(string)
  default     = []
}
variable "interface_services" {
  description = "Interface endpoint service suffixes (com.amazonaws.<region>.<suffix>)."
  type        = list(string)
}
variable "flow_log" {
  description = "vpc-flow-logs-enabled: flow logs for the enclave VPC (false where dod-scca already emits them)."
  type        = bool
  default     = true
}
variable "kms_key_arn" {
  type    = string
  default = null
}
variable "cloudwatch_retention_days" {
  type    = number
  default = 365
}
variable "tags" {
  type    = map(string)
  default = {}
}
""")
    main = (_seam_header("enclave-network", SEAM_RAW, "raw aws_vpc_endpoint", "swap internals only") + """\
# SGEA-BR-09: keep Bedrock / AgentCore / control-plane traffic on private endpoints.
data "aws_region" "this" {}

# Interface endpoints only in subnets whose AZ the service supports (e.g. cognito-idp is not in
# every us-east-1 AZ); a service with no supported subnet is skipped.
data "aws_vpc_endpoint_service" "this" {
  for_each     = toset(var.interface_services)
  service      = each.value
  service_type = "Interface"
}

data "aws_subnet" "this" {
  for_each = toset(var.subnet_ids)
  id       = each.value
}

locals {
  supported_subnets = { for svc in var.interface_services : svc => [
    for id, sn in data.aws_subnet.this : id if contains(data.aws_vpc_endpoint_service.this[svc].availability_zones, sn.availability_zone)
  ] }
}

module "endpoints" {
  source  = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
  version = "6.7.3"

  vpc_id             = var.vpc_id
  security_group_ids = var.security_group_ids
  endpoints = merge(
    { for svc in var.interface_services : replace(svc, ".", "_") => {
      service             = svc
      private_dns_enabled = true
      subnet_ids          = local.supported_subnets[svc]
      tags                = { Name = "sgea-${var.env}-${svc}" }
    } if length(local.supported_subnets[svc]) > 0 },
    { s3 = { service = "s3", service_type = "Gateway", route_table_ids = var.route_table_ids, tags = { Name = "sgea-${var.env}-s3" } } },
    # token-control ledger (meter + gateway interceptor run in the VPC)
    { dynamodb = { service = "dynamodb", service_type = "Gateway", route_table_ids = var.route_table_ids, tags = { Name = "sgea-${var.env}-dynamodb" } } },
  )
  tags = var.tags
}

# ----- vpc-flow-logs-enabled: the enclave records its VPC's traffic (CMK-encrypted, pack retention) -----
module "flow_log_group" {
  source  = "terraform-aws-modules/cloudwatch/aws//modules/log-group"
  version = "5.7.3"
  create  = var.flow_log

  name              = "/sgea/${var.env}/vpc-flow-logs"
  retention_in_days = var.cloudwatch_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

resource "aws_iam_role" "flow_logs" {
  count = var.flow_log ? 1 : 0
  name  = "sgea-${var.env}-vpc-flow-logs"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "vpc-flow-logs.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}

resource "aws_iam_policy" "flow_logs" {
  count = var.flow_log ? 1 : 0
  name  = "sgea-${var.env}-vpc-flow-logs"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
    Resource = "${module.flow_log_group.cloudwatch_log_group_arn}:*" }]
  })
}

resource "aws_iam_role_policy_attachment" "flow_logs" {
  count      = var.flow_log ? 1 : 0
  role       = aws_iam_role.flow_logs[0].name
  policy_arn = aws_iam_policy.flow_logs[0].arn
}

resource "aws_flow_log" "vpc" {
  count                    = var.flow_log ? 1 : 0
  vpc_id                   = var.vpc_id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = module.flow_log_group.cloudwatch_log_group_arn
  iam_role_arn             = aws_iam_role.flow_logs[0].arn
  max_aggregation_interval = 60
  tags                     = var.tags
}
""")
    outputs = 'output "endpoint_ids" { value = { for k, e in module.endpoints.endpoints : k => e.id } }\n'
    readme = ("# enclave-network (SGEA wrapper seam)\n\n"
              "Interface VPC endpoints (private DNS) for the services the resolved `services.allow` "
              "needs, plus an S3 gateway endpoint. The enclave VPC itself is customer-supplied.\n\n"
              "> Endpoint service names are checked by the EC2 API at apply time; confirm availability "
              "per region (especially GovCloud) on first sandbox apply.\n")
    return {"versions.tf": _versions_tf(partition, False), "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme}


def _mod_enclave_aurora(partition):
    variables = (_seam_header("enclave-aurora", SEAM_RAW, "raw aws_rds_cluster + AWS Backup",
                              "point at an official Aurora module") + """\
variable "env" { type = string }
variable "kms_key_arn" { type = string }
variable "subnet_ids" { type = list(string) }
variable "security_group_ids" { type = list(string) }
variable "backup_retention_days" {
  description = "From the composed conformance packs (backup-plan-min-frequency-and-min-retention-check)."
  type        = number
}
variable "cloudwatch_retention_days" {
  type    = number
  default = 365
}
variable "instance_count" {
  description = "rds-cluster-multi-az-enabled: >= 2 instances across AZs."
  type        = number
  default     = 2
  validation {
    condition     = var.instance_count >= 2
    error_message = "rds-cluster-multi-az-enabled requires at least 2 instances."
  }
}
variable "min_acu" {
  type    = number
  default = 0.5
}
variable "max_acu" {
  type    = number
  default = 8
}
variable "tags" {
  type    = map(string)
  default = {}
}
""")
    main = (_seam_header("enclave-aurora", SEAM_RAW, "raw aws_rds_cluster + AWS Backup", "swap internals only") + """\
# Aurora PostgreSQL (pgvector) knowledge-base store, configured to the composed packs'
# rds-* / backup-* rules. pgvector schema (CREATE EXTENSION vector, KB table) is applied
# by the enclave bootstrap, not Terraform.
data "aws_partition" "this" {}

module "aurora" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "10.4.1"

  name                                = "sgea-${var.env}-vector"
  engine                              = "aurora-postgresql"
  engine_version                      = "16.15"
  engine_mode                         = "provisioned"
  database_name                       = "sgea"
  master_username                     = "sgea_admin" # rds-instance-default-admin-check
  manage_master_user_password         = true
  master_user_secret_kms_key_id       = var.kms_key_arn
  storage_encrypted                   = true # rds-storage-encrypted, rds-snapshot-encrypted
  kms_key_id                          = var.kms_key_arn
  iam_database_authentication_enabled = true
  enable_http_endpoint                = true # RDS Data API, required by Bedrock KB
  deletion_protection                 = true # rds-cluster-deletion-protection-enabled
  backup_retention_period             = min(var.backup_retention_days, 35)
  copy_tags_to_snapshot               = true
  enabled_cloudwatch_logs_exports     = ["postgresql"] # rds-logging-enabled
  # The exported log group is created here (CMK + pack retention) instead of by RDS (unencrypted):
  # cloudwatch-log-group-encrypted, cw-loggroup-retention-period-check.
  create_cloudwatch_log_group            = true
  cloudwatch_log_group_retention_in_days = var.cloudwatch_retention_days
  cloudwatch_log_group_kms_key_id        = var.kms_key_arn
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "sgea-${var.env}-vector-final"

  create_db_subnet_group = true
  db_subnet_group_name   = "sgea-${var.env}-aurora"
  subnets                = var.subnet_ids
  create_security_group  = false
  vpc_security_group_ids = var.security_group_ids

  cluster_parameter_group = {
    name   = "sgea-${var.env}-aurora-pg16"
    family = "aurora-postgresql16"
    parameters = [
      { name = "rds.force_ssl", value = "1" }, # encryption in transit
      { name = "log_connections", value = "1" },
      { name = "log_disconnections", value = "1" },
    ]
  }

  serverlessv2_scaling_configuration = { min_capacity = var.min_acu, max_capacity = var.max_acu }
  create_monitoring_role             = true
  cluster_monitoring_interval        = 60 # rds-enhanced-monitoring-enabled
  instances = { for i in range(var.instance_count) : tostring(i) => {
    identifier                 = "sgea-${var.env}-vector-${i}"
    instance_class             = "db.serverless"
    publicly_accessible        = false # rds-instance-public-access-check
    auto_minor_version_upgrade = true  # rds-automatic-minor-version-upgrade-enabled
    monitoring_interval        = 60
    performance_insights_enabled          = true
    performance_insights_kms_key_id       = var.kms_key_arn
    performance_insights_retention_period = 7
  } }

  cluster_tags = { "sgea:backup" = "true" }
  tags         = var.tags
}

""")
    outputs = ('output "cluster_arn" { value = module.aurora.cluster_arn }\n'
               'output "secret_arn" { value = module.aurora.cluster_master_user_secret[0].secret_arn }\n')
    readme = ("# enclave-aurora (SGEA wrapper seam)\n\n"
              "Aurora PostgreSQL Serverless v2 vector store for Bedrock Knowledge Bases, configured from "
              "the composed conformance packs' `rds-*` / `backup-*` rules. Backup retention and vault lock "
              "come from the pack parameters in `catalog/<baseline>.json` (e.g. `requiredRetentionDays`), "
              "not from SGEA defaults.\n\n"
              "> The pgvector schema (`CREATE EXTENSION vector`, KB table + index) is applied by the "
              "enclave bootstrap via the RDS Data API after apply.\n")
    return {"versions.tf": _versions_tf(partition, False), "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme}


def _mod_enclave_backup(partition):
    variables = (_seam_header("enclave-backup", SEAM_RAW, "raw aws_backup_*", "point at an official AWS Backup module") + """\
variable "env" { type = string }
variable "kms_key_arn" { type = string }
variable "backup_retention_days" {
  description = "From the composed conformance packs (backup-plan-min-frequency-and-min-retention-check)."
  type        = number
}
variable "backup_vault_lock" {
  description = "backup-recovery-point-manual-deletion-disabled is in a composed pack."
  type        = bool
}
variable "resources" {
  description = "ARNs of the enclave data stores to protect (Aurora cluster, token ledger, log / config stores)."
  type        = list(string)
}
variable "s3_backup" {
  description = "Resources include S3 buckets (attach the AWS Backup S3 service policies)."
  type        = bool
  default     = true
}
variable "tags" {
  type    = map(string)
  default = {}
}
""")
    main = (_seam_header("enclave-backup", SEAM_RAW, "raw aws_backup_*", "point at an official AWS Backup module") +
            'data "aws_partition" "this" {}\n\n' + """resource "aws_backup_vault" "this" {
  name        = "sgea-${var.env}"
  kms_key_arn = var.kms_key_arn # backup-recovery-point-encrypted
  tags        = var.tags
}

resource "aws_backup_vault_lock_configuration" "this" {
  count              = var.backup_vault_lock ? 1 : 0 # backup-recovery-point-manual-deletion-disabled
  backup_vault_name  = aws_backup_vault.this.name
  min_retention_days = var.backup_retention_days
}

resource "aws_backup_plan" "this" {
  name = "sgea-${var.env}"
  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.this.name
    schedule          = "cron(0 5 * * ? *)" # requiredFrequencyValue = 1 day
    lifecycle {
      delete_after = var.backup_retention_days
    }
  }
  tags = var.tags
}

resource "aws_iam_role" "backup" {
  name = "sgea-${var.env}-backup"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "backup.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:${data.aws_partition.this.partition}:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

# backup-recovery-point-manual-deletion-disabled: the vault access policy denies deleting recovery points
# (and changing their lifecycle) to every principal; vault lock alone does not satisfy the rule.
resource "aws_backup_vault_policy" "this" {
  backup_vault_name = aws_backup_vault.this.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyRecoveryPointDeletion"
      Effect    = "Deny"
      Principal = { AWS = "*" }
      Action    = ["backup:DeleteRecoveryPoint", "backup:UpdateRecoveryPointLifecycle", "backup:PutBackupVaultAccessPolicy"]
      Resource  = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "backup_s3" {
  for_each   = var.s3_backup ? toset(["AWSBackupServiceRolePolicyForS3Backup", "AWSBackupServiceRolePolicyForS3Restore"]) : toset([])
  role       = aws_iam_role.backup.name
  policy_arn = "arn:${data.aws_partition.this.partition}:iam::aws:policy/${each.value}"
}

# Every enclave data store the composed packs require in a backup plan:
# aurora-/rds-*-backup-plan, dynamodb-*-backup-plan (token ledger), s3-resources-protected-by-backup-plan.
resource "aws_backup_selection" "this" {
  name         = "sgea-${var.env}-enclave"
  plan_id      = aws_backup_plan.this.id
  iam_role_arn = aws_iam_role.backup.arn
  resources    = var.resources
  depends_on   = [aws_iam_role_policy_attachment.backup, aws_iam_role_policy_attachment.backup_s3]
}
""")
    outputs = ('output "vault_name" { value = aws_backup_vault.this.name }\n'
               'output "plan_id" { value = aws_backup_plan.this.id }\n')
    readme = ("# enclave-backup (SGEA wrapper seam)\n\n"
              "AWS Backup vault (enclave CMK, optional vault lock), daily plan with the pack-derived retention, "
              "and one selection covering every enclave data store (Aurora, token ledger, log / config stores).\n")
    return {"versions.tf": _versions_tf(partition, False), "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme}


def _mod_account_baseline(partition):
    variables = (_seam_header("account-baseline", SEAM_RAW, "raw aws_* account settings",
                              "defer to Control Tower / LZA controls where they own the setting") + """\
variable "settings" {
  description = "_derived.account_baseline: which account settings the composed packs require (strictest parameters)."
  type        = any
}
variable "kms_key_arn" { type = string }
variable "vpc_id" {
  type    = string
  default = null
}
""")
    main = (_seam_header("account-baseline", SEAM_RAW, "raw aws_* account settings", "swap internals only") + """\
# Account-level settings the enclave's packs evaluate (they are per account + region). Where a landing
# zone already owns a setting, set manage_account_baseline = false at the root and keep the LZA control.

# ec2-ebs-encryption-by-default (+ the enclave CMK as the default EBS key)
resource "aws_ebs_encryption_by_default" "this" {
  count   = var.settings.ebs_encryption_by_default ? 1 : 0
  enabled = true
}

resource "aws_ebs_default_kms_key" "this" {
  count   = var.settings.ebs_encryption_by_default ? 1 : 0
  key_arn = var.kms_key_arn
}

# ebs-snapshot-public-restorable-check
resource "aws_ebs_snapshot_block_public_access" "this" {
  count = var.settings.snapshot_block_public_access ? 1 : 0
  state = "block-all-sharing"
}

# s3-account-level-public-access-blocks-periodic
resource "aws_s3_account_public_access_block" "this" {
  count                   = var.settings.s3_account_public_access_block ? 1 : 0
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# iam-password-policy / iam-password-policy-2 (break-glass IAM users; workforce identity is IAM Identity Center)
resource "aws_iam_account_password_policy" "this" {
  count                        = var.settings.password_policy != null ? 1 : 0
  minimum_password_length      = var.settings.password_policy.minimum_password_length
  password_reuse_prevention    = var.settings.password_policy.password_reuse_prevention
  max_password_age             = var.settings.password_policy.max_password_age
  require_lowercase_characters = var.settings.password_policy.require_lowercase_characters
  require_uppercase_characters = var.settings.password_policy.require_uppercase_characters
  require_numbers              = var.settings.password_policy.require_numbers
  require_symbols              = var.settings.password_policy.require_symbols
}

# vpc-default-security-group-closed: adopt the enclave VPC's default SG with no rules.
resource "aws_default_security_group" "this" {
  count  = var.settings.default_security_group_closed && var.vpc_id != null ? 1 : 0
  vpc_id = var.vpc_id
}
""")
    outputs = 'output "password_policy" { value = one(aws_iam_account_password_policy.this[*].id) }\n'
    readme = ("# account-baseline (SGEA wrapper seam)\n\n"
              "Account-level settings the composed conformance packs evaluate: EBS encryption by default "
              "(enclave CMK), EBS snapshot public-sharing block, account S3 Block Public Access, the IAM "
              "password policy (pack parameters, strictest wins) and a rule-less VPC default security group. "
              "Disable with `manage_account_baseline = false` where the landing zone owns them.\n")
    return {"versions.tf": _versions_tf(partition, False), "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme}


def _mod_security_services(partition):
    variables = (_seam_header("security-services", SEAM_RAW, "raw aws_guardduty_detector / aws_securityhub_*",
                              "point at an org-level delegated-admin module") + """\
variable "env" { type = string }
variable "create_guardduty" {
  description = "false where GuardDuty is already enabled (org delegated admin / existing detector)."
  type        = bool
  default     = true
}
variable "create_securityhub" {
  description = "false where Security Hub is already enabled."
  type        = bool
  default     = true
}
variable "inspector_resource_types" {
  description = "inspector-*-scan-enabled rules in the composed packs (ECR / LAMBDA / EC2)."
  type        = list(string)
  default     = []
}
variable "create_inspector" {
  description = "false where Inspector is managed by an org delegated admin."
  type        = bool
  default     = true
}
variable "tags" {
  type    = map(string)
  default = {}
}
""")
    main = (_seam_header("security-services", SEAM_RAW, "raw GuardDuty / Security Hub", "swap internals only") + """\
# Threat detection and posture (guardduty-enabled-centralized, securityhub-enabled; DoD SCCA VDMS).
# Skip (create_security_services = false) where Control Tower / LZA delegated admins already run them:
# a second GuardDuty detector / Security Hub enablement in the same account-region fails.
data "aws_partition" "this" {}
data "aws_region" "this" {}

resource "aws_guardduty_detector" "this" {
  count                        = var.create_guardduty ? 1 : 0
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  tags                         = var.tags
}

resource "aws_securityhub_account" "this" {
  count                    = var.create_securityhub ? 1 : 0
  enable_default_standards = false
}

resource "aws_securityhub_standards_subscription" "nist_800_53" {
  count         = var.create_securityhub ? 1 : 0
  standards_arn = "arn:${data.aws_partition.this.partition}:securityhub:${data.aws_region.this.region}::standards/nist-800-53/v/5.0.0"
  depends_on    = [aws_securityhub_account.this]
}

# inspector-ecr-scan-enabled / inspector-lambda-standard-scan-enabled / inspector-ec2-scan-enabled
data "aws_caller_identity" "this" {}

resource "aws_inspector2_enabler" "this" {
  count          = var.create_inspector && length(var.inspector_resource_types) > 0 ? 1 : 0
  account_ids    = [data.aws_caller_identity.this.account_id]
  resource_types = var.inspector_resource_types
}
""")
    outputs = 'output "guardduty_detector_id" { value = one(aws_guardduty_detector.this[*].id) }\n'
    readme = ("# security-services (SGEA wrapper seam)\n\n"
              "GuardDuty (15-minute findings) and Security Hub with the **NIST SP 800-53 Rev5** standard. "
              "Satisfies the packs' `guardduty-enabled-centralized` / `securityhub-enabled` rules and is the "
              "monitoring half of the DoD SCCA VDMS. Disable with `create_security_services = false` where an "
              "org delegated admin (Control Tower / LZA) already manages them.\n")
    return {"versions.tf": _versions_tf(partition, False), "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme}


def _mod_dod_scca(partition):
    variables = (_seam_header("dod-scca", SEAM_RAW, "raw aws_networkfirewall_* / aws_flow_log",
                              "point at an official SCCA module if one ships") + """\
variable "env" { type = string }
variable "kms_key_arn" { type = string }
variable "vpc_id" { type = string }
variable "firewall_subnet_ids" {
  description = "Dedicated firewall subnets, one per AZ (VDSS inspection)."
  type        = list(string)
}
variable "egress_domains" {
  description = "Allowed egress FQDNs (TLS SNI / HTTP Host), e.g. '.amazonaws.com'. Empty = all egress dropped."
  type        = list(string)
  default     = []
}
variable "cloudwatch_retention_days" { type = number }
variable "tags" {
  type    = map(string)
  default = {}
}
""")
    main = (_seam_header("dod-scca", SEAM_RAW, "raw AWS Network Firewall + VPC flow logs", "swap internals only") + """\
# DoD Secure Cloud Computing Architecture (SCCA) — in-account components (AWS SCCA on GovCloud RA):
#   VDSS: AWS Network Firewall, default-drop strict-order policy, egress domain allow-list.
#   VDMS: firewall alert/flow logs + VPC flow logs to encrypted CloudWatch (GuardDuty / Security Hub
#         come from modules/security-services).
# NOT created here (customer / DISA prerequisites): the BCAP connection (Direct Connect via DISA),
# route tables steering traffic through the firewall endpoints, and the TCCM credential process.
locals {
  name = "sgea-${var.env}"
}

module "egress_allowlist" {
  source  = "terraform-aws-modules/network-firewall/aws//modules/rule-group"
  version = "2.3.0"
  create  = length(var.egress_domains) > 0

  name     = "${local.name}-egress-allowlist"
  type     = "STATEFUL"
  capacity = 100
  rule_group = {
    rules_source = {
      rules_source_list = {
        generated_rules_type = "ALLOWLIST"
        target_types         = ["TLS_SNI", "HTTP_HOST"]
        targets              = var.egress_domains
      }
    }
    stateful_rule_options = { rule_order = "STRICT_ORDER" }
  }
  encryption_configuration = { key_id = var.kms_key_arn, type = "CUSTOMER_KMS" }
  create_resource_policy   = false
  tags                     = var.tags
}

module "log_group" {
  source   = "terraform-aws-modules/cloudwatch/aws//modules/log-group"
  version  = "5.7.3"
  for_each = toset(["alert", "flow"])

  name              = "/sgea/${var.env}/network-firewall/${each.key}"
  retention_in_days = var.cloudwatch_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

module "firewall" {
  source  = "terraform-aws-modules/network-firewall/aws"
  version = "2.3.0"

  name                              = "${local.name}-vdss"
  vpc_id                            = var.vpc_id
  subnet_mapping                    = { for i, id in var.firewall_subnet_ids : tostring(i) => { subnet_id = id } }
  delete_protection                 = true
  subnet_change_protection          = true
  firewall_policy_change_protection = true
  encryption_configuration          = { key_id = var.kms_key_arn, type = "CUSTOMER_KMS" }

  policy_name                              = "${local.name}-vdss"
  policy_stateless_default_actions         = ["aws:forward_to_sfe"]
  policy_stateless_fragment_default_actions = ["aws:forward_to_sfe"]
  policy_stateful_default_actions          = ["aws:drop_strict", "aws:alert_strict"]
  policy_stateful_engine_options           = { rule_order = "STRICT_ORDER" }
  policy_stateful_rule_group_reference = length(var.egress_domains) > 0 ? {
    egress = { priority = 100, resource_arn = module.egress_allowlist.arn }
  } : {}
  policy_encryption_configuration = { key_id = var.kms_key_arn, type = "CUSTOMER_KMS" }

  create_logging_configuration = true
  logging_configuration_destination_config = [
    { log_destination = { logGroup = module.log_group["alert"].cloudwatch_log_group_name }, log_destination_type = "CloudWatchLogs", log_type = "ALERT" },
    { log_destination = { logGroup = module.log_group["flow"].cloudwatch_log_group_name }, log_destination_type = "CloudWatchLogs", log_type = "FLOW" },
  ]
  tags = var.tags
}

# VPC flow logs (vpc-flow-logs-enabled; VDMS).
module "vpc_flow_log_group" {
  source  = "terraform-aws-modules/cloudwatch/aws//modules/log-group"
  version = "5.7.3"

  name              = "/sgea/${var.env}/vpc-flow-logs"
  retention_in_days = var.cloudwatch_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

resource "aws_iam_role" "flow_logs" {
  name = "${local.name}-vpc-flow-logs"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "vpc-flow-logs.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
  tags = var.tags
}

# iam-no-inline-policy-check: customer-managed policy + attachment (no inline role policies).
resource "aws_iam_policy" "flow_logs" {
  name = "sgea-${var.env}-flow-logs"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
    Resource = "${module.vpc_flow_log_group.cloudwatch_log_group_arn}:*" }]
  })
}

resource "aws_iam_role_policy_attachment" "flow_logs" {
  role       = aws_iam_role.flow_logs.id
  policy_arn = aws_iam_policy.flow_logs.arn
}

resource "aws_flow_log" "vpc" {
  vpc_id                   = var.vpc_id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = module.vpc_flow_log_group.cloudwatch_log_group_arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60
  tags                     = var.tags
}
""")
    outputs = ('output "firewall_endpoints" {\n  description = "Per-AZ firewall endpoint ids: route enclave subnets\' 0.0.0.0/0 and BCAP traffic through these."\n'
               '  value = module.firewall.status\n}\n')
    readme = ("# dod-scca (SGEA wrapper seam)\n\n"
              "In-account components of the **DoD Secure Cloud Computing Architecture** for IL4/IL5 "
              "(reference: the AWS GovCloud (US) DoD SCCA reference architecture):\n\n"
              "| SCCA component | Emitted here | Customer / DISA prerequisite |\n|---|---|---|\n"
              "| BCAP (Boundary Cloud Access Point) | — | Direct Connect / DISA BCAP connection |\n"
              "| VDSS (security stack) | AWS Network Firewall, default drop, egress domain allow-list, KMS, protections on | Route tables steering traffic via `firewall_endpoints` |\n"
              "| VDMS (management) | Firewall alert/flow logs, VPC flow logs (+ GuardDuty / Security Hub NIST in `security-services`) | Mission-owner SOC integration |\n"
              "| TCCM (credential manager) | — | Process: privileged credential control, break-glass |\n")
    return {"versions.tf": _versions_tf(partition, False), "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme}


# -------------------- governance-layer wrapper modules --------------------
def _mod_org_guardrail(partition):
    variables = (_seam_header("org-guardrail", SEAM_RAW, "none — raw aws_organizations_policy",
                              "point at an official org-policy module if one ever exists") + """\
variable "bundles" {
  description = "Policy documents: name -> {type, packs, needs}. SGEA packs are bin-packed into at most 4 SCPs and 4 RCPs (AWS allows 5 attached per target, including the AWS-managed full-access policy)."
  type = map(object({
    type  = string
    packs = list(string)
    needs = list(string)
  }))
}
variable "policy_overrides" {
  description = "Optional bundle name -> JSON document replacing the rendered SGEA library statements."
  type        = map(string)
  default     = {}
}
variable "org_id" {
  description = "AWS Organizations id (o-...). Required by the data-perimeter / identity-perimeter packs."
  type        = string
  default     = null
}
variable "perimeter_vpc_ids" {
  description = "Enclave VPC ids allowed by the network-perimeter RCP."
  type        = list(string)
  default     = []
}
variable "perimeter_cidrs" {
  description = "Corporate egress CIDRs allowed by the network-perimeter RCP."
  type        = list(string)
  default     = []
}
variable "target_ids" {
  type    = list(string)
  default = []
}
variable "tags" {
  type    = map(string)
  default = {}
}
""")
    main = (_seam_header("org-guardrail", SEAM_RAW, "raw aws_organizations_policy", "no official equivalent") + """\
# GOVERNANCE SEAM — no official module exists for org-level SCP/RCP enforcement.
# Statements come from the SGEA policy library (emitters/policy_library.py), rendered from
# the resolved config and bundled into ./policies/<bundle>.json.tftpl; deploy-time values
# are filled here. Deploy from the Organizations management (or delegated) account.
data "aws_partition" "this" {}

locals {
  vars = {
    partition         = data.aws_partition.this.partition
    org_id            = coalesce(var.org_id, "o-unset")
    perimeter_vpc_ids = var.perimeter_vpc_ids
    perimeter_cidrs   = var.perimeter_cidrs
  }
  documents = { for name, b in var.bundles :
    name => lookup(var.policy_overrides, name, templatefile("${path.module}/policies/${name}.json.tftpl", local.vars))
  }
}

resource "aws_organizations_policy" "this" {
  for_each    = var.bundles
  name        = each.key
  description = "SGEA packs: ${join(", ", each.value.packs)}"
  type        = each.value.type
  content     = local.documents[each.key]
  tags        = var.tags

  lifecycle {
    precondition {
      condition     = !contains(each.value.needs, "org_id") || var.org_id != null
      error_message = "org_id is required by ${each.key} (${join(", ", each.value.packs)})."
    }
    precondition {
      condition     = !contains(each.value.needs, "perimeter_cidrs") || length(var.perimeter_vpc_ids) + length(var.perimeter_cidrs) > 0
      error_message = "${each.key} (network perimeter) needs perimeter_vpc_ids and/or perimeter_cidrs; an empty perimeter would deny all access."
    }
  }
}

# Attach every bundle to every target (root / OU / account ids).
resource "aws_organizations_policy_attachment" "this" {
  for_each  = { for pair in setproduct(keys(var.bundles), var.target_ids) : "${pair[0]}/${pair[1]}" => pair }
  policy_id = aws_organizations_policy.this[each.value[0]].id
  target_id = each.value[1]
}
""")
    outputs = 'output "policy_ids" { value = { for k, p in aws_organizations_policy.this : k => p.id } }\n'
    readme = ("# org-guardrail (SGEA wrapper seam)\n\n"
              "**Seam kind:** raw governance adapter — **no official module exists** for org-level "
              "SCP/RCP enforcement, so this wraps raw `aws_organizations_policy` resources.\n\n"
              "The SGEA policy library (`emitters/policy_library.py`) is rendered from the resolved config "
              "and **bundled** into at most 4 SCPs and 4 RCPs (AWS allows 5 attached per target, including "
              "FullAWSAccess / RCPFullAWSAccess). Audit `policies/*.json.tftpl`; each policy's description "
              "lists the packs inside. Override a bundle with `policy_overrides`.\n\n"
              "| Pack | Effect |\n|---|---|\n"
              "| region-lockdown | deny outside `regions.allowed` (global services exempt) |\n"
              "| bedrock-surface | deny services outside `services.allow` + foundation services |\n"
              "| inference-profile | deny invoke via `global.*` / other-geo inference profiles |\n"
              "| guardrail-enforce | deny invoke without a guardrail |\n"
              "| data-perimeter | deny data access to resources outside the org |\n"
              "| tenant-isolation | deny when `sgea:tenant` principal tag != resource tag |\n"
              "| model-allowlist | deny foundation models not authorized for every composed baseline (AWS FedRAMP/DoD model table) |\n"
              "| identity-perimeter (RCP) | deny principals outside the org |\n"
              "| network-perimeter (RCP) | deny requests from outside enclave VPCs / CIDRs |\n\n"
              "> Review before attaching: the data perimeter can block AWS-owned resources some services "
              "use (e.g. public ECR / SSM buckets); add exceptions via `policy_overrides`. Test in a "
              "sandbox OU first.\n")
    return {"versions.tf": _versions_tf(partition, False), "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme}


def _mod_token_control(partition):
    variables = (_seam_header("token-control", SEAM_RAW, "none — raw DynamoDB + Lambda",
                              "point at an official module if one ever exists") +
        'variable "env" { type = string }\n'
        'variable "token_control" {\n  description = "Resolved-config token_control block."\n  type = any\n}\n'
        'variable "kms_key_arn" { type = string }\n'
        'variable "meter" {\n'
        '  description = "token_control.enabled && model-invocation logging: meter the ledger from the invocation log group."\n'
        '  type        = bool\n'
        '  default     = false\n}\n'
        'variable "invocation_log_group_name" {\n  type    = string\n  default = null\n}\n'
        'variable "lambda_subnet_ids" {\n  type    = list(string)\n  default = []\n}\n'
        'variable "lambda_security_group_ids" {\n  type    = list(string)\n  default = []\n}\n'
        'variable "cloudwatch_retention_days" { type = number }\n'
        + '''variable "alarm_topic_arn" {
  description = "Enclave security-alarm SNS topic (cloudwatch-alarm-action-check)."
  type        = string
  default     = null
}
variable "alarms" {
  type    = bool
  default = true
}
variable "alarm_insufficient_data_action" {
  description = "cloudwatch-alarm-action-check insufficientDataActionRequired."
  type        = bool
  default     = true
}
variable "reserved_concurrency" {
  description = "lambda-concurrency-check: within the pack's [ConcurrencyLimitLow, ConcurrencyLimitHigh]."
  type        = number
  default     = 20
}
''' +
        'variable "tags" {\n  type = map(string)\n  default = {}\n}\n')
    main = (_seam_header("token-control", SEAM_RAW, "terraform-aws-modules/dynamodb-table 5.5.2 + lambda 8.12.0", "no official equivalent") +
        '# GOVERNANCE SEAM — the per-user token-control layer (doc 13) has no official module.\n'
        '# Usage ledger (DynamoDB, terraform-aws-modules) keyed per user/tenant. The enforcement\n'
        '# Lambda + client library ship with the enclave package; this wrapper provisions the ledger.\n'
        'module "usage_ledger" {\n'
        '  source  = "terraform-aws-modules/dynamodb-table/aws"\n'
        '  version = "5.5.2"\n\n'
        '  name                               = "sgea-token-usage-${var.env}"\n'
        '  billing_mode                       = "PAY_PER_REQUEST"\n'
        '  hash_key                           = "pk"\n'
        '  range_key                          = "sk"\n'
        '  attributes                         = [{ name = "pk", type = "S" }, { name = "sk", type = "S" }]\n'
        '  ttl_enabled                        = true\n'
        '  ttl_attribute_name                 = "expires_at"\n'
        '  server_side_encryption_enabled     = true # dynamodb-table-encrypted-kms\n'
        '  server_side_encryption_kms_key_arn = var.kms_key_arn\n'
        '  point_in_time_recovery_enabled     = true # dynamodb-pitr-enabled\n'
        '  deletion_protection_enabled        = true\n'
        '  tags                               = var.tags\n'
        '}\n\n'
        '# SGEA-TC-02: the meter credits the ledger from Bedrock model-invocation logs (token counts,\n'
        '# requestMetadata sgea_user / sgea_team) and writes a heartbeat every 15 minutes; the gateway\n'
        '# interceptor (SGEA-TC-01) denies tool calls past budget and fails closed on a stale heartbeat.\n'
        'data "aws_region" "this" {}\n'
        'data "aws_caller_identity" "this" {}\n\n'
        'module "meter" {\n'
        '  source  = "terraform-aws-modules/lambda/aws"\n'
        '  version = "8.12.0"\n'
        '  create  = var.meter\n\n'
        '  function_name                     = "sgea-${var.env}-token-meter"\n'
        '  runtime                           = "python3.15"\n'
        '  handler                           = "token_meter.handler"\n'
        '  create_package                    = false\n'
        '  local_existing_package            = "${path.module}/token_meter.zip"\n'
        '  timeout                           = 30\n'
        '  memory_size                       = 256\n'
        '  reserved_concurrent_executions    = var.reserved_concurrency # lambda-concurrency-check\n'
        '  kms_key_arn                       = var.kms_key_arn\n'
        '  environment_variables = {\n'
        '    TOKEN_LEDGER_TABLE = module.usage_ledger.dynamodb_table_id\n'
        '    TOKEN_TIMEZONE     = try(var.token_control.default_timezone, "UTC")\n'
        '  }\n'
        '  tracing_mode                      = "Active"\n'
        '  vpc_subnet_ids                    = length(var.lambda_subnet_ids) > 0 ? var.lambda_subnet_ids : null # lambda-inside-vpc\n'
        '  vpc_security_group_ids            = length(var.lambda_subnet_ids) > 0 ? var.lambda_security_group_ids : null\n'
        '  dead_letter_target_arn            = try(aws_sqs_queue.meter_dlq[0].arn, null) # lambda-dlq-check\n'
        '  cloudwatch_logs_retention_in_days = var.cloudwatch_retention_days\n'
        '  cloudwatch_logs_kms_key_id        = var.kms_key_arn\n'
        '  # iam-no-inline-policy-check: no module inline policies; one customer-managed policy + AWS managed ones.\n'
        '  attach_cloudwatch_logs_policy = false\n'
        '  attach_tracing_policy         = false\n'
        '  attach_network_policy         = false\n'
        '  attach_dead_letter_policy     = false\n'
        '  attach_policies               = true\n'
        '  number_of_policies            = 3\n'
        '  policies = [\n'
        '    try(aws_iam_policy.meter[0].arn, ""),\n'
        '    "arn:${data.aws_partition.this.partition}:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",\n'
        '    "arn:${data.aws_partition.this.partition}:iam::aws:policy/AWSXRayDaemonWriteAccess",\n'
        '  ]\n'
        '  allowed_triggers = {\n'
        '    invocation_logs = {\n'
        '      principal  = "logs.amazonaws.com"\n'
        '      source_arn = "arn:${data.aws_partition.this.partition}:logs:${data.aws_region.this.region}:${data.aws_caller_identity.this.account_id}:log-group:${coalesce(var.invocation_log_group_name, "none")}:*"\n'
        '    }\n'
        '    heartbeat = { principal = "events.amazonaws.com", source_arn = try(aws_cloudwatch_event_rule.heartbeat[0].arn, null) }\n'
        '  }\n'
        '  create_current_version_allowed_triggers = false\n'
        '  tags                              = var.tags\n'
        '}\n\n'
        'data "aws_partition" "this" {}\n\n'
        'resource "aws_cloudwatch_metric_alarm" "meter_errors" {\n'
        '  count                     = var.meter && var.alarms ? 1 : 0\n'
        '  alarm_name                = "sgea-${var.env}-token-meter-errors"\n'
        '  alarm_description         = "SGEA token meter errors: budgets stop crediting usage."\n'
        '  namespace                 = "AWS/Lambda"\n'
        '  metric_name               = "Errors"\n'
        '  dimensions                = { FunctionName = "sgea-${var.env}-token-meter" }\n'
        '  statistic                 = "Sum"\n'
        '  period                    = 300\n'
        '  evaluation_periods        = 1\n'
        '  threshold                 = 0\n'
        '  comparison_operator       = "GreaterThanThreshold"\n'
        '  treat_missing_data        = "notBreaching"\n'
        '  alarm_actions             = [var.alarm_topic_arn]\n'
        '  insufficient_data_actions = var.alarm_insufficient_data_action ? [var.alarm_topic_arn] : []\n'
        '  tags                      = var.tags\n'
        '}\n\n'
        '# The heartbeat runs every 15 minutes: no invocation for 30 minutes = meter down (the gateway\n'
        '# interceptor then fails closed after fail_closed_hours).\n'
        'resource "aws_cloudwatch_metric_alarm" "meter_silent" {\n'
        '  count                     = var.meter && var.alarms ? 1 : 0\n'
        '  alarm_name                = "sgea-${var.env}-token-meter-silent"\n'
        '  alarm_description         = "SGEA token meter has not run for 30 minutes."\n'
        '  namespace                 = "AWS/Lambda"\n'
        '  metric_name               = "Invocations"\n'
        '  dimensions                = { FunctionName = "sgea-${var.env}-token-meter" }\n'
        '  statistic                 = "Sum"\n'
        '  period                    = 900\n'
        '  evaluation_periods        = 2\n'
        '  threshold                 = 1\n'
        '  comparison_operator       = "LessThanThreshold"\n'
        '  treat_missing_data        = "breaching"\n'
        '  alarm_actions             = [var.alarm_topic_arn]\n'
        '  insufficient_data_actions = var.alarm_insufficient_data_action ? [var.alarm_topic_arn] : []\n'
        '  tags                      = var.tags\n'
        '}\n\n'
        'resource "aws_sqs_queue" "meter_dlq" {\n'
        '  count                     = var.meter ? 1 : 0\n'
        '  name                      = "sgea-${var.env}-token-meter-dlq"\n'
        '  kms_master_key_id         = var.kms_key_arn\n'
        '  message_retention_seconds = 1209600\n'
        '  tags                      = var.tags\n'
        '}\n\n'
        'resource "aws_iam_policy" "meter" {\n'
        '  count = var.meter ? 1 : 0\n'
        '  name  = "sgea-${var.env}-token-meter-function"\n'
        '  policy = jsonencode({\n'
        '    Version = "2012-10-17"\n'
        '    Statement = [\n'
        '      { Sid = "TokenLedger", Effect = "Allow", Action = ["dynamodb:UpdateItem", "dynamodb:PutItem"], Resource = module.usage_ledger.dynamodb_table_arn },\n'
        '      { Sid = "EnclaveKey", Effect = "Allow", Action = ["kms:Decrypt", "kms:GenerateDataKey"], Resource = var.kms_key_arn },\n'
        '      { Sid = "DeadLetter", Effect = "Allow", Action = "sqs:SendMessage", Resource = aws_sqs_queue.meter_dlq[0].arn },\n'
        '    ]\n'
        '  })\n'
        '  tags = var.tags\n'
        '}\n\n'
        'resource "aws_cloudwatch_log_subscription_filter" "meter" {\n'
        '  count           = var.meter ? 1 : 0\n'
        '  name            = "sgea-${var.env}-token-meter"\n'
        '  log_group_name  = var.invocation_log_group_name\n'
        '  filter_pattern  = ""\n'
        '  destination_arn = module.meter.lambda_function_arn\n'
        '  depends_on      = [module.meter]\n'
        '}\n\n'
        'resource "aws_cloudwatch_event_rule" "heartbeat" {\n'
        '  count               = var.meter ? 1 : 0\n'
        '  name                = "sgea-${var.env}-token-meter-heartbeat"\n'
        '  schedule_expression = "rate(15 minutes)"\n'
        '  tags                = var.tags\n'
        '}\n\n'
        'resource "aws_cloudwatch_event_target" "heartbeat" {\n'
        '  count = var.meter ? 1 : 0\n'
        '  rule  = aws_cloudwatch_event_rule.heartbeat[0].name\n'
        '  arn   = module.meter.lambda_function_arn\n'
        '}\n')
    outputs = ('output "usage_ledger_table_name" { value = module.usage_ledger.dynamodb_table_id }\n'
               'output "usage_ledger_table_arn" { value = module.usage_ledger.dynamodb_table_arn }\n'
               'output "meter_function_name" { value = module.meter.lambda_function_name }\n'
               'output "fail_closed_hours" { value = try(var.token_control.fail_closed_hours, 4) }\n')
    readme = ("# token-control (SGEA wrapper seam)\n\n"
              "**Seam kind:** raw governance adapter — the per-user/per-team token-control layer has "
              "**no official module**. This wrapper provisions the usage ledger (DynamoDB, encrypted, "
              "PITR, TTL) from the resolved-config `token_control` block.\n\n"
              "The enforcement Lambda and the client library ship with the enclave package; keeping "
              "them behind this wrapper means a future official module is a one-file swap.\n")
    return {"versions.tf": _versions_tf(partition, False), "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme}


# -------------------- enclave monitoring (ADR 0002) --------------------
# M2: CloudTrail metric filters (CIS-style). Literal CloudWatch Logs filter patterns, ADR 0002 table order.
CT_FILTERS = [
    ("unauthorized-api", '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'),
    ("console-no-mfa", '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }'),
    ("root-usage", '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'),
    ("iam-policy-changes", '{ ($.eventSource = "iam.amazonaws.com") && (($.eventName = "Put*Policy") || ($.eventName = "Delete*Policy") || ($.eventName = "Create*Policy*") || ($.eventName = "Attach*Policy") || ($.eventName = "Detach*Policy")) }'),
    ("cloudtrail-changes", '{ ($.eventName = "CreateTrail") || ($.eventName = "UpdateTrail") || ($.eventName = "DeleteTrail") || ($.eventName = "StartLogging") || ($.eventName = "StopLogging") || ($.eventName = "PutEventSelectors") }'),
    ("console-auth-failures", '{ ($.eventName = "ConsoleLogin") && ($.errorMessage = "Failed authentication") }'),
    ("kms-key-disable-or-delete", '{ ($.eventSource = "kms.amazonaws.com") && (($.eventName = "DisableKey") || ($.eventName = "ScheduleKeyDeletion")) }'),
    ("s3-bucket-policy-changes", '{ ($.eventSource = "s3.amazonaws.com") && (($.eventName = "PutBucketAcl") || ($.eventName = "PutBucketPolicy") || ($.eventName = "PutBucketCors") || ($.eventName = "PutBucketLifecycle") || ($.eventName = "PutBucketReplication") || ($.eventName = "DeleteBucketPolicy") || ($.eventName = "DeleteBucketCors") || ($.eventName = "DeleteBucketLifecycle") || ($.eventName = "DeleteBucketReplication")) }'),
    ("config-changes", '{ ($.eventSource = "config.amazonaws.com") && (($.eventName = "StopConfigurationRecorder") || ($.eventName = "DeleteDeliveryChannel") || ($.eventName = "PutDeliveryChannel") || ($.eventName = "PutConfigurationRecorder") || ($.eventName = "DeleteConfigurationRecorder")) }'),
    ("security-group-changes", '{ ($.eventName = "AuthorizeSecurityGroupIngress") || ($.eventName = "AuthorizeSecurityGroupEgress") || ($.eventName = "RevokeSecurityGroupIngress") || ($.eventName = "RevokeSecurityGroupEgress") || ($.eventName = "CreateSecurityGroup") || ($.eventName = "DeleteSecurityGroup") }'),
    ("nacl-changes", '{ ($.eventName = "CreateNetworkAcl") || ($.eventName = "CreateNetworkAclEntry") || ($.eventName = "DeleteNetworkAcl") || ($.eventName = "DeleteNetworkAclEntry") || ($.eventName = "ReplaceNetworkAclEntry") || ($.eventName = "ReplaceNetworkAclAssociation") }'),
    ("network-gateway-changes", '{ ($.eventName = "CreateCustomerGateway") || ($.eventName = "DeleteCustomerGateway") || ($.eventName = "AttachInternetGateway") || ($.eventName = "CreateInternetGateway") || ($.eventName = "DeleteInternetGateway") || ($.eventName = "DetachInternetGateway") }'),
    ("route-table-changes", '{ ($.eventSource = "ec2.amazonaws.com") && (($.eventName = "CreateRoute") || ($.eventName = "CreateRouteTable") || ($.eventName = "ReplaceRoute") || ($.eventName = "ReplaceRouteTableAssociation") || ($.eventName = "DeleteRouteTable") || ($.eventName = "DeleteRoute") || ($.eventName = "DisassociateRouteTable")) }'),
    ("vpc-changes", '{ ($.eventName = "CreateVpc") || ($.eventName = "DeleteVpc") || ($.eventName = "ModifyVpcAttribute") || ($.eventName = "AcceptVpcPeeringConnection") || ($.eventName = "CreateVpcPeeringConnection") || ($.eventName = "DeleteVpcPeeringConnection") || ($.eventName = "RejectVpcPeeringConnection") || ($.eventName = "AttachClassicLinkVpc") || ($.eventName = "DetachClassicLinkVpc") || ($.eventName = "DisableVpcClassicLink") || ($.eventName = "EnableVpcClassicLink") }'),
    ("organizations-changes", '{ ($.eventSource = "organizations.amazonaws.com") && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreatePolicy") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy")) }'),
]
# M1: EventBridge rule names (stack-drift is CDK only: Terraform drift = scheduled `terraform plan -detailed-exitcode`).
EVENT_RULES = ["guardduty", "securityhub", "inspector", "config-compliance", "backup", "secret-rotation", "access-analyzer"]
# M3: service-health alarm names.
HEALTH_ALARMS = ["bedrock-throttles", "bedrock-server-errors", "bedrock-invocation-log-delivery",
                 "guardrail-interventions", "gateway-system-errors", "gateway-throttles"]


def _health_alarm(key, name, desc, namespace, metric, stat, period, evals, threshold, op, dims, missing="notBreaching"):
    return ('resource "aws_cloudwatch_metric_alarm" "' + key + '" {\n'
            '  alarm_name                = "sgea-${var.env}-' + name + '"\n'
            '  alarm_description         = "' + desc + '"\n'
            '  namespace                 = "' + namespace + '"\n'
            '  metric_name               = "' + metric + '"\n'
            + ('  dimensions                = ' + dims + '\n' if dims else '') +
            '  statistic                 = "' + stat + '"\n'
            '  period                    = ' + str(period) + '\n'
            '  evaluation_periods        = ' + str(evals) + '\n'
            '  datapoints_to_alarm       = ' + str(evals) + '\n'
            '  threshold                 = ' + threshold + '\n'
            '  comparison_operator       = "' + op + '"\n'
            '  treat_missing_data        = "' + missing + '"\n'
            '  alarm_actions             = [var.alarm_topic_arn]\n'
            '  ok_actions                = local.ok_actions\n'
            '  insufficient_data_actions = local.insufficient_data_actions\n'
            '  tags                      = var.tags\n'
            '}\n\n')


def _mod_enclave_monitoring(partition, gateway=True, invocation_logging=True):
    """ADR 0002 enclave-monitoring layer. Emit-time switches: `gateway` (AgentCore gateway exists),
    `invocation_logging` (model-invocation logging on); Budgets / Cost Anomaly Detection only in the
    commercial partition (GovCloud billing lives in the commercial payer account)."""
    cost = partition == "aws"
    variables = (_seam_header("enclave-monitoring", SEAM_RAW, "raw EventBridge / CloudWatch / Budgets / CE / Access Analyzer / X-Ray",
                              "point at an official monitoring module if one ships") + """\
variable "env" { type = string }
variable "alarm_topic_arn" {
  description = "Enclave security-alarm SNS topic sgea-<env>-security-alarms (CMK-encrypted); every notification goes here."
  type        = string
}
variable "kms_key_arn" {
  description = "Enclave CMK (aws/spans log group)."
  type        = string
}
variable "cloudtrail_log_group_name" {
  description = "Enclave trail log group (/sgea/<env>/cloudtrail) the M2 metric filters read."
  type        = string
}
variable "cloudwatch_retention_days" {
  description = "Pack retention for the aws/spans log group (cw-loggroup-retention-period-check)."
  type        = number
}
variable "alarm_insufficient_data_action" {
  description = "cloudwatch-alarm-action-check insufficientDataActionRequired."
  type        = bool
  default     = true
}
variable "alarm_ok_action" {
  description = "cloudwatch-alarm-action-check okActionRequired."
  type        = bool
  default     = false
}
variable "create_access_analyzer" {
  type    = bool
  default = true
}
variable "create_unused_access_analyzer" {
  type    = bool
  default = false
}
variable "manage_transaction_search" {
  type    = bool
  default = true
}
variable "monthly_budget_usd" {
  type    = number
  default = 0
}
variable "create_cost_anomaly_monitor" {
  type    = bool
  default = false
}
variable "break_glass" {
  description = "The break-glass role exists (create_break_glass_role): alarm on every assumption."
  type        = bool
  default     = false
}
variable "break_glass_role_arn" {
  type    = string
  default = null
}
variable "guardrail_arn" { type = string }
variable "guardrail_version" { type = string }
variable "guardrail_intervention_threshold" {
  type    = number
  default = 50
}
""" + ("""variable "gateway_arn" {
  description = "AgentCore gateway ARN (gateway-* alarms)."
  type        = string
}
""" if gateway else "") + """variable "tags" {
  type    = map(string)
  default = {}
}
""")
    filters = "".join("    %s = %s\n" % (json.dumps(n), json.dumps(p)) for n, p in CT_FILTERS)
    main = (_seam_header("enclave-monitoring", SEAM_RAW, "raw EventBridge / CloudWatch / Budgets / CE / Access Analyzer / X-Ray",
                         "swap internals only") + """\
# ADR 0002 — enclave monitoring, audit protection and break-glass. Every notification goes to the
# CMK-encrypted topic sgea-<env>-security-alarms (topic policy: enclave-logging; key policy
# statement EventDeliveryToEncryptedSns: enclave-kms).
data "aws_caller_identity" "this" {}
data "aws_partition" "this" {}
data "aws_region" "this" {}

locals {
  account                   = data.aws_caller_identity.this.account_id
  arn                       = data.aws_partition.this.partition
  region                    = data.aws_region.this.region
  ok_actions                = var.alarm_ok_action ? [var.alarm_topic_arn] : []
  insufficient_data_actions = var.alarm_insufficient_data_action ? [var.alarm_topic_arn] : []
  analyzer                  = var.create_access_analyzer || var.create_unused_access_analyzer
}

# ----- M1: event routing (EventBridge default bus -> SNS) -----
locals {
  event_patterns = merge({
    guardduty = {
      source      = ["aws.guardduty"]
      detail-type = ["GuardDuty Finding"]
      detail      = { severity = [{ numeric = [">=", 7] }] }
    }
    securityhub = {
      source      = ["aws.securityhub"]
      detail-type = ["Security Hub Findings - Imported"]
      detail = { findings = {
        Severity = { Label = ["HIGH", "CRITICAL"] }
        Workflow = { Status = ["NEW"] }
      } }
    }
    inspector = {
      source      = ["aws.inspector2"]
      detail-type = ["Inspector2 Finding"]
      detail      = { severity = ["HIGH", "CRITICAL"] }
    }
    config-compliance = {
      source      = ["aws.config"]
      detail-type = ["Config Rules Compliance Change"]
      detail      = { newEvaluationResult = { complianceType = ["NON_COMPLIANT"] } }
    }
    backup = {
      source      = ["aws.backup"]
      detail-type = ["Backup Job State Change", "Copy Job State Change", "Restore Job State Change"]
      detail      = { state = ["FAILED", "ABORTED", "EXPIRED"] }
    }
    secret-rotation = {
      source      = ["aws.secretsmanager"]
      detail-type = ["AWS Service Event via CloudTrail"]
      detail      = { eventName = ["RotationFailed"] }
    }
    }, local.analyzer ? {
    access-analyzer = {
      source      = ["aws.access-analyzer"]
      detail-type = ["Access Analyzer Finding"]
      detail      = { status = ["ACTIVE"] }
    }
  } : {})
}

resource "aws_cloudwatch_event_rule" "this" {
  for_each      = local.event_patterns
  name          = "sgea-${var.env}-evt-${each.key}"
  description   = "SGEA ${each.key} events to the enclave security-alarm topic."
  event_pattern = jsonencode(each.value)
  tags          = var.tags
}

resource "aws_cloudwatch_event_target" "this" {
  for_each  = local.event_patterns
  rule      = aws_cloudwatch_event_rule.this[each.key].name
  target_id = "sgea-security-alarms"
  arn       = var.alarm_topic_arn
}

# ----- M2: CloudTrail metric filters + alarms (/sgea/<env>/cloudtrail) -----
locals {
  ct_filters = merge({
""" + filters + """  }, var.break_glass ? {
    break-glass-assumed = "{ ($.eventName = \\"AssumeRole\\") && ($.requestParameters.roleArn = \\"${var.break_glass_role_arn}\\") }"
  } : {})
}

resource "aws_cloudwatch_log_metric_filter" "this" {
  for_each       = local.ct_filters
  name           = "sgea-${var.env}-ct-${each.key}"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = each.value
  metric_transformation {
    name      = each.key
    namespace = "SGEA/${var.env}/CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail" {
  for_each                  = local.ct_filters
  alarm_name                = "sgea-${var.env}-ct-${each.key}"
  alarm_description         = "SGEA CloudTrail ${each.key} (metric filter on the enclave trail)."
  namespace                 = "SGEA/${var.env}/CloudTrail"
  metric_name               = each.key
  statistic                 = "Sum"
  period                    = 300
  evaluation_periods        = 1
  threshold                 = 1
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  treat_missing_data        = "notBreaching"
  alarm_actions             = [var.alarm_topic_arn]
  ok_actions                = local.ok_actions
  insufficient_data_actions = local.insufficient_data_actions
  tags                      = var.tags
  depends_on                = [aws_cloudwatch_log_metric_filter.this]
}

# ----- M3: service health -----
""" + _health_alarm("bedrock_throttles", "bedrock-throttles", "Bedrock invocation throttles (account aggregate).",
                    "AWS/Bedrock", "InvocationThrottles", "Sum", 300, 2, "10", "GreaterThanOrEqualToThreshold", None)
      + _health_alarm("bedrock_server_errors", "bedrock-server-errors", "Bedrock invocation server errors (account aggregate).",
                      "AWS/Bedrock", "InvocationServerErrors", "Sum", 300, 1, "5", "GreaterThanOrEqualToThreshold", None)
      + (_health_alarm("bedrock_invocation_log_delivery", "bedrock-invocation-log-delivery",
                       "Bedrock model-invocation logs are not reaching CloudWatch Logs.",
                       "AWS/Bedrock", "ModelInvocationLogsCloudWatchDeliverySuccess", "Minimum", 900, 1, "1",
                       "LessThanThreshold", None) if invocation_logging else "")
      + _health_alarm("guardrail_interventions", "guardrail-interventions", "Baseline guardrail interventions above threshold.",
                      "AWS/Bedrock/Guardrails", "InvocationsIntervened", "Sum", 900, 1, "var.guardrail_intervention_threshold",
                      "GreaterThanOrEqualToThreshold", "{ GuardrailArn = var.guardrail_arn, GuardrailVersion = var.guardrail_version }")
      + (_health_alarm("gateway_system_errors", "gateway-system-errors", "AgentCore gateway system errors.",
                       "AWS/Bedrock-AgentCore", "SystemErrors", "Sum", 300, 1, "5", "GreaterThanOrEqualToThreshold",
                       '{ Operation = "InvokeGateway", Protocol = "MCP", Resource = var.gateway_arn }')
         + _health_alarm("gateway_throttles", "gateway-throttles", "AgentCore gateway throttles.",
                         "AWS/Bedrock-AgentCore", "Throttles", "Sum", 300, 2, "10", "GreaterThanOrEqualToThreshold",
                         '{ Operation = "InvokeGateway", Protocol = "MCP", Resource = var.gateway_arn }') if gateway else "")
      + ("""# ----- M4: cost (commercial partition; GovCloud billing lives in the commercial payer account) -----
resource "aws_budgets_budget" "monthly" {
  count        = var.monthly_budget_usd > 0 ? 1 : 0
  name         = "sgea-${var.env}-monthly-cost"
  budget_type  = "COST"
  time_unit    = "MONTHLY"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [var.alarm_topic_arn]
  }
  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "FORECASTED"
    subscriber_sns_topic_arns = [var.alarm_topic_arn]
  }
  tags = var.tags
}

resource "aws_ce_anomaly_monitor" "services" {
  count             = var.create_cost_anomaly_monitor ? 1 : 0
  name              = "sgea-${var.env}-services"
  monitor_type      = "DIMENSIONAL"
  monitor_dimension = "SERVICE"
  tags              = var.tags
}

resource "aws_ce_anomaly_subscription" "anomalies" {
  count            = var.create_cost_anomaly_monitor ? 1 : 0
  name             = "sgea-${var.env}-anomalies"
  frequency        = "IMMEDIATE"
  monitor_arn_list = [aws_ce_anomaly_monitor.services[0].arn]
  subscriber {
    type    = "SNS"
    address = var.alarm_topic_arn
  }
  threshold_expression {
    dimension {
      key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      match_options = ["GREATER_THAN_OR_EQUAL"]
      values        = ["100"]
    }
  }
  tags = var.tags
}

""" if cost else "# ----- M4: cost — skipped in " + partition + " (Budgets / Cost Anomaly Detection live in the commercial payer account) -----\n\n")
      + """# ----- M5: IAM Access Analyzer (findings route through M1 access-analyzer) -----
resource "aws_accessanalyzer_analyzer" "external" {
  count         = var.create_access_analyzer ? 1 : 0
  analyzer_name = "sgea-${var.env}-external-access"
  type          = "ACCOUNT"
  tags          = var.tags
}

resource "aws_accessanalyzer_analyzer" "unused" {
  count         = var.create_unused_access_analyzer ? 1 : 0
  analyzer_name = "sgea-${var.env}-unused-access"
  type          = "ACCOUNT_UNUSED_ACCESS"
  configuration {
    unused_access {
      unused_access_age = 90
    }
  }
  tags = var.tags
}

# ----- M6: CloudWatch Transaction Search (OpenTelemetry spans -> aws/spans) -----
# `aws/spans` cannot be created by the enclave (log-group names starting with aws/ are reserved; sandbox
# 2026-10-26): X-Ray creates it with the first spans. CMK and retention are a post-deploy step (MANUAL-STEPS.md).
resource "aws_cloudwatch_log_resource_policy" "transaction_search" {
  count       = var.manage_transaction_search ? 1 : 0
  policy_name = "sgea-${var.env}-transaction-search"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "TransactionSearchXRayAccess"
      Effect    = "Allow"
      Principal = { Service = "xray.amazonaws.com" }
      Action    = "logs:PutLogEvents"
      Resource = [
        "arn:${local.arn}:logs:${local.region}:${local.account}:log-group:aws/spans:*",
        "arn:${local.arn}:logs:${local.region}:${local.account}:log-group:/aws/application-signals/data:*",
      ]
      Condition = {
        ArnLike      = { "aws:SourceArn" = "arn:${local.arn}:xray:${local.region}:${local.account}:*" }
        StringEquals = { "aws:SourceAccount" = local.account }
      }
    }]
  })
}

# AWS::XRay::TransactionSearchConfig: spans to CloudWatch Logs, 1 % indexed as trace summaries.
resource "awscc_xray_transaction_search_config" "this" {
  count               = var.manage_transaction_search ? 1 : 0
  indexing_percentage = 1
  depends_on          = [aws_cloudwatch_log_resource_policy.transaction_search]
}
""")
    outputs = ('output "event_rule_names" { value = [for r in aws_cloudwatch_event_rule.this : r.name] }\n'
               'output "cloudtrail_alarm_names" { value = [for a in aws_cloudwatch_metric_alarm.cloudtrail : a.alarm_name] }\n'
               'output "external_access_analyzer_arn" { value = one(aws_accessanalyzer_analyzer.external[*].arn) }\n'
               'output "spans_log_group" { value = var.manage_transaction_search ? "aws/spans" : null }\n')
    readme = ("# enclave-monitoring (SGEA wrapper seam, ADR 0002)\n\n"
              "Every notification goes to the CMK-encrypted topic `sgea-<env>-security-alarms`.\n\n"
              "- **M1** EventBridge rules `sgea-<env>-evt-*`: GuardDuty (severity >= 7), Security Hub (HIGH/CRITICAL, NEW), "
              "Inspector (HIGH/CRITICAL), Config NON_COMPLIANT, Backup / copy / restore failures, Secrets Manager "
              "RotationFailed, Access Analyzer ACTIVE findings (when an analyzer is created). Stack drift is CDK-only; "
              "with Terraform run a scheduled `terraform plan -detailed-exitcode` in the pipeline (OPERATIONS.md).\n"
              "- **M2** CloudTrail metric filters + alarms `sgea-<env>-ct-*` on `/sgea/<env>/cloudtrail` "
              "(namespace `SGEA/<env>/CloudTrail`); `ct-break-glass-assumed` only with the break-glass role.\n"
              "- **M3** Bedrock throttles / server errors" + (" / invocation-log delivery" if invocation_logging else "") +
              ", guardrail interventions" + (", AgentCore gateway system errors / throttles" if gateway else "") + ".\n"
              + ("- **M4** AWS Budgets `sgea-<env>-monthly-cost` (when `monthly_budget_usd` > 0) and Cost Anomaly Detection "
                 "`sgea-<env>-services` / `sgea-<env>-anomalies` (>= USD 100 total impact).\n" if cost else
                 "- **M4** skipped in " + partition + ": billing lives in the commercial payer account.\n") +
              "- **M5** IAM Access Analyzer `sgea-<env>-external-access` (optional `sgea-<env>-unused-access`, 90 days).\n"
              "- **M6** CloudWatch Transaction Search: the X-Ray log resource policy and Transaction Search (X-Ray creates `aws/spans`; CMK and retention are a post-deploy step), the X-Ray "
              "log resource policy, `awscc_xray_transaction_search_config` at 1 % indexing.\n\n"
              "> Where `kms_key_arn` is customer-supplied, its key policy needs the `EventDeliveryToEncryptedSns` "
              "statement (events / budgets / costalerts) or EventBridge and cost notifications are dropped.\n")
    return {"versions.tf": _versions_tf(partition, True), "variables.tf": variables,
            "main.tf": main, "outputs.tf": outputs, "README.md": readme}


WRAPPERS = {
    "bedrock-guardrail": _mod_bedrock_guardrail,
    "bedrock-knowledge-base": _mod_bedrock_kb,
    "agentcore-runtime": _mod_agentcore_runtime,
    "enclave-kms": _mod_enclave_kms,
    "agentcore-platform": _mod_agentcore_platform,
    "enclave-network": _mod_enclave_network,
    "enclave-aurora": _mod_enclave_aurora,
    "security-services": _mod_security_services,
    "dod-scca": _mod_dod_scca,
    "enclave-logging": _mod_enclave_logging,
    "config-conformance": _mod_config_conformance,
    "org-guardrail": _mod_org_guardrail,
    "token-control": _mod_token_control,
    "enclave-backup": _mod_enclave_backup,
    "account-baseline": _mod_account_baseline,
}


INTERCEPTOR_SOURCE = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "lambda",
                                       "tool_policy_interceptor.py")).read()
METER_SOURCE = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "lambda", "token_meter.py")).read()


def _write_zip(path, files):
    """Deterministic zip (fixed timestamps) so source_code_hash only changes with the code."""
    import zipfile
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            z.writestr(info, content)


def derive_bundles(resolved, root):
    return policy_library.bundles(resolved, authorized_model_ids(resolved, root))


MONITORING_VARIABLES = """\
# ----- ADR 0002 monitoring toggles (a landing zone may own these) -----
variable "manage_monitoring" {
  description = "ADR 0002 enclave-monitoring layer (event routing, CloudTrail / service alarms, cost, Access Analyzer, Transaction Search)."
  type        = bool
  default     = true
}
variable "create_access_analyzer" {
  description = "IAM Access Analyzer sgea-<env>-external-access (type ACCOUNT). false where the landing zone runs one."
  type        = bool
  default     = true
}
variable "create_unused_access_analyzer" {
  description = "IAM Access Analyzer sgea-<env>-unused-access (ACCOUNT_UNUSED_ACCESS, 90 days; paid)."
  type        = bool
  default     = false
}
variable "manage_transaction_search" {
  description = "CloudWatch Transaction Search (log resource policy + TransactionSearchConfig). X-Ray creates aws/spans; apply the CMK and retention after the first spans (MANUAL-STEPS.md)."
  type        = bool
  default     = true
}
variable "monthly_budget_usd" {
  description = "AWS Budgets monthly cost budget sgea-<env>-monthly-cost in USD; 0 = off. Commercial partition only."
  type        = number
  default     = 0
}
variable "create_cost_anomaly_monitor" {
  description = "Cost Anomaly Detection sgea-<env>-services / sgea-<env>-anomalies. Commercial partition only. Off by default: an account allows one SERVICE monitor and AWS often creates a default one."
  type        = bool
  default     = false
}
variable "create_break_glass_role" {
  description = "Break-glass role sgea-<env>-break-glass (AdministratorAccess, MFA within 1 hour; needs break_glass_principal_arns)."
  type        = bool
  default     = false
  validation {
    condition     = !var.create_break_glass_role || length(var.break_glass_principal_arns) > 0
    error_message = "create_break_glass_role needs break_glass_principal_arns (who may assume the role)."
  }
}
variable "break_glass_principal_arns" {
  description = "IAM principals that may assume the break-glass role (with MFA)."
  type        = list(string)
  default     = []
}
variable "guardrail_intervention_threshold" {
  description = "sgea-<env>-guardrail-interventions: baseline-guardrail interventions per 15 minutes."
  type        = number
  default     = 50
}
"""


def _root_monitoring(resolved, root, agentcore, inv_logging):
    """Root-stack HCL: ADR 0002 break-glass role + the enclave-monitoring module call."""
    ab = account_baseline(resolved, root)
    return (
        '# ----- ADR 0002: break-glass role (MFA, 1-hour sessions; every assumption alarms) -----\n'
        'data "aws_partition" "current" {}\n\n'
        'resource "aws_iam_role" "break_glass" {\n'
        '  count                = var.create_break_glass_role ? 1 : 0\n'
        '  name                 = "sgea-${var.env}-break-glass" # SCP DenyAuditTampering exempts arn:<partition>:iam::*:role/sgea-*-break-glass\n'
        '  description          = "SGEA break-glass access. Post-use review: docs/operations/access-review.md."\n'
        '  max_session_duration = 3600\n'
        '  assume_role_policy = jsonencode({\n'
        '    Version = "2012-10-17"\n'
        '    Statement = [{\n'
        '      Sid       = "BreakGlassWithMfa"\n'
        '      Effect    = "Allow"\n'
        '      Principal = { AWS = var.break_glass_principal_arns }\n'
        '      Action    = "sts:AssumeRole"\n'
        '      Condition = {\n'
        '        Bool            = { "aws:MultiFactorAuthPresent" = "true" }\n'
        '        NumericLessThan = { "aws:MultiFactorAuthAge" = "3600" }\n'
        '      }\n'
        '    }]\n'
        '  })\n'
        '  tags = { "sgea:role" = "break-glass" }\n'
        '}\n\n'
        '# AWS managed AdministratorAccess (no inline policy: iam-no-inline-policy-check).\n'
        'resource "aws_iam_role_policy_attachment" "break_glass" {\n'
        '  count      = var.create_break_glass_role ? 1 : 0\n'
        '  role       = aws_iam_role.break_glass[0].name\n'
        '  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess"\n'
        '}\n\n'
        '# ----- ADR 0002: enclave monitoring (events, CloudTrail / service alarms, cost, Access Analyzer, Transaction Search) -----\n'
        'module "enclave_monitoring" {\n'
        '  source                           = "./modules/enclave-monitoring"\n'
        '  count                            = var.manage_monitoring ? 1 : 0\n'
        '  env                              = var.env\n'
        '  alarm_topic_arn                  = module.enclave_logging.monitoring_topic_arn\n'
        '  kms_key_arn                      = local.kms_key_arn\n'
        '  cloudtrail_log_group_name        = module.enclave_logging.cloudtrail_log_group\n'
        '  cloudwatch_retention_days        = ' + str(log_retention_days(resolved, root)) + '\n'
        '  alarm_insufficient_data_action   = ' + ("true" if ab["alarm_insufficient_data_action"] else "false") + '\n'
        '  alarm_ok_action                  = ' + ("true" if ab["alarm_ok_action"] else "false") + '\n'
        '  create_access_analyzer           = var.create_access_analyzer\n'
        '  create_unused_access_analyzer    = var.create_unused_access_analyzer\n'
        '  manage_transaction_search        = var.manage_transaction_search\n'
        '  monthly_budget_usd               = var.monthly_budget_usd\n'
        '  create_cost_anomaly_monitor      = var.create_cost_anomaly_monitor\n'
        '  break_glass                      = var.create_break_glass_role\n'
        '  break_glass_role_arn             = one(aws_iam_role.break_glass[*].arn)\n'
        '  guardrail_arn                    = module.baseline_guardrail.guardrail_arn\n'
        '  guardrail_version                = module.baseline_guardrail.guardrail_version\n'
        '  guardrail_intervention_threshold = var.guardrail_intervention_threshold\n'
        + ('  gateway_arn                      = module.agentcore_platform.gateway_arn\n' if agentcore else '') +
        '}\n\n')


def emit(resolved, prof, outdir, root=None):
    written = []
    partition = resolved["partition"]
    primary = resolved["regions"]["primary"]
    govcloud = partition == "aws-us-gov"
    pid = resolved["profile"]["id"]
    header = ("# GENERATED BY SGEA (wrapper-seam design, ADR 0001) — do not edit by hand.\n"
              "# Profile: " + pid + "  Baselines: " + ", ".join(resolved["baselines"]) + "\n"
              "# Partition: " + partition + "  Primary region: " + primary + "\n\n")

    # ---- wrapper modules ----
    for name, fn in WRAPPERS.items():
        files = fn(partition)
        for fname, content in files.items():
            written.append(_w(os.path.join(outdir, "modules", name, fname), content))

    # ---- ADR 0002 monitoring layer (emit-time: gateway / invocation logging / partition) ----
    agentcore = "bedrock-agentcore" in resolved["services"]["allow"]
    inv_logging = bool(resolved["logging"].get("model_invocation_logging"))
    for fname, content in _mod_enclave_monitoring(partition, gateway=agentcore, invocation_logging=inv_logging).items():
        written.append(_w(os.path.join(outdir, "modules", "enclave-monitoring", fname), content))

    # ---- tool-path interceptor Lambda package (deterministic zip) ----
    _write_zip(os.path.join(outdir, "modules", "agentcore-platform", "tool_policy_interceptor.zip"),
               {"tool_policy_interceptor.py": INTERCEPTOR_SOURCE})
    written.append(os.path.join(outdir, "modules", "agentcore-platform", "tool_policy_interceptor.zip"))
    _write_zip(os.path.join(outdir, "modules", "token-control", "token_meter.zip"), {"token_meter.py": METER_SOURCE})
    written.append(os.path.join(outdir, "modules", "token-control", "token_meter.zip"))

    # ---- SCP/RCP statement library (resolved config -> templatefile documents) ----
    bundles = derive_bundles(resolved, root)
    for b in bundles:
        written.append(_w(os.path.join(outdir, "modules", "org-guardrail", "policies", b["name"] + ".json.tftpl"),
                          b["template"] + "\n"))

    # ---- conformance pack templates (pinned AWS sources -> module) ----
    packs = resolved.get("evidence", {}).get("conformance_packs", [])
    pack_files = {}
    for pack in packs:
        fname = "Operational-Best-Practices-for-" + pack + ".yaml"
        src = os.path.join(root or ".", "sources", "conformance-packs", fname)
        if not os.path.exists(src):
            raise SystemExit("conformance pack template missing: " + src)
        written.append(_w(os.path.join(outdir, "modules", "config-conformance", "packs", fname), pack_template(root, fname)))
        pack_files[pack_resource_name(pack)] = fname

    # ---- providers.tf (both official providers; awscc is the AgentCore path) ----
    providers = header + (
        'terraform {\n  required_version = ">= 1.11"\n  required_providers {\n'
        '    aws   = { source = "hashicorp/aws",   version = ">= 6.0" }\n'
        '    awscc = { source = "hashicorp/awscc", version = ">= 1.100" }\n'
        '  }\n}\n\n'
        'provider "aws" {\n  region = var.primary_region\n'
        + ('  # GovCloud partition\n' if govcloud else '')
        + '  default_tags { tags = var.default_tags }\n}\n\n'
        'provider "aws" {\n  alias  = "replica"\n  region = var.replica_region\n  default_tags { tags = var.default_tags }\n}\n\n'
        'provider "awscc" {\n  region = var.primary_region\n}\n')
    written.append(_w(os.path.join(outdir, "providers.tf"), providers))

    # ---- backend.tf ----
    tf = (resolved.get("emit", {}) or {}).get("terraform", {}) or {}
    if tf.get("backend", "s3") == "s3":
        back = header + ('terraform {\n  backend "s3" {\n    key     = "sgea/' + pid + '/terraform.tfstate"\n    encrypt = true\n  }\n}\n')
    else:
        back = header + 'terraform {\n  backend "local" {}\n}\n'
    written.append(_w(os.path.join(outdir, "backend.tf"), back))

    # ---- variables.tf (environment identifiers — supplied by the customer, NOT the profile) ----
    variables = header + (
        'variable "primary_region" { type = string }\n'
        'variable "replica_region" { type = string }\n'
        'variable "default_tags" {\n  type = map(string)\n  default = {}\n}\n'
        '# Environment identifiers (customer-supplied; not control decisions):\n'
        'variable "env" {\n  type = string\n  default = "nonprod"\n}\n'
        'variable "kms_key_arn" {\n  description = "Existing enclave CMK; when null SGEA creates one (modules/enclave-kms)."\n  type = string\n  default = null\n}\n'
        'variable "create_config_recorder" {\n  type = bool\n  default = false\n}\n'
        'variable "vpc_id" {\n  description = "Enclave VPC (customer-supplied). Endpoints are emitted only when set."\n  type = string\n  default = null\n}\n'
        'variable "endpoint_subnet_ids" {\n  type = list(string)\n  default = []\n}\n'
        'variable "endpoint_security_group_ids" {\n  type = list(string)\n  default = []\n}\n'
        'variable "endpoint_route_table_ids" {\n  type = list(string)\n  default = []\n}\n'
        'variable "create_guardduty" {\n  description = "false where GuardDuty is already enabled (org delegated admin / existing detector)."\n  type = bool\n  default = true\n}\n'
        'variable "create_inspector" {\n  description = "false where Amazon Inspector is managed by an org delegated admin."\n  type = bool\n  default = true\n}\n'
        'variable "manage_account_baseline" {\n  description = "Account settings the packs evaluate (EBS default encryption, snapshot / S3 public-access blocks, password policy, closed default SG). false where the landing zone owns them."\n  type = bool\n  default = true\n}\n'
        'variable "create_securityhub" {\n  description = "false where Security Hub is already enabled."\n  type = bool\n  default = true\n}\n'
        'variable "deploy_org_policies" {\n  description = "Create/attach the SCP/RCP bundles. Requires the Organizations management (or delegated) account; false for single-account sandboxes."\n  type = bool\n  default = true\n}\n'
        'variable "scca_firewall_subnet_ids" {\n  description = "DoD SCCA VDSS: dedicated firewall subnets (one per AZ) in vpc_id. Emitted only for DoD IL4/IL5 when set."\n  type = list(string)\n  default = []\n}\n'
        'variable "scca_egress_domains" {\n  description = "DoD SCCA VDSS: allowed egress FQDNs. Empty = all egress dropped."\n  type = list(string)\n  default = []\n}\n'
        'variable "aurora_subnet_ids" {\n  description = "Private subnets (>= 2 AZs) for the Aurora vector store. Emitted only when set."\n  type = list(string)\n  default = []\n}\n'
        'variable "aurora_security_group_ids" {\n  type = list(string)\n  default = []\n}\n'
        'variable "tool_policy" {\n  description = "Tool-path interceptor rules (GovCloud): JSON list of {effect, tools[], claim?, values[]}. Default denies every tools/call."\n  type = string\n  default = "[]"\n}\n'
        'variable "memory_event_expiry_days" {\n  type = number\n  default = 30\n}\n'
        'variable "agent_subnet_ids" {\n  type = list(string)\n  default = []\n}\n'
        'variable "agent_security_group_ids" {\n  type = list(string)\n  default = []\n}\n'
        'variable "agent_jwt_discovery_url" {\n  type = string\n  default = null\n}\n'
        'variable "agent_jwt_allowed_clients" {\n  type = list(string)\n  default = []\n}\n'
        'variable "org_target_ids" {\n  type = list(string)\n  default = []\n}\n'
        'variable "scp_policy_documents" {\n  description = "Optional bundle name (sgea-scp-N / sgea-rcp-N) -> JSON overriding the rendered statements."\n  type = map(string)\n  default = {}\n}\n'
        'variable "org_id" {\n  type = string\n  default = null\n}\n'
        'variable "perimeter_vpc_ids" {\n  type = list(string)\n  default = []\n}\n'
        'variable "perimeter_cidrs" {\n  type = list(string)\n  default = []\n}\n'
        'variable "kb_role_arn" {\n  type = string\n  default = null\n}\n'
        'variable "kb_embedding_model_arn" {\n  type = string\n  default = null\n}\n'
        'variable "kb_aurora" {\n  type = any\n  default = null\n  description = "Aurora/pgvector storage inputs for the knowledge-base wrapper."\n}\n'
        'variable "agent_execution_role_arn" {\n  type = string\n  default = null\n}\n'
        'variable "agent_container_uri" {\n  type = string\n  default = null\n}\n'
        + MONITORING_VARIABLES)
    written.append(_w(os.path.join(outdir, "variables.tf"), variables))

    # ---- resolved control decisions as tfvars ----
    tfvars = {
        "primary_region": primary,
        "replica_region": replica_region(resolved),
        # "+"-joined: commas are not valid in AWS tag values.
        "default_tags": {"sgea:profile": pid, "sgea:baselines": "+".join(resolved["baselines"])},
    }
    written.append(_w(os.path.join(outdir, "sgea.auto.tfvars.json"), json.dumps(tfvars, indent=2) + "\n"))

    # ---- root stack: call the wrapper modules with resolved-config values ----
    g = resolved["guardrails"]
    guardrail_hcl = json.dumps(g)
    bk = backup_policy(resolved, root)
    main = header + (
        'locals {\n'
        '  # The resolved control decisions SGEA baked in (audit copy in resolved_profile.json).\n'
        '  guardrail     = jsondecode(' + json.dumps(guardrail_hcl) + ')\n'
        '  scp_packs     = ' + json.dumps(resolved["policies"]["scps"]) + '\n'
        '  rcp_packs     = ' + json.dumps(resolved["policies"]["rcps"]) + '\n'
        '  token_control = jsondecode(' + json.dumps(json.dumps(resolved["token_control"])) + ')\n'
        '  logging       = jsondecode(' + json.dumps(json.dumps(resolved["logging"])) + ')\n'
        '  kms_key_arn   = var.kms_key_arn != null ? var.kms_key_arn : module.enclave_kms[0].key_arn\n'
        '}\n\n'
        '# ----- enclave foundation (KMS, logging, detective controls) -----\n'
        '# AWS Config service-linked role first: the enclave CMK and the Config store name it as a principal\n'
        '# (no wildcard principals). Where the landing zone owns Config (create_config_recorder = false) it exists.\n'
        'resource "aws_iam_service_linked_role" "config" {\n'
        '  count            = var.create_config_recorder ? 1 : 0\n'
        '  aws_service_name = "config.amazonaws.com"\n'
        '}\n\n'
        'locals {\n'
        '  # Referencing the role (not module depends_on, which would defer every module value) orders it first.\n'
        '  config_service_role_arn = one(aws_iam_service_linked_role.config[*].arn)\n'
        '}\n\n'
        'module "enclave_kms" {\n'
        '  source                  = "./modules/enclave-kms"\n'
        '  count                   = var.kms_key_arn == null ? 1 : 0\n'
        '  env                     = var.env\n'
        '  config_service_role_arn = local.config_service_role_arn\n'
        '}\n\n'
        'module "enclave_logging" {\n'
        '  source                    = "./modules/enclave-logging"\n'
        '  config_service_role_arn   = local.config_service_role_arn # Config-store bucket policy names it\n'
        '  env                       = var.env\n'
        '  kms_key_arn   = local.kms_key_arn\n'
        '  logging       = local.logging\n'
        '  cloudwatch_retention_days = ' + str(log_retention_days(resolved, root)) + '\n'
        '  data_event_resource_types = ' + json.dumps(data_event_types(resolved)) + '\n'
        '  replica_region            = var.replica_region\n'
        '  event_publishers          = var.manage_monitoring # ADR 0002 topic policy\n'
        + ('  cost_publishers           = var.manage_monitoring && (var.monthly_budget_usd > 0 || var.create_cost_anomaly_monitor)\n'
           if not govcloud else '  cost_publishers           = false # Budgets / Cost Anomaly Detection: commercial partition only\n') +
        '  providers = {\n    aws         = aws\n    aws.replica = aws.replica\n  }\n'
        '}\n\n'
        'module "enclave_network" {\n'
        '  source             = "./modules/enclave-network"\n'
        '  count              = var.vpc_id == null ? 0 : 1\n'
        '  env                = var.env\n'
        '  vpc_id             = var.vpc_id\n'
        '  subnet_ids         = var.endpoint_subnet_ids\n'
        '  security_group_ids = var.endpoint_security_group_ids\n'
        '  route_table_ids    = var.endpoint_route_table_ids\n'
        '  interface_services = ' + json.dumps(endpoint_services(resolved)) + '\n'
        '  flow_log           = ' + ("false" if scca_required(resolved) else "true") + ' # dod-scca emits the VDMS flow log\n'
        '  kms_key_arn        = local.kms_key_arn\n'
        '  cloudwatch_retention_days = ' + str(log_retention_days(resolved, root)) + '\n'
        '}\n\n'
        + ('module "agentcore_platform" {\n'
           '  source                   = "./modules/agentcore-platform"\n'
           '  env                      = var.env\n'
           '  kms_key_arn              = local.kms_key_arn\n'
           # Policy engine only where AWS offers it (not GovCloud): `sgea check` then reports the
           # gateway_tool_path controls as unmet instead of the apply failing.
           '  gateway_tool_path        = ' + ("true" if "gateway_tool_path" in resolved["guardrails"].get("levels", [])
                                               and policy_engine_available(resolved, root) else "false") + '\n'
           '  jwt_discovery_url        = var.agent_jwt_discovery_url\n'
           '  jwt_allowed_clients      = var.agent_jwt_allowed_clients\n'
           '  memory_event_expiry_days = var.memory_event_expiry_days\n'
           '  tool_policy_interceptor  = ' + ("true" if "gateway_tool_path" in resolved["guardrails"].get("levels", [])
                                               and not policy_engine_available(resolved, root) else "false") + '\n'
           '  tool_policy              = var.tool_policy\n'
           '  token_budget_enforce     = ' + ("true" if resolved["token_control"].get("enabled") else "false") + '\n'
           '  token_control            = local.token_control\n'
           '  token_ledger_table       = module.token_control.usage_ledger_table_name\n'
           '  token_ledger_arn         = module.token_control.usage_ledger_table_arn\n'
           '  alarm_topic_arn          = module.enclave_logging.alarm_topic_arn\n'
           '  alarm_insufficient_data_action = ' + ("true" if account_baseline(resolved, root)["alarm_insufficient_data_action"] else "false") + '\n'
           '  reserved_concurrency     = ' + str(account_baseline(resolved, root)["lambda_reserved_concurrency"] or 100) + '\n'
           '  lambda_subnet_ids        = var.agent_subnet_ids\n'
           '  lambda_security_group_ids = var.agent_security_group_ids\n'
           '  cloudwatch_retention_days = ' + str(log_retention_days(resolved, root)) + '\n'
           '}\n\n' if "bedrock-agentcore" in resolved["services"]["allow"] else '') +
        ('module "enclave_aurora" {\n'
           '  source                = "./modules/enclave-aurora"\n'
           '  count                 = length(var.aurora_subnet_ids) == 0 ? 0 : 1\n'
           '  env                   = var.env\n'
           '  kms_key_arn           = local.kms_key_arn\n'
           '  subnet_ids            = var.aurora_subnet_ids\n'
           '  security_group_ids    = var.aurora_security_group_ids\n'
           '  backup_retention_days = ' + str(bk["retention_days"]) + '\n'
           '  cloudwatch_retention_days = ' + str(log_retention_days(resolved, root)) + '\n'
           '}\n\n' if resolved.get("vector_store") == "aurora-postgresql" else '') +
        '# ----- AWS Backup for every enclave data store (backup-plan / *-protected-by-backup-plan rules) -----\n'
        'module "enclave_backup" {\n'
        '  source                = "./modules/enclave-backup"\n'
        '  env                   = var.env\n'
        '  kms_key_arn           = local.kms_key_arn\n'
        '  backup_retention_days = ' + str(bk["retention_days"]) + '\n'
        '  backup_vault_lock     = ' + ("true" if bk["vault_lock"] else "false") + '\n'
        '  resources = concat(\n'
        + ('    module.enclave_aurora[*].cluster_arn,\n' if resolved.get("vector_store") == "aurora-postgresql" else '') +
        '    [module.token_control.usage_ledger_table_arn],\n'
        '    [module.enclave_logging.log_bucket_arn, module.enclave_logging.config_bucket_arn],\n'
        '  )\n'
        '}\n\n' +
        'module "security_services" {\n'
        '  source             = "./modules/security-services"\n'
        '  env                = var.env\n'
        '  create_guardduty   = var.create_guardduty\n'
        '  create_securityhub = var.create_securityhub\n'
        '  create_inspector   = var.create_inspector\n'
        '  inspector_resource_types = ' + json.dumps(account_baseline(resolved, root)["inspector_resource_types"]) + '\n'
        '}\n\n'
        'module "account_baseline" {\n'
        '  source      = "./modules/account-baseline"\n'
        '  count       = var.manage_account_baseline ? 1 : 0\n'
        '  settings    = jsondecode(' + json.dumps(json.dumps(account_baseline(resolved, root))) + ')\n'
        '  kms_key_arn = local.kms_key_arn\n'
        '  vpc_id      = var.vpc_id\n'
        '}\n\n'
        + ('module "dod_scca" {\n'
           '  source                    = "./modules/dod-scca"\n'
           '  count                     = var.vpc_id != null && length(var.scca_firewall_subnet_ids) > 0 ? 1 : 0\n'
           '  env                       = var.env\n'
           '  kms_key_arn               = local.kms_key_arn\n'
           '  vpc_id                    = var.vpc_id\n'
           '  firewall_subnet_ids       = var.scca_firewall_subnet_ids\n'
           '  egress_domains            = var.scca_egress_domains\n'
           '  cloudwatch_retention_days = ' + str(log_retention_days(resolved, root)) + '\n'
           '}\n\n' if scca_required(resolved) else '') +
        'module "config_conformance" {\n'
        '  source                 = "./modules/config-conformance"\n'
        '  env                    = var.env\n'
        '  packs                  = ' + json.dumps(pack_files) + '\n'
        '  create_config_recorder = var.create_config_recorder\n'
        '  delivery_bucket        = module.enclave_logging.config_bucket\n'
        '  delivery_kms_key_arn   = local.kms_key_arn\n'
        '}\n\n'
        '# ----- governance layer (SGEA-owned seams; no official module exists) -----\n'
        'module "org_guardrail" {\n'
        '  source           = "./modules/org-guardrail"\n'
        '  count            = var.deploy_org_policies ? 1 : 0\n'
        '  bundles           = ' + json.dumps({b["name"]: {"type": b["type"], "packs": b["packs"], "needs": b["needs"]} for b in bundles}) + '\n'
        '  policy_overrides  = var.scp_policy_documents\n'
        '  org_id            = var.org_id\n'
        '  perimeter_vpc_ids = var.perimeter_vpc_ids\n'
        '  perimeter_cidrs   = var.perimeter_cidrs\n'
        '  target_ids        = var.org_target_ids\n'
        '}\n\n'
        'module "token_control" {\n'
        '  source        = "./modules/token-control"\n'
        '  env           = var.env\n'
        '  token_control = local.token_control\n'
        '  kms_key_arn   = local.kms_key_arn\n'
        '  meter         = ' + ("true" if resolved["token_control"].get("enabled") and resolved["logging"].get("model_invocation_logging") else "false") + '\n'
        '  invocation_log_group_name = module.enclave_logging.invocation_log_group\n'
        '  lambda_subnet_ids         = var.agent_subnet_ids\n'
        '  lambda_security_group_ids = var.agent_security_group_ids\n'
        '  cloudwatch_retention_days = ' + str(log_retention_days(resolved, root)) + '\n'
        '  alarm_topic_arn           = module.enclave_logging.alarm_topic_arn\n'
        '  alarm_insufficient_data_action = ' + ("true" if account_baseline(resolved, root)["alarm_insufficient_data_action"] else "false") + '\n'
        '  reserved_concurrency      = ' + str(account_baseline(resolved, root)["lambda_reserved_concurrency"] or 20) + '\n'
        '}\n\n'
        + ('# lambda-concurrency-check: the packs require reserved concurrency >= ' + str(account_baseline(resolved, root)["lambda_reserved_concurrency"]) +
           ' per enclave function, and Lambda keeps 100 unreserved: raise the account quota first.\n'
           'data "aws_servicequotas_service_quota" "lambda_concurrency" {\n'
           '  service_code = "lambda"\n'
           '  quota_code   = "L-B99A9384"\n'
           '}\n\n'
           'check "lambda_concurrency_quota" {\n'
           '  assert {\n'
           '    condition     = data.aws_servicequotas_service_quota.lambda_concurrency.value >= ' + str(2 * account_baseline(resolved, root)["lambda_reserved_concurrency"] + 100) + '\n'
           '    error_message = "Lambda concurrent-executions quota must be >= ' + str(2 * account_baseline(resolved, root)["lambda_reserved_concurrency"] + 100) +
           ' (2 enclave functions x ' + str(account_baseline(resolved, root)["lambda_reserved_concurrency"]) + ' reserved + 100 unreserved; lambda-concurrency-check). Request an increase in Service Quotas."\n'
           '  }\n'
           '}\n\n' if account_baseline(resolved, root)["lambda_reserved_concurrency"] else '') +
        ('# The gateway interceptor fails closed until the meter has written a heartbeat: write the first one\n'
           '# at deploy (otherwise a fresh enclave denies every tool call for up to 15 minutes).\n'
           'resource "aws_lambda_invocation" "token_meter_first_heartbeat" {\n'
           '  function_name = module.token_control.meter_function_name\n'
           '  input         = jsonencode({ source = "sgea-deploy" })\n'
           '  depends_on    = [module.enclave_network]\n'
           '}\n\n' if resolved["token_control"].get("enabled") and resolved["logging"].get("model_invocation_logging") else '') +
        _root_monitoring(resolved, root, agentcore, inv_logging) +
        '# ----- resource layer (official pass-through seams) -----\n'
        'module "baseline_guardrail" {\n'
        '  source      = "./modules/bedrock-guardrail"\n'
        '  name        = "sgea-${var.env}-baseline"\n'
        '  guardrail   = local.guardrail\n'
        '  kms_key_arn = local.kms_key_arn\n'
        '  enforce_account_wide  = ' + ("true" if "L2_account_baseline" in g.get("levels", []) else "false") + '\n'
        '  inference_profile_geo = "' + resolved["regions"]["inference_profile_geo"] + '"\n'
        '}\n\n'
        '# Knowledge base + AgentCore runtime are per-tenant/app; the root wires one\n'
        '# illustrative instance guarded by the customer-supplied inputs being set.\n'
        'module "knowledge_base" {\n'
        '  source              = "./modules/bedrock-knowledge-base"\n'
        '  count               = var.kb_role_arn == null ? 0 : 1\n'
        '  name                = "sgea-${var.env}-kb"\n'
        '  role_arn            = var.kb_role_arn\n'
        '  embedding_model_arn = var.kb_embedding_model_arn\n'
        '  aurora              = var.kb_aurora\n'
        '}\n\n'
        'module "agentcore_runtime" {\n'
        '  source             = "./modules/agentcore-runtime"\n'
        '  count              = var.agent_execution_role_arn == null ? 0 : 1\n'
        '  name               = "sgea_${var.env}_runtime"\n'
        '  execution_role_arn = var.agent_execution_role_arn\n'
        '  container_uri      = var.agent_container_uri\n'
        '  subnet_ids         = var.agent_subnet_ids\n'
        '  security_group_ids = var.agent_security_group_ids\n'
        '  jwt_discovery_url  = var.agent_jwt_discovery_url\n'
        '  jwt_allowed_clients = var.agent_jwt_allowed_clients\n'
        '}\n')
    written.append(_w(os.path.join(outdir, "main.tf"), main))

    # ---- outputs.tf: what tenant apps (e.g. examples/sample-agent) consume ----
    outputs = header + (
        'output "enclave" {\n'
        '  description = "Enclave facts for tenant apps (examples/sample-agent reads this via terraform output -json)."\n'
        '  value = {\n'
        '    env                  = var.env\n'
        '    profile              = "' + pid + '"\n'
        '    partition            = "' + partition + '"\n'
        '    region               = var.primary_region\n'
        '    kms_key_arn          = local.kms_key_arn\n'
        '    log_bucket           = module.enclave_logging.log_bucket\n'
        '    agentcore_log_group  = module.enclave_logging.agentcore_log_group\n'
        '    guardrail_id         = module.baseline_guardrail.guardrail_id\n'
        '    guardrail_version    = module.baseline_guardrail.guardrail_version\n'
        '    token_ledger_table   = module.token_control.usage_ledger_table_name\n'
        '    log_retention_days   = ' + str(log_retention_days(resolved, root)) + '\n'
        '    token_timezone       = "' + resolved["token_control"].get("default_timezone", "UTC") + '"\n'
        '    token_per_user_daily = ' + str(resolved["token_control"].get("per_user_daily_tokens", 0)) + '\n'
        '    authorized_model_ids = ' + json.dumps(authorized_model_ids(resolved, root) or []) + '\n'
        '    inference_profile_geo = "' + resolved["regions"]["inference_profile_geo"] + '"\n'
        + ('    gateway_id           = module.agentcore_platform.gateway_id\n'
           '    gateway_url          = module.agentcore_platform.gateway_url\n'
           '    gateway_arn          = module.agentcore_platform.gateway_arn\n'
           '    policy_engine_id     = module.agentcore_platform.policy_engine_id\n'
           '    gateway_role_name    = module.agentcore_platform.gateway_role_name\n'
           '    memory_id            = module.agentcore_platform.memory_id\n'
           '    agents_repository_url = module.agentcore_platform.agents_repository_url\n'
           if "bedrock-agentcore" in resolved["services"]["allow"] else '') +
        '    vpc_id               = var.vpc_id\n'
        '  }\n'
        '}\n\n'
        'output "break_glass_role_arn" {\n'
        '  description = "ADR 0002 break-glass role (null unless create_break_glass_role)."\n'
        '  value       = one(aws_iam_role.break_glass[*].arn)\n'
        '}\n')
    written.append(_w(os.path.join(outdir, "outputs.tf"), outputs))

    # ---- README ----
    readme = ("# SGEA Terraform output — " + resolved["profile"]["name"] + "\n\n"
              "Generated from `" + resolved["_generated"]["source_profile"] + "` using the wrapper-seam "
              "design (see `docs/adr/0001`).\n\n"
              "## Structure\n\n"
              "- `main.tf` calls thin **wrapper modules** under `modules/`, passing resolved control values.\n"
              "- Resource-layer wrappers are **official pass-throughs** (`aws_bedrock_guardrail`, "
              "`awscc_bedrock_knowledge_base` on Aurora/RDS, `awscc_bedrockagentcore_runtime`).\n"
              "- Governance-layer wrappers (`org-guardrail`, `token-control`) hold **raw official "
              "resources** because nothing official exists; each is a single swap point.\n"
              "- `sgea.auto.tfvars.json` carries the resolved control decisions; environment identifiers "
              "(account IDs, role ARNs, Aurora cluster, SCP JSON) are the `variables.tf` the customer fills.\n\n"
              "## Verify\n\n```\nsgea verify --out .\n# runs: terraform init -backend=false && terraform validate\n```\n"
              "First `terraform validate` confirms the exact official-resource attribute names against the "
              "provider schema — fix any the awscc schema reports, in the wrapper module only.\n\n"
              "Partition: **" + partition + "**, primary region **" + primary + "**.\n")
    written.append(_w(os.path.join(outdir, "README.md"), readme))

    # Canonical formatting (cosmetic only) when the toolchain is present.
    if shutil.which("terraform"):
        subprocess.run(["terraform", "fmt", "-recursive", "-list=false", outdir], check=False)  # nosec B603  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    return written
