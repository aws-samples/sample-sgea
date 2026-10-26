# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Shared guardrail vocabulary for both emitters.

The resolved config expresses PII intent as `guardrails.pii = {mode, action,
phi_entities}`. Bedrock needs explicit entity types, so this module is the ONE
place that expands the flag into AWS::Bedrock::Guardrail PiiEntityConfig types.
Both emitters render from these lists, so Terraform and CDK cannot drift.

Entity names are the Bedrock `GuardrailPiiEntityType` enum values. The PHI set
covers the HIPAA Safe Harbor identifiers that Bedrock can detect natively;
identifiers with no native type (e.g. medical record / health-plan numbers)
need customer-specific regexes — see verticals/hipaa/open-items.md.
"""

PII_ENTITIES = [
    "NAME", "EMAIL", "PHONE", "ADDRESS", "USERNAME", "PASSWORD", "PIN",
    "US_SOCIAL_SECURITY_NUMBER", "US_PASSPORT_NUMBER", "DRIVER_ID",
    "US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER",
    "CREDIT_DEBIT_CARD_NUMBER", "CREDIT_DEBIT_CARD_CVV", "CREDIT_DEBIT_CARD_EXPIRY",
    "US_BANK_ACCOUNT_NUMBER", "US_BANK_ROUTING_NUMBER",
    "AWS_ACCESS_KEY", "AWS_SECRET_KEY",
]

PHI_ENTITIES = [
    "AGE", "IP_ADDRESS", "URL", "MAC_ADDRESS", "LICENSE_PLATE",
    "VEHICLE_IDENTIFICATION_NUMBER", "CA_HEALTH_NUMBER",
    "UK_NATIONAL_HEALTH_SERVICE_NUMBER",
]

# Entities that also match ordinary text (place names, people in questions, "age", links): the
# "France" -> ADDRESS false positive. They take `guardrails.pii.contextual_action` (ANONYMIZE in the
# shipped baselines: masked before the model / caller sees them) while hard identifiers keep `action`.
CONTEXTUAL_ENTITIES = ["NAME", "ADDRESS", "AGE", "USERNAME", "URL"]

# Order the Bedrock API returns content filters in. Emitting the same order keeps the awscc list
# stable (otherwise every plan shows a diff and re-cuts the guardrail version).
FILTER_ORDER = ["VIOLENCE", "PROMPT_ATTACK", "MISCONDUCT", "HATE", "SEXUAL", "INSULTS"]

# Bedrock rejects any output strength other than NONE for the prompt-attack filter.
INPUT_ONLY_FILTERS = ["PROMPT_ATTACK"]
