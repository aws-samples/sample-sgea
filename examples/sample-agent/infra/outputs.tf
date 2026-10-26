# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
output "runtime_arn" { value = module.runtime.agent_runtime_arn }
output "user_pool_id" { value = aws_cognito_user_pool.test_idp.id }
output "client_id" { value = aws_cognito_user_pool_client.agent.id }
output "region" { value = local.region }
output "token_ledger_table" { value = var.enclave.token_ledger_table }
output "token_timezone" { value = var.enclave.token_timezone }
output "token_per_user_daily" { value = var.enclave.token_per_user_daily }
