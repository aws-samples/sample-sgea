// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// SGEA CDK app — customer-supplied environment inputs (NOT control decisions).
// Control decisions come from config.json (resolved profile + `_derived`).
// Mirrors the Terraform root variables; set with `cdk synth -c sgea:vpcId=vpc-...`
// or in cdk.context.json. Lists accept JSON arrays or comma-separated strings.
import { Node } from 'constructs';

export interface EnvInputs {
  env: string;
  kmsKeyArn?: string;
  orgId?: string;
  orgTargetIds: string[];
  perimeterVpcIds: string[];
  perimeterCidrs: string[];
  createConfigRecorder: boolean;
  vpcId?: string;
  endpointSubnetIds: string[];
  endpointSecurityGroupIds: string[];
  endpointRouteTableIds: string[];
  auroraSubnetIds: string[];
  auroraSecurityGroupIds: string[];
  agentExecutionRoleArn?: string;
  agentContainerUri?: string;
  agentSubnetIds: string[];
  agentSecurityGroupIds: string[];
  jwtDiscoveryUrl?: string;
  jwtAllowedClients: string[];
  memoryEventExpiryDays: number;
  toolPolicy: string;
  createGuardDuty: boolean;
  createSecurityHub: boolean;
  deployOrgPolicies: boolean;
  manageAccountBaseline: boolean;   // EBS default encryption, snapshot / S3 public-access blocks, password policy, default SG
  createInspector: boolean;
  sccaFirewallSubnetIds: string[];
  sccaEgressDomains: string[];         // interceptor rules JSON; default '[]' = deny every tools/call
  kbRoleArn?: string;
  kbEmbeddingModelArn?: string;
  kbAurora?: any;             // JSON: {resourceArn, credentialsSecretArn, databaseName, tableName, primaryKeyField, vectorField, textField, metadataField}
}

function list(node: Node, key: string): string[] {
  const v = node.tryGetContext('sgea:' + key);
  if (v === undefined || v === null || v === '') return [];
  if (Array.isArray(v)) return v.map(String);
  const s = String(v).trim();
  return s.startsWith('[') ? JSON.parse(s) : s.split(',').map((x) => x.trim()).filter(Boolean);
}

function str(node: Node, key: string): string | undefined {
  const v = node.tryGetContext('sgea:' + key);
  return v === undefined || v === null || v === '' ? undefined : String(v);
}

export function envInputs(node: Node): EnvInputs {
  return {
    env: str(node, 'env') ?? 'nonprod',
    kmsKeyArn: str(node, 'kmsKeyArn'),
    orgId: str(node, 'orgId'),
    orgTargetIds: list(node, 'orgTargetIds'),
    perimeterVpcIds: list(node, 'perimeterVpcIds'),
    perimeterCidrs: list(node, 'perimeterCidrs'),
    createConfigRecorder: str(node, 'createConfigRecorder') === 'true',
    vpcId: str(node, 'vpcId'),
    endpointSubnetIds: list(node, 'endpointSubnetIds'),
    endpointSecurityGroupIds: list(node, 'endpointSecurityGroupIds'),
    endpointRouteTableIds: list(node, 'endpointRouteTableIds'),
    auroraSubnetIds: list(node, 'auroraSubnetIds'),
    auroraSecurityGroupIds: list(node, 'auroraSecurityGroupIds'),
    agentExecutionRoleArn: str(node, 'agentExecutionRoleArn'),
    agentContainerUri: str(node, 'agentContainerUri'),
    agentSubnetIds: list(node, 'agentSubnetIds'),
    agentSecurityGroupIds: list(node, 'agentSecurityGroupIds'),
    jwtDiscoveryUrl: str(node, 'jwtDiscoveryUrl'),
    jwtAllowedClients: list(node, 'jwtAllowedClients'),
    memoryEventExpiryDays: Number(str(node, 'memoryEventExpiryDays') ?? 30),
    toolPolicy: str(node, 'toolPolicy') ?? '[]',
    createGuardDuty: str(node, 'createGuardDuty') !== 'false',
    createSecurityHub: str(node, 'createSecurityHub') !== 'false',
    deployOrgPolicies: str(node, 'deployOrgPolicies') !== 'false',
    manageAccountBaseline: str(node, 'manageAccountBaseline') !== 'false',
    createInspector: str(node, 'createInspector') !== 'false',
    sccaFirewallSubnetIds: list(node, 'sccaFirewallSubnetIds'),
    sccaEgressDomains: list(node, 'sccaEgressDomains'),
    kbRoleArn: str(node, 'kbRoleArn'),
    kbEmbeddingModelArn: str(node, 'kbEmbeddingModelArn'),
    kbAurora: str(node, 'kbAurora') ? JSON.parse(str(node, 'kbAurora') as string) : undefined,
  };
}
