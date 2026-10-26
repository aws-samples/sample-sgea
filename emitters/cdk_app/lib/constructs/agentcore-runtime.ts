// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// SGEA WRAPPER CONSTRUCT (seam) — agentcore-runtime (mirrors modules/agentcore-runtime)
// seam-kind: official-passthrough -> aws_bedrockagentcore.CfnRuntime. VPC-only (no PUBLIC),
// custom JWT inbound auth, idle session <= 900 s, account-scoped resource policy.
import { Construct } from 'constructs';
import { Stack, aws_bedrockagentcore as agentcore } from 'aws-cdk-lib';

export interface RuntimeProps {
  name: string; executionRoleArn: string; containerUri: string;
  subnetIds: string[]; securityGroupIds: string[];
  jwtDiscoveryUrl: string; jwtAllowedClients?: string[];
  idleSessionTimeoutSeconds?: number; maxLifetimeSeconds?: number; requestHeaderAllowlist?: string[];
  allowedSourceVpceIds?: string[];
}

export class AgentCoreRuntime extends Construct {
  public readonly cfn: agentcore.CfnRuntime;
  constructor(scope: Construct, id: string, p: RuntimeProps) {
    super(scope, id);
    if (!p.subnetIds.length || !p.securityGroupIds.length) {
      throw new Error('SGEA-AC-RT-02/03: VPC network mode requires subnets and security groups.');
    }
    const idle = p.idleSessionTimeoutSeconds ?? 900;
    if (idle > 900) throw new Error('SGEA-AC-RT-06: idle_runtime_session_timeout must be <= 900 seconds.');
    this.cfn = new agentcore.CfnRuntime(this, 'Runtime', {
      agentRuntimeName: p.name, roleArn: p.executionRoleArn,
      agentRuntimeArtifact: { containerConfiguration: { containerUri: p.containerUri } },
      networkConfiguration: { networkMode: 'VPC',
        networkModeConfig: { subnets: p.subnetIds, securityGroups: p.securityGroupIds } },
      authorizerConfiguration: { customJwtAuthorizer: { discoveryUrl: p.jwtDiscoveryUrl,
        allowedClients: p.jwtAllowedClients?.length ? p.jwtAllowedClients : undefined } },
      lifecycleConfiguration: { idleRuntimeSessionTimeout: idle, maxLifetime: p.maxLifetimeSeconds ?? 28800 },
      requestHeaderConfiguration: p.requestHeaderAllowlist?.length
        ? { requestHeaderAllowlist: p.requestHeaderAllowlist } : undefined,
    });
    // SGEA-AC-ID-04: network-restrict invocation (OAuth runtimes: wildcard principal + aws:SourceVpce, per AWS docs).
    // Without endpoint ids NO resource policy (never an unconditioned wildcard Allow); the JWT authorizer
    // still gates every call and `sgea check` reports SGEA-AC-ID-04 unmet.
    const vpces = p.allowedSourceVpceIds ?? [];
    if (vpces.length) {
      new agentcore.CfnResourcePolicy(this, 'Policy', { resourceArn: this.cfn.attrAgentRuntimeArn,
        policy: Stack.of(this).toJsonString({ Version: '2012-10-17', Statement: [{ Sid: 'AllowOnlyThroughEnclaveEndpoints',
          Effect: 'Allow', Principal: '*', Action: 'bedrock-agentcore:InvokeAgentRuntime', Resource: this.cfn.attrAgentRuntimeArn,
          Condition: { StringEquals: { 'aws:SourceVpce': vpces } } }] }) });
    }
  }
}
