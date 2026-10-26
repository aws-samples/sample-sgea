// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// SGEA WRAPPER CONSTRUCT (seam) — agentcore-platform (mirrors modules/agentcore-platform)
// AgentCore Gateway / Memory / PolicyEngine: official L1 (the L2 is experimental alpha — ADR 0001).
// ECR, Lambda, IAM: official L2. Token-vault CMK has no CloudFormation type: AwsCustomResource.
import { Construct } from 'constructs';
import { Aws, Duration, RemovalPolicy, aws_bedrockagentcore as agentcore, aws_dynamodb as ddb, aws_ecr as ecr, aws_iam as iam,
  aws_kms as kms, aws_lambda as lambda, aws_logs as logs, aws_sns as sns, aws_sqs as sqs, custom_resources as cr } from 'aws-cdk-lib';
import { lambdaAlarm } from './alarms';
import * as path from 'path';
import { EnvInputs } from './context';
import { PropagationWait } from './propagation-wait';

export interface PlatformProps { inputs: EnvInputs; key: kms.IKey; gatewayToolPath: boolean;
  alarmTopic?: sns.ITopic; alarmInsufficientData?: boolean; reservedConcurrency?: number;
  toolPolicyInterceptor: boolean; cloudwatchRetentionDays: number;
  tokenControl?: any; ledger?: ddb.ITable; }  // token budgets (SGEA-TC-01) when tokenControl.enabled

export class AgentCorePlatform extends Construct {
  public outputs: Record<string, string> = {};
  constructor(scope: Construct, id: string, props: PlatformProps) {
    super(scope, id);
    const i = props.inputs, acct = Aws.ACCOUNT_ID, part = Aws.PARTITION, region = Aws.REGION, key = props.key;
    if (i.memoryEventExpiryDays < 7 || i.memoryEventExpiryDays > 365) {
      throw new Error('sgea:memoryEventExpiryDays must be 7..365');
    }
    const agentcorePrincipal = () => new iam.ServicePrincipal('bedrock-agentcore.amazonaws.com', { conditions: {
      StringEquals: { 'aws:SourceAccount': acct }, ArnLike: { 'aws:SourceArn': `arn:${part}:bedrock-agentcore:${region}:${acct}:*` } } });

    // ----- agent images: SGEA-AC-RT-08/09, ecr-private-lifecycle-policy-configured -----
    const repo = new ecr.Repository(this, 'Agents', {
      repositoryName: `sgea-${i.env}-agents`, imageTagMutability: ecr.TagMutability.IMMUTABLE, imageScanOnPush: true,
      encryption: ecr.RepositoryEncryption.KMS, encryptionKey: key, removalPolicy: RemovalPolicy.RETAIN,
      lifecycleRules: [
        { rulePriority: 1, description: 'Expire untagged images after 14 days', tagStatus: ecr.TagStatus.UNTAGGED, maxImageAge: Duration.days(14) },
        { rulePriority: 2, description: 'Keep the most recent 100 images', tagStatus: ecr.TagStatus.ANY, maxImageCount: 100 },
      ],
    });

    // ----- token vault CMK: SGEA-AC-ID-01 -----
    // Lambda's bundled SDK predates AgentCore: install the client (v3 package name).
    const vault = { service: '@aws-sdk/client-bedrock-agentcore-control', action: 'SetTokenVaultCMKCommand',
      parameters: { kmsConfiguration: { keyType: 'CustomerManagedKey', kmsKeyArn: key.keyArn } },
      physicalResourceId: cr.PhysicalResourceId.of(`sgea-${i.env}-token-vault-cmk`) };
    const vaultCr = new cr.AwsCustomResource(this, 'TokenVaultCmk', {
      resourceType: 'Custom::SgeaTokenVaultCmk', onCreate: vault, onUpdate: vault,
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({ actions: ['bedrock-agentcore:SetTokenVaultCMK', 'bedrock-agentcore:GetTokenVault'],
          resources: [`arn:${part}:bedrock-agentcore:${region}:${acct}:token-vault/default`] }),   // the account's token vault only
        // SetTokenVaultCMK uses the caller's own KMS permissions via bedrock-agentcore (CloudTrail, sandbox
        // 2026-10-15): Decrypt, DescribeKey, Encrypt (incl. a DryRun) and GenerateDataKeyWithoutPlaintext.
        new iam.PolicyStatement({ actions: ['kms:DescribeKey', 'kms:CreateGrant', 'kms:Decrypt', 'kms:Encrypt',
          'kms:GenerateDataKey', 'kms:GenerateDataKeyWithoutPlaintext'], resources: [key.keyArn] }),
      ]),
      installLatestAwsSdk: true,
    });
    // The call runs with the custom-resource role, whose policy is created in the same deploy: wait for it.
    const vaultWait = new PropagationWait(this, 'TokenVaultIamWait', { seconds: 30 });
    vaultWait.node.addDependency(vaultCr.node.findChild('CustomResourcePolicy'));
    vaultCr.node.findChild('Resource').node.addDependency(vaultWait);

    // ----- tool path: SGEA-AC-GW-01..04 -----
    const gwRole = new iam.Role(this, 'GatewayRole', { roleName: `sgea-${i.env}-agentcore-gateway`, assumedBy: agentcorePrincipal() });
    // The gateway encrypts its configuration by assuming this role directly (verified in sandbox).
    key.grant(gwRole, 'kms:GenerateDataKey', 'kms:Decrypt');
    let engine: agentcore.CfnPolicyEngine | undefined;
    if (props.gatewayToolPath) {
      // AWS docs (AgentCore Gateway and Policy IAM permissions): the gateway role reads and evaluates its engine.
      gwRole.addToPolicy(new iam.PolicyStatement({ sid: 'PolicyEngineConfiguration', actions: ['bedrock-agentcore:GetPolicyEngine'],
        resources: [`arn:${part}:bedrock-agentcore:${region}:${acct}:policy-engine/*`] }));
      gwRole.addToPolicy(new iam.PolicyStatement({ sid: 'PolicyEngineAuthorization',
        actions: ['bedrock-agentcore:AuthorizeAction', 'bedrock-agentcore:PartiallyAuthorizeActions'],
        resources: [`arn:${part}:bedrock-agentcore:${region}:${acct}:policy-engine/*`, `arn:${part}:bedrock-agentcore:${region}:${acct}:gateway/*`] }));
      // Policy engine + gateway are encrypted with the enclave CMK (AWS docs: policy-encryption).
      // AgentCore reaches KMS for the role without a regional kms:ViaService (verified in sandbox).
      gwRole.addToPolicy(new iam.PolicyStatement({ sid: 'EnclaveKeyViaAgentCore', actions: ['kms:Decrypt', 'kms:GenerateDataKey', 'kms:DescribeKey'],
        resources: [key.keyArn], conditions: { Bool: { 'aws:ViaAWSService': 'true' }, StringEquals: { 'kms:CallerAccount': acct } } }));
      engine = new agentcore.CfnPolicyEngine(this, 'ToolPolicy', { name: `sgea_${i.env}_tool_policy`,
        description: 'SGEA gateway_tool_path guardrail level: Cedar policies on tool invocations.', encryptionKeyArn: key.keyArn });
    }
    // Gateway REQUEST interceptor: policy-engine stand-in where AWS does not offer it (GovCloud,
    // SGEA-AC-GW-03) and token budgets (SGEA-TC-01).
    let interceptor: lambda.Function | undefined;
    const tc = props.tokenControl ?? {};
    const budgets = !!(tc.enabled && props.ledger);
    if (props.toolPolicyInterceptor || budgets) {
      const fname = `sgea-${i.env}-tool-policy`;
      const group = new logs.LogGroup(this, 'InterceptorLogs', { logGroupName: `/aws/lambda/${fname}`,
        retention: props.cloudwatchRetentionDays as logs.RetentionDays, encryptionKey: key, removalPolicy: RemovalPolicy.RETAIN });
      interceptor = new lambda.Function(this, 'ToolPolicyInterceptor', {
        functionName: fname, runtime: lambda.Runtime.PYTHON_3_12, handler: 'tool_policy_interceptor.handler',
        code: lambda.Code.fromAsset(path.join(__dirname, '..', '..', 'lambda')), // > 4 KB: no inline ZipFile
        timeout: Duration.seconds(5), memorySize: 256, reservedConcurrentExecutions: props.reservedConcurrency ?? 100, // lambda-concurrency-check
        deadLetterQueue: new sqs.Queue(this, 'InterceptorDlq', { queueName: `${fname}-dlq`, encryption: sqs.QueueEncryption.KMS,
          encryptionMasterKey: key, retentionPeriod: Duration.days(14) }), // lambda-dlq-check
        environment: { TOOL_POLICY: i.toolPolicy, TOOL_POLICY_ENFORCE: String(props.toolPolicyInterceptor),
          ...(budgets ? { TOKEN_LEDGER_TABLE: props.ledger!.tableName,
            PER_USER_DAILY_TOKENS: String(tc.per_user_daily_tokens ?? 0), PER_TEAM_MONTHLY_TOKENS: String(tc.per_team_monthly_tokens ?? 0),
            FAIL_CLOSED_HOURS: String(tc.fail_closed_hours ?? 4), TOKEN_TIMEZONE: tc.default_timezone ?? 'UTC',
            TEAM_CLAIM: tc.team_claim ?? 'cognito:groups' } : {}) }, environmentEncryption: key, tracing: lambda.Tracing.ACTIVE, logGroup: group,
      });
      if (i.agentSubnetIds.length) {
        // Escape hatch: VPC config from subnet / SG ids (the L2 needs an IVpc object).
        (interceptor.node.defaultChild as lambda.CfnFunction).vpcConfig = { subnetIds: i.agentSubnetIds, securityGroupIds: i.agentSecurityGroupIds };
        interceptor.role!.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaVPCAccessExecutionRole'));
      }
      interceptor.grantInvoke(gwRole);
      if (props.alarmTopic) lambdaAlarm(this, 'InterceptorErrors', interceptor, 'Errors', props.alarmTopic, !!props.alarmInsufficientData,
        `${fname}-errors`, 'SGEA gateway interceptor errors: tool-path policy / token budgets fail closed.');
      if (budgets) { props.ledger!.grant(interceptor, 'dynamodb:GetItem'); key.grantDecrypt(interceptor); }
    }
    // The gateway checks its role (GetPolicyEngine, KMS) at create: wait for the policy to propagate.
    const iamWait = new PropagationWait(this, 'GatewayIamWait', { seconds: 30 });
    iamWait.node.addDependency(gwRole);
    const gateway = new agentcore.CfnGateway(this, 'Gateway', {
      name: `sgea-${i.env}-gateway`, roleArn: gwRole.roleArn, protocolType: 'MCP',
      authorizerType: i.jwtDiscoveryUrl ? 'CUSTOM_JWT' : 'AWS_IAM',
      authorizerConfiguration: i.jwtDiscoveryUrl ? { customJwtAuthorizer: { discoveryUrl: i.jwtDiscoveryUrl,
        allowedClients: i.jwtAllowedClients.length ? i.jwtAllowedClients : undefined } } : undefined,
      kmsKeyArn: key.keyArn,
      policyEngineConfiguration: engine ? { arn: engine.attrPolicyEngineArn, mode: 'ENFORCE' } : undefined,
      // Tokens are passed to the interceptor (claims for rules); it never logs them.
      interceptorConfigurations: interceptor ? [{ interceptor: { lambda: { arn: interceptor.functionArn } },
        interceptionPoints: ['REQUEST'], inputConfiguration: { passRequestHeaders: true } }] : undefined,
    });
    gateway.node.addDependency(iamWait);
    if (interceptor) gateway.node.addDependency(interceptor);

    // ----- agent memory: SGEA-AC-MEM-01..03 -----
    const memRole = new iam.Role(this, 'MemoryRole', { roleName: `sgea-${i.env}-agentcore-memory`, assumedBy: agentcorePrincipal() });
    memRole.addToPolicy(new iam.PolicyStatement({ sid: 'InvokeModelsForMemoryStrategies',
      actions: ['bedrock:InvokeModel', 'bedrock:InvokeModelWithResponseStream'],
      resources: [`arn:${part}:bedrock:*::foundation-model/*`, `arn:${part}:bedrock:*:${acct}:inference-profile/*`] }));
    key.grant(memRole, 'kms:Decrypt', 'kms:GenerateDataKey*');
    const memory = new agentcore.CfnMemory(this, 'Memory', {
      name: `sgea_${i.env}_memory`, description: 'SGEA enclave agent memory', eventExpiryDuration: i.memoryEventExpiryDays,
      encryptionKeyArn: key.keyArn, memoryExecutionRoleArn: memRole.roleArn,
    });
    this.outputs = { gateway_id: gateway.attrGatewayIdentifier, gateway_url: gateway.attrGatewayUrl,
      gateway_arn: gateway.attrGatewayArn, ...(engine ? { policy_engine_id: engine.attrPolicyEngineId } : {}),
      gateway_role_name: gwRole.roleName, memory_id: memory.attrMemoryId, agents_repository_url: repo.repositoryUri };
  }
}
