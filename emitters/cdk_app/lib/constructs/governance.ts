// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// SGEA WRAPPER CONSTRUCT (seam) — governance (mirrors modules/org-guardrail + token-control)
// seam-kind: raw-governance-adapter. SCP/RCP statements are the SGEA policy library,
// rendered from the resolved config and bundled into config._derived.policy_bundles; deploy-time
// values (partition, org id, perimeter) are substituted here.
import { Construct } from 'constructs';
import { Annotations, Aws, Duration, RemovalPolicy, aws_dynamodb as ddb, aws_events as events, aws_events_targets as targets,
  aws_iam as iam, aws_kms as kms, aws_lambda as lambda, aws_logs as logs, aws_logs_destinations as destinations,
  aws_sns as sns, aws_sqs as sqs, aws_stepfunctions as sfn, aws_cloudwatch as cloudwatch, aws_cloudwatch_actions as cw_actions,
  aws_organizations as orgs } from 'aws-cdk-lib';
import * as path from 'path';
import { EnvInputs } from './context';
import { lambdaAlarm } from './alarms';

export interface PolicyBundle { name: string; type: string; packs: string[]; needs: string[]; template: string; }

export interface GovernanceProps { bundles: PolicyBundle[]; inputs: EnvInputs; key: kms.IKey;
  alarmTopic?: sns.ITopic; alarmInsufficientData?: boolean; reservedConcurrency?: number;
  tokenControl: any; invocationLogGroup?: logs.ILogGroup; cloudwatchRetentionDays: number;
  // ADR 0003 model-call breaker (config._derived.token_model_enforce / token_breaker).
  modelEnforce?: boolean; breaker?: { source: string; detail_type: string; denied_actions: string[]; asl: string }; }

export class Governance extends Construct {
  public readonly ledger: ddb.Table;
  public meter?: lambda.Function;
  public budgetExhaustedPolicyArn?: string;
  constructor(scope: Construct, id: string, props: GovernanceProps) {
    super(scope, id);
    const i = props.inputs;
    const render = (tpl: string) => JSON.parse(tpl
      .split('${partition}').join(Aws.PARTITION)
      .split('${org_id}').join(i.orgId ?? 'o-unset')
      .split('${jsonencode(perimeter_cidrs)}').join(JSON.stringify(i.perimeterCidrs))
      .split('${jsonencode(perimeter_vpc_ids)}').join(JSON.stringify(i.perimeterVpcIds))
      .split('$${').join('${'));
    // Packs are pre-bundled (<= 4 SCPs + 4 RCPs: AWS allows 5 attached per target incl. FullAWSAccess).
    for (const b of props.bundles) {
      // Same guards as the Terraform preconditions: never ship a perimeter that denies everything.
      if (b.needs.includes('org_id') && !i.orgId) {
        Annotations.of(this).addWarning(`${b.name} (${b.packs.join(', ')}) not synthesized: set context sgea:orgId`); continue;
      }
      if (b.needs.includes('perimeter_cidrs') && i.perimeterVpcIds.length + i.perimeterCidrs.length === 0) {
        Annotations.of(this).addWarning(`${b.name} (${b.packs.join(', ')}) not synthesized: set sgea:perimeterVpcIds / sgea:perimeterCidrs`); continue;
      }
      new orgs.CfnPolicy(this, 'Policy' + b.name.replace(/[^A-Za-z0-9]/g, ''), {
        name: b.name, description: 'SGEA packs: ' + b.packs.join(', '), type: b.type, content: render(b.template),
        targetIds: i.orgTargetIds.length ? i.orgTargetIds : undefined,
      });
    }
    // Per-user token-control ledger: official L2 (dynamodb-table-encrypted-kms, dynamodb-pitr-enabled).
    const ledger = this.ledger = new ddb.Table(this, 'UsageLedger', {
      tableName: `sgea-token-usage-${i.env}`, billingMode: ddb.BillingMode.PAY_PER_REQUEST,
      partitionKey: { name: 'pk', type: ddb.AttributeType.STRING }, sortKey: { name: 'sk', type: ddb.AttributeType.STRING },
      timeToLiveAttribute: 'expires_at', encryption: ddb.TableEncryption.CUSTOMER_MANAGED, encryptionKey: props.key,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true }, deletionProtection: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    // SGEA-TC-02: meter the ledger from Bedrock model-invocation logs (+ 15-minute heartbeat; the
    // gateway interceptor fails closed when the heartbeat is stale).
    const tc = props.tokenControl ?? {};
    if (tc.enabled && props.invocationLogGroup) {
      const fname = `sgea-${i.env}-token-meter`;
      const group = new logs.LogGroup(this, 'MeterLogs', { logGroupName: `/aws/lambda/${fname}`,
        retention: props.cloudwatchRetentionDays as logs.RetentionDays, encryptionKey: props.key, removalPolicy: RemovalPolicy.RETAIN });
      const meter = new lambda.Function(this, 'TokenMeter', {
        functionName: fname, runtime: new lambda.Runtime('python3.15', lambda.RuntimeFamily.PYTHON, { supportsInlineCode: true }), handler: 'token_meter.handler',
        code: lambda.Code.fromAsset(path.join(__dirname, '..', '..', 'lambda')),
        timeout: Duration.seconds(30), memorySize: 256, reservedConcurrentExecutions: props.reservedConcurrency ?? 20, // lambda-concurrency-check
        deadLetterQueue: new sqs.Queue(this, 'MeterDlq', { queueName: `${fname}-dlq`, encryption: sqs.QueueEncryption.KMS,
          encryptionMasterKey: props.key, retentionPeriod: Duration.days(14) }), // lambda-dlq-check
        environment: { TOKEN_LEDGER_TABLE: ledger.tableName, TOKEN_TIMEZONE: tc.default_timezone ?? 'UTC',
          PER_TEAM_MONTHLY_TOKENS: String(tc.per_team_monthly_tokens ?? 0), TOKEN_BREAKER: props.modelEnforce && props.breaker ? '1' : '0' },
        environmentEncryption: props.key, tracing: lambda.Tracing.ACTIVE, logGroup: group,
      });
      if (i.agentSubnetIds.length) {
        (meter.node.defaultChild as lambda.CfnFunction).vpcConfig = { subnetIds: i.agentSubnetIds, securityGroupIds: i.agentSecurityGroupIds };
        meter.role!.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaVPCAccessExecutionRole'));
      }
      ledger.grant(meter, 'dynamodb:UpdateItem', 'dynamodb:PutItem', 'dynamodb:GetItem', 'dynamodb:Query', 'dynamodb:DeleteItem');
      this.meter = meter;
      if (props.alarmTopic) {
        lambdaAlarm(this, 'MeterErrors', meter, 'Errors', props.alarmTopic, !!props.alarmInsufficientData, `${fname}-errors`,
          'SGEA token meter errors: budgets stop crediting usage.');
        lambdaAlarm(this, 'MeterSilent', meter, 'Invocations', props.alarmTopic, !!props.alarmInsufficientData, `${fname}-silent`,
          'SGEA token meter has not run for 30 minutes.');
      }
      props.key.grant(meter, 'kms:Decrypt', 'kms:GenerateDataKey');
      new logs.SubscriptionFilter(this, 'MeterSubscription', { logGroup: props.invocationLogGroup,
        filterName: fname, destination: new destinations.LambdaDestination(meter), filterPattern: logs.FilterPattern.allEvents() });
      new events.Rule(this, 'MeterHeartbeat', { ruleName: `${fname}-heartbeat`, schedule: events.Schedule.rate(Duration.minutes(15)),
        targets: [new targets.LambdaFunction(meter)] });
      if (props.modelEnforce && props.breaker) this.modelBreaker(meter, ledger, props);
    }
  }

  // ADR 0003: the in-VPC meter cannot reach IAM, so it raises an EventBridge event; a Step Functions
  // state machine (no Lambda) attaches / detaches one static deny policy, only on what the ledger records
  // and only on roles tagged sgea:team = the exhausted team. Mirrors modules/token-control.
  private modelBreaker(meter: lambda.Function, ledger: ddb.Table, props: GovernanceProps) {
    const b = props.breaker!, env = props.inputs.env, part = Aws.PARTITION, acct = Aws.ACCOUNT_ID, region = Aws.REGION;
    const name = `sgea-${env}-token-breaker`;
    const deny = new iam.ManagedPolicy(this, 'BudgetExhausted', { managedPolicyName: `sgea-${env}-token-budget-exhausted`,
      description: 'SGEA ADR 0003: attached by the token breaker to runtime roles of a team past its monthly token budget.',
      statements: [new iam.PolicyStatement({ sid: 'TeamTokenBudgetExhausted', effect: iam.Effect.DENY, actions: b.denied_actions, resources: ['*'] })] });
    this.budgetExhaustedPolicyArn = deny.managedPolicyArn;
    const group = new logs.LogGroup(this, 'BreakerLogs', { logGroupName: `/aws/vendedlogs/states/${name}`,
      retention: props.cloudwatchRetentionDays as logs.RetentionDays, encryptionKey: props.key, removalPolicy: RemovalPolicy.RETAIN });
    const role = new iam.Role(this, 'BreakerRole', { roleName: name,
      assumedBy: new iam.ServicePrincipal('states.amazonaws.com', { conditions: { StringEquals: { 'aws:SourceAccount': acct },
        ArnLike: { 'aws:SourceArn': `arn:${part}:states:${region}:${acct}:stateMachine:${name}` } } }) });
    const roles = `arn:${part}:iam::${acct}:role/*`;
    // Least privilege: attach / detach ONLY the deny policy, attach ONLY to roles that carry sgea:team (the
    // state machine also checks the tag value); never the break-glass role. Logs / X-Ray delivery are
    // account-level APIs (no resource-level scoping).
    const breakerPolicy = new iam.ManagedPolicy(this, 'BreakerPolicy', { managedPolicyName: name, roles: [role], statements: [
      new iam.PolicyStatement({ sid: 'ReadTrips', actions: ['dynamodb:GetItem'], resources: [ledger.tableArn] }),
      new iam.PolicyStatement({ sid: 'LedgerKey', actions: ['kms:Decrypt'], resources: [props.key.keyArn] }),
      new iam.PolicyStatement({ sid: 'ReadRoleTags', actions: ['iam:GetRole'], resources: [roles] }),
      new iam.PolicyStatement({ sid: 'AttachDenyToTeamRoles', actions: ['iam:AttachRolePolicy'], resources: [roles],
        conditions: { ArnEquals: { 'iam:PolicyARN': deny.managedPolicyArn }, Null: { 'aws:ResourceTag/sgea:team': 'false' } } }),
      new iam.PolicyStatement({ sid: 'DetachDeny', actions: ['iam:DetachRolePolicy'], resources: [roles],
        conditions: { ArnEquals: { 'iam:PolicyARN': deny.managedPolicyArn } } }),
      new iam.PolicyStatement({ sid: 'NeverBreakGlass', effect: iam.Effect.DENY, actions: ['iam:AttachRolePolicy', 'iam:DetachRolePolicy'],
        resources: [`arn:${part}:iam::${acct}:role/sgea-*-break-glass`] }),
      new iam.PolicyStatement({ sid: 'LogDelivery', resources: ['*'], actions: ['logs:CreateLogDelivery', 'logs:GetLogDelivery',
        'logs:UpdateLogDelivery', 'logs:DeleteLogDelivery', 'logs:ListLogDeliveries', 'logs:PutResourcePolicy',
        'logs:DescribeResourcePolicies', 'logs:DescribeLogGroups'] }),
      new iam.PolicyStatement({ sid: 'Tracing', resources: ['*'], actions: ['xray:PutTraceSegments', 'xray:PutTelemetryRecords',
        'xray:GetSamplingRules', 'xray:GetSamplingTargets'] }),
    ] });
    const definition = b.asl.split('${partition}').join(part).split('${policy_arn}').join(deny.managedPolicyArn)
      .split('${ledger_table}').join(ledger.tableName);
    const machine = new sfn.CfnStateMachine(this, 'Breaker', { stateMachineName: name, stateMachineType: 'STANDARD',
      roleArn: role.roleArn, definitionString: definition, tracingConfiguration: { enabled: true },
      loggingConfiguration: { level: 'ERROR', includeExecutionData: false, destinations: [{ cloudWatchLogsLogGroup: { logGroupArn: group.logGroupArn } }] } });
    machine.node.addDependency(breakerPolicy);
    // L1 rule: the L2 SfnStateMachine target would add an unscoped grant.
    const rule = new events.CfnRule(this, 'BreakerRule', { name, state: 'ENABLED', eventBusName: 'default',
      description: `SGEA ADR 0003: token meter breaker requests -> ${name}`,
      eventPattern: { source: [b.source], 'detail-type': [b.detail_type] } });
    const evRole = new iam.Role(this, 'BreakerEventsRole', { roleName: `${name}-events`,
      assumedBy: new iam.ServicePrincipal('events.amazonaws.com', { conditions: { StringEquals: { 'aws:SourceAccount': acct },
        ArnEquals: { 'aws:SourceArn': `arn:${part}:events:${region}:${acct}:rule/${name}` } } }) });   // not attrArn: cycle
    const evPolicy = new iam.ManagedPolicy(this, 'BreakerEventsPolicy', { managedPolicyName: `${name}-events`, roles: [evRole],
      statements: [new iam.PolicyStatement({ sid: 'StartBreaker', actions: ['states:StartExecution'], resources: [machine.attrArn] })] });
    rule.targets = [{ id: 'breaker', arn: machine.attrArn, roleArn: evRole.roleArn }];
    rule.node.addDependency(evPolicy);
    // Breaker requests go to the default bus under the meter's own source only.
    meter.addToRolePolicy(new iam.PolicyStatement({ sid: 'BreakerEvents', actions: ['events:PutEvents'],
      resources: [`arn:${part}:events:${region}:${acct}:event-bus/default`], conditions: { StringEquals: { 'events:source': b.source } } }));
    if (props.alarmTopic) {
      const a = new cloudwatch.Alarm(this, 'BreakerFailures', { alarmName: `${name}-failures`,
        alarmDescription: "SGEA token breaker (ADR 0003) failed: an exhausted team's model calls may not be denied, or a release may be stuck.",
        metric: new cloudwatch.Metric({ namespace: 'AWS/States', metricName: 'ExecutionsFailed', statistic: 'Sum', period: Duration.minutes(5),
          dimensionsMap: { StateMachineArn: machine.attrArn } }),
        threshold: 1, evaluationPeriods: 1, comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING });
      a.addAlarmAction(new cw_actions.SnsAction(props.alarmTopic));
      if (props.alarmInsufficientData) a.addInsufficientDataAction(new cw_actions.SnsAction(props.alarmTopic));
    }
  }
}
