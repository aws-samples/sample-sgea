// SGEA WRAPPER CONSTRUCT (seam) — governance (mirrors modules/org-guardrail + token-control)
// seam-kind: raw-governance-adapter. SCP/RCP statements are the SGEA policy library,
// rendered from the resolved config and bundled into config._derived.policy_bundles; deploy-time
// values (partition, org id, perimeter) are substituted here.
import { Construct } from 'constructs';
import { Annotations, Aws, Duration, RemovalPolicy, aws_dynamodb as ddb, aws_events as events, aws_events_targets as targets,
  aws_iam as iam, aws_kms as kms, aws_lambda as lambda, aws_logs as logs, aws_logs_destinations as destinations,
  aws_sns as sns, aws_sqs as sqs,
  aws_organizations as orgs } from 'aws-cdk-lib';
import * as path from 'path';
import { EnvInputs } from './context';
import { lambdaAlarm } from './alarms';

export interface PolicyBundle { name: string; type: string; packs: string[]; needs: string[]; template: string; }

export interface GovernanceProps { bundles: PolicyBundle[]; inputs: EnvInputs; key: kms.IKey;
  alarmTopic?: sns.ITopic; alarmInsufficientData?: boolean; reservedConcurrency?: number;
  tokenControl: any; invocationLogGroup?: logs.ILogGroup; cloudwatchRetentionDays: number; }

export class Governance extends Construct {
  public readonly ledger: ddb.Table;
  public meter?: lambda.Function;
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
        functionName: fname, runtime: lambda.Runtime.PYTHON_3_12, handler: 'token_meter.handler',
        code: lambda.Code.fromAsset(path.join(__dirname, '..', '..', 'lambda')),
        timeout: Duration.seconds(30), memorySize: 256, reservedConcurrentExecutions: props.reservedConcurrency ?? 20, // lambda-concurrency-check
        deadLetterQueue: new sqs.Queue(this, 'MeterDlq', { queueName: `${fname}-dlq`, encryption: sqs.QueueEncryption.KMS,
          encryptionMasterKey: props.key, retentionPeriod: Duration.days(14) }), // lambda-dlq-check
        environment: { TOKEN_LEDGER_TABLE: ledger.tableName, TOKEN_TIMEZONE: tc.default_timezone ?? 'UTC' },
        environmentEncryption: props.key, tracing: lambda.Tracing.ACTIVE, logGroup: group,
      });
      if (i.agentSubnetIds.length) {
        (meter.node.defaultChild as lambda.CfnFunction).vpcConfig = { subnetIds: i.agentSubnetIds, securityGroupIds: i.agentSecurityGroupIds };
        meter.role!.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaVPCAccessExecutionRole'));
      }
      ledger.grant(meter, 'dynamodb:UpdateItem', 'dynamodb:PutItem');
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
    }
  }
}
