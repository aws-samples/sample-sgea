// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// SGEA WRAPPER CONSTRUCT (seam) — enclave-monitoring (mirrors modules/enclave-monitoring, ADR 0002)
// M1 EventBridge -> SNS (+ CDK-only daily stack-drift detection via EventBridge Scheduler), M2 CloudTrail metric
// filters + alarms, M3 Bedrock / AgentCore health alarms, M4 Budgets + Cost Anomaly Detection (commercial
// partition only), M5 IAM Access Analyzer, M6 CloudWatch Transaction Search (aws/spans), optional break-glass role.
// Official L2: logs.LogGroup / MetricFilter, cloudwatch.Alarm, iam.Role / ManagedPolicy. L1 elsewhere: events.CfnRule
// (the L2 SnsTopic target would add an unconditioned topic-policy grant), scheduler, budgets, ce, accessanalyzer, xray.
import { Construct } from 'constructs';
import { Aws, Duration, RemovalPolicy, Stack, aws_accessanalyzer as aa, aws_budgets as budgets, aws_ce as ce,
  aws_cloudwatch as cloudwatch, aws_cloudwatch_actions as cw_actions, aws_events as events, aws_iam as iam,
  aws_kms as kms, aws_logs as logs, aws_scheduler as scheduler, aws_sns as sns, aws_xray as xray } from 'aws-cdk-lib';
import { EnvInputs } from './context';

export interface MonitoringProps {
  inputs: EnvInputs; key: kms.IKey; alarmTopic: sns.ITopic; alarmInsufficientData?: boolean;
  partition: string;                   // config.json partition (aws | aws-us-gov): Budgets / CE are commercial-only
  trailLogGroup: logs.ILogGroup;       // /sgea/<env>/cloudtrail
  retentionDays: number;               // pack CloudWatch retention (aws/spans)
  modelInvocationLogging: boolean;     // bedrock-invocation-log-delivery alarm only where logging is on
  guardrailArn: string; guardrailVersion: string;
  gatewayArn?: string;                 // gateway alarms only where the gateway exists
  stackNames: string[];                // SGEA stacks in this region (drift detection)
}

// M2 — CIS-style CloudTrail metric filters (ADR 0002, literal patterns).
const CT_FILTERS: Record<string, string> = {
  'unauthorized-api': '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
  'console-no-mfa': '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }',
  'root-usage': '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }',
  'iam-policy-changes': '{ ($.eventSource = "iam.amazonaws.com") && (($.eventName = "Put*Policy") || ($.eventName = "Delete*Policy") || ($.eventName = "Create*Policy*") || ($.eventName = "Attach*Policy") || ($.eventName = "Detach*Policy")) }',
  'cloudtrail-changes': '{ ($.eventName = "CreateTrail") || ($.eventName = "UpdateTrail") || ($.eventName = "DeleteTrail") || ($.eventName = "StartLogging") || ($.eventName = "StopLogging") || ($.eventName = "PutEventSelectors") }',
  'console-auth-failures': '{ ($.eventName = "ConsoleLogin") && ($.errorMessage = "Failed authentication") }',
  'kms-key-disable-or-delete': '{ ($.eventSource = "kms.amazonaws.com") && (($.eventName = "DisableKey") || ($.eventName = "ScheduleKeyDeletion")) }',
  's3-bucket-policy-changes': '{ ($.eventSource = "s3.amazonaws.com") && (($.eventName = "PutBucketAcl") || ($.eventName = "PutBucketPolicy") || ($.eventName = "PutBucketCors") || ($.eventName = "PutBucketLifecycle") || ($.eventName = "PutBucketReplication") || ($.eventName = "DeleteBucketPolicy") || ($.eventName = "DeleteBucketCors") || ($.eventName = "DeleteBucketLifecycle") || ($.eventName = "DeleteBucketReplication")) }',
  'config-changes': '{ ($.eventSource = "config.amazonaws.com") && (($.eventName = "StopConfigurationRecorder") || ($.eventName = "DeleteDeliveryChannel") || ($.eventName = "PutDeliveryChannel") || ($.eventName = "PutConfigurationRecorder") || ($.eventName = "DeleteConfigurationRecorder")) }',
  'security-group-changes': '{ ($.eventName = "AuthorizeSecurityGroupIngress") || ($.eventName = "AuthorizeSecurityGroupEgress") || ($.eventName = "RevokeSecurityGroupIngress") || ($.eventName = "RevokeSecurityGroupEgress") || ($.eventName = "CreateSecurityGroup") || ($.eventName = "DeleteSecurityGroup") }',
  'nacl-changes': '{ ($.eventName = "CreateNetworkAcl") || ($.eventName = "CreateNetworkAclEntry") || ($.eventName = "DeleteNetworkAcl") || ($.eventName = "DeleteNetworkAclEntry") || ($.eventName = "ReplaceNetworkAclEntry") || ($.eventName = "ReplaceNetworkAclAssociation") }',
  'network-gateway-changes': '{ ($.eventName = "CreateCustomerGateway") || ($.eventName = "DeleteCustomerGateway") || ($.eventName = "AttachInternetGateway") || ($.eventName = "CreateInternetGateway") || ($.eventName = "DeleteInternetGateway") || ($.eventName = "DetachInternetGateway") }',
  'route-table-changes': '{ ($.eventSource = "ec2.amazonaws.com") && (($.eventName = "CreateRoute") || ($.eventName = "CreateRouteTable") || ($.eventName = "ReplaceRoute") || ($.eventName = "ReplaceRouteTableAssociation") || ($.eventName = "DeleteRouteTable") || ($.eventName = "DeleteRoute") || ($.eventName = "DisassociateRouteTable")) }',
  'vpc-changes': '{ ($.eventName = "CreateVpc") || ($.eventName = "DeleteVpc") || ($.eventName = "ModifyVpcAttribute") || ($.eventName = "AcceptVpcPeeringConnection") || ($.eventName = "CreateVpcPeeringConnection") || ($.eventName = "DeleteVpcPeeringConnection") || ($.eventName = "RejectVpcPeeringConnection") || ($.eventName = "AttachClassicLinkVpc") || ($.eventName = "DetachClassicLinkVpc") || ($.eventName = "DisableVpcClassicLink") || ($.eventName = "EnableVpcClassicLink") }',
  'organizations-changes': '{ ($.eventSource = "organizations.amazonaws.com") && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreatePolicy") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy")) }',
};

const pascal = (s: string) => s.split('-').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join('');

export class EnclaveMonitoring extends Construct {
  public breakGlassRoleArn?: string;
  constructor(scope: Construct, id: string, p: MonitoringProps) {
    super(scope, id);
    const i = p.inputs, env = i.env, acct = Aws.ACCOUNT_ID, part = Aws.PARTITION, region = Aws.REGION;
    const topic = p.alarmTopic;
    const commercial = p.partition !== 'aws-us-gov';   // billing lives in the commercial payer account
    const budget = commercial && i.monthlyBudgetUsd > 0;
    const anomaly = commercial && i.createCostAnomalyMonitor;
    const analyzers = i.createAccessAnalyzer || i.createUnusedAccessAnalyzer;

    // ----- topic policy: who may publish to the CMK-encrypted alarm topic -----
    // A topic policy replaces SNS's default policy, so the CloudWatch alarm publisher is stated explicitly too.
    const publish = (sid: string, service: string, extra: any = {}) => topic.addToResourcePolicy(new iam.PolicyStatement({ sid,
      actions: ['sns:Publish'], principals: [new iam.ServicePrincipal(service)], resources: [topic.topicArn],
      conditions: { StringEquals: { 'aws:SourceAccount': acct }, ...extra } }));
    publish('CloudWatchAlarms', 'cloudwatch.amazonaws.com', { ArnLike: { 'aws:SourceArn': `arn:${part}:cloudwatch:${region}:${acct}:alarm:*` } });
    publish('EventBridgeRules', 'events.amazonaws.com', { ArnLike: { 'aws:SourceArn': `arn:${part}:events:${region}:${acct}:rule/sgea-${env}-evt-*` } });
    if (budget) publish('Budgets', 'budgets.amazonaws.com');
    if (anomaly) publish('CostAnomalyDetection', 'costalerts.amazonaws.com');

    // ----- M1: EventBridge -> SNS -----
    const rule = (name: string, pattern: any) => new events.CfnRule(this, 'Evt' + pascal(name), {
      name: `sgea-${env}-evt-${name}`, description: `SGEA ${name} events -> sgea-${env}-security-alarms`,
      eventBusName: 'default', state: 'ENABLED', eventPattern: pattern,
      targets: [{ id: 'security-alarms', arn: topic.topicArn }] });
    rule('guardduty', { source: ['aws.guardduty'], 'detail-type': ['GuardDuty Finding'], detail: { severity: [{ numeric: ['>=', 7] }] } });
    rule('securityhub', { source: ['aws.securityhub'], 'detail-type': ['Security Hub Findings - Imported'],
      detail: { findings: { Severity: { Label: ['HIGH', 'CRITICAL'] }, Workflow: { Status: ['NEW'] } } } });
    rule('inspector', { source: ['aws.inspector2'], 'detail-type': ['Inspector2 Finding'], detail: { severity: ['HIGH', 'CRITICAL'] } });
    rule('config-compliance', { source: ['aws.config'], 'detail-type': ['Config Rules Compliance Change'],
      detail: { newEvaluationResult: { complianceType: ['NON_COMPLIANT'] } } });
    rule('backup', { source: ['aws.backup'], 'detail-type': ['Backup Job State Change', 'Copy Job State Change', 'Restore Job State Change'],
      detail: { state: ['FAILED', 'ABORTED', 'EXPIRED'] } });
    rule('secret-rotation', { source: ['aws.secretsmanager'], 'detail-type': ['AWS Service Event via CloudTrail'],
      detail: { eventName: ['RotationFailed'] } });
    if (analyzers) rule('access-analyzer', { source: ['aws.access-analyzer'], 'detail-type': ['Access Analyzer Finding'],
      detail: { status: ['ACTIVE'] } });
    // CDK only. CloudFormation publishes the drift result under detail.status-details.stack-drift-status
    // (the ADR's shorthand `stack-drift-detection-status` is not a field of this event).
    rule('stack-drift', { source: ['aws.cloudformation'], 'detail-type': ['CloudFormation Drift Detection Status Change'],
      detail: { 'status-details': { 'stack-drift-status': ['DRIFTED'] } } });

    // Daily drift detection: EventBridge Scheduler universal target (no Lambda), role limited to the SGEA stacks.
    const stackArns = p.stackNames.map((s) => `arn:${part}:cloudformation:${region}:${acct}:stack/${s}/*`);
    // Drift detection reads every resource in the stack, so the role also needs read access to their services:
    // AWS managed ReadOnlyAccess (read-only, no inline policy) beside the two drift actions on the SGEA stacks.
    const driftRole = new iam.Role(this, 'DriftSchedulerRole', { roleName: `sgea-${env}-drift-scheduler`,
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName('ReadOnlyAccess')],
      assumedBy: new iam.ServicePrincipal('scheduler.amazonaws.com', { conditions: { StringEquals: { 'aws:SourceAccount': acct },
        // Scheduler sets aws:SourceArn to the schedule-group ARN (not the schedule ARN); the schedules use the default group.
        ArnEquals: { 'aws:SourceArn': `arn:${part}:scheduler:${region}:${acct}:schedule-group/default` } } }) });
    const driftPolicy = new iam.ManagedPolicy(this, 'DriftSchedulerPolicy', { managedPolicyName: `sgea-${env}-drift-scheduler`,
      roles: [driftRole], statements: [new iam.PolicyStatement({ sid: 'DetectSgeaStackDrift',
        actions: ['cloudformation:DetectStackDrift', 'cloudformation:DetectStackResourceDrift'], resources: stackArns })] });
    p.stackNames.forEach((s, k) => {
      const sched = new scheduler.CfnSchedule(this, k ? `DriftDetect${k}` : 'DriftDetect', {
        name: k ? `sgea-${env}-drift-detect-${k}` : `sgea-${env}-drift-detect`, description: `SGEA daily drift detection: ${s}`,
        scheduleExpression: 'rate(1 day)', flexibleTimeWindow: { mode: 'OFF' }, state: 'ENABLED',
        target: { arn: `arn:${part}:scheduler:::aws-sdk:cloudformation:detectStackDrift`, roleArn: driftRole.roleArn,
          input: JSON.stringify({ StackName: s }), retryPolicy: { maximumRetryAttempts: 3 } } });
      sched.node.addDependency(driftPolicy);
    });

    // ----- alarms (shared shape) -----
    const alarm = (aid: string, name: string, description: string, metric: cloudwatch.IMetric, threshold: number,
                   op: cloudwatch.ComparisonOperator, periods = 1) => {
      const a = new cloudwatch.Alarm(this, aid, { alarmName: name, alarmDescription: description, metric, threshold,
        comparisonOperator: op, evaluationPeriods: periods, datapointsToAlarm: periods,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING });
      a.addAlarmAction(new cw_actions.SnsAction(topic));
      if (p.alarmInsufficientData) a.addInsufficientDataAction(new cw_actions.SnsAction(topic));   // cloudwatch-alarm-action-check
      return a;
    };
    const GTE = cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD;

    // ----- break-glass role (optional) -----
    const filters = { ...CT_FILTERS };
    if (i.createBreakGlassRole) {
      if (!i.breakGlassPrincipalArns.length) throw new Error('sgea:createBreakGlassRole=true needs sgea:breakGlassPrincipalArns');
      const name = `sgea-${env}-break-glass`;
      const bg = new iam.CfnRole(this, 'BreakGlassRole', { roleName: name, maxSessionDuration: 3600,
        description: 'SGEA break-glass administrator (MFA, 1 h sessions). Every assumption alarms; review per docs/operations/access-review.md.',
        assumeRolePolicyDocument: { Version: '2012-10-17', Statement: [{ Sid: 'BreakGlassWithMfa', Effect: 'Allow',
          Principal: { AWS: i.breakGlassPrincipalArns }, Action: 'sts:AssumeRole',
          Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' }, NumericLessThan: { 'aws:MultiFactorAuthAge': '3600' } } }] },
        managedPolicyArns: [`arn:${part}:iam::aws:policy/AdministratorAccess`],
        tags: [{ key: 'sgea:role', value: 'break-glass' }] });
      this.breakGlassRoleArn = bg.attrArn;
      filters['break-glass-assumed'] = `{ ($.eventName = "AssumeRole") && ($.requestParameters.roleArn = "arn:${part}:iam::${acct}:role/${name}") }`;
    }

    // ----- M2: CloudTrail metric filters + alarms -----
    const ns = `SGEA/${env}/CloudTrail`;
    for (const [name, pattern] of Object.entries(filters)) {
      const mf = new logs.MetricFilter(this, 'Ct' + pascal(name), { logGroup: p.trailLogGroup, filterName: `sgea-${env}-ct-${name}`,
        metricNamespace: ns, metricName: name, metricValue: '1', filterPattern: logs.FilterPattern.literal(pattern) });
      alarm('Ct' + pascal(name) + 'Alarm', `sgea-${env}-ct-${name}`, `SGEA CloudTrail: ${name} (CIS-style metric filter).`,
        mf.metric({ statistic: 'Sum', period: Duration.minutes(5) }), 1, GTE);
    }

    // ----- M3: service health -----
    const m = (namespace: string, metricName: string, statistic: string, minutes: number, dimensionsMap?: Record<string, string>) =>
      new cloudwatch.Metric({ namespace, metricName, statistic, period: Duration.minutes(minutes), dimensionsMap });
    alarm('BedrockThrottles', `sgea-${env}-bedrock-throttles`, 'SGEA Bedrock invocation throttles (account aggregate).',
      m('AWS/Bedrock', 'InvocationThrottles', 'Sum', 5), 10, GTE, 2);
    alarm('BedrockServerErrors', `sgea-${env}-bedrock-server-errors`, 'SGEA Bedrock invocation server errors (account aggregate).',
      m('AWS/Bedrock', 'InvocationServerErrors', 'Sum', 5), 5, GTE);
    if (p.modelInvocationLogging) {
      alarm('BedrockInvocationLogDelivery', `sgea-${env}-bedrock-invocation-log-delivery`,
        'SGEA Bedrock model-invocation log delivery to CloudWatch failed.',
        m('AWS/Bedrock', 'ModelInvocationLogsCloudWatchDeliverySuccess', 'Minimum', 15), 1, cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD);
    }
    alarm('GuardrailInterventions', `sgea-${env}-guardrail-interventions`, 'SGEA baseline guardrail interventions above threshold.',
      m('AWS/Bedrock/Guardrails', 'InvocationsIntervened', 'Sum', 15, { GuardrailArn: p.guardrailArn, GuardrailVersion: p.guardrailVersion }),
      i.guardrailInterventionThreshold, GTE);
    if (p.gatewayArn) {
      const dims = { Operation: 'InvokeGateway', Protocol: 'MCP', Resource: p.gatewayArn };
      alarm('GatewaySystemErrors', `sgea-${env}-gateway-system-errors`, 'SGEA AgentCore gateway system errors.',
        m('AWS/Bedrock-AgentCore', 'SystemErrors', 'Sum', 5, dims), 5, GTE);
      alarm('GatewayThrottles', `sgea-${env}-gateway-throttles`, 'SGEA AgentCore gateway throttles.',
        m('AWS/Bedrock-AgentCore', 'Throttles', 'Sum', 5, dims), 10, GTE, 2);
    }

    // ----- M4: cost (commercial partition only) -----
    if (budget) {
      const sub = [{ subscriptionType: 'SNS', address: topic.topicArn }];
      new budgets.CfnBudget(this, 'MonthlyCost', {
        budget: { budgetName: `sgea-${env}-monthly-cost`, budgetType: 'COST', timeUnit: 'MONTHLY',
          budgetLimit: { amount: i.monthlyBudgetUsd, unit: 'USD' } },
        notificationsWithSubscribers: [
          { notification: { notificationType: 'ACTUAL', comparisonOperator: 'GREATER_THAN', threshold: 80, thresholdType: 'PERCENTAGE' }, subscribers: sub },
          { notification: { notificationType: 'FORECASTED', comparisonOperator: 'GREATER_THAN', threshold: 100, thresholdType: 'PERCENTAGE' }, subscribers: sub },
        ] });
    }
    if (anomaly) {
      const monitor = new ce.CfnAnomalyMonitor(this, 'CostMonitor', { monitorName: `sgea-${env}-services`,
        monitorType: 'DIMENSIONAL', monitorDimension: 'SERVICE' });
      new ce.CfnAnomalySubscription(this, 'CostAnomalies', { subscriptionName: `sgea-${env}-anomalies`, frequency: 'IMMEDIATE',
        monitorArnList: [monitor.attrMonitorArn], subscribers: [{ type: 'SNS', address: topic.topicArn }],
        thresholdExpression: JSON.stringify({ Dimensions: { Key: 'ANOMALY_TOTAL_IMPACT_ABSOLUTE',
          MatchOptions: ['GREATER_THAN_OR_EQUAL'], Values: ['100'] } }) });
    }

    // ----- M5: IAM Access Analyzer (findings route through evt-access-analyzer) -----
    if (i.createAccessAnalyzer) new aa.CfnAnalyzer(this, 'ExternalAccess', { analyzerName: `sgea-${env}-external-access`, type: 'ACCOUNT' });
    if (i.createUnusedAccessAnalyzer) new aa.CfnAnalyzer(this, 'UnusedAccess', { analyzerName: `sgea-${env}-unused-access`,
      type: 'ACCOUNT_UNUSED_ACCESS', analyzerConfiguration: { unusedAccessConfiguration: { unusedAccessAge: 90 } } });

    // ----- M6: Transaction Search. `aws/spans` cannot be created here (log-group names starting with aws/ are
    // reserved; sandbox 2026-10-26): X-Ray creates it with the first spans; CMK + retention are a post-deploy step.
    if (i.manageTransactionSearch) {
      const policy = new logs.CfnResourcePolicy(this, 'TransactionSearchPolicy', { policyName: `sgea-${env}-transaction-search`,
        policyDocument: Stack.of(this).toJsonString({ Version: '2012-10-17', Statement: [{ Sid: 'TransactionSearchXRayAccess',
          Effect: 'Allow', Principal: { Service: 'xray.amazonaws.com' }, Action: 'logs:PutLogEvents',
          Resource: [`arn:${part}:logs:${region}:${acct}:log-group:aws/spans:*`,
            `arn:${part}:logs:${region}:${acct}:log-group:/aws/application-signals/data:*`],
          Condition: { StringEquals: { 'aws:SourceAccount': acct }, ArnLike: { 'aws:SourceArn': `arn:${part}:xray:${region}:${acct}:*` } } }] }) });
      const ts = new xray.CfnTransactionSearchConfig(this, 'TransactionSearch', { indexingPercentage: 1 });
      ts.node.addDependency(policy);
    }
  }
}
