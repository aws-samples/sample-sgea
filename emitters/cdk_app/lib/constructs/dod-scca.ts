// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// SGEA WRAPPER CONSTRUCT (seam) — dod-scca (mirrors modules/dod-scca)
// DoD SCCA in-account components: VDSS (AWS Network Firewall, default drop, egress allow-list)
// and VDMS logging (firewall + VPC flow logs). BCAP, routing via the firewall endpoints, and
// TCCM are customer / DISA prerequisites — see the module README.
import { Construct } from 'constructs';
import { Fn, RemovalPolicy, aws_ec2 as ec2, aws_kms as kms, aws_logs as logs, aws_networkfirewall as nfw } from 'aws-cdk-lib';

export interface SccaProps { env: string; key: kms.IKey; vpcId: string; firewallSubnetIds: string[];
  egressDomains: string[]; cloudwatchRetentionDays: number; }

export class DodScca extends Construct {
  constructor(scope: Construct, id: string, p: SccaProps) {
    super(scope, id);
    const name = `sgea-${p.env}`;
    // CloudFormation exposes no customer-managed KMS option for Network Firewall config (the Terraform
    // provider does): firewall configuration uses an AWS-owned key here; all logs use the enclave CMK.
    const groups: nfw.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty[] = [];
    if (p.egressDomains.length) {
      const rg = new nfw.CfnRuleGroup(this, 'EgressAllowlist', { ruleGroupName: `${name}-egress-allowlist`,
        type: 'STATEFUL', capacity: 100,
        ruleGroup: { rulesSource: { rulesSourceList: { generatedRulesType: 'ALLOWLIST',
          targetTypes: ['TLS_SNI', 'HTTP_HOST'], targets: p.egressDomains } },
          statefulRuleOptions: { ruleOrder: 'STRICT_ORDER' } } });
      groups.push({ priority: 100, resourceArn: rg.attrRuleGroupArn });
    }
    const policy = new nfw.CfnFirewallPolicy(this, 'Policy', { firewallPolicyName: `${name}-vdss`,
      firewallPolicy: { statelessDefaultActions: ['aws:forward_to_sfe'], statelessFragmentDefaultActions: ['aws:forward_to_sfe'],
        statefulDefaultActions: ['aws:drop_strict', 'aws:alert_strict'], statefulEngineOptions: { ruleOrder: 'STRICT_ORDER' },
        statefulRuleGroupReferences: groups.length ? groups : undefined } });
    const fw = new nfw.CfnFirewall(this, 'Firewall', { firewallName: `${name}-vdss`, vpcId: p.vpcId,
      firewallPolicyArn: policy.attrFirewallPolicyArn, deleteProtection: true, subnetChangeProtection: true,
      firewallPolicyChangeProtection: true, subnetMappings: p.firewallSubnetIds.map((subnetId) => ({ subnetId })) });
    const group = (gid: string, n: string) => new logs.LogGroup(this, gid, { logGroupName: n,
      retention: p.cloudwatchRetentionDays as logs.RetentionDays, encryptionKey: p.key, removalPolicy: RemovalPolicy.RETAIN });
    const alert = group('AlertLogs', `/sgea/${p.env}/network-firewall/alert`);
    const flow = group('FlowLogs', `/sgea/${p.env}/network-firewall/flow`);
    new nfw.CfnLoggingConfiguration(this, 'Logging', { firewallArn: fw.attrFirewallArn, loggingConfiguration: {
      logDestinationConfigs: [
        { logDestination: { logGroup: alert.logGroupName }, logDestinationType: 'CloudWatchLogs', logType: 'ALERT' },
        { logDestination: { logGroup: flow.logGroupName }, logDestinationType: 'CloudWatchLogs', logType: 'FLOW' }] } });
    // VPC flow logs (vpc-flow-logs-enabled; VDMS): official L2 ec2.FlowLog (creates its delivery role).
    const vpc = ec2.Vpc.fromVpcAttributes(this, 'Vpc', { vpcId: p.vpcId, availabilityZones: [Fn.select(0, Fn.getAzs())] });
    new ec2.FlowLog(this, 'VpcFlowLog', { resourceType: ec2.FlowLogResourceType.fromVpc(vpc), trafficType: ec2.FlowLogTrafficType.ALL,
      destination: ec2.FlowLogDestination.toCloudWatchLogs(group('VpcFlowLogs', `/sgea/${p.env}/vpc-flow-logs`)),
      maxAggregationInterval: ec2.FlowLogMaxAggregationInterval.ONE_MINUTE });
  }
}
