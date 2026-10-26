// SGEA WRAPPER CONSTRUCT (seam) — enclave-network (mirrors modules/enclave-network)
// SGEA-BR-09: interface endpoints (private DNS) for the services the profile allows.
// Like the Terraform module, each endpoint only gets the subnets in AZs its service supports
// (e.g. cognito-idp is not offered in every us-east-1 AZ): CDK context lookups, used when the
// stack has a concrete account/region (credential-free synth keeps every subnet).
import { Construct } from 'constructs';
import { Aws, ContextProvider, RemovalPolicy, Stack, Token, aws_ec2 as ec2, aws_iam as iam, aws_kms as kms, aws_logs as logs } from 'aws-cdk-lib';
import * as cxschema from 'aws-cdk-lib/cloud-assembly-schema';

export interface NetworkProps { vpcId: string; subnetIds: string[]; securityGroupIds: string[];
  routeTableIds: string[]; services: string[];
  env?: string; key?: kms.IKey; retentionDays?: number; flowLog?: boolean; }  // vpc-flow-logs-enabled

export class EnclaveNetwork extends Construct {
  constructor(scope: Construct, id: string, p: NetworkProps) {
    super(scope, id);
    const stack = Stack.of(this);
    const lookup = !Token.isUnresolved(stack.account) && !Token.isUnresolved(stack.region);
    const region = lookup ? stack.region : Aws.REGION;
    const subnetAz: Record<string, string> = {};
    if (lookup) {
      const vpc = ec2.Vpc.fromLookup(this, 'Vpc', { vpcId: p.vpcId });
      for (const s of [...vpc.privateSubnets, ...vpc.isolatedSubnets, ...vpc.publicSubnets]) subnetAz[s.subnetId] = s.availabilityZone;
    }
    const subnetsFor = (serviceName: string): string[] => {
      if (!lookup) return p.subnetIds;
      const azs: string[] = ContextProvider.getValue(this, {
        provider: cxschema.ContextProvider.ENDPOINT_SERVICE_AVAILABILITY_ZONE_PROVIDER,
        props: { serviceName }, dummyValue: [] }).value;
      return p.subnetIds.filter((sid) => subnetAz[sid] === undefined || azs.includes(subnetAz[sid]));
    };
    for (const svc of p.services) {
      const serviceName = `com.amazonaws.${region}.${svc}`;
      const subnets = subnetsFor(serviceName);
      if (!subnets.length) continue; // service offered in none of the enclave AZs (Terraform skips it too)
      new ec2.CfnVPCEndpoint(this, 'Ep' + svc.replace(/[^A-Za-z0-9]/g, ''), {
        vpcId: p.vpcId, serviceName, vpcEndpointType: 'Interface',
        subnetIds: subnets, securityGroupIds: p.securityGroupIds, privateDnsEnabled: true });
    }
    new ec2.CfnVPCEndpoint(this, 'S3', { vpcId: p.vpcId, serviceName: `com.amazonaws.${region}.s3`,
      vpcEndpointType: 'Gateway', routeTableIds: p.routeTableIds.length ? p.routeTableIds : undefined });
    // vpc-flow-logs-enabled: the enclave records its VPC's traffic (CMK-encrypted, pack retention);
    // skipped where dod-scca already emits the VDMS flow log.
    if (p.flowLog && p.key) {
      const group = new logs.LogGroup(this, 'FlowLogs', { logGroupName: `/sgea/${p.env}/vpc-flow-logs`,
        retention: p.retentionDays as logs.RetentionDays, encryptionKey: p.key, removalPolicy: RemovalPolicy.RETAIN });
      const role = new iam.Role(this, 'FlowLogsRole', { roleName: `sgea-${p.env}-vpc-flow-logs`,
        assumedBy: new iam.ServicePrincipal('vpc-flow-logs.amazonaws.com') });
      group.grantWrite(role);
      role.addToPolicy(new iam.PolicyStatement({ actions: ['logs:DescribeLogGroups', 'logs:DescribeLogStreams'], resources: [group.logGroupArn] }));
      new ec2.CfnFlowLog(this, 'FlowLog', { resourceId: p.vpcId, resourceType: 'VPC', trafficType: 'ALL',
        logDestinationType: 'cloud-watch-logs', logGroupName: group.logGroupName, deliverLogsPermissionArn: role.roleArn,
        maxAggregationInterval: 60 });
    }
    // token-control ledger (meter + gateway interceptor run in the VPC)
    new ec2.CfnVPCEndpoint(this, 'DynamoDb', { vpcId: p.vpcId, serviceName: `com.amazonaws.${region}.dynamodb`,
      vpcEndpointType: 'Gateway', routeTableIds: p.routeTableIds.length ? p.routeTableIds : undefined });
  }
}
