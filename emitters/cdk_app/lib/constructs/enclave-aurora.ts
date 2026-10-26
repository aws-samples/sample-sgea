// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// SGEA WRAPPER CONSTRUCT (seam) — enclave-aurora (mirrors modules/enclave-aurora)
// Official L2 rds.DatabaseCluster (Aurora PostgreSQL Serverless v2), configured from the composed packs'
// rds-* rules; AWS Backup lives in enclave-backup. Network objects are imported from customer-supplied ids.
import { Construct } from 'constructs';
import { Duration, Fn, RemovalPolicy, aws_ec2 as ec2, aws_kms as kms, aws_logs as logs, aws_rds as rds } from 'aws-cdk-lib';

export interface AuroraProps { env: string; key: kms.IKey; vpcId: string; subnetIds: string[]; securityGroupIds: string[];
  backup: { retention_days: number; vault_lock: boolean }; retentionDays?: number; }

export class EnclaveAurora extends Construct {
  public readonly clusterArn: string;
  constructor(scope: Construct, id: string, p: AuroraProps) {
    super(scope, id);
    const vpc = ec2.Vpc.fromVpcAttributes(this, 'Vpc', { vpcId: p.vpcId,
      availabilityZones: p.subnetIds.map((_, k) => Fn.select(k, Fn.getAzs())), privateSubnetIds: p.subnetIds });
    const engine = rds.DatabaseClusterEngine.auroraPostgres({ version: rds.AuroraPostgresEngineVersion.VER_16_9 });
    const instance = { publiclyAccessible: false, autoMinorVersionUpgrade: true,       // rds-instance-public-access-check
      enablePerformanceInsights: true, performanceInsightEncryptionKey: p.key };
    const cluster = new rds.DatabaseCluster(this, 'Cluster', {
      clusterIdentifier: `sgea-${p.env}-vector`, engine, defaultDatabaseName: 'sgea',
      // RDS-managed admin secret: rotated by RDS (secretsmanager-rotation-enabled-check), CMK below
      // (secretsmanager-using-cmk); non-default admin name (rds-instance-default-admin-check).
      credentials: rds.Credentials.fromUsername('sgea_admin'), manageMasterUserPassword: true,
      storageEncrypted: true, storageEncryptionKey: p.key, iamAuthentication: true, enableDataApi: true,
      deletionProtection: true, copyTagsToSnapshot: true, cloudwatchLogsExports: ['postgresql'],
      backup: { retention: Duration.days(Math.min(p.backup.retention_days, 35)) },
      vpc, vpcSubnets: { subnets: p.subnetIds.map((s, k) => ec2.Subnet.fromSubnetId(this, `Subnet${k}`, s)) },
      securityGroups: p.securityGroupIds.map((s, k) => ec2.SecurityGroup.fromSecurityGroupId(this, `Sg${k}`, s)),
      parameterGroup: new rds.ParameterGroup(this, 'Params', { engine,
        parameters: { 'rds.force_ssl': '1', log_connections: '1', log_disconnections: '1' } }),
      serverlessV2MinCapacity: 0.5, serverlessV2MaxCapacity: 8, monitoringInterval: Duration.seconds(60),
      writer: rds.ClusterInstance.serverlessV2('writer', instance),
      readers: [rds.ClusterInstance.serverlessV2('reader', { ...instance, scaleWithWriter: true })], // multi-AZ
      removalPolicy: RemovalPolicy.SNAPSHOT,
    });
    (cluster.node.defaultChild as rds.CfnDBCluster).masterUserSecret = { kmsKeyId: p.key.keyArn };
    // The exported log group exists (CMK + pack retention) before RDS would create it unencrypted:
    // cloudwatch-log-group-encrypted, cw-loggroup-retention-period-check.
    const pgLogs = new logs.LogGroup(this, 'PostgresLogs', { logGroupName: `/aws/rds/cluster/sgea-${p.env}-vector/postgresql`,
      retention: (p.retentionDays ?? 365) as logs.RetentionDays, encryptionKey: p.key, removalPolicy: RemovalPolicy.RETAIN });
    cluster.node.addDependency(pgLogs);
    this.clusterArn = cluster.clusterArn;
  }
}
