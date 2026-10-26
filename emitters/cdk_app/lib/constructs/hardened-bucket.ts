// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// SGEA hardened S3 bucket (mirrors modules/enclave-logging/bucket): official L2 s3.Bucket for
// every enclave log bucket — versioning, SSE-KMS, block public access, ACLs disabled,
// enforceSSL, optional Object Lock, lifecycle, server access logging (L2 grants delivery).
// Escape hatches (CloudFormation properties the L2 does not model):
//   - EventBridge notifications set directly (the L2 path deploys a helper Lambda)
//   - cross-region replication by ARN (destination lives in the replica-region stack)
import { Construct } from 'constructs';
import { Duration, RemovalPolicy, Tags, aws_iam as iam, aws_kms as kms, aws_s3 as s3 } from 'aws-cdk-lib';

export interface HardenedBucketProps {
  name: string;
  encryptionKey?: kms.IKey;           // required for SSE-KMS
  sseAlgorithm?: 'aws:kms' | 'AES256';
  objectLock: boolean;
  retentionDays: number;
  logTargetBucket?: s3.IBucket;
  role: 'log-store' | 'access-log-sink' | 'replica' | 'config-delivery';
  extraStatements?: any[];
  /** s3-event-notifications-enabled: object-removal events to this SNS topic (primary-region stores). */
  notificationTopicArn?: string;
  replication?: s3.CfnBucket.ReplicationConfigurationProperty;
}

export class HardenedBucket extends Construct {
  public readonly bucket: s3.Bucket;
  public readonly name: string;
  public readonly arn: string;
  constructor(scope: Construct, id: string, p: HardenedBucketProps) {
    super(scope, id);
    const kmsSse = (p.sseAlgorithm ?? 'aws:kms') === 'aws:kms';
    this.name = p.name;
    this.bucket = new s3.Bucket(this, 'Bucket', {
      bucketName: p.name, versioned: true,
      encryption: kmsSse ? s3.BucketEncryption.KMS : s3.BucketEncryption.S3_MANAGED,
      encryptionKey: kmsSse ? p.encryptionKey : undefined, bucketKeyEnabled: kmsSse,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL, objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      // TLS-only: explicit statement below (Principal "*" literal — enforceSSL renders {AWS:*}, which some
      // cfn-guard rules do not recognise; IAM treats both the same).
      objectLockEnabled: p.objectLock || undefined,
      objectLockDefaultRetention: p.objectLock ? s3.ObjectLockRetention.governance(Duration.days(p.retentionDays)) : undefined,
      lifecycleRules: [{ id: 'retention', expiration: Duration.days(p.retentionDays),
        noncurrentVersionExpiration: Duration.days(30) }],
      serverAccessLogsBucket: p.logTargetBucket, serverAccessLogsPrefix: p.logTargetBucket ? `${p.name}/` : undefined,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.arn = this.bucket.bucketArn;
    const cfn = this.bucket.node.defaultChild as s3.CfnBucket;
    cfn.notificationConfiguration = { eventBridgeConfiguration: { eventBridgeEnabled: true },
      // EventBridge alone fails s3-event-notifications-enabled (it counts SNS / SQS / Lambda destinations).
      topicConfigurations: p.notificationTopicArn ? [{ event: 's3:ObjectRemoved:*', topic: p.notificationTopicArn }] : undefined };
    if (p.replication) cfn.replicationConfiguration = p.replication;
    Tags.of(this.bucket).add('sgea:role', p.role);
    this.bucket.addToResourcePolicy(new iam.PolicyStatement({ sid: 'DenyInsecureTransport', effect: iam.Effect.DENY,
      principals: [new iam.StarPrincipal()], actions: ['s3:*'], resources: [this.bucket.bucketArn, this.bucket.arnForObjects('*')],
      conditions: { Bool: { 'aws:SecureTransport': false } } }));   // s3-bucket-ssl-requests-only (boolean: cfn-guard S3_BUCKET_SSL_REQUESTS_ONLY compares == false)
    for (const st of p.extraStatements ?? []) this.bucket.addToResourcePolicy(iam.PolicyStatement.fromJson(st));
  }
}
