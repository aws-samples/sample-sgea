// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// SGEA WRAPPER CONSTRUCT (seam) — enclave-kms (mirrors modules/enclave-kms)
// Official L2 kms.Key: rotation, 30-day deletion window, alias; key policy admits CloudWatch
// Logs, CloudTrail and Bedrock invocation-log delivery for this account only.
import { Construct } from 'constructs';
import { Aws, Duration, RemovalPolicy, aws_iam as iam, aws_kms as kms } from 'aws-cdk-lib';

export class EnclaveKms extends Construct {
  public readonly key: kms.Key;
  constructor(scope: Construct, id: string, props: { env: string }) {
    super(scope, id);
    const acct = Aws.ACCOUNT_ID, part = Aws.PARTITION, region = Aws.REGION;
    this.key = new kms.Key(this, 'Key', {
      description: `SGEA enclave CMK (${props.env})`, enableKeyRotation: true,
      pendingWindow: Duration.days(30), alias: `alias/sgea-${props.env}`, removalPolicy: RemovalPolicy.RETAIN,
    });
    const allow = (st: any) => this.key.addToResourcePolicy(iam.PolicyStatement.fromJson({ Effect: 'Allow', Resource: '*', ...st }));
    allow({ Sid: 'CloudWatchLogs', Principal: { Service: `logs.${region}.amazonaws.com` },
      Action: ['kms:Encrypt*', 'kms:Decrypt*', 'kms:ReEncrypt*', 'kms:GenerateDataKey*', 'kms:Describe*'],
      Condition: { ArnLike: { 'kms:EncryptionContext:aws:logs:arn': `arn:${part}:logs:${region}:${acct}:*` } } });
    allow({ Sid: 'CloudTrail', Principal: { Service: 'cloudtrail.amazonaws.com' }, Action: ['kms:GenerateDataKey*', 'kms:DescribeKey'],
      Condition: { StringLike: { 'kms:EncryptionContext:aws:cloudtrail:arn': `arn:${part}:cloudtrail:*:${acct}:trail/*` } } });
    // AWS Config's service-linked role, named directly (no wildcard principal): the stack creates it before this key.
    allow({ Sid: 'ConfigDelivery', Principal: { AWS: `arn:${part}:iam::${acct}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig` },
      Action: ['kms:GenerateDataKey*', 'kms:Decrypt'] });
    // AWS Config's delivery-channel writability check runs as the service principal (verified in sandbox).
    allow({ Sid: 'ConfigServicePrincipal', Principal: { Service: 'config.amazonaws.com' }, Action: ['kms:Decrypt', 'kms:GenerateDataKey'],
      Condition: { StringEquals: { 'aws:SourceAccount': acct } } });
    allow({ Sid: 'BedrockInvocationLogDelivery', Principal: { Service: 'bedrock.amazonaws.com' },
      Action: ['kms:GenerateDataKey*', 'kms:Decrypt'], Condition: { StringEquals: { 'aws:SourceAccount': acct } } });
    // S3 event notifications publish to the CMK-encrypted log-store-events topic.
    allow({ Sid: 'S3EventNotificationsToEncryptedSns', Principal: { Service: 's3.amazonaws.com' },
      Action: ['kms:GenerateDataKey*', 'kms:Decrypt'], Condition: { StringEquals: { 'aws:SourceAccount': acct } } });
    // CloudWatch alarms publish to the CMK-encrypted security-alarm topic (sns-encrypted-kms).
    allow({ Sid: 'CloudWatchAlarmsToEncryptedSns', Principal: { Service: 'cloudwatch.amazonaws.com' },
      Action: ['kms:GenerateDataKey*', 'kms:Decrypt'], Condition: { StringEquals: { 'aws:SourceAccount': acct } } });
  }
}
