// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// SGEA WRAPPER CONSTRUCT (seam) — account-baseline (mirrors modules/account-baseline)
// Account settings the composed packs evaluate. None has a CloudFormation type, so each is an official
// AwsCustomResource SDK call (settings are left in place on stack delete: they are account guardrails).
// Disable with -c sgea:manageAccountBaseline=false where the landing zone owns them.
import { Construct } from 'constructs';
import { Aws, aws_iam as iam, aws_kms as kms, custom_resources as cr } from 'aws-cdk-lib';

export interface AccountBaselineProps { settings: any; key: kms.IKey; vpcId?: string; }

export class AccountBaseline extends Construct {
  constructor(scope: Construct, id: string, p: AccountBaselineProps) {
    super(scope, id);
    const s = p.settings;
    // resources: '*' only for account-level APIs without resource-level permissions (EBS default encryption /
    // key, snapshot block, account S3 public-access block, password policy, DescribeSecurityGroups).
    const call = (cid: string, resourceType: string, service: string, action: string, parameters: any,
                  actions: string[], extra: Partial<cr.AwsSdkCall> = {}, resources: string[] = ['*']) => {
      const sdk: cr.AwsSdkCall = { service, action, parameters, physicalResourceId: cr.PhysicalResourceId.of(`sgea-${cid}`), ...extra };
      return new cr.AwsCustomResource(this, cid, { resourceType, onCreate: sdk, onUpdate: sdk, installLatestAwsSdk: false,
        policy: cr.AwsCustomResourcePolicy.fromStatements([new iam.PolicyStatement({ actions, resources })]) });
    };
    if (s.ebs_encryption_by_default) {   // ec2-ebs-encryption-by-default
      const on = call('EbsEncryptionByDefault', 'Custom::SgeaEbsEncryptionByDefault', 'EC2', 'EnableEbsEncryptionByDefault', {},
        ['ec2:EnableEbsEncryptionByDefault']);
      call('EbsDefaultKmsKey', 'Custom::SgeaEbsDefaultKmsKey', 'EC2', 'ModifyEbsDefaultKmsKeyId', { KmsKeyId: p.key.keyArn },
        ['ec2:ModifyEbsDefaultKmsKeyId']).node.addDependency(on);
    }
    if (s.snapshot_block_public_access) {   // ebs-snapshot-public-restorable-check
      call('SnapshotBlockPublicAccess', 'Custom::SgeaSnapshotBlockPublicAccess', 'EC2', 'EnableSnapshotBlockPublicAccess',
        { State: 'block-all-sharing' }, ['ec2:EnableSnapshotBlockPublicAccess']);
    }
    if (s.s3_account_public_access_block) {   // s3-account-level-public-access-blocks-periodic
      call('S3AccountPublicAccessBlock', 'Custom::SgeaS3AccountPublicAccessBlock', 'S3Control', 'PutPublicAccessBlock',
        { AccountId: Aws.ACCOUNT_ID, PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true,
          BlockPublicPolicy: true, RestrictPublicBuckets: true } }, ['s3:PutAccountPublicAccessBlock']);
    }
    if (s.password_policy) {   // iam-password-policy / iam-password-policy-2
      const pw = s.password_policy;
      call('PasswordPolicy', 'Custom::SgeaPasswordPolicy', 'IAM', 'UpdateAccountPasswordPolicy', {
        MinimumPasswordLength: pw.minimum_password_length, PasswordReusePrevention: pw.password_reuse_prevention,
        MaxPasswordAge: pw.max_password_age, RequireLowercaseCharacters: pw.require_lowercase_characters,
        RequireUppercaseCharacters: pw.require_uppercase_characters, RequireNumbers: pw.require_numbers,
        RequireSymbols: pw.require_symbols }, ['iam:UpdateAccountPasswordPolicy']);
    }
    if (s.default_security_group_closed && p.vpcId) {   // vpc-default-security-group-closed
      const find = call('DefaultSg', 'Custom::SgeaDefaultSecurityGroupLookup', 'EC2', 'DescribeSecurityGroups',
        { Filters: [{ Name: 'vpc-id', Values: [p.vpcId] }, { Name: 'group-name', Values: ['default'] }] },
        ['ec2:DescribeSecurityGroups'], { outputPaths: ['SecurityGroups.0.GroupId'] });
      const sg = find.getResponseField('SecurityGroups.0.GroupId');
      const notFound = { ignoreErrorCodesMatching: 'InvalidPermission.NotFound' };
      const sgArn = [`arn:${Aws.PARTITION}:ec2:${Aws.REGION}:${Aws.ACCOUNT_ID}:security-group/${sg}`];   // this VPC's default SG only
      call('DefaultSgNoIngress', 'Custom::SgeaDefaultSecurityGroupClosed', 'EC2', 'RevokeSecurityGroupIngress',
        { GroupId: sg, IpPermissions: [{ IpProtocol: '-1', UserIdGroupPairs: [{ GroupId: sg }] }] },
        ['ec2:RevokeSecurityGroupIngress'], notFound, sgArn);
      call('DefaultSgNoEgress', 'Custom::SgeaDefaultSecurityGroupClosed', 'EC2', 'RevokeSecurityGroupEgress',
        { GroupId: sg, IpPermissions: [{ IpProtocol: '-1', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }] },
        ['ec2:RevokeSecurityGroupEgress'], notFound, sgArn);
    }
  }
}
