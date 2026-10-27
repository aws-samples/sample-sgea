// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// SGEA CDK aspects (applied to the whole app in bin/app.ts).
//  * NoInlinePolicies — iam-no-inline-policy-check: CDK grants write inline AWS::IAM::Policy resources
//    (DefaultPolicy, custom-resource policies). Each is re-emitted as an AWS::IAM::ManagedPolicy with the
//    same document and roles, inside the same construct (so dependencies on it still hold).
//  * DeployHelperTags — CDK framework Lambdas (AwsCustomResource provider, S3 notifications handler,
//    SGEA PropagationWait) run only during deployment: tagged sgea:role=deploy-helper so `sgea check`
//    reports them as exempt from the in-VPC / DLQ / concurrency rules (reason recorded).
import { CfnResource, IAspect, Lazy, RemovalPolicy, Stack, Tags, Token, aws_iam as iam, aws_kms as kms, aws_lambda as lambda, aws_logs as logs } from 'aws-cdk-lib';
import { IConstruct } from 'constructs';

export class NoInlinePolicies implements IAspect {
  public visit(node: IConstruct): void {
    if (node instanceof iam.CfnRole && Array.isArray(node.policies) && node.policies.length) {
      // Inline policies declared on the role itself.
      (node.policies as iam.CfnRole.PolicyProperty[]).forEach((pol, k) => new iam.CfnManagedPolicy(node, 'Inline' + k,
        { policyDocument: pol.policyDocument, roles: [node.ref] }));
      node.policies = undefined;
      return;
    }
    if (!(node instanceof iam.CfnPolicy)) return;
    const parent = node.node.scope as IConstruct;
    if (!parent || parent.node.tryFindChild('AsManaged')) return;
    new iam.CfnManagedPolicy(parent, 'AsManaged', {
      policyDocument: node.policyDocument, roles: node.roles, users: node.users, groups: node.groups,
    });
    parent.node.tryRemoveChild(node.node.id);
  }
}

const HELPER_PATHS = ['AWS679f53fac002430cb0da5b7982bd2287', 'BucketNotificationsHandler', 'sgea-propagation-wait',
  'SingletonLambda6c1f0d7e'];

export class DeployHelperTags implements IAspect {
  public visit(node: IConstruct): void {
    if (!(node instanceof lambda.CfnFunction)) return;
    const path = node.node.path;
    if (HELPER_PATHS.some((h) => path.includes(h)) && !Token.isUnresolved(path)) {
      node.tags.setTag('sgea:role', 'deploy-helper');
    }
  }
}

// DeployHelperLogs — cloudwatch-log-group-encrypted / cw-loggroup-retention-period-check for the CDK deploy
// helpers: each gets a pre-created log group (enclave CMK, pack retention) instead of the unencrypted
// /aws/lambda/<fn> group Lambda would create. Applied per stack (needs the stack's key).
export class DeployHelperLogs implements IAspect {
  private n = 0;
  constructor(private readonly key: kms.IKey, private readonly retentionDays: number, private readonly env: string) {}
  public visit(node: IConstruct): void {
    if (!(node instanceof lambda.CfnFunction)) return;
    if (!HELPER_PATHS.some((h) => node.node.path.includes(h)) || node.loggingConfig) return;
    const stack = Stack.of(node);
    const group = new logs.LogGroup(stack, `DeployHelperLogs${this.n++}`, {
      logGroupName: `/aws/lambda/sgea-${this.env}-deploy-helper-${this.n}`, encryptionKey: this.key,
      retention: this.retentionDays as logs.RetentionDays, removalPolicy: RemovalPolicy.DESTROY });
    node.loggingConfig = { logGroup: group.logGroupName };
    node.addDependency(group.node.defaultChild as logs.CfnLogGroup);
  }
}

// ScannerSuppressions — attaches cfn-guard (`Metadata.guard.SuppressedRules`) and Checkov (`Metadata.checkov.skip`)
// suppressions to resources where a finding is verified by design / not applicable, so the justification travels
// with the template. Each one is conditional on the property that makes it true.
// Evaluated lazily at synthesis, after every tag / property aspect has run.
type Skip = { id: string; comment: string };

function suppressions(node: CfnResource): { guard: string[]; checkov: Skip[] } {
  const p: any = node;   // L1 property fields
  const resolve = (v: any) => Stack.of(node).resolve(v);
  const tags: Record<string, string> = p.tags?.tagValues?.() ?? {};
  const guard: string[] = [], checkov: Skip[] = [];
  switch (node.cfnResourceType) {
    case 'AWS::RDS::DBInstance':     // Aurora member: encryption and multi-AZ are cluster properties
      // (and the master password belongs to the cluster: ManageMasterUserPassword, an RDS-managed secret)
      if (resolve(p.dbClusterIdentifier)) guard.push('RDS_MULTI_AZ_SUPPORT', 'RDS_STORAGE_ENCRYPTED', 'RDS_MASTER_USER_PASSWORD_USES_SECURE_PARAMETER');
      break;
    case 'AWS::RDS::DBCluster':      // RDS-managed, rotating admin secret; no password in the template
      if (resolve(p.manageMasterUserPassword) === true) guard.push('RDS_MASTER_USER_PASSWORD_USES_SECURE_PARAMETER');
      break;
    case 'AWS::RDS::DBClusterParameterGroup':   // the rule's type regex /AWS::RDS::DBCluster/ also matches this type
      guard.push('RDS_STORAGE_ENCRYPTED');
      break;
    case 'AWS::CloudTrail::Trail':   // KMSKeyId is the enclave CMK (Fn::GetAtt, not resolved by the rule)
      if (resolve(p.kmsKeyId)) guard.push('CLOUD_TRAIL_ENCRYPTION_ENABLED');
      break;
    case 'AWS::S3::Bucket': {
      if (resolve(p.ownershipControls)?.rules?.[0]?.objectOwnership === 'BucketOwnerEnforced') guard.push('S3_BUCKET_NO_PUBLIC_RW_ACL');
      const role = tags['sgea:role'];
      if (role === 'access-log-sink') {   // rule-dispositions.yaml exceptions
        guard.push('S3_BUCKET_LOGGING_ENABLED', 'S3_BUCKET_DEFAULT_LOCK_ENABLED');
        checkov.push({ id: 'CKV_AWS_18', comment: 'S3 server-access-log target: cannot log to itself' });
      }
      if (role === 'config-delivery') guard.push('S3_BUCKET_DEFAULT_LOCK_ENABLED');   // AWS Config delivery rejects Object Lock
      break;
    }
    case 'AWS::IAM::Role':           // ADR 0002 break-glass: AdministratorAccess by design (MFA, 1 h, every use alarms)
      if (tags['sgea:role'] === 'break-glass') {
        checkov.push({ id: 'CKV_AWS_274', comment: 'Break-glass role (ADR 0002): AdministratorAccess by design; MFA-gated trust, 1 h sessions, every assumption raises sgea-<env>-ct-break-glass-assumed' });
      }
      break;
    case 'AWS::Lambda::Function':
      if (tags['sgea:role'] === 'deploy-helper') {
        const why = 'CDK deploy helper: runs only during deployment, invoked synchronously by CloudFormation, no enclave data';
        guard.push('LAMBDA_INSIDE_VPC', 'LAMBDA_DLQ_CHECK', 'LAMBDA_CONCURRENCY_CHECK');
        checkov.push({ id: 'CKV_AWS_115', comment: why }, { id: 'CKV_AWS_116', comment: why }, { id: 'CKV_AWS_117', comment: why });
      }
      break;
  }
  return { guard, checkov };
}

export class ScannerSuppressions implements IAspect {
  public visit(node: IConstruct): void {
    if (!(node instanceof CfnResource)) return;
    node.addMetadata('guard', Lazy.any({ produce: () => {
      const g = suppressions(node).guard; return g.length ? { SuppressedRules: g } : undefined; } }));
    node.addMetadata('checkov', Lazy.any({ produce: () => {
      const c = suppressions(node).checkov; return c.length ? { skip: c } : undefined; } }));
  }
}
