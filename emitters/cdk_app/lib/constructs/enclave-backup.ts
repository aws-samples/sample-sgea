// SGEA WRAPPER CONSTRUCT (seam) — enclave-backup (mirrors modules/enclave-backup)
// AWS Backup vault (enclave CMK, optional vault lock), daily plan with the pack-derived retention, and
// one selection covering every enclave data store: aurora-/rds-*-backup-plan, dynamodb-*-backup-plan
// (token ledger), s3-resources-protected-by-backup-plan (log / config stores).
import { Construct } from 'constructs';
import { Duration, RemovalPolicy, aws_backup as backup, aws_events as events, aws_iam as iam, aws_kms as kms } from 'aws-cdk-lib';

export interface BackupProps { env: string; key: kms.IKey; retentionDays: number; vaultLock: boolean; resourceArns: string[]; }

export class EnclaveBackup extends Construct {
  constructor(scope: Construct, id: string, p: BackupProps) {
    super(scope, id);
    const vault = new backup.BackupVault(this, 'Vault', { backupVaultName: `sgea-${p.env}`, encryptionKey: p.key,
      lockConfiguration: p.vaultLock ? { minRetention: Duration.days(p.retentionDays) } : undefined,
      // backup-recovery-point-manual-deletion-disabled: Config requires ONE Deny covering all three actions
      // (blockRecoveryPointDeletion omits PutBackupVaultAccessPolicy) — same statement as the Terraform module.
      accessPolicy: new iam.PolicyDocument({ statements: [new iam.PolicyStatement({ sid: 'DenyRecoveryPointDeletion',
        effect: iam.Effect.DENY, principals: [new iam.AnyPrincipal()], resources: ['*'],
        actions: ['backup:DeleteRecoveryPoint', 'backup:UpdateRecoveryPointLifecycle', 'backup:PutBackupVaultAccessPolicy'] })] }),
      removalPolicy: RemovalPolicy.RETAIN });
    const plan = new backup.BackupPlan(this, 'Plan', { backupPlanName: `sgea-${p.env}`, backupVault: vault,
      backupPlanRules: [new backup.BackupPlanRule({ ruleName: 'daily', scheduleExpression: events.Schedule.cron({ minute: '0', hour: '5' }),
        deleteAfter: Duration.days(p.retentionDays) })] });
    const role = new iam.Role(this, 'Role', { roleName: `sgea-${p.env}-backup`, assumedBy: new iam.ServicePrincipal('backup.amazonaws.com'),
      managedPolicies: ['service-role/AWSBackupServiceRolePolicyForBackup', 'service-role/AWSBackupServiceRolePolicyForRestores',
        'AWSBackupServiceRolePolicyForS3Backup', 'AWSBackupServiceRolePolicyForS3Restore']
        .map((n) => iam.ManagedPolicy.fromAwsManagedPolicyName(n)) });
    plan.addSelection('Enclave', { backupSelectionName: `sgea-${p.env}-enclave`, role,
      resources: p.resourceArns.map((a) => backup.BackupResource.fromArn(a)) });
  }
}
