// SGEA WRAPPER CONSTRUCT (seam) — enclave-logging (mirrors modules/enclave-logging)
// Official L2s: s3.Bucket (via HardenedBucket), logs.LogGroup, iam.Role, cloudtrail.Trail.
// Bedrock model-invocation logging has no CloudFormation type: official AwsCustomResource SDK call.
// Escape hatch: CloudTrail advanced event selectors (not modeled by the Trail L2).
import { Construct } from 'constructs';
import { Aws, RemovalPolicy, aws_cloudtrail as ct, aws_iam as iam, aws_kms as kms, aws_logs as logs,
  aws_sns as sns, custom_resources as cr } from 'aws-cdk-lib';
import { HardenedBucket } from './hardened-bucket';

export interface EnclaveLoggingProps { env: string; key: kms.IKey; logging: any; derived: any; }

export class EnclaveLogging extends Construct {
  public readonly logStoreName: string;
  public readonly invocationLogGroup: logs.ILogGroup;
  public readonly alarmTopic: sns.ITopic;          // cloudwatch-alarm-action-check, sns-encrypted-kms
  public readonly dataStoreArns: string[] = [];    // log / config stores for enclave-backup
  public configBucketName!: string;
  constructor(scope: Construct, id: string, p: EnclaveLoggingProps) {
    super(scope, id);
    const acct = Aws.ACCOUNT_ID, part = Aws.PARTITION, region = Aws.REGION;
    const retention: number = p.logging.retention_days;
    const replicaRegion: string = p.derived.replica_region;
    const names = {
      logStore: `sgea-${p.env}-logs-${acct}-${region}`,
      access: `sgea-${p.env}-access-logs-${acct}-${region}`,
      replica: `sgea-${p.env}-logs-replica-${acct}-${replicaRegion}`,
      config: `sgea-${p.env}-config-${acct}-${region}`,
    };
    this.logStoreName = names.logStore;

    // Log-store event notifications (s3-event-notifications-enabled): object removals -> SNS (CMK). One topic
    // policy for every store, created before the buckets (S3 validates the destination on PutBucketNotification).
    const events = new sns.Topic(this, 'LogStoreEvents', { topicName: `sgea-${p.env}-log-store-events`, masterKey: p.key });
    const eventsPolicy = new sns.TopicPolicy(this, 'LogStoreEventsPolicy', { topics: [events] });
    eventsPolicy.document.addStatements(new iam.PolicyStatement({ sid: 'S3EventNotifications', actions: ['sns:Publish'],
      principals: [new iam.ServicePrincipal('s3.amazonaws.com')], resources: [events.topicArn],
      conditions: { StringEquals: { 'aws:SourceAccount': acct }, ArnLike: { 'aws:SourceArn': `arn:${part}:s3:::sgea-${p.env}-*` } } }));
    const access = new HardenedBucket(this, 'AccessLogs', { name: names.access, sseAlgorithm: 'AES256',
      objectLock: false, retentionDays: retention, role: 'access-log-sink', notificationTopicArn: events.topicArn });
    access.node.addDependency(eventsPolicy);

    const replRole = new iam.Role(this, 'ReplicationRole', { roleName: `sgea-${p.env}-log-replication`,
      assumedBy: new iam.ServicePrincipal('s3.amazonaws.com') });
    replRole.addToPolicy(iam.PolicyStatement.fromJson({ Effect: 'Allow', Action: ['s3:GetReplicationConfiguration', 's3:ListBucket'],
      Resource: `arn:${part}:s3:::${names.logStore}` }));
    replRole.addToPolicy(iam.PolicyStatement.fromJson({ Effect: 'Allow', Action: ['s3:GetObjectVersionForReplication',
      's3:GetObjectVersionAcl', 's3:GetObjectVersionTagging', 's3:GetObjectRetention', 's3:GetObjectLegalHold'],
      Resource: `arn:${part}:s3:::${names.logStore}/*` }));
    replRole.addToPolicy(iam.PolicyStatement.fromJson({ Effect: 'Allow', Action: ['s3:ReplicateObject', 's3:ReplicateDelete',
      's3:ReplicateTags'], Resource: `arn:${part}:s3:::${names.replica}/*` }));   // same-account replica: no owner override
    p.key.grantDecrypt(replRole);
    // Replica key ARN, published by the replica stack (SSM, replica region): the role names the exact key.
    const paramName = `/sgea/${p.env}/log-replica-key-arn`;
    const replicaKeyArn = new cr.AwsCustomResource(this, 'ReplicaKeyArn', { resourceType: 'Custom::SgeaReplicaKeyArn',
      onUpdate: { service: 'SSM', action: 'GetParameter', region: replicaRegion, parameters: { Name: paramName },
        physicalResourceId: cr.PhysicalResourceId.of(paramName) },
      policy: cr.AwsCustomResourcePolicy.fromStatements([new iam.PolicyStatement({ actions: ['ssm:GetParameter'],
        resources: [`arn:${part}:ssm:${replicaRegion}:${acct}:parameter${paramName}`] })]),
      installLatestAwsSdk: false }).getResponseField('Parameter.Value');
    replRole.addToPolicy(iam.PolicyStatement.fromJson({ Effect: 'Allow', Action: ['kms:Encrypt', 'kms:GenerateDataKey'], Resource: replicaKeyArn }));

    const store = new HardenedBucket(this, 'LogStore', {
      name: names.logStore, encryptionKey: p.key, objectLock: !!p.logging.most_sensitive_store, retentionDays: retention,
      logTargetBucket: access.bucket, notificationTopicArn: events.topicArn, role: 'log-store',
      replication: { role: replRole.roleArn, rules: [{ id: 'replicate-all', status: 'Enabled', priority: 1, filter: { prefix: '' },
        deleteMarkerReplication: { status: 'Disabled' }, sourceSelectionCriteria: { sseKmsEncryptedObjects: { status: 'Enabled' } },
        destination: { bucket: `arn:${part}:s3:::${names.replica}`, storageClass: 'STANDARD',
          encryptionConfiguration: { replicaKmsKeyId: replicaKeyArn } } }] },
      extraStatements: [
        { Sid: 'BedrockInvocationLogWrite', Effect: 'Allow', Principal: { Service: 'bedrock.amazonaws.com' },
        Action: 's3:PutObject', Resource: `arn:${part}:s3:::${names.logStore}/bedrock/*`,
        Condition: { StringEquals: { 'aws:SourceAccount': acct }, ArnLike: { 'aws:SourceArn': `arn:${part}:bedrock:${region}:${acct}:*` } } }],
    });

    // AWS Config delivery bucket: no Object Lock (S3 requires a checksum on writes to Object Lock buckets;
    // the AWS Config writer sends none — verified in sandbox). Otherwise the same hardening.
    const configStore = new HardenedBucket(this, 'ConfigStore', { name: names.config, encryptionKey: p.key, objectLock: false,
      retentionDays: retention, logTargetBucket: access.bucket, notificationTopicArn: events.topicArn, role: 'config-delivery', extraStatements: [
        { Sid: 'ConfigBucketCheck', Effect: 'Allow', Principal: { Service: 'config.amazonaws.com' },
          Action: ['s3:GetBucketAcl', 's3:ListBucket'], Resource: `arn:${part}:s3:::${names.config}`,
          Condition: { StringEquals: { 'AWS:SourceAccount': acct } } },
        { Sid: 'ConfigDelivery', Effect: 'Allow', Principal: { Service: 'config.amazonaws.com' }, Action: 's3:PutObject',
          Resource: `arn:${part}:s3:::${names.config}/config/AWSLogs/${acct}/Config/*`,
          Condition: { StringEquals: { 'AWS:SourceAccount': acct, 's3:x-amz-acl': 'bucket-owner-full-control' } } },
        { Sid: 'ConfigServiceLinkedRole', Effect: 'Allow',
          Principal: { AWS: `arn:${part}:iam::${acct}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig` },
          Action: ['s3:GetBucketAcl', 's3:ListBucket', 's3:PutObject'],
          Resource: [`arn:${part}:s3:::${names.config}`, `arn:${part}:s3:::${names.config}/config/AWSLogs/${acct}/Config/*`] },
      ] });
    this.configBucketName = configStore.name;
    this.dataStoreArns.push(store.bucket.bucketArn, configStore.bucket.bucketArn);
    this.alarmTopic = new sns.Topic(this, 'SecurityAlarms', { topicName: `sgea-${p.env}-security-alarms`, masterKey: p.key });

    // ----- CloudWatch log groups -----
    const group = (gid: string, name: string) => new logs.LogGroup(this, gid, { logGroupName: name,
      retention: p.derived.cloudwatch_retention_days as logs.RetentionDays, encryptionKey: p.key,
      removalPolicy: RemovalPolicy.RETAIN });
    const invocations = group('BedrockInvocations', `/sgea/${p.env}/bedrock/model-invocations`);
    this.invocationLogGroup = invocations;
    group('AgentCore', `/sgea/${p.env}/agentcore`);
    const trailGroup = group('CloudTrailGroup', `/sgea/${p.env}/cloudtrail`);

    // ----- Bedrock model-invocation logging -----
    if (p.logging.model_invocation_logging) {
      const role = new iam.Role(this, 'BedrockLoggingRole', { roleName: `sgea-${p.env}-bedrock-invocation-logging`,
        assumedBy: new iam.ServicePrincipal('bedrock.amazonaws.com', { conditions: {
          StringEquals: { 'aws:SourceAccount': acct }, ArnLike: { 'aws:SourceArn': `arn:${part}:bedrock:${region}:${acct}:*` } } }) });
      invocations.grantWrite(role);
      const call = { service: 'Bedrock', action: 'putModelInvocationLoggingConfiguration',
        parameters: { loggingConfig: { textDataDeliveryEnabled: true, imageDataDeliveryEnabled: true,
          embeddingDataDeliveryEnabled: true, videoDataDeliveryEnabled: true,
          cloudWatchConfig: { logGroupName: invocations.logGroupName, roleArn: role.roleArn,
            largeDataDeliveryS3Config: { bucketName: names.logStore, keyPrefix: 'bedrock/large-data' } },
          s3Config: { bucketName: names.logStore, keyPrefix: 'bedrock/invocations' } } },
        physicalResourceId: cr.PhysicalResourceId.of(`sgea-${p.env}-invocation-logging`) };
      const res = new cr.AwsCustomResource(this, 'ModelInvocationLogging', {
        resourceType: 'Custom::SgeaBedrockInvocationLogging', onCreate: call, onUpdate: call,
        onDelete: { service: 'Bedrock', action: 'deleteModelInvocationLoggingConfiguration' },
        policy: cr.AwsCustomResourcePolicy.fromStatements([
          new iam.PolicyStatement({ actions: ['bedrock:PutModelInvocationLoggingConfiguration',
            'bedrock:DeleteModelInvocationLoggingConfiguration'], resources: ['*'] }),
          new iam.PolicyStatement({ actions: ['iam:PassRole'], resources: [role.roleArn] }),
        ]),
        installLatestAwsSdk: false,
      });
      res.node.addDependency(store);
    }

    // ----- CloudTrail (L2 grants its own bucket / log-group permissions) -----
    const trail = new ct.Trail(this, 'Trail', { trailName: `sgea-${p.env}`, bucket: store.bucket, s3KeyPrefix: 'cloudtrail',
      isMultiRegionTrail: true, includeGlobalServiceEvents: true, enableFileValidation: true, encryptionKey: p.key,
      sendToCloudWatchLogs: true, cloudWatchLogGroup: trailGroup });
    (trail.node.defaultChild as ct.CfnTrail).advancedEventSelectors = [
      { name: 'management-events', fieldSelectors: [{ field: 'eventCategory', equalTo: ['Management'] }] },
      ...(p.derived.data_event_resource_types as string[]).map((t) => ({ name: `data-events-${t}`,
        fieldSelectors: [{ field: 'eventCategory', equalTo: ['Data'] }, { field: 'resources.type', equalTo: [t] },
          // Never log the trail's own deliveries to the log store (AWS best practice).
          ...(t === 'AWS::S3::Object' ? [{ field: 'resources.ARN', notStartsWith: [`arn:${part}:s3:::${names.logStore}/`] }] : [])] })),
    ];
  }
}
