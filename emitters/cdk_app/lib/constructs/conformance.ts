// SGEA WRAPPER CONSTRUCT (seam) — config-conformance (mirrors modules/config-conformance)
// One AWS-published conformance pack per composed baseline; templates pinned in
// sources/conformance-packs and copied to ./packs at export.
import { Construct } from 'constructs';
import { Aws, aws_config as config, aws_iam as iam } from 'aws-cdk-lib';
import * as fs from 'fs';
import * as path from 'path';
import { PropagationWait } from './propagation-wait';

export interface ConformanceProps { packs: Record<string, string>; env: string;
  createRecorder: boolean; deliveryBucket: string; deliveryKmsKeyArn: string; slr?: iam.CfnServiceLinkedRole; }

export class Conformance extends Construct {
  constructor(scope: Construct, id: string, props: ConformanceProps) {
    super(scope, id);
    let recorder: config.CfnConfigurationRecorder | undefined;
    if (props.createRecorder) {
      // Created by the stack before the enclave CMK (whose key policy names it); see enclave-stack.ts.
      const slr = props.slr ?? new iam.CfnServiceLinkedRole(this, 'ConfigSlr', { awsServiceName: 'config.amazonaws.com' });
      recorder = new config.CfnConfigurationRecorder(this, 'Recorder', {
        name: `sgea-${props.env}`,
        roleArn: `arn:${Aws.PARTITION}:iam::${Aws.ACCOUNT_ID}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig`,
        recordingGroup: { allSupported: true, includeGlobalResourceTypes: true },
      });
      const wait = new PropagationWait(this, 'SlrWait', { seconds: 30 });  // fresh Config SLR propagation
      wait.node.addDependency(slr);
      recorder.node.addDependency(wait);
      // The CloudFormation recorder handler stabilizes by STARTING the recorder, which needs the delivery
      // channel, while PutDeliveryChannel needs the recorder to exist: a channel that depends on the
      // recorder deadlocks (NoAvailableDeliveryChannelException until timeout; sandbox 2026-10-15). So the
      // channel runs beside the recorder, 30 s later, inside the handler's ~9-minute start-retry window.
      const channelWait = new PropagationWait(this, 'ChannelWait', { seconds: 60 });
      channelWait.node.addDependency(slr);
      new config.CfnDeliveryChannel(this, 'Delivery', { name: `sgea-${props.env}`,
        s3BucketName: props.deliveryBucket, s3KeyPrefix: 'config', s3KmsKeyArn: props.deliveryKmsKeyArn }).node.addDependency(channelWait);
    }
    for (const [name, file] of Object.entries(props.packs)) {
      const pack = new config.CfnConformancePack(this, 'Pack' + name.replace(/[^A-Za-z0-9]/g, ''), {
        conformancePackName: name,
        templateBody: fs.readFileSync(path.join(__dirname, '..', '..', 'packs', file), 'utf-8'),
      });
      if (recorder) pack.node.addDependency(recorder);
    }
  }
}
