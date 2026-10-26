// SGEA WRAPPER CONSTRUCT (seam) — security-services (mirrors modules/security-services)
// GuardDuty + Security Hub with the NIST SP 800-53 Rev5 standard (DoD SCCA VDMS; packs'
// guardduty-enabled-centralized / securityhub-enabled). Disable with -c sgea:createSecurityServices=false
// where an org delegated admin already runs them (-c sgea:createGuardDuty=false / createSecurityHub=false).
import { Construct } from 'constructs';
import { Aws, aws_guardduty as guardduty, aws_iam as iam, aws_securityhub as securityhub, custom_resources as cr } from 'aws-cdk-lib';

export class SecurityServices extends Construct {
  constructor(scope: Construct, id: string, props: { guardDuty: boolean; securityHub: boolean; inspector?: string[] }) {
    super(scope, id);
    if (props.guardDuty) new guardduty.CfnDetector(this, 'Detector', { enable: true, findingPublishingFrequency: 'FIFTEEN_MINUTES' });
    if (props.securityHub) {
      const hub = new securityhub.CfnHub(this, 'Hub', { enableDefaultStandards: false });
      new securityhub.CfnStandard(this, 'Nist80053', {
        standardsArn: `arn:${Aws.PARTITION}:securityhub:${Aws.REGION}::standards/nist-800-53/v/5.0.0` }).node.addDependency(hub);
    }
    // inspector-ecr-scan-enabled / inspector-lambda-standard-scan-enabled / inspector-ec2-scan-enabled
    // (no CloudFormation type for the account enabler: official AwsCustomResource).
    if (props.inspector?.length) {
      const enable: cr.AwsSdkCall = { service: 'Inspector2', action: 'Enable',
        parameters: { accountIds: [Aws.ACCOUNT_ID], resourceTypes: props.inspector },
        physicalResourceId: cr.PhysicalResourceId.of('sgea-inspector') };
      new cr.AwsCustomResource(this, 'Inspector', { resourceType: 'Custom::SgeaInspector', onCreate: enable, onUpdate: enable,
        installLatestAwsSdk: false, policy: cr.AwsCustomResourcePolicy.fromStatements([
          // inspector2:Enable / BatchGetAccountStatus have no resource-level permissions.
          new iam.PolicyStatement({ actions: ['inspector2:Enable', 'inspector2:BatchGetAccountStatus'], resources: ['*'] }),
          // Only Inspector's own service-linked role.
          new iam.PolicyStatement({ actions: ['iam:CreateServiceLinkedRole'],
            resources: [`arn:${Aws.PARTITION}:iam::${Aws.ACCOUNT_ID}:role/aws-service-role/inspector2.amazonaws.com/AWSServiceRoleForAmazonInspector2`],
            conditions: { StringEquals: { 'iam:AWSServiceName': 'inspector2.amazonaws.com' } } })]) });
    }
  }
}
