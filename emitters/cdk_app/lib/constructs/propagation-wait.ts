// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// SGEA deploy helper — waits for IAM propagation (mirrors Terraform's time_sleep.iam_propagation).
// CloudFormation creates a resource the moment its role policy reports complete, but services that
// check the role at create time (AgentCore Gateway: GetPolicyEngine; AWS Config: a freshly created
// service-linked role) can still be denied for a few seconds. Inline Python (no assets); it answers
// CloudFormation itself — cfnresponse is not injected for inline python3.12+ (sandbox, 2026-10-15).
import { Construct } from 'constructs';
import { CustomResource, Duration, Tags, aws_lambda as lambda } from 'aws-cdk-lib';

const CODE = `import json, time, urllib.request
def handler(event, context):
    status, reason = "SUCCESS", "ok"
    try:
        if event["RequestType"] != "Delete":
            time.sleep(int(event["ResourceProperties"].get("Seconds", "30")))
    except Exception as e:
        status, reason = "FAILED", type(e).__name__
    body = json.dumps({"Status": status, "Reason": reason, "PhysicalResourceId": event.get("PhysicalResourceId") or "sgea-propagation-wait",
                       "StackId": event["StackId"], "RequestId": event["RequestId"], "LogicalResourceId": event["LogicalResourceId"], "Data": {}}).encode()
    req = urllib.request.Request(event["ResponseURL"], data=body, method="PUT", headers={"Content-Type": "", "Content-Length": str(len(body))})
    urllib.request.urlopen(req, timeout=30)
`;

export interface PropagationWaitProps { seconds?: number; trigger?: string; }

export class PropagationWait extends Construct {
  public readonly resource: CustomResource;
  constructor(scope: Construct, id: string, props: PropagationWaitProps = {}) {
    super(scope, id);
    const fn = new lambda.SingletonFunction(this, 'Fn', { uuid: '6c1f0d7e-sgea-propagation-wait',
      runtime: new lambda.Runtime('python3.15', lambda.RuntimeFamily.PYTHON, { supportsInlineCode: true }), handler: 'index.handler', code: lambda.Code.fromInline(CODE),
      timeout: Duration.seconds(120), description: 'SGEA deploy helper: IAM propagation wait' });
    Tags.of(fn).add('sgea:role', 'deploy-helper');
    this.resource = new CustomResource(this, 'Wait', { serviceToken: fn.functionArn, resourceType: 'Custom::SgeaPropagationWait',
      serviceTimeout: Duration.minutes(5), // never hang the stack for the 1-hour default
      properties: { Seconds: String(props.seconds ?? 30), Trigger: props.trigger ?? '' } });
  }
}
