// SGEA enclave alarms (mirrors the Terraform aws_cloudwatch_metric_alarm resources).
import { Construct } from 'constructs';
import { Duration, aws_cloudwatch as cloudwatch, aws_cloudwatch_actions as cw_actions, aws_lambda as lambda,
  aws_sns as sns } from 'aws-cdk-lib';

// cloudwatch-alarm-action-check: Lambda errors / silence -> the enclave security-alarm topic.
export function lambdaAlarm(scope: Construct, id: string, fn: lambda.IFunction, metric: 'Errors' | 'Invocations',
                            topic: sns.ITopic, insufficientData: boolean, name: string, description: string) {
  const silent = metric === 'Invocations';
  const alarm = new cloudwatch.Alarm(scope, id, { alarmName: name, alarmDescription: description,
    metric: (silent ? fn.metricInvocations : fn.metricErrors).call(fn, { period: Duration.minutes(silent ? 15 : 5), statistic: 'Sum' }),
    threshold: silent ? 1 : 0, evaluationPeriods: silent ? 2 : 1,
    comparisonOperator: silent ? cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD : cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
    treatMissingData: silent ? cloudwatch.TreatMissingData.BREACHING : cloudwatch.TreatMissingData.NOT_BREACHING });
  alarm.addAlarmAction(new cw_actions.SnsAction(topic));
  if (insufficientData) alarm.addInsufficientDataAction(new cw_actions.SnsAction(topic));
  return alarm;
}
