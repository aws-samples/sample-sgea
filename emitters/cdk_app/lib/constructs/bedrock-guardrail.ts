// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
// SGEA WRAPPER CONSTRUCT (seam) — bedrock-guardrail (mirrors modules/bedrock-guardrail)
// seam-kind: official-passthrough -> aws_bedrock.CfnGuardrail (+ version, account enforcement)
// Props = SGEA resolved-config `guardrails` block; entity lists/tier come from config._derived.
import { Construct } from 'constructs';
import { Aws, aws_bedrock as bedrock } from 'aws-cdk-lib';

export interface GuardrailProps { name: string; guardrail: any; derived: any; kmsKeyArn: string; geo: string; }

export class BedrockGuardrail extends Construct {
  public readonly cfn: bedrock.CfnGuardrail;
  public readonly version: bedrock.CfnGuardrailVersion;
  constructor(scope: Construct, id: string, props: GuardrailProps) {
    super(scope, id);
    const g = props.guardrail, d = props.derived.guardrail;
    const order: string[] = d.filter_order ?? [];
    const entries = Object.entries(g.content_filters ?? {}).sort(([a], [b]) =>
      (order.indexOf(a) < 0 ? 99 : order.indexOf(a)) - (order.indexOf(b) < 0 ? 99 : order.indexOf(b)));
    const filters = entries.map(([type, strength]) => ({
      type, inputStrength: strength as string,
      outputStrength: (d.input_only_filters as string[]).includes(type) ? 'NONE' : strength as string }));
    const piiTypes: string[] = (g.pii?.mode ?? 'off') === 'off' ? []
      : [...d.pii_entities, ...(g.pii?.phi_entities ? d.phi_entities : [])];
    const piiAction = g.pii?.action ?? 'BLOCK';
    const ctxAction = g.pii?.contextual_action ?? piiAction; // contextual entities (guardrail_map.CONTEXTUAL_ENTITIES)
    const pii = piiTypes.map((type) => ({ type, action: d.contextual_entities.includes(type) ? ctxAction : piiAction }));
    const topics = (g.denied_topics ?? []).map((t: string) => ({ name: t, definition: t, type: 'DENY' }));
    const tier: string = d.tier;
    this.cfn = new bedrock.CfnGuardrail(this, 'Guardrail', {
      name: props.name,
      blockedInputMessaging: 'Blocked by enclave guardrail.',
      blockedOutputsMessaging: 'Blocked by enclave guardrail.',
      contentPolicyConfig: { filtersConfig: filters, contentFiltersTierConfig: { tierName: tier } },
      sensitiveInformationPolicyConfig: pii.length ? { piiEntitiesConfig: pii } : undefined,
      topicPolicyConfig: topics.length ? { topicsConfig: topics, topicsTierConfig: { tierName: tier } } : undefined,
      crossRegionConfig: tier === 'STANDARD' ? { guardrailProfileArn:
        `arn:${Aws.PARTITION}:bedrock:${Aws.REGION}:${Aws.ACCOUNT_ID}:guardrail-profile/${props.geo}.guardrail.v1:0` } : undefined,
      kmsKeyArn: props.kmsKeyArn,
    });
    this.version = new bedrock.CfnGuardrailVersion(this, 'Version', {
      guardrailIdentifier: this.cfn.attrGuardrailId, description: `SGEA ${props.name}`,
    });
    // SGEA-BR-03: L2 account-baseline level = account-enforced guardrail.
    if (d.enforce_account_wide) {
      new bedrock.CfnEnforcedGuardrailConfiguration(this, 'Enforced', {
        guardrailIdentifier: this.cfn.attrGuardrailId, guardrailVersion: this.version.attrVersion, // API stores the id
        // SGEA-BR-03a: user messages / tool results always guarded; system prompt only where tagged.
        selectiveContentGuarding: { messages: 'COMPREHENSIVE', system: 'SELECTIVE' },
      });
    }
  }
}
