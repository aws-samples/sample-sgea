// SGEA WRAPPER CONSTRUCT (seam) — bedrock-knowledge-base (mirrors modules/bedrock-knowledge-base)
// seam-kind: official-passthrough -> aws_bedrock.CfnKnowledgeBase with RDS (Aurora PostgreSQL /
// pgvector) storage: the enclave's Aurora-only vector-store decision, no OpenSearch / S3 Vectors.
import { Construct } from 'constructs';
import { aws_bedrock as bedrock } from 'aws-cdk-lib';

export interface AuroraStorage {
  resourceArn: string; credentialsSecretArn: string; databaseName: string; tableName: string;
  primaryKeyField: string; vectorField: string; textField: string; metadataField: string;
}
export interface KnowledgeBaseProps { name: string; roleArn: string; embeddingModelArn: string; aurora: AuroraStorage; }

export class BedrockKnowledgeBase extends Construct {
  public readonly cfn: bedrock.CfnKnowledgeBase;
  constructor(scope: Construct, id: string, p: KnowledgeBaseProps) {
    super(scope, id);
    this.cfn = new bedrock.CfnKnowledgeBase(this, 'KnowledgeBase', {
      name: p.name, roleArn: p.roleArn,
      knowledgeBaseConfiguration: { type: 'VECTOR',
        vectorKnowledgeBaseConfiguration: { embeddingModelArn: p.embeddingModelArn } },
      storageConfiguration: { type: 'RDS', rdsConfiguration: {
        resourceArn: p.aurora.resourceArn, credentialsSecretArn: p.aurora.credentialsSecretArn,
        databaseName: p.aurora.databaseName, tableName: p.aurora.tableName,
        fieldMapping: { primaryKeyField: p.aurora.primaryKeyField, vectorField: p.aurora.vectorField,
          textField: p.aurora.textField, metadataField: p.aurora.metadataField } } },
    });
  }
}
