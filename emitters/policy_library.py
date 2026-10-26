"""
SGEA SCP / RCP statement library.

Renders the policy packs named in the resolved config (`policies.scps`,
`policies.rcps`) into JSON policy documents. Values that are control decisions
(allowed regions, service allow-list, inference-profile geo, guardrail levels)
come from the resolved config and are baked in. Values only known at deploy
time (organization id, baseline guardrail ARN, perimeter VPCs / CIDRs) are left
as Terraform `templatefile` placeholders:

    ${partition}  ${org_id}
    ${jsonencode(perimeter_vpc_ids)}  ${jsonencode(perimeter_cidrs)}

IAM policy variables (e.g. aws:PrincipalTag) are written `$${...}` so
templatefile passes them through literally.

Both emitters consume `render(resolved)`; a pack id with no renderer is an
error, so a profile can never silently ship an empty `{}` policy.
"""
import json

SCP_MAX_CHARS = 5120  # AWS Organizations limit for SCPs and RCPs (minified).
# AWS Organizations: at most 5 SCPs (and 5 RCPs) attached per root/OU/account, INCLUDING the
# AWS-managed FullAWSAccess / RCPFullAWSAccess. SGEA packs are bundled into at most 4 each.
MAX_ATTACHED = 4

# services.allow ids -> IAM service prefixes they need.
SERVICE_PREFIXES = {
    "bedrock": ["bedrock"], "bedrock-agentcore": ["bedrock-agentcore"],
    "aurora-postgresql": ["rds", "rds-data", "rds-db"], "kms": ["kms"],
    "cloudwatch": ["cloudwatch", "logs"], "cloudtrail": ["cloudtrail"], "s3": ["s3"],
    "lambda": ["lambda"], "dynamodb": ["dynamodb"], "sns": ["sns"], "eventbridge": ["events", "scheduler"],
    "firehose": ["firehose"], "cognito": ["cognito-idp", "cognito-identity"],
    "elasticache": ["elasticache"],
}
# Always-needed control-plane / security services (identity, networking, detective controls).
FOUNDATION_PREFIXES = [
    "iam", "sts", "organizations", "account", "sso", "identitystore", "ec2", "ecr", "secretsmanager",
    "ssm", "config", "guardduty", "securityhub", "access-analyzer", "tag", "resource-groups",
    "support", "health", "trustedadvisor", "servicequotas", "cloudformation", "backup", "xray",
    "network-firewall",
]
# Global / us-east-1-only services exempt from the region lockdown (AWS sample SCP).
GLOBAL_ACTIONS = [
    "a4b:*", "account:*", "aws-portal:*", "budgets:*", "ce:*", "chime:*", "cloudfront:*", "cur:*",
    "globalaccelerator:*", "health:*", "iam:*", "importexport:*", "mobileanalytics:*",
    "organizations:*", "pricing:*", "route53:*", "route53domains:*", "s3:GetAccountPublic*",
    "s3:ListAllMyBuckets", "s3:PutAccountPublic*", "shield:*", "sso:*", "sts:*", "support:*",
    "trustedadvisor:*", "waf:*", "wafv2:*", "ec2:DescribeRegions",
]
INVOKE_ACTIONS = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream",
                  "bedrock:Converse", "bedrock:ConverseStream"]
TENANT_TAG = "sgea:tenant"
NOT_AWS_SERVICE = {"BoolIfExists": {"aws:PrincipalIsAWSService": "false"}}


def _doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def scp_region_lockdown(r):
    return _doc({
        "Sid": "DenyOutsideAllowedRegions", "Effect": "Deny", "NotAction": GLOBAL_ACTIONS,
        "Resource": "*",
        "Condition": {"StringNotEquals": {"aws:RequestedRegion": r["regions"]["allowed"]}},
    })


def scp_bedrock_surface(r):
    prefixes = []
    for svc in r["services"]["allow"]:
        if svc not in SERVICE_PREFIXES:
            raise SystemExit("policy library: no IAM prefix mapping for services.allow entry " + repr(svc))
        prefixes += SERVICE_PREFIXES[svc]
    allowed = sorted({p + ":*" for p in prefixes + FOUNDATION_PREFIXES})
    return _doc({
        "Sid": "DenyServicesOutsideEnclaveAllowList", "Effect": "Deny", "NotAction": allowed,
        "Resource": "*",
    })


def scp_inference_profile(r):
    geo = r["regions"]["inference_profile_geo"]
    arn = "arn:${partition}:bedrock:*:"
    return _doc({
        "Sid": "DenyInferenceOutsideApprovedGeo", "Effect": "Deny", "Action": INVOKE_ACTIONS,
        # Permit only same-geo cross-region profiles; global.* and other geos are denied.
        "NotResource": [arn + "*:inference-profile/" + geo + ".*", arn + ":foundation-model/*",
                        arn + "*:application-inference-profile/*", arn + "*:provisioned-model/*",
                        arn + "*:custom-model/*", arn + "*:imported-model/*"],
    })


def scp_guardrail_enforce(r):
    # Require *a* guardrail on every invocation. Not pinned to the baseline ARN:
    # tenant (L3) guardrails must also pass; the account-enforced (L2) guardrail
    # guarantees the baseline one is applied regardless.
    return _doc({
        "Sid": "DenyInvokeWithoutGuardrail", "Effect": "Deny", "Action": INVOKE_ACTIONS,
        "Resource": "*", "Condition": {"Null": {"bedrock:GuardrailIdentifier": "true"}},
    })


def scp_data_perimeter(r):
    return _doc({
        "Sid": "DenyDataAccessOutsideOrg", "Effect": "Deny",
        "Action": ["s3:*", "dynamodb:*", "rds-data:*", "secretsmanager:*", "bedrock:Retrieve*"],
        "Resource": "*",
        "Condition": {"StringNotEqualsIfExists": {"aws:ResourceOrgID": "${org_id}"}, **NOT_AWS_SERVICE},
    })


def scp_tenant_isolation(r):
    pt, rt = "aws:PrincipalTag/" + TENANT_TAG, "aws:ResourceTag/" + TENANT_TAG
    return _doc({
        "Sid": "DenyCrossTenantAccess", "Effect": "Deny",
        "Action": ["bedrock:*", "bedrock-agentcore:*", "s3:GetObject*", "s3:PutObject*",
                   "dynamodb:*", "rds-data:*", "secretsmanager:GetSecretValue"],
        "Resource": "*",
        "Condition": {"StringNotEquals": {rt: "$${" + pt + "}"},
                      "Null": {pt: "false", rt: "false"}},
    })


def rcp_identity_perimeter(r):
    return _doc({
        "Sid": "EnforceIdentityPerimeter", "Effect": "Deny", "Principal": "*",
        "Action": ["s3:*", "sts:AssumeRole", "kms:*", "secretsmanager:*", "sqs:*"],
        "Resource": "*",
        "Condition": {"StringNotEqualsIfExists": {"aws:PrincipalOrgID": "${org_id}"}, **NOT_AWS_SERVICE},
    })


def rcp_network_perimeter(r):
    return _doc({
        "Sid": "EnforceNetworkPerimeter", "Effect": "Deny", "Principal": "*",
        "Action": ["s3:*", "kms:*", "secretsmanager:*", "sqs:*"],
        "Resource": "*",
        "Condition": {
            "NotIpAddressIfExists": {"aws:SourceIp": "__PERIMETER_CIDRS__"},
            "StringNotEqualsIfExists": {"aws:SourceVpc": "__PERIMETER_VPCS__"},
            "BoolIfExists": {"aws:PrincipalIsAWSService": "false", "aws:ViaAWSService": "false"},
        },
    })


def scp_model_allowlist(r, model_ids=None):
    """Deny invoking foundation models not authorized for every composed baseline (AWS FedRAMP /
    DoD Bedrock model table, catalog/_regions.json). Exact model IDs; only same-model variant
    suffixes (':0', ':0:8k') collapse to ':*'. Inference profiles pass here — IAM also evaluates
    the underlying foundation-model ARN, which this statement covers."""
    if not model_ids:
        raise SystemExit("policy library: bre-scp-07-model-allowlist needs authorized model IDs "
                         "(run tools/build_catalog.py)")
    ids = sorted({i.split(":", 1)[0] + ":*" if ":" in i else i for i in model_ids})
    return _doc({
        "Sid": "DenyUnauthorizedFoundationModels", "Effect": "Deny", "Action": INVOKE_ACTIONS,
        "NotResource": ["arn:*:bedrock:*::foundation-model/" + i for i in ids] +
                       ["arn:*:bedrock:*:*:" + k + "/*" for k in
                        ("inference-profile", "application-inference-profile", "provisioned-model",
                         "custom-model", "imported-model")],
    })


RENDERERS = {
    "bre-scp-01-region-lockdown": scp_region_lockdown,
    "bre-scp-02-bedrock-surface": scp_bedrock_surface,
    "bre-scp-03-inference-profile": scp_inference_profile,
    "bre-scp-04-guardrail-enforce": scp_guardrail_enforce,
    "bre-scp-05-data-perimeter": scp_data_perimeter,
    "bre-scp-06-tenant-isolation": scp_tenant_isolation,
    "rcp-01-identity-perimeter": rcp_identity_perimeter,
    "rcp-02-network-perimeter": rcp_network_perimeter,
    "bre-scp-07-model-allowlist": scp_model_allowlist,
}
# Packs whose placeholders need deploy-time inputs beyond partition.
NEEDS = {
    "bre-scp-05-data-perimeter": ["org_id"],
    "rcp-01-identity-perimeter": ["org_id"],
    "rcp-02-network-perimeter": ["perimeter_vpc_ids", "perimeter_cidrs"],
}


def _template(doc):
    s = json.dumps(doc, separators=(",", ":"))
    return (s.replace('"__PERIMETER_CIDRS__"', "${jsonencode(perimeter_cidrs)}")
             .replace('"__PERIMETER_VPCS__"', "${jsonencode(perimeter_vpc_ids)}"))


def _sample(tpl):
    """Template with realistic deploy-time values, for size checks."""
    return (tpl.replace("${partition}", "aws-us-gov").replace("${org_id}", "o-abcdefghij")
               .replace("${jsonencode(perimeter_cidrs)}", '["10.0.0.0/8","172.16.0.0/12"]')
               .replace("${jsonencode(perimeter_vpc_ids)}", '["vpc-0123456789abcdef0","vpc-0123456789abcdef1"]'))


def _docs(resolved, model_ids):
    out = {}
    for pack in resolved["policies"]["scps"] + resolved["policies"]["rcps"]:
        if pack not in RENDERERS:
            raise SystemExit("policy library: no statements defined for pack " + repr(pack))
        fn = RENDERERS[pack]
        out[pack] = fn(resolved, model_ids) if pack == "bre-scp-07-model-allowlist" else fn(resolved)
    return out


def render(resolved, model_ids=None):
    """pack id -> minified JSON policy template (templatefile syntax)."""
    out = {}
    for pack, doc in _docs(resolved, model_ids).items():
        tpl = _template(doc)
        if len(_sample(tpl)) > SCP_MAX_CHARS:
            raise SystemExit("policy library: %s renders to %d chars (> %d limit)" % (pack, len(_sample(tpl)), SCP_MAX_CHARS))
        out[pack] = tpl
    return out


def bundles(resolved, model_ids=None):
    """Packs bin-packed into attachable policy documents (<= MAX_ATTACHED per type, each
    <= SCP_MAX_CHARS). Packs needing the same deploy-time inputs share bundles, so a missing
    input never blocks unrelated packs. -> [{name, type, packs, needs, template}]"""
    docs = _docs(resolved, model_ids)
    result = []
    for ptype, packs in (("SERVICE_CONTROL_POLICY", resolved["policies"]["scps"]),
                         ("RESOURCE_CONTROL_POLICY", resolved["policies"]["rcps"])):
        groups = {}
        for pack in packs:
            groups.setdefault(tuple(NEEDS.get(pack, [])), []).append(pack)
        bins = []
        for needs, members in groups.items():
            gbins = []
            for pack in sorted(members, key=lambda p: -len(_template(docs[p]))):
                for b in gbins:
                    trial = _doc(*(b["statements"] + docs[pack]["Statement"]))
                    if len(_sample(_template(trial))) <= SCP_MAX_CHARS:
                        b["statements"] += docs[pack]["Statement"]; b["packs"].append(pack)
                        break
                else:
                    if len(_sample(_template(docs[pack]))) > SCP_MAX_CHARS:
                        raise SystemExit("policy library: %s alone exceeds %d chars" % (pack, SCP_MAX_CHARS))
                    gbins.append({"statements": list(docs[pack]["Statement"]), "packs": [pack], "needs": list(needs)})
            bins += gbins
        if len(bins) > MAX_ATTACHED:
            raise SystemExit("policy library: %d %s documents needed; AWS allows %d attached per target "
                             "besides the AWS-managed full-access policy" % (len(bins), ptype, MAX_ATTACHED))
        prefix = "scp" if ptype == "SERVICE_CONTROL_POLICY" else "rcp"
        for n, b in enumerate(bins, 1):
            result.append({"name": "sgea-%s-%d" % (prefix, n), "type": ptype, "packs": sorted(b["packs"]),
                           "needs": b["needs"], "template": _template(_doc(*b["statements"]))})
    return result
