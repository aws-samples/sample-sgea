# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Day-2 operations runbook and continuous-monitoring evidence calendar for ONE resolved profile.

Written to <out>/<profile-id>/OPERATIONS.md by `sgea export`, next to MANUAL-STEPS.md. Like manual_steps.py,
every value that varies by profile (retention, backup schedule / retention, the alarms emitted, token control,
AgentCore, Aurora, Inspector, baselines, partition, regions) is derived from the resolved config, the composed
packs' parameters (catalog/<baseline>.json), derived.py and the rule-disposition register, never hard-coded.
"""
import json, os

try:
    from .derived import (account_baseline, backup_policy, catalog_rules, conformance_pack_files,
                          log_retention_days, policy_engine_available, replica_region)
    from . import manual_steps
except ImportError:  # in-repo fallback import (sgea._load_emitters)
    from derived import (account_baseline, backup_policy, catalog_rules, conformance_pack_files,
                         log_retention_days, policy_engine_available, replica_region)
    import manual_steps

# AWS Backup plan rule the emitters write (modules/enclave-backup aws_backup_plan, CDK EnclaveBackup 'daily'):
# satisfies backup-plan-min-frequency-and-min-retention-check requiredFrequencyValue = 1 day.
BACKUP_SCHEDULE = "cron(0 5 * * ? *)"

# Static runbooks (docs/operations/) the generated runbook points to.
STATIC_DOCS = [
    ("Incident response", "docs/operations/incident-response.md"),
    ("Key and secret management", "docs/operations/key-and-secret-management.md"),
    ("Change and upgrade", "docs/operations/change-and-upgrade.md"),
    ("Tenant onboarding", "docs/operations/tenant-onboarding.md"),
    ("Decommissioning", "docs/operations/decommissioning.md"),
    ("Access review", "docs/operations/access-review.md"),
]

# Cadence for the "process" rule dispositions (sources/inferred/rule-dispositions.yaml carries no cadence).
PROCESS_CADENCE = {
    "annual-risk-assessment-performed": "Annually",
    "response-plan-tested": "Annually (and after a major change)",
    "vuln-management-plan-exists": "Annually (plan review)",
}
PROCESS_CADENCE_DEFAULT = "As set in the SSP"

FEDRAMP = ("fedramp-low", "fedramp-moderate", "fedramp-high")
DOD = ("dod-il2", "dod-il4", "dod-il5")


def has_aurora(resolved):
    """The emitters create the Aurora cluster when it is the vector store (and the service is allowed)."""
    return (resolved.get("vector_store") == "aurora-postgresql"
            and "aurora-postgresql" in resolved["services"]["allow"])


def alarms(resolved, root):
    """CloudWatch alarms the emitters create on the security-alarm topic (same conditions as Terraform / CDK).

    Returns (name, metric, fires when, what it means) with `<env>` for the deploy's env name."""
    agentcore = "bedrock-agentcore" in resolved["services"]["allow"]
    tc = bool(resolved.get("token_control", {}).get("enabled"))
    tool_path = "gateway_tool_path" in resolved["guardrails"].get("levels", [])
    interceptor = agentcore and (tc or (tool_path and not policy_engine_available(resolved, root)))
    meter = tc and bool(resolved["logging"].get("model_invocation_logging"))
    out = []
    if interceptor:
        out.append(("sgea-<env>-tool-policy-errors", "`AWS/Lambda` `Errors`, FunctionName `sgea-<env>-tool-policy`",
                    "Sum > 0 over 5 min", "Gateway interceptor failing: tool calls%s fail closed (denied)." % (
                        " and token budgets" if tc else "")))
    if meter:
        out.append(("sgea-<env>-token-meter-errors", "`AWS/Lambda` `Errors`, FunctionName `sgea-<env>-token-meter`",
                    "Sum > 0 over 5 min", "Token meter failing: usage stops being credited to the ledger."))
        out.append(("sgea-<env>-token-meter-silent", "`AWS/Lambda` `Invocations`, FunctionName `sgea-<env>-token-meter`",
                    "Sum < 1 for 2 x 15 min (missing data = breaching)",
                    "Meter heartbeat stopped; after `fail_closed_hours` (%s h) the interceptor denies every tool call." % (
                        resolved["token_control"].get("fail_closed_hours", 4))))
    return out


def _functions(resolved, root):
    """Enclave Lambda functions and their dead-letter queues, matching the alarm conditions."""
    names = {a[0] for a in alarms(resolved, root)}
    out = []
    if "sgea-<env>-tool-policy-errors" in names:
        out.append("sgea-<env>-tool-policy")
    if "sgea-<env>-token-meter-errors" in names:
        out.append("sgea-<env>-token-meter")
    return out


def _restore_targets(resolved):
    """Data stores in the enclave backup selection that a quarterly restore test covers."""
    out = []
    if has_aurora(resolved):
        out.append(("Aurora PostgreSQL cluster", "`sgea-<env>-vector`", "rds",
                    "a new cluster (`DBClusterIdentifier` = `sgea-<env>-vector-restore-test`, same subnet group / "
                    "security groups, enclave CMK) and one instance; connect and confirm the pgvector extension and "
                    "knowledge-base table row counts"))
    out.append(("Token ledger (DynamoDB)", "`sgea-token-usage-<env>`", "dynamodb",
                "a new table (`TargetTableName` = `sgea-token-usage-<env>-restore-test`); compare item counts and a "
                "sample of `user#` / `team#` items with the source"))
    return out


def _baselines_with_rule(resolved, root, rule):
    """The profile's baselines whose composed packs contain `rule`."""
    out = []
    for b in resolved["baselines"]:
        cat = json.load(open(os.path.join(root or ".", "catalog", b + ".json")))
        if any(r["config_rule"] == rule for lst in cat["services"].values() for r in lst):
            out.append(b)
    return out


def _conmon_rows(resolved, root, packs, engines, inspector_on):
    """(cadence, evidence, how to collect, baselines) rows for the profile's baselines only."""
    base = resolved["baselines"]
    src = resolved.get("_generated", {}).get("source_profile", "<profile>.json")
    pid = resolved["profile"]["id"]
    allb = ", ".join(base)
    scan = ("Amazon Inspector findings export (`aws inspector2 create-findings-report`) for %s" % "/".join(
        account_baseline(resolved, root)["inspector_resource_types"]) if inspector_on else
        "your vulnerability scanner's results (the composed packs do not require Amazon Inspector, so the enclave "
        "does not enable it; use the landing zone's scanner)")
    rows = [
        ("Monthly", "Conformance-pack results (%s)" % ", ".join("`%s`" % p for p in packs),
         "`aws configservice get-conformance-pack-compliance-summary` + `describe-conformance-pack-compliance` "
         "per pack, saved as JSON", allb),
        ("Monthly", "As-deployed configuration evidence",
         " / ".join("`python3 tools/collect_evidence.py --profile profiles/%s --engine %s`" % (src, e) for e in engines)
         + " -> `docs/evidence/%s-<engine>.{md,json}` (read-only; account id redacted)" % pid, allb),
    ]
    fed = [b for b in base if b in FEDRAMP]
    if fed:
        rows += [
            ("Monthly", "FedRAMP ConMon: vulnerability scan results (OS / infrastructure, web, database, container)",
             scan, ", ".join(fed)),
            ("Monthly", "FedRAMP ConMon: POA&M update and inventory",
             "Open findings from the scans, Security Hub (NIST SP 800-53 Rev. 5 standard) and the pack results, "
             "with remediation dates; deviation requests for risk-accepted items", ", ".join(fed)),
            ("Annually", "FedRAMP annual assessment",
             "3PAO assessment, SSP and attachments update, contingency-plan test (CP-4)%s" % (
                 ", incident-response test (IR-3)" if any(b != "fedramp-low" for b in fed) else ""), ", ".join(fed)),
        ]
    dod = [b for b in base if b in DOD]
    if dod:
        hi = [b for b in dod if b in ("dod-il4", "dod-il5")]
        rows += [
            ("Monthly", "DoD CC SRG ConMon package (scan results + POA&M) to the authorizing official",
             scan + ("; same POA&M as the FedRAMP ConMon row" if fed else "; POA&M with remediation dates"), ", ".join(dod)),
            ("Annually", "DoD annual assessment / authorization review",
             "Updated SSP, control assessment results, SCCA boundary documentation" if hi else
             "Updated SSP and control assessment results", ", ".join(dod)),
        ]
        if hi:
            rows.append(("Quarterly", "SCCA / CSSP review",
                         "Confirm the mission owner's CSSP receives the enclave's GuardDuty / Security Hub findings and "
                         "the VDSS / VDMS logs; record the confirmation", ", ".join(hi)))
    if "hipaa" in base:
        rows += [
            ("Monthly", "HIPAA information-system activity review (45 CFR 164.308(a)(1)(ii)(D))",
             "Review CloudTrail and Bedrock model-invocation logs (`/sgea/<env>/cloudtrail`, "
             "`/sgea/<env>/bedrock/model-invocations`); record reviewer, date and follow-ups", "hipaa"),
            ("Annually", "HIPAA risk analysis and risk management update (164.308(a)(1)(ii)(A)-(B)) and periodic "
             "evaluation (164.308(a)(8))", "Signed risk analysis using this calendar's evidence; BAA still in effect",
             "hipaa"),
        ]
    if "hitrust" in base:
        rows += [
            ("Quarterly", "HITRUST evidence upkeep",
             "Upload this quarter's pack results, restore test and access review to the assessment tool", "hitrust"),
            ("Annually", "HITRUST interim assessment / recertification",
             "r2: interim assessment at year 1, recertification every 2 years (e1 / i1: annual)", "hitrust"),
        ]
    if "fda-21-cfr-part-11" in base:
        rows += [
            ("Monthly", "Part 11 audit-trail review (21 CFR 11.10(e))",
             "Review the CloudTrail / invocation-log audit trail of record changes; confirm the log store's Object "
             "Lock retention (%d days) is intact" % resolved["logging"]["retention_days"], "fda-21-cfr-part-11"),
            ("Quarterly", "Part 11 access and signature-authority check (11.10(d), (g))",
             "Same as the access review, plus the list of users authorized to sign records", "fda-21-cfr-part-11"),
            ("Annually", "Part 11 periodic review of the validated state (11.10(a))",
             "Change log since the last validation, re-run of `sgea check` on the deployed plan / templates, "
             "revalidation decision", "fda-21-cfr-part-11"),
        ]
    rows += [("Quarterly", "Backup restore test record", "Section 3: %s" % " / ".join(
                 t[0] for t in _restore_targets(resolved)), allb),
             ("Quarterly", "Access review record", "docs/operations/access-review.md", allb)]
    for rule, why in manual_steps._dispositions(root, resolved, "process"):
        rows.append((PROCESS_CADENCE.get(rule, PROCESS_CADENCE_DEFAULT), "Process control `%s`" % rule, why,
                     ", ".join(_baselines_with_rule(resolved, root, rule))))
    order = {"Monthly": 0, "Quarterly": 1}
    return sorted(rows, key=lambda r: order.get(r[0], 2))


def render(resolved, root, targets):
    pid, part = resolved["profile"]["id"], resolved["partition"]
    primary, replica = resolved["regions"]["primary"], replica_region(resolved)
    base = resolved["baselines"]
    ab = account_baseline(resolved, root)
    bk = backup_policy(resolved, root)
    cw_days, s3_days = log_retention_days(resolved, root), resolved["logging"]["retention_days"]
    packs = sorted(conformance_pack_files(resolved))
    tc = resolved.get("token_control", {})
    agentcore = "bedrock-agentcore" in resolved["services"]["allow"]
    inspector_on = bool(ab["inspector_resource_types"])
    al = alarms(resolved, root)
    fns = _functions(resolved, root)
    rg = "--region %s" % primary
    arn = lambda svc, res: "arn:%s:%s:%s:<account>:%s" % (part, svc, primary, res)
    freq = catalog_rules(resolved, root).get("backup-plan-min-frequency-and-min-retention-check") or {}
    engines = [t for t in targets if t in ("terraform", "cdk")] or ["terraform"]

    out = ["# Operations — %s" % pid, "",
           "Generated by `sgea export` from the resolved profile, the composed conformance packs and "
           "`sources/inferred/rule-dispositions.yaml`. Day-2 runbook and continuous-monitoring evidence calendar for "
           "the deployed enclave. `<env>` is the env name you deployed with (Terraform `var.env`, CDK `-c sgea:env`), "
           "`<account>` the enclave account. Commands are read-only unless marked.", "",
           "Partition `%s` · primary region `%s` · log replica region `%s` · baselines: %s" % (
               part, primary, replica, ", ".join(base)), "",
           "| Fact | Value (from this profile) |", "|---|---|",
           "| CloudWatch log retention | %d days (`logging.retention_days` %d%s) |" % (
               cw_days, s3_days, ", raised to the pack minimum / a CloudWatch value" if cw_days != s3_days else ""),
           "| Log store (S3) retention | %d days%s, replicated to `%s` |" % (
               s3_days, ", Object Lock" if resolved["logging"].get("most_sensitive_store") else "", replica),
           "| AWS Backup | vault / plan `sgea-<env>`, `%s` (pack minimum: every %s %s), retention %d days%s |" % (
               BACKUP_SCHEDULE, freq.get("requiredFrequencyValue", "1"), freq.get("requiredFrequencyUnit", "days"),
               bk["retention_days"], ", vault lock on" if bk["vault_lock"] else ""),
           "| Conformance packs | %s |" % ", ".join("`%s`" % p for p in packs),
           "| AgentCore | %s |" % ("deployed (gateway `sgea-<env>-gateway`)" if agentcore else "not in this profile"),
           "| Aurora PostgreSQL vector store | %s |" % ("`sgea-<env>-vector`" if has_aurora(resolved) else "not in this profile"),
           "| Token control | %s |" % ("on: %s tokens / user / day, %s tokens / team / month, fail closed after %s h (%s)" % (
               "{:,}".format(tc.get("per_user_daily_tokens", 0)), "{:,}".format(tc.get("per_team_monthly_tokens", 0)),
               tc.get("fail_closed_hours", 4), tc.get("default_timezone", "UTC")) if tc.get("enabled") else "off"),
           ""]

    # ---------------- 1. daily / weekly ----------------
    out += ["## 1. Daily and weekly checks", "",
            "| Cadence | Check | Command / where | Healthy |", "|---|---|---|---|",
            "| Daily | Security alarms topic `sgea-<env>-security-alarms` has a confirmed subscription | "
            "`aws sns list-subscriptions-by-topic --topic-arn %s %s` | at least one confirmed endpoint (not "
            "`PendingConfirmation`) |" % (arn("sns", "sgea-<env>-security-alarms"), rg)]
    if al:
        out.append("| Daily | Enclave alarms (below) not in ALARM | `aws cloudwatch describe-alarms --alarm-names %s "
                   "--state-value ALARM %s` | empty |" % (" ".join(a[0] for a in al), rg))
    out.append("| Daily | Log-store events topic `sgea-<env>-log-store-events` (`s3:ObjectRemoved:*` on the log "
               "store, Config store and access-log sink) | subscribe the security team; any message is a deletion "
               "there "
               "and must match a lifecycle expiry or an approved change | no unexplained removals |")
    out.append("| Daily | GuardDuty findings | `aws guardduty list-findings --detector-id $(aws guardduty list-detectors "
               "--query 'DetectorIds[0]' --output text %s) --finding-criteria "
               "'{\"Criterion\":{\"service.archived\":{\"Eq\":[\"false\"]}}}' %s` | no unarchived findings without a "
               "ticket |" % (rg, rg))
    out.append("| Daily | Security Hub findings (NIST SP 800-53 Rev. 5 standard) | `aws securityhub get-findings "
               "--filters '{\"WorkflowStatus\":[{\"Value\":\"NEW\",\"Comparison\":\"EQUALS\"}],"
               "\"RecordState\":[{\"Value\":\"ACTIVE\",\"Comparison\":\"EQUALS\"}],"
               "\"SeverityLabel\":[{\"Value\":\"CRITICAL\",\"Comparison\":\"EQUALS\"},"
               "{\"Value\":\"HIGH\",\"Comparison\":\"EQUALS\"}]}' %s` | none untriaged |" % rg)
    if inspector_on:
        out.append("| Daily | Amazon Inspector findings (%s) | `aws inspector2 list-findings --filter-criteria "
                   "'{\"findingStatus\":[{\"comparison\":\"EQUALS\",\"value\":\"ACTIVE\"}],"
                   "\"severity\":[{\"comparison\":\"EQUALS\",\"value\":\"CRITICAL\"}]}' %s` | none untriaged |" % (
                       ", ".join(ab["inspector_resource_types"]), rg))
    out.append("| Daily | AWS Backup jobs (vault `sgea-<env>`) | `aws backup list-backup-jobs --by-backup-vault-name "
               "sgea-<env> --by-state FAILED --by-created-after <yesterday> %s` (also `ABORTED`, `EXPIRED`) | empty; "
               "one `COMPLETED` job per protected resource per day |" % rg)
    for f in fns:
        out.append("| Daily | Dead-letter queue `%s-dlq` | `aws sqs get-queue-attributes --queue-url $(aws sqs "
                   "get-queue-url --queue-name %s-dlq --query QueueUrl --output text %s) --attribute-names "
                   "ApproximateNumberOfMessages %s` | 0 |" % (f, f, rg, rg))
    for p in packs:
        out.append("| Weekly | Conformance pack `%s` | `aws configservice describe-conformance-pack-compliance "
                   "--conformance-pack-name %s --filters ComplianceType=NON_COMPLIANT %s` | no rule NON_COMPLIANT "
                   "beyond the known findings / runtime-only rules in MANUAL-STEPS.md |" % (p, p, rg))
    out.append("")
    out += ["GuardDuty, Security Hub and Inspector are created by the enclave only where `create_guardduty` / "
            "`create_securityhub` / `create_inspector` (CDK `createGuardDuty` / `createSecurityHub` / "
            "`createInspector`) are `true`; where the landing zone owns them (MANUAL-STEPS.md section 2), run these "
            "checks in the delegated-administrator account instead.%s" % (
                "" if inspector_on else " The composed packs require no Amazon Inspector scan type, so this profile "
                "does not enable Inspector."), ""]
    if al:
        out += ["### Alarms emitted for this profile", "",
                "All publish to `sgea-<env>-security-alarms`%s." % (
                    " (ALARM and INSUFFICIENT_DATA, `cloudwatch-alarm-action-check`)"
                    if ab["alarm_insufficient_data_action"] else " (ALARM)"), "",
                "| Alarm | Metric | Fires when | Meaning / first action |", "|---|---|---|---|"] + \
               ["| `%s` | %s | %s | %s |" % a for a in al] + \
               ["", "First action for any of them: the function's log group `/aws/lambda/<function>` and its "
                "dead-letter queue; see docs/operations/incident-response.md.", ""]
    else:
        out += ["This profile emits no CloudWatch alarms (no gateway interceptor or token meter).", ""]

    # ---------------- 2. monthly ----------------
    out += ["## 2. Monthly", ""]
    n = 1
    if tc.get("enabled"):
        out += ["%d. **Token budgets.** Ledger `sgea-token-usage-<env>` (items `pk=user#<id>` / `sk=day#YYYY-MM-DD`, "
                "`pk=team#<id>` / `sk=month#YYYY-MM`, attribute `tokens`). Compare each team's month against "
                "%s tokens and the top users' days against %s tokens; raise or lower `token_control` in the profile "
                "and re-export (docs/operations/change-and-upgrade.md). Confirm the heartbeat item (`pk=meter`, "
                "`sk=heartbeat`) is recent:" % (n, "{:,}".format(tc.get("per_team_monthly_tokens", 0)),
                                                "{:,}".format(tc.get("per_user_daily_tokens", 0))), "",
                "   ```bash",
                "   aws dynamodb get-item --table-name sgea-token-usage-<env> --key '{\"pk\":{\"S\":\"meter\"},\"sk\":{\"S\":\"heartbeat\"}}' %s" % rg,
                "   aws dynamodb query --table-name sgea-token-usage-<env> --key-condition-expression 'pk = :p AND sk = :s' \\",
                "       --expression-attribute-values '{\":p\":{\"S\":\"team#<team>\"},\":s\":{\"S\":\"month#<YYYY-MM>\"}}' %s" % rg,
                "   ```", ""]
        if not agentcore:
            out += ["   Budgets are metered but **not enforced** in this profile (no AgentCore gateway interceptor).", ""]
        n += 1
    quota = manual_steps.lambda_quota_need(resolved, root)
    if quota:
        need, qfns, per = quota
        out += ["%d. **Lambda concurrency headroom** in `%s`. The enclave reserves %d per function for %s "
                "(`lambda-concurrency-check`), so the account quota must stay at least **%d** (MANUAL-STEPS.md "
                "section 1) and tenant functions need their own headroom on top:" % (
                    n, primary, per, ", ".join(qfns), need), "",
                "   ```bash",
                "   aws service-quotas get-service-quota --service-code lambda --quota-code %s %s" % (manual_steps.LAMBDA_QUOTA_CODE, rg),
                "   aws lambda get-account-settings %s   # AccountLimit.ConcurrentExecutions / UnreservedConcurrentExecutions" % rg,
                "   ```", "",
                "   Act when `UnreservedConcurrentExecutions` approaches %d (Lambda's floor) or tenant throttles appear "
                "(`AWS/Lambda` `Throttles`)." % manual_steps.LAMBDA_UNRESERVED_MIN, ""]
        n += 1
    lines = manual_steps.cost_estimate(resolved)
    floor = sum(v for _, v in lines)
    out += ["%d. **Cost vs estimate.** MANUAL-STEPS.md puts the enclave's fixed floor at **USD %.2f / month** (list "
            "prices %s; %s). Compare with the month's actual cost of resources tagged `sgea:profile = %s` (activate "
            "it as a cost allocation tag first):" % (
                n, floor, manual_steps.PRICE_DATE, "; ".join("%s %.2f" % (k, v) for k, v in lines), pid), "",
            "   ```bash",
            "   aws ce get-cost-and-usage --time-period Start=<YYYY-MM-01>,End=<next-YYYY-MM-01> --granularity MONTHLY \\",
            "       --metrics UnblendedCost --group-by Type=DIMENSION,Key=SERVICE \\",
            "       --filter '{\"Tags\":{\"Key\":\"sgea:profile\",\"Values\":[\"%s\"]}}'" % pid,
            "   ```", "",
            "   " + ("GovCloud (US) usage is billed to the linked commercial account: run Cost Explorer there. "
                     if part == "aws-us-gov" else "") +
            "Usage-priced lines (Bedrock, AgentCore, Config evaluations, data events, log ingestion) come on top of "
            "the floor; untagged usage (e.g. Config, GuardDuty) does not appear in the tag filter.", ""]
    n += 1
    out += ["%d. **Log retention.** Every enclave log group keeps **%d days**; the log store keeps %d days%s:" % (
                n, cw_days, s3_days, " under Object Lock" if resolved["logging"].get("most_sensitive_store") else ""), "",
            "   ```bash",
            "   for p in /sgea/<env>/ /aws/lambda/sgea-<env>-; do",
            "     aws logs describe-log-groups --log-group-name-prefix $p %s \\" % rg,
            "         --query 'logGroups[?retentionInDays!=`%d`].[logGroupName,retentionInDays]' --output text" % cw_days,
            "   done   # expect no output",
            "   aws s3api get-object-lock-configuration --bucket sgea-<env>-logs-<account>-%s" % primary,
            "   ```", "",
            "   A shorter value fails `cw-loggroup-retention-period-check`; fix it in IaC, not the console.", ""]

    # ---------------- 3. quarterly ----------------
    out += ["## 3. Quarterly", "",
            "### Backup restore test (evidence)", "",
            "Restore the latest recovery point from vault `sgea-<env>` into a **new** resource (never over the source), "
            "validate it, record the result, then remove only the restored copy. Role: `arn:%s:iam::<account>:role/"
            "sgea-<env>-backup`. AWS Backup restore testing (`aws backup create-restore-testing-plan`) can automate this." % part, "",
            "| Data store | Source | Restore into and validate |", "|---|---|---|"] + \
           ["| %s | %s | %s |" % (name, src, how) for name, src, _, how in _restore_targets(resolved)] + \
           ["", "```bash",
            "aws backup list-recovery-points-by-backup-vault --backup-vault-name sgea-<env> --by-resource-arn <source-arn> %s" % rg,
            "aws backup get-recovery-point-restore-metadata --backup-vault-name sgea-<env> --recovery-point-arn <rp-arn> %s" % rg,
            "# WRITE: creates the restored copy",
            "aws backup start-restore-job --recovery-point-arn <rp-arn> --iam-role-arn arn:%s:iam::<account>:role/sgea-<env>-backup \\" % part,
            "    --metadata file://restore-metadata.json %s" % rg,
            "aws backup describe-restore-job --restore-job-id <id> %s" % rg,
            "```", "",
            "Evidence to keep: restore job id, recovery point date, start / completion time (achieved RTO), recovery "
            "point age (achieved RPO, schedule `%s`), validation result, operator and reviewer." % BACKUP_SCHEDULE, "",
            "### Guardrail block-rate review", "",
            "Review the baseline guardrail `sgea-<env>-baseline` for false positives: `AWS/Bedrock/Guardrails` "
            "`InvocationsIntervened` vs `Invocations` per policy type, and a sample of intervened requests in "
            "`/sgea/<env>/bedrock/model-invocations`. Content filters in this profile: %s." % ", ".join(
                "%s %s" % (k, v) for k, v in sorted(resolved["guardrails"].get("content_filters", {}).items()))]
    if resolved["guardrails"].get("content_filters", {}).get("PROMPT_ATTACK") == "HIGH":
        out += ["", "Known false positive: in sandbox validation (2026-10-21) the prompt-attack filter at HIGH strength "
                "blocked a benign prompt at LOW confidence. Tune with tenant-side prompt wording or a documented "
                "strength change in the profile, never by disabling the filter."]
    out += ["", "### Access review", "",
            "Follow docs/operations/access-review.md: IAM roles and policies in the enclave account, Identity Center "
            "assignments, AgentCore gateway JWT clients%s, KMS key policy grantees, and the security-alarm topic "
            "subscribers. Keep the signed review as evidence." % ("" if agentcore else " (n/a: no AgentCore)"), ""]

    # ---------------- 4. evidence calendar ----------------
    rows = _conmon_rows(resolved, root, packs, engines, inspector_on)
    out += ["## 4. Continuous-monitoring evidence calendar", "",
            "Rows for this profile's baselines only (%s; control catalogs: %s). Keep each item with its collection "
            "date in the evidence repository the assessor reads." % (
                ", ".join(base), ", ".join(resolved.get("evidence", {}).get("control_catalogs", [])) or "none"), "",
            "| Cadence | Evidence | How to collect | Baselines |", "|---|---|---|---|"] + \
           ["| %s | %s | %s | %s |" % r for r in rows] + [""]

    # ---------------- 5. related runbooks ----------------
    out += ["## 5. Related runbooks", ""] + ["- %s: `%s`" % d for d in STATIC_DOCS] + [""]
    return "\n".join(out)
