#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Collect as-deployed configuration evidence from a live SGEA sandbox (READ-ONLY: describe/get/list calls only).

For every enclave resource the profile deploys, records the observed setting, the value the resolved profile
expects (where SGEA decides it) and the framework controls it evidences (AWS Config rule names / SGEA control
IDs). Also records the live AWS Config conformance-pack compliance. Customer-facing: the account id is
redacted, and no secrets, prompts or log contents are read.

  python3 tools/collect_evidence.py --profile profiles/X.json --engine terraform|cdk [--env sbx] [--out docs/evidence]
Credentials: the ambient AWS credential chain (AWS_PROFILE / AWS_* environment variables / instance role); the
teardown runs it with the credentials it resolved. Needs a boto3 with bedrock-agentcore-control: $SGEA_BOTO
(default /tmp/sgea-boto, see tools/bootstrap_sdk.sh) is used first if it exists, else this interpreter's boto3;
exits if the service is unknown (the AgentCore evidence would silently be missing).
"""
import argparse, datetime, json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "emitters"))


IAM_ID = re.compile(r"\b(?:AKIA|ASIA|ANPA|ANVA|AROA|AIDA|AGPA|AIPA|APKA)[A-Z0-9]{16,17}\b")


class Evidence:
    def __init__(self, account):
        self.account, self.rows, self.errors = account, [], []

    def red(self, v):
        s = json.dumps(v, default=str) if not isinstance(v, str) else v
        # IAM unique ids (ANPA… policy, AROA… role, AIDA… user, AKIA/ASIA… keys) are account-specific: redacted too.
        return IAM_ID.sub("<iam-id>", s.replace(self.account, "<account>"))

    def add(self, area, resource, setting, observed, controls, expected=None):
        ok = None
        if expected is not None:
            ok = (str(observed).lower() == str(expected).lower()) if not callable(expected) else bool(expected(observed))
            expected = "(rule)" if callable(expected) else expected
        self.rows.append({"area": area, "resource": self.red(resource), "setting": self.red(setting),
                          "observed": self.red(observed), "expected": None if expected is None else self.red(expected),
                          "meets": ok, "controls": controls})

    def probe(self, area, fn):
        try:
            fn()
        except Exception as e:  # record, never abort the whole collection
            self.errors.append({"area": area, "error": "%s: %s" % (type(e).__name__, str(e)[:200].replace(self.account, "<account>"))})


def collect(profile, engine, env, session):
    import sgea, derived
    resolved, _ = sgea.resolve(profile)
    region = resolved["regions"]["primary"]
    replica = derived.replica_region(resolved)
    c = lambda svc, r=region: session.client(svc, region_name=r)
    acct = c("sts").get_caller_identity()["Account"]
    ev = Evidence(acct)
    ab = derived.account_baseline(resolved, ROOT)
    retention = derived.log_retention_days(resolved, ROOT)
    g = resolved["guardrails"]

    # ---------------- KMS ----------------
    def kms():
        k = c("kms")
        for page in k.get_paginator("list_keys").paginate():
            for key in page["Keys"]:
                m = k.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                if m["KeyManager"] != "CUSTOMER" or m["KeyState"] != "Enabled" or not m.get("Description", "").startswith("SGEA enclave CMK (%s)" % env):
                    continue
                ev.add("Encryption", "KMS " + m["Description"], "key rotation enabled",
                       k.get_key_rotation_status(KeyId=m["KeyId"])["KeyRotationEnabled"], ["kms-cmk-rotation-enabled", "SC-12", "SC-28"], True)
                ev.add("Encryption", "KMS " + m["Description"], "key spec / usage", "%s / %s" % (m["KeySpec"], m["KeyUsage"]), ["SC-13"])
                pol = json.loads(k.get_key_policy(KeyId=m["KeyId"], PolicyName="default")["Policy"])
                ev.add("Encryption", "KMS " + m["Description"], "key-policy statements", [s.get("Sid") for s in pol["Statement"]], ["SC-12", "AC-6"])
    ev.probe("KMS", kms)

    # ---------------- S3 stores ----------------
    def s3():
        for r in (region, replica):
            s = c("s3", r)
            for b in s.list_buckets()["Buckets"]:
                n = b["Name"]
                if not (n.startswith("sgea-%s-" % env) and n.endswith(r)):
                    continue
                enc = s.get_bucket_encryption(Bucket=n)["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]
                ev.add("Log stores (S3)", n, "default encryption", enc["SSEAlgorithm"] + (" (CMK)" if enc.get("KMSMasterKeyID") else ""),
                       ["s3-default-encryption-kms", "s3-bucket-server-side-encryption-enabled", "SC-28"])
                ev.add("Log stores (S3)", n, "versioning", s.get_bucket_versioning(Bucket=n).get("Status"), ["s3-bucket-versioning-enabled", "CP-9"], "Enabled")
                pab = s.get_public_access_block(Bucket=n)["PublicAccessBlockConfiguration"]
                ev.add("Log stores (S3)", n, "block public access (all four)", all(pab.values()),
                       ["s3-bucket-level-public-access-prohibited", "s3-bucket-public-read-prohibited", "s3-bucket-public-write-prohibited", "AC-3"], True)
                try:
                    ol = s.get_object_lock_configuration(Bucket=n)["ObjectLockConfiguration"]
                    rule = ol.get("Rule", {}).get("DefaultRetention", {})
                    ev.add("Log stores (S3)", n, "Object Lock", "%s %s %s days" % (ol.get("ObjectLockEnabled"), rule.get("Mode"), rule.get("Days")),
                           ["s3-bucket-default-lock-enabled", "AU-9", "AU-11"])
                except s.exceptions.ClientError:
                    ev.add("Log stores (S3)", n, "Object Lock", "not enabled (by design for this bucket)", ["s3-bucket-default-lock-enabled"])
                lg = s.get_bucket_logging(Bucket=n).get("LoggingEnabled")
                ev.add("Log stores (S3)", n, "server access logging", bool(lg), ["s3-bucket-logging-enabled", "AU-2"])
                try:
                    pol = json.loads(s.get_bucket_policy(Bucket=n)["Policy"])
                    tls = any(st.get("Effect") == "Deny" and "aws:SecureTransport" in json.dumps(st.get("Condition", {})) for st in pol["Statement"])
                    ev.add("Log stores (S3)", n, "TLS-only bucket policy", tls, ["s3-bucket-ssl-requests-only", "SC-8"], True)
                except s.exceptions.ClientError:
                    ev.add("Log stores (S3)", n, "TLS-only bucket policy", False, ["s3-bucket-ssl-requests-only"], True)
                try:
                    rep = s.get_bucket_replication(Bucket=n)["ReplicationConfiguration"]["Rules"]
                    ev.add("Log stores (S3)", n, "cross-region replication", [x["Status"] for x in rep], ["s3-bucket-replication-enabled", "CP-6"])
                except s.exceptions.ClientError:
                    pass
    ev.probe("S3", s3)

    # ---------------- CloudTrail ----------------
    def trail():
        ct = c("cloudtrail")
        for t in ct.describe_trails()["trailList"]:
            if not t["Name"].startswith("sgea-%s" % env):
                continue
            ev.add("Audit logging", "CloudTrail " + t["Name"], "multi-region", t["IsMultiRegionTrail"], ["multi-region-cloudtrail-enabled", "cloudtrail-security-trail-enabled", "AU-2"], True)
            ev.add("Audit logging", "CloudTrail " + t["Name"], "log file validation", t["LogFileValidationEnabled"], ["cloud-trail-log-file-validation-enabled", "AU-9"], True)
            ev.add("Audit logging", "CloudTrail " + t["Name"], "KMS encrypted", bool(t.get("KmsKeyId")), ["cloud-trail-encryption-enabled", "AU-9"], True)
            ev.add("Audit logging", "CloudTrail " + t["Name"], "CloudWatch Logs delivery", bool(t.get("CloudWatchLogsLogGroupArn")), ["cloud-trail-cloud-watch-logs-enabled", "AU-6"], True)
            ev.add("Audit logging", "CloudTrail " + t["Name"], "logging", ct.get_trail_status(Name=t["TrailARN"])["IsLogging"], ["cloudtrail-enabled"], True)
            sel = ct.get_event_selectors(TrailName=t["TrailARN"]).get("AdvancedEventSelectors") or []
            types = sorted({f["Equals"][0] for s_ in sel for f in s_["FieldSelectors"] if f["Field"] == "resources.type" and f.get("Equals")})
            ev.add("Audit logging", "CloudTrail " + t["Name"], "data-event resource types", types, ["SGEA-BR-02", "SGEA-AC-LOG-01", "AU-12"])
    ev.probe("CloudTrail", trail)

    # ---------------- CloudWatch log groups + Bedrock invocation logging ----------------
    def logs():
        lg = c("logs")
        for prefix in ("/sgea/%s/" % env, "/aws/lambda/sgea-%s-" % env, "/aws/bedrock-agentcore/runtimes/"):
            for page in lg.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=prefix):
                for grp in page["logGroups"]:
                    ev.add("Audit logging", "log group " + grp["logGroupName"], "retention days / KMS",
                           "%s / %s" % (grp.get("retentionInDays"), "CMK" if grp.get("kmsKeyId") else "none"),
                           ["cw-loggroup-retention-period-check", "cloudwatch-log-group-encrypted", "AU-11"],
                           lambda v: v.startswith(str(retention)) and v.endswith("CMK"))
        cfg = c("bedrock").get_model_invocation_logging_configuration().get("loggingConfig") or {}
        ev.add("Audit logging", "Bedrock model-invocation logging", "S3 + CloudWatch delivery",
               "s3=%s cloudwatch=%s text=%s" % (bool(cfg.get("s3Config")), bool(cfg.get("cloudWatchConfig")), cfg.get("textDataDeliveryEnabled")),
               ["SGEA-BR-01", "AU-2", "AU-12"], "s3=True cloudwatch=True text=True" if resolved["logging"].get("model_invocation_logging") else None)
    ev.probe("Logs", logs)

    # ---------------- Bedrock guardrail ----------------
    def guardrail():
        b = c("bedrock")
        gl = [x for x in b.list_guardrails()["guardrails"] if x["name"] == "sgea-%s-baseline" % env]
        if not gl:
            return
        gid = gl[0]["id"]
        d = b.get_guardrail(guardrailIdentifier=gid)
        name = "guardrail sgea-%s-baseline" % env
        for f in d["contentPolicy"]["filters"]:
            ev.add("Guardrails", name, "content filter %s (input/output)" % f["type"], "%s / %s" % (f["inputStrength"], f["outputStrength"]),
                   ["SGEA guardrails.content_filters", "SI-10", "SI-4"], (g["content_filters"].get(f["type"]) or "") + " / " +
                   ("NONE" if f["type"] == "PROMPT_ATTACK" else g["content_filters"].get(f["type"], "")))
        pii = {e["type"]: e["action"] for e in (d.get("sensitiveInformationPolicy") or {}).get("piiEntities", [])}
        ev.add("Guardrails", name, "PII/PHI entities (count; actions)", "%d; %s" % (len(pii), sorted(set(pii.values()))), ["SC-28", "HIPAA 164.312", "SGEA guardrails.pii"])
        for t in ("US_SOCIAL_SECURITY_NUMBER", "CREDIT_DEBIT_CARD_NUMBER", "ADDRESS", "NAME"):
            if t in pii:
                ev.add("Guardrails", name, "PII %s action" % t, pii[t], ["SGEA guardrails.pii"],
                       g["pii"].get("contextual_action", g["pii"]["action"]) if t in ("ADDRESS", "NAME") else g["pii"]["action"])
        ev.add("Guardrails", name, "KMS encrypted", bool(d.get("kmsKeyArn")), ["SGEA-BR-04"], True)
        ev.add("Guardrails", name, "content tier", (d.get("contentPolicy", {}).get("tier") or {}).get("tierName"), ["SGEA guardrails.tier"])
        enf = b.list_enforced_guardrails_configuration().get("guardrailsConfig", [])
        mine = [x for x in enf if x.get("guardrailId") == gid]
        ev.add("Guardrails", "account-enforced guardrail", "enforced on every invocation", bool(mine), ["SGEA-BR-03"],
               "L2_account_baseline" in g.get("levels", []))
        if mine:
            ev.add("Guardrails", "account-enforced guardrail", "version", mine[0].get("guardrailVersion"), ["SGEA-BR-03"])
    ev.probe("Guardrail", guardrail)

    # ---------------- AgentCore ----------------
    def agentcore():
        if "bedrock-agentcore" not in resolved["services"]["allow"]:
            return
        ac = c("bedrock-agentcore-control")
        for gw in ac.list_gateways().get("items", []):
            if gw["name"] != "sgea-%s-gateway" % env:
                continue
            d = ac.get_gateway(gatewayIdentifier=gw["gatewayId"])
            ev.add("AgentCore", "gateway " + gw["name"], "authorizer", d.get("authorizerType"), ["SGEA-AC-GW-01", "IA-2"])
            ev.add("AgentCore", "gateway " + gw["name"], "KMS encrypted", bool(d.get("kmsKeyArn")), ["SGEA-AC-GW-02"], True)
            pe = d.get("policyEngineConfiguration") or {}
            ev.add("AgentCore", "gateway " + gw["name"], "policy engine mode", pe.get("mode") or "none", ["SGEA-AC-GW-03", "AC-3"])
            ics = d.get("interceptorConfigurations") or []
            ev.add("AgentCore", "gateway " + gw["name"], "REQUEST interceptor", bool(ics), ["SGEA-AC-GW-03", "SGEA-TC-01"],
                   bool(resolved["token_control"].get("enabled")) or None)
        for m in ac.list_memories().get("memories", []):
            if not m.get("id", "").startswith("sgea_%s_memory" % env):
                continue
            d = ac.get_memory(memoryId=m["id"])["memory"]
            ev.add("AgentCore", "memory " + m["id"].split("-")[0], "KMS encrypted / event expiry days",
                   "%s / %s" % (bool(d.get("encryptionKeyArn")), d.get("eventExpiryDuration")), ["SGEA-AC-MEM-01", "SGEA-AC-MEM-02"])
        tv = ac.get_token_vault().get("kmsConfiguration", {})
        ev.add("AgentCore", "token vault", "key type", tv.get("keyType"), ["SGEA-AC-ID-01", "SC-12"], "CustomerManagedKey")
        for rt in ac.list_agent_runtimes().get("agentRuntimes", []):
            d = ac.get_agent_runtime(agentRuntimeId=rt["agentRuntimeId"])
            nm = rt["agentRuntimeName"]
            ev.add("AgentCore (tenant runtime)", "runtime " + nm, "network mode", d.get("networkConfiguration", {}).get("networkMode"), ["SGEA-AC-RT-01", "SC-7"], "VPC")
            ev.add("AgentCore (tenant runtime)", "runtime " + nm, "inbound authorizer",
                   "CUSTOM_JWT" if (d.get("authorizerConfiguration") or {}).get("customJWTAuthorizer") else "none", ["SGEA-AC-RT-04", "IA-2"], "CUSTOM_JWT")
            ev.add("AgentCore (tenant runtime)", "runtime " + nm, "idle session timeout (s)",
                   (d.get("lifecycleConfiguration") or {}).get("idleRuntimeSessionTimeout"), ["SGEA-AC-RT-06", "AC-12"], lambda v: v is not None and int(v) <= 900)
    ev.probe("AgentCore", agentcore)

    # ---------------- Network: VPC endpoints ----------------
    def endpoints():
        e = c("ec2")
        eps = e.describe_vpc_endpoints(Filters=[{"Name": "tag:Name", "Values": ["sgea-%s-*" % env]}])["VpcEndpoints"]
        if not eps:  # CDK endpoints carry no Name tag: match by the enclave's service list
            want = set(derived.endpoint_services(resolved))
            eps = [x for x in e.describe_vpc_endpoints()["VpcEndpoints"] if x["ServiceName"].split(".", 3)[-1] in want | {"s3", "dynamodb"}]
        for x in sorted(eps, key=lambda x: x["ServiceName"]):
            ev.add("Network", "VPC endpoint " + x["ServiceName"].split(".", 3)[-1], "type / private DNS / state",
                   "%s / %s / %s" % (x["VpcEndpointType"], x.get("PrivateDnsEnabled"), x["State"]), ["SGEA-BR-09", "SC-7"])
    ev.probe("Endpoints", endpoints)

    # ---------------- Aurora ----------------
    def aurora():
        r = c("rds")
        try:
            cl = r.describe_db_clusters(DBClusterIdentifier="sgea-%s-vector" % env)["DBClusters"][0]
        except r.exceptions.DBClusterNotFoundFault:
            return
        n = "Aurora sgea-%s-vector" % env
        for setting, val, ctl, exp in [
            ("storage encrypted (CMK)", cl["StorageEncrypted"] and bool(cl.get("KmsKeyId")), ["rds-storage-encrypted", "SC-28"], True),
            ("IAM database authentication", cl.get("IAMDatabaseAuthenticationEnabled"), ["IA-2"], True),
            ("deletion protection", cl["DeletionProtection"], ["rds-cluster-deletion-protection-enabled"], True),
            ("backup retention days", cl["BackupRetentionPeriod"], ["db-instance-backup-enabled", "CP-9"], None),
            ("instances (multi-AZ)", len(cl["DBClusterMembers"]), ["rds-cluster-multi-az-enabled", "CP-10"], lambda v: int(v) >= 2),
            ("log exports", cl.get("EnabledCloudwatchLogsExports"), ["rds-logging-enabled", "AU-2"], None),
            ("admin secret RDS-managed + CMK", bool((cl.get("MasterUserSecret") or {}).get("KmsKeyId")), ["secretsmanager-using-cmk", "secretsmanager-rotation-enabled-check"], True),
            ("engine version", cl["EngineVersion"], ["SI-2"], None)]:
            ev.add("Vector store (Aurora)", n, setting, val, ctl, exp)
        for m in cl["DBClusterMembers"]:
            i = r.describe_db_instances(DBInstanceIdentifier=m["DBInstanceIdentifier"])["DBInstances"][0]
            ev.add("Vector store (Aurora)", "instance " + i["DBInstanceIdentifier"], "publicly accessible / PI encrypted",
                   "%s / %s" % (i["PubliclyAccessible"], bool(i.get("PerformanceInsightsKMSKeyId"))), ["rds-instance-public-access-check", "SC-7"], "False / True")
        pg = cl["DBClusterParameterGroup"]
        ssl = [p for pg_ in r.get_paginator("describe_db_cluster_parameters").paginate(DBClusterParameterGroupName=pg)
               for p in pg_["Parameters"] if p["ParameterName"] == "rds.force_ssl"]
        ev.add("Vector store (Aurora)", n, "rds.force_ssl", ssl[0].get("ParameterValue") if ssl else None, ["SC-8"], "1")
    ev.probe("Aurora", aurora)

    # ---------------- DynamoDB ledger ----------------
    def ledger():
        d = c("dynamodb")
        name = "sgea-token-usage-%s" % env
        t = d.describe_table(TableName=name)["Table"]
        ev.add("Token control", "DynamoDB " + name, "SSE / billing / deletion protection",
               "%s / %s / %s" % (t.get("SSEDescription", {}).get("SSEType"), t.get("BillingModeSummary", {}).get("BillingMode"), t.get("DeletionProtectionEnabled")),
               ["dynamodb-table-encrypted-kms", "dynamodb-autoscaling-enabled"], "KMS / PAY_PER_REQUEST / True")
        p = d.describe_continuous_backups(TableName=name)["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"]
        ev.add("Token control", "DynamoDB " + name, "point-in-time recovery", p, ["dynamodb-pitr-enabled", "CP-9"], "ENABLED")
    ev.probe("Ledger", ledger)

    # ---------------- AWS Backup ----------------
    def backup():
        bk = c("backup")
        for v in bk.list_backup_vaults()["BackupVaultList"]:
            if v["BackupVaultName"] != "sgea-%s" % env:
                continue
            ev.add("Backup", "vault " + v["BackupVaultName"], "CMK encrypted / locked (min days)",
                   "%s / %s (%s)" % (bool(v.get("EncryptionKeyArn")), v.get("Locked"), v.get("MinRetentionDays")),
                   ["backup-recovery-point-encrypted", "backup-recovery-point-manual-deletion-disabled", "CP-9"])
        for pl in bk.list_backup_plans()["BackupPlansList"]:
            if pl["BackupPlanName"] != "sgea-%s" % env:
                continue
            rules = bk.get_backup_plan(BackupPlanId=pl["BackupPlanId"])["BackupPlan"]["Rules"]
            ev.add("Backup", "plan " + pl["BackupPlanName"], "schedule / retention days",
                   ["%s / %s" % (r_["ScheduleExpression"], r_.get("Lifecycle", {}).get("DeleteAfterDays")) for r_ in rules],
                   ["backup-plan-min-frequency-and-min-retention-check", "CP-9"])
            for sel in bk.list_backup_selections(BackupPlanId=pl["BackupPlanId"])["BackupSelectionsList"]:
                res = bk.get_backup_selection(BackupPlanId=pl["BackupPlanId"], SelectionId=sel["SelectionId"])["BackupSelection"]["Resources"]
                kinds = sorted({re.sub(r"^arn:[^:]+:([^:]+):.*$", r"\1", x) for x in res})
                ev.add("Backup", "selection " + sel["SelectionName"], "protected resource types", kinds,
                       ["aurora-/rds-resources-protected-by-backup-plan", "dynamodb-in-backup-plan", "s3-resources-protected-by-backup-plan"])
    ev.probe("Backup", backup)

    # ---------------- Lambda + IAM ----------------
    def functions():
        lm, iam = c("lambda"), c("iam")
        for page in lm.get_paginator("list_functions").paginate():
            for f in page["Functions"]:
                if not f["FunctionName"].startswith("sgea-%s-" % env):
                    continue
                tenant = f["FunctionName"].startswith("sgea-%s-sample" % env)
                area = "Tenant app (sample)" if tenant else "Enclave functions"
                n = "Lambda " + f["FunctionName"]
                conc = lm.get_function_concurrency(FunctionName=f["FunctionName"]).get("ReservedConcurrentExecutions")
                ev.add(area, n, "reserved concurrency", conc, ["lambda-concurrency-check", "SC-5"],
                       (lambda v, lo=ab["lambda_reserved_concurrency"]: v is not None and (lo is None or int(v) >= lo)))
                ev.add(area, n, "in VPC / DLQ / X-Ray / env KMS",
                       "%s / %s / %s / %s" % (bool(f.get("VpcConfig", {}).get("SubnetIds")), bool(f.get("DeadLetterConfig")),
                                             f.get("TracingConfig", {}).get("Mode"), bool(f.get("KMSKeyArn"))),
                       ["lambda-inside-vpc", "lambda-dlq-check"], "True / True / Active / True")
                role = f["Role"].split("/")[-1]
                ev.add(area, n, "execution role inline policies", len(iam.list_role_policies(RoleName=role)["PolicyNames"]),
                       ["iam-no-inline-policy-check"], 0)
        roles = [r_["RoleName"] for page in iam.get_paginator("list_roles").paginate() for r_ in page["Roles"]
                 if r_["RoleName"].startswith(("sgea-%s-" % env, "SgeaEnclave"))]
        for label, group in (("enclave", [r_ for r_ in roles if not r_.startswith("sgea-%s-sample" % env)]),
                             ("tenant (sample)", [r_ for r_ in roles if r_.startswith("sgea-%s-sample" % env)])):
            inl = {r_: iam.list_role_policies(RoleName=r_)["PolicyNames"] for r_ in group}
            bad = sorted("%s: %s" % (r_, ",".join(v)) for r_, v in inl.items() if v)
            ev.add("Identity", "%d %s IAM roles" % (len(group), label), "roles with inline policies", bad or "none",
                   ["iam-no-inline-policy-check", "AC-6"], "none")
    ev.probe("Lambda/IAM", functions)

    # ---------------- alarms ----------------
    def alarms():
        sns, cw = c("sns"), c("cloudwatch")
        for t in sns.list_topics()["Topics"]:
            if t["TopicArn"].endswith(":sgea-%s-security-alarms" % env):
                a = sns.get_topic_attributes(TopicArn=t["TopicArn"])["Attributes"]
                ev.add("Monitoring", "SNS sgea-%s-security-alarms" % env, "KMS encrypted", bool(a.get("KmsMasterKeyId")), ["sns-encrypted-kms", "SC-28"], True)
        for a in cw.describe_alarms(AlarmNamePrefix="sgea-%s-" % env)["MetricAlarms"]:
            ev.add("Monitoring", "alarm " + a["AlarmName"], "alarm / insufficient-data actions",
                   "%d / %d" % (len(a["AlarmActions"]), len(a["InsufficientDataActions"])), ["cloudwatch-alarm-action-check", "SI-4", "IR-6"],
                   lambda v: v.split(" / ")[0] != "0")
    ev.probe("Alarms", alarms)

    # ---------------- Config + detective services ----------------
    import fnmatch, yaml
    excs = (yaml.safe_load(open(os.path.join(ROOT, "sources", "inferred", "rule-dispositions.yaml"))) or {}).get("exceptions") or []
    rds_names, key_desc = {}, {}
    deployed_at = []   # this deployment's start: creation time of the live enclave CMK

    def deploy_time():
        k = c("kms")
        for page in k.get_paginator("list_keys").paginate():
            for key in page["Keys"]:
                m = k.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                if m["KeyState"] == "Enabled" and m.get("Description", "").startswith("SGEA enclave CMK (%s)" % env):
                    deployed_at.append(m["CreationDate"])
    ev.probe("Detective", deploy_time)

    def resolve_ids():
        r = c("rds")
        for cl in r.describe_db_clusters()["DBClusters"]:
            rds_names[cl["DbClusterResourceId"]] = cl["DBClusterIdentifier"]
        for i in r.describe_db_instances()["DBInstances"]:
            rds_names[i["DbiResourceId"]] = i["DBInstanceIdentifier"]
    ev.probe("Detective", resolve_ids)

    def detective():
        cfg = c("config")
        st = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
        ev.add("Detective controls", "AWS Config recorder", "recording", [x.get("recording") for x in st], ["CM-8", "CA-7"])
        for p in cfg.describe_conformance_packs().get("ConformancePackDetails", []):
            if not p["ConformancePackName"].startswith("sgea-"):
                continue
            rules = cfg.describe_conformance_pack_compliance(ConformancePackName=p["ConformancePackName"]).get("ConformancePackRuleComplianceList", [])
            cnt = {}
            for r_ in rules:
                cnt[r_["ComplianceType"]] = cnt.get(r_["ComplianceType"], 0) + 1
            nc = sorted(r_["ConfigRuleName"].split("-conformance-pack-")[0] for r_ in rules if r_["ComplianceType"] == "NON_COMPLIANT")
            ev.add("Detective controls", "conformance pack " + p["ConformancePackName"], "rule compliance (live, at collection time)",
                   "%s%s" % (json.dumps(cnt, sort_keys=True), ("; NON_COMPLIANT: " + ", ".join(nc)) if nc else ""), ["CA-2", "CA-7"])
            # Which resources Config flagged, and who owns them: enclave / tenant (sample) / CDK deploy helper /
            # other (pre-existing account resources outside the enclave, e.g. the landing zone).
            for r_ in rules:
                if r_["ComplianceType"] != "NON_COMPLIANT":
                    continue
                res, annotations, stale = [], {}, set()
                for page in cfg.get_paginator("get_compliance_details_by_config_rule").paginate(
                        ConfigRuleName=r_["ConfigRuleName"], ComplianceTypes=["NON_COMPLIANT"]):
                    for e in page["EvaluationResults"]:
                        q = e["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
                        res.append((q.get("ResourceType"), q.get("ResourceId")))
                        if e.get("Annotation"):
                            annotations[(q.get("ResourceId"))] = e["Annotation"][:160]
                        if deployed_at and e.get("ResultRecordedTime") and e["ResultRecordedTime"] < max(deployed_at):
                            stale.add(q.get("ResourceId"))
                def owner(rid):
                    rid = str(rds_names.get(rid, rid))
                    if rid not in key_desc and re.fullmatch(r"[0-9a-f-]{36}", rid):
                        try:
                            m_ = c("kms").describe_key(KeyId=rid)["KeyMetadata"]
                            key_desc[rid] = (m_.get("Description", ""), m_["KeyState"])
                        except Exception:
                            key_desc[rid] = ("", "")
                    if rid in key_desc and key_desc[rid][0].startswith("SGEA") and key_desc[rid][1] == "PendingDeletion":
                        return "sandbox-artifact"   # keys of earlier, torn-down sandbox runs (30-day deletion window)
                    if "sample" in rid:
                        return "tenant"
                    if "AWS679f53fac002430cb0da5b7982bd2287" in rid or "SingletonLambda" in rid or "BucketNotificationsHandler" in rid:
                        return "cdk-deploy-helper"
                    if "sgea" in rid.lower() or "SgeaEnclave" in rid:
                        return "enclave"
                    if re.search(r"\bsgea-%s-" % re.escape(env), annotations.get(rid, "")):
                        return "enclave"   # account-level result (resource = the account) naming an enclave resource
                    return "other"
                rule = r_["ConfigRuleName"].split("-conformance-pack-")[0]
                by = {}
                for t_, rid in res:
                    who, name = owner(rid), str(rds_names.get(rid, rid))
                    if rid in stale and who in ("enclave", "tenant"):
                        who += ", stale: evaluated before this deployment"
                    if who in ("enclave", "cdk-deploy-helper"):
                        why = next((x["reason"] for x in excs if x["rule"] == rule and x.get("owner", "enclave") == who
                                    and fnmatch.fnmatchcase(name, x["resource"].replace("<env>", env))), None)
                        if why:
                            ev.add("Detective controls (live findings)", "%s [%s, documented exception]" % (rule, who), name, "NON_COMPLIANT", [rule])
                            ev.rows[-1]["exception"] = why
                            continue
                    by.setdefault(who, []).append("%s %s%s" % (t_, name, (" (Config: %s)" % annotations[rid]) if rid in annotations else ""))
                for who, items in sorted(by.items()):
                    ev.add("Detective controls (live findings)", "%s [%s]" % (rule, who), "NON_COMPLIANT resources (%d)" % len(items),
                           "; ".join(sorted(items)[:8]) + (" ..." if len(items) > 8 else ""), [rule],
                           None if who in ("other", "cdk-deploy-helper", "sandbox-artifact") or "stale" in who else "none")
        gd = c("guardduty").list_detectors().get("DetectorIds", [])
        ev.add("Detective controls", "GuardDuty", "detector enabled", bool(gd), ["guardduty-enabled-centralized", "SI-4"])
        try:
            stds = [x["StandardsArn"].split("/standards/")[-1] for x in c("securityhub").get_enabled_standards()["StandardsSubscriptions"]]
            ev.add("Detective controls", "Security Hub", "enabled standards", stds, ["securityhub-enabled", "CA-7"])
        except Exception:
            ev.add("Detective controls", "Security Hub", "enabled standards", "not enabled", ["securityhub-enabled"])
        if ab["inspector_resource_types"]:
            s_ = c("inspector2").batch_get_account_status(accountIds=[acct])["accounts"][0]["resourceState"]
            ev.add("Detective controls", "Amazon Inspector", "scan status", {k: v.get("status") for k, v in s_.items()}, ["inspector-*-scan-enabled", "RA-5"])
    ev.probe("Detective", detective)

    # ---------------- account baseline ----------------
    def account():
        e = c("ec2")
        ev.add("Account baseline", "EC2 (region)", "EBS encryption by default", e.get_ebs_encryption_by_default()["EbsEncryptionByDefault"],
               ["ec2-ebs-encryption-by-default", "SC-28"], True if ab["ebs_encryption_by_default"] else None)
        ev.add("Account baseline", "EC2 (region)", "EBS snapshot public sharing", e.get_snapshot_block_public_access_state()["State"],
               ["ebs-snapshot-public-restorable-check", "AC-3"], "block-all-sharing" if ab["snapshot_block_public_access"] else None)
        pab = c("s3control").get_public_access_block(AccountId=acct)["PublicAccessBlockConfiguration"]
        ev.add("Account baseline", "S3 (account)", "Block Public Access (all four)", all(pab.values()),
               ["s3-account-level-public-access-blocks-periodic", "AC-3"], True if ab["s3_account_public_access_block"] else None)
        try:
            pp = c("iam").get_account_password_policy()["PasswordPolicy"]
            ev.add("Account baseline", "IAM password policy", "min length / reuse / max age",
                   "%s / %s / %s" % (pp.get("MinimumPasswordLength"), pp.get("PasswordReusePrevention"), pp.get("MaxPasswordAge")),
                   ["iam-password-policy", "IA-5"],
                   "%s / %s / %s" % tuple(ab["password_policy"][k] for k in ("minimum_password_length", "password_reuse_prevention", "max_password_age"))
                   if ab["password_policy"] else None)
        except Exception:
            ev.add("Account baseline", "IAM password policy", "min length / reuse / max age", "none", ["iam-password-policy"])
        lq = c("lambda").get_account_settings()["AccountLimit"]["ConcurrentExecutions"]
        ev.add("Account baseline", "Lambda (region)", "concurrent-executions quota", lq, ["lambda-concurrency-check (prerequisite)"])
        repo = c("ecr").describe_repositories(repositoryNames=["sgea-%s-agents" % env])["repositories"][0]
        ev.add("Supply chain", "ECR sgea-%s-agents" % env, "tag immutability / scan on push / KMS",
               "%s / %s / %s" % (repo["imageTagMutability"], repo["imageScanningConfiguration"]["scanOnPush"], repo["encryptionConfiguration"]["encryptionType"]),
               ["ecr-private-tag-immutability-enabled", "ecr-private-image-scanning-enabled", "SI-7"], "IMMUTABLE / True / KMS")
    ev.probe("Account", account)

    return resolved, ev


def render_md(resolved, engine, ev, when):
    rows = ev.rows
    fails = [r for r in rows if r["meets"] is False]
    out = ["# As-deployed configuration evidence — %s (%s)" % (resolved["profile"]["id"], "Terraform" if engine == "terraform" else "CloudFormation (CDK)"), "",
           "Observed %s by `tools/collect_evidence.py` (read-only describe/get calls) on the SGEA sandbox deployment, after the "
           "end-to-end test and before teardown. Baselines: %s. Partition `%s`, region `%s`. Account id redacted." % (
               when, ", ".join(resolved["baselines"]), resolved["partition"], resolved["regions"]["primary"]), "",
           "**%d settings observed; %d compared with the value the profile requires: %d meet it, %d do not.**" % (
               len(rows), sum(1 for r in rows if r["meets"] is not None), sum(1 for r in rows if r["meets"]), len(fails)), ""]
    if fails:
        out += ["## Deviations", "", "| Resource | Setting | Observed | Expected |", "|---|---|---|---|"] + \
               ["| %s | %s | %s | %s |" % (r["resource"], r["setting"], r["observed"], r["expected"]) for r in fails] + [""]
    area = None
    for r in rows:
        if r["area"] != area:
            area = r["area"]
            out += ["## " + area, "", "| Resource | Setting | Observed | Expected | Meets | Controls |", "|---|---|---|---|---|---|"]
        meets = "exception: " + r["exception"] if r.get("exception") else {True: "yes", False: "**no**", None: "—"}[r["meets"]]
        out.append("| %s | %s | %s | %s | %s | %s |" % (r["resource"], r["setting"], str(r["observed"]).replace("|", "/"),
                   "" if r["expected"] is None else r["expected"], meets, ", ".join(r["controls"])))
        if r is rows[-1] or rows[rows.index(r) + 1]["area"] != area:
            out.append("")
    if ev.errors:
        out += ["## Not collected", "", "| Area | Error |", "|---|---|"] + ["| %s | %s |" % (e["area"], e["error"]) for e in ev.errors] + [""]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True)
    ap.add_argument("--engine", choices=("terraform", "cdk"), required=True)
    ap.add_argument("--env", default="sbx")
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "evidence"))
    a = ap.parse_args(argv)
    sdk = os.environ.get("SGEA_BOTO") or "/tmp/sgea-boto"  # nosec B108 (operator's own SDK dir)
    if os.path.isdir(sdk) and sdk not in sys.path:
        sys.path.insert(0, sdk)
    import boto3, botocore
    if "bedrock-agentcore-control" not in boto3.session.Session().get_available_services():
        sys.exit("evidence: this boto3/botocore (%s) has no bedrock-agentcore-control; run tools/bootstrap_sdk.sh "
                 "or `python3 -m pip install --upgrade boto3`" % botocore.__version__)
    resolved, ev = collect(a.profile, a.engine, a.env, boto3.Session())
    when = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    os.makedirs(a.out, exist_ok=True)
    base = os.path.join(a.out, "%s-%s" % (resolved["profile"]["id"], a.engine))
    json.dump({"profile": resolved["profile"]["id"], "engine": a.engine, "collected_at": when, "baselines": resolved["baselines"],
               "observations": ev.rows, "not_collected": ev.errors}, open(base + ".json", "w"), indent=1)
    open(base + ".md", "w").write(render_md(resolved, a.engine, ev, when))
    print("evidence: %s.md (%d settings, %d deviations, %d not collected)" % (
        base, len(ev.rows), sum(1 for r in ev.rows if r["meets"] is False), len(ev.errors)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
