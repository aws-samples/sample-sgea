#!/usr/bin/env python3
"""
Tear down an SGEA sandbox deployment created by examples/run_sandbox_test.sh.

The enclave is built to resist deletion (that is the point of the controls), so a plain
`terraform destroy` fails. In order this script:
  1. destroys the sample tenant app
  2. lifts the enclave's deletion protections: Aurora cluster, DynamoDB ledger, Network Firewall,
     AWS Backup vault lock (+ deletes recovery points)
  3. empties the enclave's sgea-<env>-* buckets in both regions, bypassing Object Lock GOVERNANCE
     retention (versions + delete markers)
  4. destroys the enclave, then the sandbox network
With --cdk (enclave deployed by `run_sandbox_test.sh --cdk`): step 4 runs `cdk destroy`, then deletes
the resources the CDK app RETAINs (log groups, buckets, ECR repo, token ledger, Aurora, KMS keys) —
only names under the sandbox env prefix.

SANDBOX ONLY. It refuses to run unless the caller's account id equals --account-id, and asks
you to type the account id back. KMS keys enter their 30-day deletion window; Aurora leaves a
final snapshot (skip_final_snapshot = false).

usage: python3 tools/sandbox_teardown.py --account <credentials> --account-id 123456789012 \\
           [--profile profiles/fedramp-moderate-hipaa.commercial.json] [--env sbx] [--cdk] [--network] [--no-evidence]

SDK: needs a boto3/botocore with bedrock-agentcore-control (token-vault reset). If the directory
$SGEA_BOTO (default /tmp/sgea-boto, created by tools/bootstrap_sdk.sh) exists it is used first,
otherwise this interpreter's boto3; the script exits before touching anything if the service is missing.

<credentials> (also the first argument of examples/run_sandbox_test.sh and tools/sandbox_matrix.sh;
the region is always the profile's resolved primary region):
  an AWS CLI profile name   AWS_PROFILE=<name> (static AWS_* keys in the environment are dropped)
  env                       the ambient credential chain as-is (AWS_* environment variables, instance role)
"""
# subprocess calls in this file: argv lists, never a shell; arguments come from the operator (nosec / nosemgrep).
import argparse, configparser, json, os, shlex, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

STATIC_KEYS = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
CREDENTIALS_HELP = "credentials: an AWS CLI profile name or 'env' (ambient credential chain)"


# ---- credentials (shared with tools/sandbox_plan.py) ---------------------------------------------
def credential_mode(creds):
    """'env' (the literal value env) or 'profile' (anything else)."""
    if not creds or not creds.strip():
        raise SystemExit("no credentials given; " + CREDENTIALS_HELP)
    return "env" if creds == "env" else "profile"


def profile_region(name, environ=None):
    """The `region` of AWS CLI profile <name> in $AWS_CONFIG_FILE (default ~/.aws/config), or None."""
    environ = os.environ if environ is None else environ
    cfg = configparser.RawConfigParser()
    cfg.read(environ.get("AWS_CONFIG_FILE") or os.path.expanduser("~/.aws/config"))
    for sec in (("profile " + name, "default") if name == "default" else ("profile " + name,)):
        if cfg.has_section(sec) and cfg.get(sec, "region", fallback=None):
            return cfg.get(sec, "region")
    return None


def credential_env(creds, region=None, role="admin", environ=None, run=None, helper=None):
    """The environment (a new dict) the sandbox tools run with for <creds>. No AWS calls."""
    env = dict(os.environ if environ is None else environ)
    mode = credential_mode(creds)
    if mode == "profile":
        for k in STATIC_KEYS:   # static keys in the environment would take precedence over the profile
            env.pop(k, None)
        env["AWS_PROFILE"] = creds
        region = region or profile_region(creds, env)
    if region:
        env["AWS_REGION"] = env["AWS_DEFAULT_REGION"] = region
    return env


# ---- SDK -----------------------------------------------------------------------------------------
def use_sdk_dir(environ=None, path=sys.path):
    """Put $SGEA_BOTO (default /tmp/sgea-boto) first on sys.path if it exists; return it or None."""
    d = (os.environ if environ is None else environ).get("SGEA_BOTO") or "/tmp/sgea-boto"  # nosec B108 (operator's own SDK dir)
    if os.path.isdir(d):
        if d not in path:
            path.insert(0, d)
        return d
    return None


def require_agentcore_sdk(boto3, botocore, sdk_dir):
    if "bedrock-agentcore-control" not in boto3.session.Session().get_available_services():
        sys.exit("this boto3/botocore (%s, from %s) has no bedrock-agentcore-control. Install a current SDK: "
                 "tools/bootstrap_sdk.sh (into /tmp/sgea-boto, used automatically) or "
                 "`python3 -m pip install --upgrade boto3`" % (botocore.__version__, sdk_dir or os.path.dirname(os.path.dirname(botocore.__file__))))


def terraform(*args, check=True, cwd=None):
    print("+ terraform " + " ".join(args))
    return subprocess.run(["terraform", *args], check=check, cwd=cwd)  # nosec B603  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit


def npx(*args, check=True, cwd=None):
    print("+ npx " + " ".join(args))
    return subprocess.run(["npx", *args], check=check, cwd=cwd)  # nosec B603  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit


def cdk_destroy(a, acct, region, regions, state, empty_buckets):
    import boto3
    cdk = os.path.join(ROOT, "build", os.path.basename(state)[:-4], "cdk")
    npx("cdk", "destroy", "--all", "--force", "-c", "sgea:env=" + a.env, cwd=cdk)
    env = a.env
    empty_buckets()  # logging writes until the trail / Config / log delivery are gone
    for r in regions:
        logs = boto3.client("logs", region_name=r)
        for prefix in ("/sgea/%s/" % env, "/aws/lambda/sgea-%s-" % env, "/aws/bedrock-agentcore/",
                       "/aws/lambda/SgeaEnclave-"):   # CDK helper functions' default log groups (pre-DeployHelperLogs runs)
            for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=prefix):
                for g in page["logGroups"]:
                    if prefix.startswith("/aws/bedrock-agentcore") and "sgea_%s" % env not in g["logGroupName"]:
                        continue
                    print("delete log group " + g["logGroupName"]); logs.delete_log_group(logGroupName=g["logGroupName"])
        s3 = boto3.client("s3", region_name=r)
        for b in s3.list_buckets()["Buckets"]:
            n = b["Name"]
            if n.startswith("sgea-%s-" % env) and acct in n and n.endswith(r):
                print("delete bucket " + n); s3.delete_bucket(Bucket=n)
        # By description, not alias: `cdk destroy` deletes the aliases but RETAINs the keys.
        kms = boto3.client("kms", region_name=r)
        for page in kms.get_paginator("list_keys").paginate():
            for k in page["Keys"]:
                m = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                d = m.get("Description", "")
                if m["KeyManager"] == "CUSTOMER" and m["KeyState"] == "Enabled" and d.startswith("SGEA") and "(%s)" % env in d:
                    print("schedule key deletion (30 days) %s %s" % (m["KeyId"], d))
                    kms.schedule_key_deletion(KeyId=m["KeyId"], PendingWindowInDays=30)
    ecr = boto3.client("ecr", region_name=region)
    try:
        ecr.delete_repository(repositoryName="sgea-%s-agents" % env, force=True); print("delete ECR sgea-%s-agents" % env)
    except ecr.exceptions.RepositoryNotFoundException:
        pass
    bk = boto3.client("backup", region_name=region)
    vaults = [v["BackupVaultName"] for pg in bk.get_paginator("list_backup_vaults").paginate() for v in pg["BackupVaultList"]]
    if "sgea-%s" % env in vaults:  # RETAINed by the CDK app; recovery points / lock were removed in step 2
        for page in bk.get_paginator("list_recovery_points_by_backup_vault").paginate(BackupVaultName="sgea-%s" % env):
            for rp in page["RecoveryPoints"]:
                bk.delete_recovery_point(BackupVaultName="sgea-%s" % env, RecoveryPointArn=rp["RecoveryPointArn"])
        bk.delete_backup_vault(BackupVaultName="sgea-%s" % env); print("delete backup vault sgea-%s" % env)
    ddb = boto3.client("dynamodb", region_name=region)
    try:
        ddb.delete_table(TableName="sgea-token-usage-%s" % env); print("delete table sgea-token-usage-%s" % env)
    except ddb.exceptions.ResourceNotFoundException:
        pass
    rds = boto3.client("rds", region_name=region)
    try:
        cl = rds.describe_db_clusters(DBClusterIdentifier="sgea-%s-vector" % env)["DBClusters"][0]
        for m in cl["DBClusterMembers"]:
            rds.delete_db_instance(DBInstanceIdentifier=m["DBInstanceIdentifier"])
            rds.get_waiter("db_instance_deleted").wait(DBInstanceIdentifier=m["DBInstanceIdentifier"])
        rds.delete_db_cluster(DBClusterIdentifier=cl["DBClusterIdentifier"], SkipFinalSnapshot=False,
                              FinalDBSnapshotIdentifier="sgea-%s-vector-final" % env)
        print("delete Aurora sgea-%s-vector (final snapshot kept)" % env)
    except rds.exceptions.DBClusterNotFoundFault:
        pass


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--account", required=True, metavar="CREDENTIALS", help=CREDENTIALS_HELP)
    ap.add_argument("--account-id", required=True, help="12-digit id; must match the credentials")
    ap.add_argument("--profile", default="profiles/fedramp-moderate-hipaa.commercial.json")
    ap.add_argument("--env", default=os.environ.get("SGEA_ENV", "sbx"))
    ap.add_argument("--cdk", action="store_true", help="the enclave was deployed from the CDK app")
    ap.add_argument("--network", action="store_true", help="also destroy the shared sandbox network (.sandbox/_network)")
    ap.add_argument("--no-evidence", action="store_true", help="skip the as-deployed configuration evidence (tools/collect_evidence.py)")
    a = ap.parse_args(argv)

    import sgea
    resolved, _ = sgea.resolve(os.path.join(ROOT, a.profile))
    sys.path.insert(0, os.path.join(ROOT, "emitters"))
    import derived
    pid, region = resolved["profile"]["id"], resolved["regions"]["primary"]
    regions = [region, derived.replica_region(resolved)]
    state = os.path.join(ROOT, ".sandbox", pid + ("-cdk" if a.cdk else ""))
    tf = os.path.join(ROOT, "build", pid, "terraform")

    # SDK first: fail before any credentials, prompt or deletion if the token-vault reset (step 1b) is impossible.
    # A silent skip left the vault on a deleted key and broke the next deploy (sandbox 2026-10-21, an older
    # botocore in user site-packages).
    sdk_dir = use_sdk_dir()
    import boto3, botocore
    require_agentcore_sdk(boto3, botocore, sdk_dir)
    env = credential_env(a.account, region)
    os.environ.clear(); os.environ.update(env)   # boto3 below, terraform / cdk / collect_evidence.py (subprocesses)
    acct = boto3.client("sts", region_name=region).get_caller_identity()["Account"]
    if acct != a.account_id:
        sys.exit("refusing: credentials are for %s, not %s" % (acct, a.account_id))
    typed = input("Type the account id %s to DELETE the SGEA sandbox '%s' (%s): " % (acct, a.env, pid)).strip()
    if typed != acct:
        sys.exit("aborted")

    # 0. as-deployed configuration evidence, while the enclave and the tenant are still up (read-only)
    deployed = os.path.exists(os.path.join(state, "cdk-outputs.json" if a.cdk else "enclave.tfstate"))
    if deployed and not a.no_evidence:
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import collect_evidence   # in-process: the credentials are already in os.environ
        try:
            collect_evidence.main(["--profile", a.profile, "--engine", "cdk" if a.cdk else "terraform", "--env", a.env])
        except (Exception, SystemExit) as e:   # evidence is best-effort; the teardown continues
            print("evidence: not collected (%s: %s)" % (type(e).__name__, e))

    # 1. tenant app
    sample = os.path.join(state, "sample.tfstate")
    if os.path.exists(sample):
        infra = os.path.join(ROOT, "examples", "sample-agent", "infra")
        terraform("-chdir=" + infra, "init", "-input=false", "-reconfigure", "-backend-config=path=" + sample)
        args = ("-chdir=" + infra, "destroy", "-input=false", "-auto-approve",
                "-var-file=" + os.path.join(state, "sample.tfvars.json"))
        if terraform(*args, check=False).returncode:   # AgentCore runtime deletion can report NotStabilized once
            import time; time.sleep(60)
            terraform(*args)

    # 1b. the account-wide AgentCore token vault is encrypted with the enclave CMK: hand it back to the
    #     AWS-managed key BEFORE the CMK is scheduled for deletion, or the next enclave can never switch
    #     the vault (SetTokenVaultCMK must decrypt with the old key; sandbox 2026-10-15). SDK checked at the start.
    ac = boto3.client("bedrock-agentcore-control", region_name=region)
    try:
        cur = ac.get_token_vault().get("kmsConfiguration", {})
    except ac.exceptions.ResourceNotFoundException:
        cur = {}
    if cur.get("keyType") == "CustomerManagedKey":
        ac.set_token_vault_cmk(kmsConfiguration={"keyType": "ServiceManagedKey"})
        print("token vault: back to the service-managed key (was %s)" % cur.get("kmsKeyArn"))

    # 1c. AWS Config refuses to delete a delivery channel while its recorder records (CDK stack delete
    #     fails NotStabilized on the channel): stop the enclave's recorder first.
    cfg = boto3.client("config", region_name=region)
    for st in cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", []):
        if st["name"] == "sgea-%s" % a.env and st.get("recording"):
            cfg.stop_configuration_recorder(ConfigurationRecorderName=st["name"]); print("config: recorder stopped")

    # 2. deletion protections
    rds = boto3.client("rds", region_name=region)
    # Final snapshots of earlier SANDBOX runs block the next destroy (fixed final-snapshot name — fail-safe in
    # production, where a second destroy must not overwrite the last backup). Sandbox test data only.
    for snap in rds.describe_db_cluster_snapshots(SnapshotType="manual")["DBClusterSnapshots"]:
        sid = snap["DBClusterSnapshotIdentifier"]
        if sid == "sgea-%s-vector-final" % a.env or (sid.startswith("sgeaenclave-snapshot-auroracluster")
                                                     and snap.get("DBClusterIdentifier") == "sgea-%s-vector" % a.env):
            rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=sid); print("deleted sandbox snapshot " + sid)
    try:
        rds.modify_db_cluster(DBClusterIdentifier="sgea-%s-vector" % a.env, DeletionProtection=False, ApplyImmediately=True)
        print("aurora: deletion protection off")
    except rds.exceptions.DBClusterNotFoundFault:
        pass
    ddb = boto3.client("dynamodb", region_name=region)
    try:
        ddb.update_table(TableName="sgea-token-usage-%s" % a.env, DeletionProtectionEnabled=False)
        print("dynamodb: deletion protection off")
    except ddb.exceptions.ResourceNotFoundException:
        pass
    nfw = boto3.client("network-firewall", region_name=region)
    try:
        nfw.update_firewall_delete_protection(FirewallName="sgea-%s-vdss" % a.env, DeleteProtection=False)
        print("network firewall: delete protection off")
    except nfw.exceptions.ResourceNotFoundException:
        pass
    bk = boto3.client("backup", region_name=region)
    vault = "sgea-%s" % a.env
    vaults = [v["BackupVaultName"] for pg in bk.get_paginator("list_backup_vaults").paginate() for v in pg["BackupVaultList"]]
    try:
        if vault not in vaults:
            raise bk.exceptions.ResourceNotFoundException({"Error": {"Code": "ResourceNotFoundException"}}, "ListBackupVaults")
        bk.delete_backup_vault_lock_configuration(BackupVaultName=vault)
        try:  # the access policy denies DeleteRecoveryPoint (backup-recovery-point-manual-deletion-disabled)
            bk.delete_backup_vault_access_policy(BackupVaultName=vault)
        except Exception:
            pass
        for page in bk.get_paginator("list_recovery_points_by_backup_vault").paginate(BackupVaultName=vault):
            for rp in page["RecoveryPoints"]:
                bk.delete_recovery_point(BackupVaultName=vault, RecoveryPointArn=rp["RecoveryPointArn"])
        print("backup: vault lock removed, recovery points deleted")
    except bk.exceptions.ResourceNotFoundException:
        pass

    # 3. buckets (both regions), bypassing GOVERNANCE retention; ECR images
    def empty_buckets():
        prefix = "sgea-%s-" % a.env
        for r in regions:
            s3 = boto3.client("s3", region_name=r)
            for b in s3.list_buckets()["Buckets"]:
                name = b["Name"]
                if not name.startswith(prefix) or acct not in name or not name.endswith(r):
                    continue
                print("emptying s3://" + name)
                try:
                    locked = s3.get_object_lock_configuration(Bucket=name)["ObjectLockConfiguration"].get("ObjectLockEnabled") == "Enabled"
                except s3.exceptions.ClientError:
                    locked = False
                bypass = {"BypassGovernanceRetention": True} if locked else {}
                for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
                    objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
                    for i in range(0, len(objs), 1000):
                        s3.delete_objects(Bucket=name, Delete={"Objects": objs[i:i + 1000], "Quiet": True}, **bypass)

    empty_buckets()
    ecr = boto3.client("ecr", region_name=region)
    try:
        imgs = ecr.list_images(repositoryName="sgea-%s-agents" % a.env)["imageIds"]
        if imgs:
            ecr.batch_delete_image(repositoryName="sgea-%s-agents" % a.env, imageIds=imgs)
            print("ecr: %d images deleted" % len(imgs))
    except ecr.exceptions.RepositoryNotFoundException:
        pass

    # 4. enclave, then network
    if a.cdk:
        cdk_destroy(a, acct, region, regions, state, empty_buckets)
    elif os.path.exists(os.path.join(state, "enclave.tfstate")):
        # CloudTrail / Config / access logging keep writing until they are destroyed themselves:
        # empty the buckets again and retry once.
        if terraform("-chdir=" + tf, "destroy", "-input=false", "-auto-approve", check=False).returncode:
            empty_buckets()
            terraform("-chdir=" + tf, "destroy", "-input=false", "-auto-approve")
    net = os.path.join(ROOT, ".sandbox", "_network", "network.tfstate")
    if a.network and os.path.exists(net):
        netdir = os.path.join(ROOT, "examples", "sandbox-network")
        terraform("-chdir=" + netdir, "init", "-input=false", "-reconfigure", "-backend-config=path=" + net)
        terraform("-chdir=" + netdir, "destroy", "-input=false", "-auto-approve", "-var", "region=" + region)
    # Aurora's exported log group: created by the enclave from now on, but earlier deployments (or RDS itself)
    # may have left one behind, which then blocks the next deploy (ResourceAlreadyExists / CFN early validation).
    lg = boto3.client("logs", region_name=region)
    for page in lg.get_paginator("describe_log_groups").paginate(logGroupNamePrefix="/aws/rds/cluster/sgea-%s-vector" % a.env):
        for g_ in page["logGroups"]:
            lg.delete_log_group(logGroupName=g_["logGroupName"]); print("delete log group " + g_["logGroupName"])
    print("teardown complete")


if __name__ == "__main__":
    sys.exit(main())
