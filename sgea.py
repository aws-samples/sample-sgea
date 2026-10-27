#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
SGEA — Secure GenAI Enclave Accelerator
Control-profile-driven IaC generator.

One profile -> one RESOLVED config -> two thin emitters (Terraform, CDK).
The resolved config is the single source of truth: emitters translate it,
they never re-decide what a baseline means.

Usage:
    sgea list
    sgea resolve  --profile profiles/fedramp-moderate-hipaa.commercial.json
    sgea export   --profile profiles/fedramp-moderate-hipaa.commercial.json \\
                  --out build/ [--emit terraform,cdk] [--allow-unverified]
    sgea verify   --out build/fedramp-moderate-hipaa-commercial
    sgea check    --out build/fedramp-moderate-hipaa-commercial --plan plan.json
    sgea check    --out build/fedramp-moderate-hipaa-commercial --cfn cdk.out/SgeaEnclave.template.json ...
    sgea --version

Toolkit root (where baselines/, profiles/, verticals/ live) is discovered in
this order: $SGEA_ROOT, then the nearest parent of the current directory that
contains baselines/ and profiles/, then the directory this module lives in
(in-repo use). So the installed `sgea` command works from anywhere inside a
toolkit checkout.

Exit codes: 0 ok, 2 validation error, 3 refused (unverified profile),
            4 verification failed (terraform validate / cdk synth),
            5 check failed (planned IaC misses a required catalog control).
"""
# subprocess calls in this file: argv lists, never a shell; arguments come from the operator (nosec / nosemgrep).
import argparse, copy, json, os, sys, datetime

__version__ = "0.1.0"

REQUIRED_TOP = ["schema_version", "profile", "partition", "regions", "baselines",
                "guardrails", "policies", "logging", "services", "evidence",
                "vector_store", "token_control"]

# Keys whose list values ACCUMULATE across composed baselines (union, de-duped,
# order-preserving) instead of being replaced. A Moderate+HIPAA profile must
# carry BOTH control catalogs, not just the last one composed.
ADDITIVE_LIST_KEYS = {"control_catalogs", "conformance_packs"}


# --------------------------------------------------------------------------
# Toolkit-root discovery
# --------------------------------------------------------------------------
def toolkit_root():
    """Locate the directory that holds baselines/ and profiles/."""
    env = os.environ.get("SGEA_ROOT")
    if env and os.path.isdir(os.path.join(env, "profiles")) and os.path.isdir(os.path.join(env, "baselines")):
        return os.path.abspath(env)
    d = os.getcwd()
    while True:
        if os.path.isdir(os.path.join(d, "profiles")) and os.path.isdir(os.path.join(d, "baselines")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    here = os.path.dirname(os.path.abspath(__file__))
    if os.path.isdir(os.path.join(here, "profiles")) and os.path.isdir(os.path.join(here, "baselines")):
        return here
    raise SystemExit(
        "SGEA: could not locate the toolkit root (a directory containing baselines/ and profiles/).\n"
        "Run inside a toolkit checkout, or set the SGEA_ROOT environment variable.")


def _dirs():
    root = toolkit_root()
    return root, os.path.join(root, "baselines"), os.path.join(root, "profiles")


def _load(path):
    with open(path) as f:
        return json.load(f)


# --------------------------------------------------------------------------
# Compose
# --------------------------------------------------------------------------
def deep_merge(base, over):
    """Deep-merge dicts; lists in ADDITIVE_LIST_KEYS union, others replace."""
    out = copy.deepcopy(base)
    for k, v in over.items():
        if k.startswith("_"):
            continue
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        elif k in ADDITIVE_LIST_KEYS and isinstance(out.get(k), list) and isinstance(v, list):
            merged = list(out[k])
            for item in v:
                if item not in merged:
                    merged.append(item)
            out[k] = merged
        else:
            out[k] = copy.deepcopy(v)
    return out


def resolve(profile_path, baseline_dir=None):
    """Compose a profile into a single resolved config document."""
    if baseline_dir is None:
        _, baseline_dir, _ = _dirs()
    prof = _load(profile_path)
    pmeta = prof.get("profile", {})
    extends = pmeta.get("extends", [])

    resolved = {}
    for b in extends:
        frag = _load(os.path.join(baseline_dir, b + ".json"))
        resolved = deep_merge(resolved, frag)
    resolved = deep_merge(resolved, prof.get("overrides", {}))

    resolved["schema_version"] = "1.0"
    resolved["profile"] = {k: v for k, v in pmeta.items() if k != "extends"}
    resolved["profile"]["extends"] = extends
    resolved["baselines"] = prof.get("baselines", extends)
    if "emit" in prof:
        resolved["emit"] = prof["emit"]
    for k in list(resolved.keys()):
        if k.startswith("_"):
            del resolved[k]
    resolved["_generated"] = {
        "tool": "SGEA", "version": __version__,
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_profile": os.path.basename(profile_path),
    }
    return resolved, prof


# --------------------------------------------------------------------------
# Validate
# --------------------------------------------------------------------------
def _schema_validate(resolved, profile_dir):
    """Optional structural validation against _schema.json if jsonschema is present."""
    schema_path = os.path.join(profile_dir, "_schema.json")
    if not os.path.exists(schema_path):
        return []
    try:
        import jsonschema  # optional dependency
    except Exception:
        return []  # structural validation is best-effort; semantic checks still run
    schema = _load(schema_path)
    errs = []
    validator = jsonschema.Draft7Validator(schema)
    for e in sorted(validator.iter_errors(resolved), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in e.path) or "(root)"
        errs.append(f"schema: {loc}: {e.message}")
    return errs


def validate(resolved, profile_dir=None):
    """Semantic validation (always) + structural validation (if jsonschema present)."""
    errs = []
    for k in REQUIRED_TOP:
        if k not in resolved:
            errs.append("missing required key: " + k)
    if resolved.get("partition") not in ("aws", "aws-us-gov"):
        errs.append("partition must be 'aws' or 'aws-us-gov'")
    reg = resolved.get("regions", {})
    if not reg.get("allowed"):
        errs.append("regions.allowed must be non-empty")
    if reg.get("primary") and reg.get("allowed") and reg["primary"] not in reg["allowed"]:
        errs.append("regions.primary not in regions.allowed")
    if "hipaa" in resolved.get("baselines", []):
        if not resolved.get("services", {}).get("hipaa_eligible_only"):
            errs.append("hipaa baseline requires services.hipaa_eligible_only = true")
        if not resolved.get("guardrails", {}).get("pii", {}).get("phi_entities"):
            errs.append("hipaa baseline requires guardrails.pii.phi_entities = true")
    geo = reg.get("inference_profile_geo")
    if resolved.get("partition") == "aws-us-gov" and geo != "us-gov":
        errs.append("GovCloud partition requires inference_profile_geo = 'us-gov'")
    if resolved.get("partition") == "aws" and geo == "us-gov":
        errs.append("commercial partition cannot use inference_profile_geo = 'us-gov'")
    tc = resolved.get("token_control", {})
    missing = [s for s in ("eventbridge", "stepfunctions") if s not in resolved.get("services", {}).get("allow", [])]
    if (tc.get("enabled") and tc.get("model_enforce", True) and tc.get("per_team_monthly_tokens")
            and resolved.get("logging", {}).get("model_invocation_logging") and missing):
        errs.append("token_control.model_enforce (ADR 0003) needs services.allow to include " + ", ".join(missing)
                    + "; add them or set token_control.model_enforce = false")
    if profile_dir is None:
        try:
            _, _, profile_dir = _dirs()
        except SystemExit:
            profile_dir = None
    if profile_dir:
        errs += _schema_validate(resolved, profile_dir)
        errs += _authorization_validate(resolved, os.path.dirname(profile_dir))
        errs += _region_validate(resolved, os.path.dirname(profile_dir))
    return errs


# baseline -> Services-in-Scope column (substring) the allow-list must be authorized under.
AUTHORIZATION_COLUMNS = {
    "fedramp-low": "Class C", "fedramp-moderate": "Class C", "fedramp-high": "Class D",
    "dod-il2": "IL2 (East/West)", "dod-il4": "IL4 (GovCloud)", "dod-il5": "IL5 (GovCloud)",
    "hipaa": "HIPAA Eligible",
}
AUTH_PREFIX = "authorization: "
REGION_PREFIX = "region: "
# Errors a non-production scaffold export (--allow-unverified) reports as warnings.
DOWNGRADABLE = (AUTH_PREFIX, REGION_PREFIX)
# Region groups named in the AWS Services-in-Scope column headers ("East/West", "GovCloud"):
# the FedRAMP / DoD SRG authorization boundaries.
REGION_GROUPS = {
    "East/West": ["us-east-1", "us-east-2", "us-west-1", "us-west-2"],
    "GovCloud": ["us-gov-west-1", "us-gov-east-1"],
}


def _regions_catalog(root):
    path = os.path.join(root, "catalog", "_regions.json")
    return _load(path) if os.path.exists(path) else None


def region_notes(resolved, root):
    """Non-blocking facts: allowed services unavailable in a secondary allowed region."""
    cat = _regions_catalog(root)
    if not cat:
        return []
    avail = cat["service_regions"]["services"]
    primary = resolved.get("regions", {}).get("primary")
    notes = []
    gov = cat["govcloud_differences"].get("bedrock-agentcore", {})
    if (resolved.get("partition") == "aws-us-gov"
            and "gateway_tool_path" in resolved.get("guardrails", {}).get("levels", [])
            and "AWS::BedrockAgentCore::PolicyEngine" in gov.get("unavailable_cfn_types", [])):
        notes.append("gateway_tool_path is enforced by the SGEA tool-policy interceptor Lambda: "
                     "AWS::BedrockAgentCore::PolicyEngine is not available in GovCloud (GovCloud User Guide). "
                     "Set tool_policy (default denies every tools/call).")
    for region in resolved.get("regions", {}).get("allowed", []):
        if region == primary:
            continue
        missing = [s for s in resolved.get("services", {}).get("allow", []) if avail.get(s) and region not in avail[s]]
        if missing:
            notes.append("%s not available in %s (allowed secondary region); SGEA deploys them in %s only"
                         % (", ".join(missing), region, primary))
    return notes


def _region_validate(resolved, root):
    """regions.allowed vs each baseline's authorization boundary, and service availability in
    the primary region / partition (catalog/_regions.json, built by tools/build_catalog.py)."""
    cat = _regions_catalog(root)
    sis_path = os.path.join(root, "catalog", "_services-in-scope.json")
    if not cat or not os.path.exists(sis_path):
        return []
    errs = []
    cols = next(iter(_load(sis_path)["services"].values())).keys()
    allowed = resolved.get("regions", {}).get("allowed", [])
    for b in resolved.get("baselines", []):
        hint = AUTHORIZATION_COLUMNS.get(b)
        col = next((c for c in cols if hint and hint in c), None)
        group = next((g for g in REGION_GROUPS if col and "(" + g + ")" in col), None)
        if group:
            outside = [r for r in allowed if r not in REGION_GROUPS[group]]
            if outside:
                errs.append(REGION_PREFIX + "%s is authorized in %s regions only (%s); regions.allowed has %s"
                            % (b, group, ", ".join(REGION_GROUPS[group]), ", ".join(outside)))
    avail = cat["service_regions"]["services"]
    primary = resolved.get("regions", {}).get("primary")
    for svc in resolved.get("services", {}).get("allow", []):
        if avail.get(svc) and primary not in avail[svc]:
            errs.append(REGION_PREFIX + "%s is not available in the primary region %s" % (svc, primary))
    return errs


def _authorization_validate(resolved, root):
    """services.allow vs AWS Services in Scope (catalog/_services-in-scope.json, built by
    tools/build_catalog.py from the public AWS pages). Skipped if the catalog is not built."""
    path = os.path.join(root, "catalog", "_services-in-scope.json")
    if not os.path.exists(path):
        return []
    status = _load(path)["services"]
    errs = []
    for b in resolved.get("baselines", []):
        col_hint = AUTHORIZATION_COLUMNS.get(b)
        if not col_hint:
            continue
        for svc in resolved.get("services", {}).get("allow", []):
            cols = status.get(svc)
            if cols is None:
                errs.append(AUTH_PREFIX + "%s: no Services-in-Scope mapping for %r" % (b, svc))
                continue
            col = next((c for c in cols if col_hint in c), None)
            val = cols.get(col, "") if col else ""
            if val != "\u2713":
                errs.append(AUTH_PREFIX + "%s is not authorized for %s (%s: %s)" % (svc, b, col or col_hint, val or "not listed"))
    return errs


# --------------------------------------------------------------------------
# Emit
# --------------------------------------------------------------------------
def _load_emitters():
    """Import the emitters (terraform_emitter, cdk_emitter, manual_steps, operations) from ONE place.

    The toolkit root's emitters/ wins when present: the emitters read sources/, catalog/ and baselines/ from
    the same checkout, so code and data stay in lockstep. The installed package (complete, incl. lambda/ and
    cdk_app/) is the fallback when the toolkit root carries no emitters/."""
    edir = os.path.join(toolkit_root(), "emitters")
    if os.path.isfile(os.path.join(edir, "terraform_emitter.py")):
        if edir not in sys.path:
            sys.path.insert(0, edir)
        import terraform_emitter, cdk_emitter, manual_steps, operations  # toolkit checkout
    else:
        from emitters import terraform_emitter, cdk_emitter, manual_steps, operations  # installed package
    return terraform_emitter, cdk_emitter, manual_steps, operations


def _baseline_status(prof, baseline_dir):
    """Return the id of any composed baseline marked scaffold-unverified."""
    status = None
    for b in prof.get("profile", {}).get("extends", []):
        frag = _load(os.path.join(baseline_dir, b + ".json"))
        if frag.get("_status") == "scaffold-unverified":
            status = b
    return status


def _emit(resolved, prof, outdir, targets):
    terraform_emitter, cdk_emitter, _, _ = _load_emitters()
    written = []
    if "terraform" in targets:
        written += terraform_emitter.emit(resolved, prof, os.path.join(outdir, "terraform"), toolkit_root())
    if "cdk" in targets:
        written += cdk_emitter.emit(resolved, prof, os.path.join(outdir, "cdk"), toolkit_root())
    return written


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def cmd_list(_):
    root, baseline_dir, profile_dir = _dirs()
    print("Toolkit root: " + root + "\n")
    print("Available baselines:")
    for f in sorted(os.listdir(baseline_dir)):
        if f.endswith(".json"):
            frag = _load(os.path.join(baseline_dir, f))
            tag = "  [scaffold-unverified]" if frag.get("_status") == "scaffold-unverified" else ""
            print("  - " + f[:-5] + tag)
    print("\nAvailable profiles:")
    for f in sorted(os.listdir(profile_dir)):
        if f.endswith(".json") and not f.startswith("_"):
            print("  - profiles/" + f)
    return 0


def cmd_resolve(args):
    _, baseline_dir, profile_dir = _dirs()
    resolved, _ = resolve(args.profile, baseline_dir)
    errs = validate(resolved, profile_dir)
    print(json.dumps(resolved, indent=2))
    if errs:
        sys.stderr.write("\nVALIDATION ERRORS:\n" + "\n".join("  - " + e for e in errs) + "\n")
        return 2
    for n in region_notes(resolved, toolkit_root()):
        sys.stderr.write("NOTE: " + n + "\n")
    sys.stderr.write("\nvalidation: OK\n")
    return 0


def cmd_export(args):
    _, baseline_dir, profile_dir = _dirs()
    resolved, prof = resolve(args.profile, baseline_dir)
    errs = validate(resolved, profile_dir)
    status = _baseline_status(prof, baseline_dir)
    if status and args.allow_unverified:
        # Non-production scaffold: authorization gaps are reported, not blocking.
        auth = [e for e in errs if e.startswith(DOWNGRADABLE)]
        errs = [e for e in errs if not e.startswith(DOWNGRADABLE)]
        for e in auth:
            sys.stderr.write("WARNING (non-production scaffold): " + e + "\n")
    if errs:
        sys.stderr.write("VALIDATION ERRORS:\n" + "\n".join("  - " + e for e in errs) + "\n")
        return 2
    if status and not args.allow_unverified:
        sys.stderr.write(
            "REFUSED: profile composes the unverified scaffold baseline '" + status +
            "'.\nStanding up this baseline (e.g. FedRAMP High / GovCloud, DoD IL4) is its own effort.\n"
            "Re-run with --allow-unverified to emit a NON-PRODUCTION scaffold.\n")
        return 3
    targets = args.emit.split(",") if args.emit else resolved.get("emit", {}).get("targets", ["terraform"])
    # One folder per profile: <out>/<profile-id>/{terraform,cdk,resolved_profile.json}
    outdir = os.path.join(args.out, resolved["profile"]["id"])
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "resolved_profile.json"), "w") as f:
        json.dump(resolved, f, indent=2)
    written = _emit(resolved, prof, outdir, targets)
    _, _, manual_steps, operations = _load_emitters()
    steps = os.path.join(outdir, "MANUAL-STEPS.md")
    with open(steps, "w") as f:
        f.write(manual_steps.render(resolved, toolkit_root(), targets))
    written.append(steps)
    ops = os.path.join(outdir, "OPERATIONS.md")
    with open(ops, "w") as f:
        f.write(operations.render(resolved, toolkit_root(), targets))
    written.append(ops)
    print("Exported profile '" + resolved["profile"]["id"] + "' -> " + outdir)
    print("Targets: " + ", ".join(targets))
    for w in written:
        print("  wrote " + w)
    for n in region_notes(resolved, toolkit_root()):
        print("NOTE: " + n)
    if status:
        print("\nNOTE: emitted as NON-PRODUCTION scaffold (baseline '" + status + "' is unverified).")
    print("\nBEFORE DEPLOYING: complete the manual steps (AWS requests, other accounts) in\n  " + steps)
    print("\nNext: validate the emitted IaC with real tooling:\n  sgea verify --out " + outdir)
    print("\nAFTER DEPLOYING: run the day-2 checks and evidence calendar in\n  " + ops)
    return 0


# Placeholder environment inputs for the credential-free CDK synth in `sgea verify`: the enclave is checked as it
# deploys into a VPC (endpoints, Aurora, in-VPC Lambdas, SCCA firewall). Format-valid ids that exist nowhere;
# verify never deploys. Real deploys pass the customer's ids (-c sgea:<key>=...).
VERIFY_CONTEXT = {
    "env": "verify", "vpcId": "vpc-0a0a0a0a0a0a0a0a0",
    "endpointSubnetIds": "subnet-0a0a0a0a0a0a0a0a1,subnet-0a0a0a0a0a0a0a0a2",
    "endpointSecurityGroupIds": "sg-0a0a0a0a0a0a0a0a1",
    "endpointRouteTableIds": "rtb-0a0a0a0a0a0a0a0a1,rtb-0a0a0a0a0a0a0a0a2",
    "agentSubnetIds": "subnet-0a0a0a0a0a0a0a0a1,subnet-0a0a0a0a0a0a0a0a2",
    "agentSecurityGroupIds": "sg-0a0a0a0a0a0a0a0a2",
    "auroraSubnetIds": "subnet-0a0a0a0a0a0a0a0a1,subnet-0a0a0a0a0a0a0a0a2",
    "auroraSecurityGroupIds": "sg-0a0a0a0a0a0a0a0a3",
    "sccaFirewallSubnetIds": "subnet-0a0a0a0a0a0a0a0a3,subnet-0a0a0a0a0a0a0a0a4",
}


def cmd_verify(args):
    """Run terraform validate / cdk synth against an exported build dir.

    This is the real verification stage that replaces the toolkit's
    structural brace-check. It shells out to the actual toolchains, so it
    runs on a machine that has them installed (the deployment team's box or
    CI). Missing a toolchain is reported as SKIPPED, not failure.
    """
    import glob, shutil, subprocess
    out = args.out
    if not os.path.isdir(out):
        sys.stderr.write("verify: no such directory: " + out + "\n")
        return 2
    ran, failed, skipped = [], [], []

    tfdir = os.path.join(out, "terraform")
    if os.path.isdir(tfdir):
        if shutil.which("terraform"):
            r = subprocess.run(["terraform", "fmt", "-check", "-recursive"], cwd=tfdir, check=False)  # nosec B603  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
            (ran if r.returncode == 0 else failed).append("terraform fmt -check")
            subprocess.run(["terraform", "init", "-backend=false", "-input=false"],  # nosec B603  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
                           cwd=tfdir, check=False)
            r = subprocess.run(["terraform", "validate"], cwd=tfdir, check=False)  # nosec B603  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
            (ran if r.returncode == 0 else failed).append("terraform validate")
        else:
            skipped.append("terraform (binary not found)")

    cdkdir = os.path.join(out, "cdk")
    if os.path.isdir(cdkdir):
        if shutil.which("npx") or shutil.which("cdk"):
            if shutil.which("npm"):
                subprocess.run(["npm", "install", "--silent"], cwd=cdkdir, check=False)  # nosec B603  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
            ctx = [a for k, v in VERIFY_CONTEXT.items() for a in ("-c", "sgea:%s=%s" % (k, v))]
            if shutil.which("npx"):   # the executable is a literal at each call site; only arguments vary
                r = subprocess.run(["npx", "cdk", "synth", "--quiet", *ctx], cwd=cdkdir, check=False)  # nosec B603  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
            else:
                r = subprocess.run(["cdk", "synth", "--quiet", *ctx], cwd=cdkdir, check=False)  # nosec B603  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
            (ran if r.returncode == 0 else failed).append("cdk synth")
            templates = sorted(glob.glob(os.path.join(cdkdir, "cdk.out", "*.template.json")))
            if r.returncode == 0 and templates and os.path.exists(os.path.join(out, "resolved_profile.json")):
                # Credential-free framework check of the synthesized CloudFormation (placeholder VPC inputs,
                # VERIFY_CONTEXT). Per-tenant resources (agent runtime) are allowed as NOT-EMITTED here.
                results = check(_load(os.path.join(out, "resolved_profile.json")), _cfn_resources(templates),
                                os.path.join(toolkit_root(), "catalog"), "cfn")
                fails = [x for x in results if x[2] in ("FAIL", "GAP") and x[1].get("level", "required") == "required"]
                for cid, _, _, detail in fails:
                    print("  FAIL   %s  %s" % (cid, detail[:200]))
                passed = sum(1 for x in results if x[2] == "PASS")
                (ran if not fails else failed).append("sgea check --cfn (%d pass, %d required fail)" % (passed, len(fails)))
        else:
            skipped.append("cdk (npx/cdk not found)")

    print("verify: " + out)
    for x in ran:     print("  PASS   " + x)
    for x in failed:  print("  FAIL   " + x)
    for x in skipped: print("  SKIP   " + x)
    if failed:
        return 4
    if not ran:
        sys.stderr.write("verify: nothing ran — install terraform and/or the CDK toolchain to verify.\n")
    return 0


# --------------------------------------------------------------------------
# Check: planned IaC vs the framework catalogs
# --------------------------------------------------------------------------
def _plan_resources(plan):
    """[(address, type, values, after_unknown)] for every planned resource instance."""
    unknown = {rc["address"]: (rc.get("change") or {}).get("after_unknown") or {}
               for rc in plan.get("resource_changes", [])}
    out = []

    def walk(mod):
        for r in mod.get("resources", []):
            if r.get("mode") == "managed":
                out.append((r["address"], r["type"], r.get("values") or {}, unknown.get(r["address"], {})))
        for child in mod.get("child_modules", []):
            walk(child)
    walk((plan.get("planned_values") or {}).get("root_module") or {})
    return out


def _cfn_resources(templates):
    """Same shape as _plan_resources, from synthesized CloudFormation templates."""
    out = []
    for path in templates:
        stack = os.path.basename(path).split(".")[0]
        for lid, r in (_load(path).get("Resources") or {}).items():
            values = dict(r.get("Properties") or {}, __ref__=lid)
            out.append((stack + "/" + lid, r["Type"], values, {}))
    return out


def _norm(k):
    return k.replace("_", "").replace(":", "").lower()


def _attr(values, unknown, path, fuzzy=False):
    """All (value, is_unknown) reached by a dotted path; lists (blocks) fan out.
    fuzzy: match keys case-/underscore-insensitively (snake_case path vs CFN PascalCase)."""
    cur = [(values, unknown)]
    for part in path.split("."):
        nxt = []
        for v, u in cur:
            if isinstance(v, list):
                us = u if isinstance(u, list) else [u] * len(v)
                cur_items = list(zip(v, us))
            else:
                cur_items = [(v, u)]
            for item, iu in cur_items:
                if iu is True:
                    nxt.append((None, True))
                elif isinstance(item, dict):
                    key = part
                    if fuzzy and part not in item:
                        key = next((k for k in item if _norm(k) == _norm(part)), part)
                    nxt.append((item.get(key), iu.get(key) if isinstance(iu, dict) else False))
        cur = nxt
    return cur or [(None, False)]


def _statements(doc):
    """Allow statements of an IAM policy document (dict, or the JSON string Terraform plans)."""
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except ValueError:
            return None
    if not isinstance(doc, dict):
        return None
    st = doc.get("Statement", [])
    st = st if isinstance(st, list) else [st]
    as_list = lambda v: v if isinstance(v, list) else [v]
    return [(as_list(x.get("Action", [])), as_list(x.get("Resource", []))) for x in st
            if isinstance(x, dict) and x.get("Effect") == "Allow"]


def _iam_violations(doc, op, target):
    """iam-policy-no-statements-with-admin-access / -full-access / *-blocked-kms-actions semantics."""
    import fnmatch
    st = _statements(doc)
    if st is None:
        return None
    all_res = lambda res: any(r == "*" or (isinstance(r, str) and r.endswith(":key/*")) for r in res)
    if op == "iam_no_admin":
        return [a for acts, res in st for a in acts if a == "*" and "*" in res]
    if op == "iam_no_full_access":
        return [a for acts, res in st for a in acts if isinstance(a, str) and (a == "*" or a.endswith(":*"))]
    patterns = [x.strip() for x in str(target or "kms:Decrypt,kms:ReEncryptFrom").split(",") if x.strip()]
    return [a for acts, res in st if all_res(res) for a in acts if isinstance(a, str)
            and any(fnmatch.fnmatchcase(a, pt) or fnmatch.fnmatchcase(pt, a) for pt in patterns)]


def _meets(value, is_unknown, req, target):
    op = req["op"]
    if is_unknown is True:
        return op in ("set", "not_equals")  # computed at apply; presence is all plan can prove
    if op == "empty":
        return value in (None, "", [], {})
    if op in ("iam_no_admin", "iam_no_full_access", "iam_no_blocked_kms"):
        bad = _iam_violations(value, op, target)
        return bad is not None and not bad
    if isinstance(value, list) and op == "contains":
        return any(_meets(x, False, req, target) for x in value)
    if isinstance(value, list) and op != "set":
        return bool(value) and all(_meets(x, False, req, target) for x in value)
    if op == "set":
        return value not in (None, "", [], {})
    if value is None:
        return False
    if op == "equals":
        return str(value).lower() == str(target).lower()
    if op == "not_equals":
        return str(value).lower() != str(target).lower()
    if op == "one_of":
        return str(value) in [str(t) for t in target]
    if op == "min":
        return float(value) >= float(target)
    if op == "max":
        return float(value) <= float(target)
    if op == "contains":
        return str(target) in (value if isinstance(value, str) else json.dumps(value))
    raise SystemExit("check: unknown op " + op)


def _get_path(doc, path):
    for k in path.split("."):
        if not isinstance(doc, dict) or k not in doc:
            return None
        doc = doc[k]
    return doc


def _applies(cond, resolved):
    """applies_when grammar: 'path contains a|b', 'path == v', 'path != v', 'path', joined by ' && '."""
    if not cond:
        return True
    if " && " in cond:
        return all(_applies(c, resolved) for c in cond.split(" && "))
    for op in (" != ", " == "):
        if op in cond:
            path, val = cond.split(op, 1)
            eq = str(_get_path(resolved, path.strip())) == val.strip()
            return eq if op == " == " else not eq
    if " contains " in cond:
        path, items = cond.split(" contains ", 1)
        have = _get_path(resolved, path.strip()) or []
        return any(i.strip() in have for i in items.split("|"))  # "a|b" = any of
    return bool(_get_path(resolved, cond.strip()))


def _tags(values):
    t = values.get("tags_all") or values.get("tags") or values.get("Tags") or {}
    return {x.get("Key", x.get("key")): x.get("Value", x.get("value")) for x in t} if isinstance(t, list) else t


def _ref(v):
    return v.get("Ref") if isinstance(v, dict) else v


def _cfn_type(tf_type, present):
    """awscc_bedrockagentcore_runtime -> AWS::BedrockAgentCore::Runtime (by name, among present types)."""
    want = _norm(tf_type.split("_", 1)[1])
    return next((t for t in present if _norm(t.replace("AWS::", "").replace("::", "")) == want), None)


def _evaluate(insts, attribute, req, target, fuzzy, unverified=None):
    """Failing instances. Values unknown at plan (null + after_unknown) cannot be
    proven either way: they are recorded in `unverified`, never counted as PASS."""
    bad = []
    for addr, _, values, unknown in insts:
        hits = _attr(values, unknown, attribute, fuzzy) if attribute else [(True, False)]
        if any(u is True for _, u in hits):
            if unverified is not None:
                unverified.append("%s %s=<known after apply>" % (addr, attribute))
            hits = [(v, u) for v, u in hits if u is not True]
            if not hits:
                continue
        meets = [_meets(v, u, req, target) for v, u in hits]
        if not (any(meets) if req["op"] == "contains" else all(meets)):
            bad.append("%s %s=%s" % (addr, attribute, [v for v, _ in hits]))
    return bad


def _module_calls(config):
    """[(source, expressions)] for every module call in a plan's `configuration` block."""
    out = []

    def walk(mod):
        for call in (mod or {}).get("module_calls", {}).values():
            out.append((call.get("source", ""), call.get("expressions", {})))
            walk(call.get("module"))
    walk((config or {}).get("root_module"))
    return out


def _config_evidence(calls, ev):
    """PASS evidence when every call of a module sets an input to a constant (e.g. the S3 module's
    attach_deny_insecure_transport_policy = true) and the value itself is only known after apply."""
    hits = [e for src, e in calls if src == ev["module_source"]]
    if hits and all((e.get(ev["input"]) or {}).get("constant_value") == ev["equals"] for e in hits):
        return "config evidence: %d x %s sets %s = %s" % (len(hits), ev["module_source"], ev["input"], json.dumps(ev["equals"]))
    return None


def check(resolved, resources, catalog_dir, mode="tf", config=None):
    """Evaluate the composed baselines' catalog controls + mapped Config rules against
    planned (mode=tf: terraform show -json) or synthesized (mode=cfn) resources."""
    cfn = mode == "cfn"
    fuzzy = cfn
    config_calls = _module_calls(config)
    present = {r[1] for r in resources}
    controls = {}
    for b in resolved["baselines"]:
        cat = _load(os.path.join(catalog_dir, b + ".json"))
        for svc in cat["service_guidance"].values():
            for c in svc.get("inferred_controls", []):
                controls.setdefault(c["id"], c)
    results = []
    for cid, c in sorted(controls.items()):
        if not _applies(c.get("applies_when"), resolved):
            results.append((cid, c, "N/A", "applies_when false"))
            continue
        rtype, attribute, req, where = c["resource"], c.get("attribute"), c["require"], c.get("where") or {}
        if cfn:
            o = c.get("cfn") or {}
            rtype = o.get("type") or _cfn_type(c["resource"], present) or ("(cfn) " + c["resource"])
            attribute, req, where = o.get("attribute", attribute), o.get("require", req), o.get("where", where)
        target = _get_path(resolved, c["value_from"]) if c.get("value_from") else req.get("value")
        insts = [r for r in resources if r[1] == rtype
                 and all(str(_attr(r[2], {}, k, fuzzy)[0][0]) == str(v) for k, v in where.items())]
        if not insts:
            if c.get("scope") == "per-app":
                results.append((cid, c, "N/A-APP", rtype + " is created by tenant apps, not the enclave"))
            else:
                results.append((cid, c, "NOT-EMITTED", rtype + " not in " + ("template" if cfn else "plan")))
            continue
        unv = []
        if c.get("any_of"):
            # Pass if ANY alternative attribute fully meets the requirement; otherwise report all.
            tries = []
            for alt in c["any_of"]:
                u = []
                tries.append((alt, _evaluate(insts, alt, req, target, fuzzy, u), u))
            if any(not b and not u for _, b, u in tries):
                bad = []
            elif any(not b for _, b, _ in tries):
                bad, unv = [], next(u for _, b, u in tries if not b)
            else:
                bad = ["none of %s set: %s" % (c["any_of"], "; ".join(x for _, b, _ in tries for x in b))]
        else:
            bad = _evaluate(insts, attribute, req, target, fuzzy, unv)
        status = "FAIL" if bad else ("UNVERIFIED" if unv else "PASS")
        results.append((cid, c, status, "; ".join(bad + unv) or "%d instance(s)" % len(insts)))

    # AWS Config rules from the composed packs, evaluated preventively where SGEA
    # has a mapping (sources/inferred/config-rule-plan-checks.json).
    rule_params, coverage = {}, {}
    for b in resolved["baselines"]:
        bcat = _load(os.path.join(catalog_dir, b + ".json"))
        coverage.update(bcat.get("coverage") or {})
        for svc in bcat["services"].values():
            for r in svc:
                rule_params.setdefault(r["config_rule"], {}).update(r["parameters"])
    doc = _load(os.path.join(os.path.dirname(catalog_dir), "sources", "inferred", "config-rule-plan-checks.json"))
    mapping = doc["cfn_rules" if cfn else "rules"]
    for rule in sorted(set(rule_params) & set(mapping)):
        status, details, unv = "PASS", [], []
        for chk in mapping[rule]:
            if chk.get("when_param") and str(rule_params[rule].get(chk["when_param"], "")).lower() != "true":
                continue  # this check only applies when the pack sets the parameter
            if chk["require"]["op"] == "absent":
                found = [r for r in resources if r[1] == chk["resource"]
                         and not any(_tags(r[2]).get(k) in v for k, v in (chk.get("exempt") or {}).items())]
                if found:
                    status = "FAIL"
                    details += ["%s present (must not exist)" % r[0] for r in found]
                continue
            stype = chk.get("subject", chk["resource"])
            subjects = [r for r in resources if r[1] == stype]
            exempt = chk.get("exempt") or {}
            skipped = [r for r in subjects if any(_tags(r[2]).get(k) in v for k, v in exempt.items())]
            subjects = [r for r in subjects if r not in skipped]
            details += ["exempt %s (%s)" % (r[0], ",".join("%s=%s" % (k, _tags(r[2]).get(k)) for k in exempt))
                        for r in skipped]
            if not subjects:
                if not skipped:
                    status = "N/A" if status == "PASS" else status
                    details.append(stype + " not present")
                continue
            op, target = chk["require"]["op"], chk["require"].get("value")
            req = chk["require"]
            if chk.get("value_param"):
                target = rule_params[rule].get(chk["value_param"])
                if target in (None, "") and op in ("min", "max", "equals"):
                    req, op = {"op": "set"}, "set"  # the pack leaves the bound open: presence only
            if chk.get("value_from"):
                target = _get_path(resolved, chk["value_from"])
            all_insts = subjects if chk["resource"] == stype else [r for r in resources if r[1] == chk["resource"]]
            groups = []
            if chk.get("link") and chk["resource"] != stype:
                ra, sa = chk["link"]
                for subj in subjects:
                    mod = subj[0].rsplit(".", 2)[0] if subj[0].count(".") >= 2 else ""
                    key = subj[2].get(sa)
                    # link attr unknown at plan: same wrapper module only (the bucket and its siblings, e.g.
                    # module.x.module.bucket + module.x.module.notification), never "all"
                    parent = mod.rsplit(".module.", 1)[0] if ".module." in mod else mod
                    groups.append((subj[0], [
                        r for r in all_insts
                        if (key is not None and _ref(r[2].get(ra)) == key)
                        or (r[2].get(ra) is None and (r[0].startswith(mod + ".") or r[0].startswith(parent + ".module.")))]))
            else:
                groups.append((subjects[0][0], all_insts))
            bad = []
            for subj_addr, insts in groups:
                if op == "exists":
                    if not insts:
                        bad.append("%s has no %s" % (subj_addr, chk["resource"]))
                elif op == "count_min":
                    if len(insts) < int(target):
                        bad.append("%s: %d x %s (< %s)" % (subj_addr, len(insts), chk["resource"], target))
                elif not insts:
                    bad.append("%s has no %s" % (subj_addr, chk["resource"]))
                else:
                    bad += _evaluate(insts, chk.get("attribute"), req, target, fuzzy, unv)
            if bad:
                status = "FAIL"
                details += bad
        if status == "PASS" and unv:
            ev = next((c.get("config_evidence") for c in mapping[rule] if c.get("config_evidence")), None)
            proof = _config_evidence(config_calls, ev) if (ev and not cfn) else None
            if proof:
                details.append(proof)
                unv = []
            else:
                status = "UNVERIFIED"
        results.append(("RULE:" + rule, {"level": "required"}, status, "; ".join(details + unv)))

    # Every other pack rule carries a recorded disposition (sources/inferred/rule-dispositions.yaml).
    # `implement` = enclave-owned but not emitted/checked yet: a required GAP. The rest are accounted
    # for outside the enclave IaC and listed so nothing is silently skipped.
    for rule in sorted(set(rule_params) - set(mapping)):
        cv = coverage.get(rule) or {"status": "missing", "reason": "no check and no disposition (rebuild catalogs)"}
        if cv["status"] in ("implement", "missing"):
            results.append(("RULE:" + rule, {"level": "required"}, "GAP", cv.get("reason", "")))
        else:
            results.append(("RULE:" + rule, {"level": "accounted"}, cv["status"].upper(), cv.get("reason", "")))

    # Detective coverage: every composed baseline's conformance pack is deployed.
    name_key = "ConformancePackName" if cfn else "name"
    ptype = "AWS::Config::ConformancePack" if cfn else "aws_config_conformance_pack"
    planned_packs = {v.get(name_key) for _, t, v, _ in resources if t == ptype}
    for pack in resolved.get("evidence", {}).get("conformance_packs", []):
        want = "sgea-" + "".join(ch if ch.isalnum() else "-" for ch in pack.lower()).replace("--", "-")
        results.append(("PACK:" + pack, {"level": "required"}, "PASS" if want in planned_packs else "FAIL", want))
    return results


def cmd_check(args):
    if bool(args.plan) == bool(args.cfn):
        sys.stderr.write("check: pass exactly one of --plan (Terraform) or --cfn (CDK templates)\n")
        return 2
    resolved = _load(os.path.join(args.out, "resolved_profile.json"))
    resources = _plan_resources(_load(args.plan)) if args.plan else _cfn_resources(args.cfn)
    root = toolkit_root()
    plan = _load(args.plan) if args.plan else None
    results = check(resolved, resources, os.path.join(root, "catalog"), "tf" if args.plan else "cfn",
                    (plan or {}).get("configuration"))
    counts = {}
    for cid, c, status, detail in results:
        lvl = c.get("level", "required")
        counts[(lvl, status)] = counts.get((lvl, status), 0) + 1
        if (status != "PASS" and lvl != "accounted") or args.verbose:
            print("  %-12s %-11s %-18s %s" % (status, lvl, cid, detail))
    print("check: " + args.out + (" (terraform plan)" if args.plan else " (cloudformation)"))
    for (lvl, status), n in sorted(counts.items()):
        print("  %-11s %-12s %d" % (lvl, status, n))
    gaps = [r for r in results if r[1].get("level", "required") == "required"
            and (r[2] in ("FAIL", "GAP") or (r[2] == "NOT-EMITTED" and not args.allow_gaps)
                 or (r[2] == "UNVERIFIED" and args.strict))]
    return 5 if gaps else 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sgea", description="Secure GenAI Enclave Accelerator — IaC generator")
    ap.add_argument("--version", action="version", version="SGEA " + __version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("list", help="list baselines and profiles"); s.set_defaults(fn=cmd_list)
    s = sub.add_parser("resolve", help="print the resolved config for a profile"); s.add_argument("--profile", required=True); s.set_defaults(fn=cmd_resolve)
    s = sub.add_parser("export", help="emit IaC for a profile")
    s.add_argument("--profile", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--emit", default="", help="comma list: terraform,cdk (default: profile's emit.targets)")
    s.add_argument("--allow-unverified", action="store_true", help="emit scaffold baselines (non-production)")
    s.set_defaults(fn=cmd_export)
    s = sub.add_parser("check", help="evaluate a Terraform plan (--plan) or synthesized CloudFormation (--cfn) against the framework catalogs")
    s.add_argument("--out", required=True, help="an exported build dir (contains resolved_profile.json)")
    s.add_argument("--plan", help="`terraform show -json` output (see tools/sandbox_plan.py --json-out)")
    s.add_argument("--cfn", action="append", help="synthesized CloudFormation template (CDK cdk.out/*.template.json); repeatable")
    s.add_argument("--allow-gaps", action="store_true", help="do not fail on required controls whose resource is not emitted")
    s.add_argument("--strict", action="store_true", help="fail on required controls whose value is only known after apply")
    s.add_argument("-v", "--verbose", action="store_true", help="also list passing controls")
    s.set_defaults(fn=cmd_check)
    s = sub.add_parser("verify", help="terraform fmt/validate, cdk synth and a credential-free sgea check --cfn on an exported build dir")
    s.add_argument("--out", required=True, help="an exported build dir (contains terraform/ and/or cdk/)")
    s.set_defaults(fn=cmd_verify)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
