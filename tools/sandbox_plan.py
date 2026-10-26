#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Read-only `terraform plan` of an exported build against a sandbox account.

Copies <build>/terraform to a temp dir, forces a local backend, resolves the
credentials (see below), and runs `terraform plan -refresh=false` (no apply, no
state written to the account). Prints the plan summary and any errors; full log
goes to <tmp>/plan.log.

Usage:
    python3 -I tools/sandbox_plan.py build/<profile> --account <credentials> \\
        [--region us-east-1] [--var org_id=o-example ...] [--json-out plan.json]

<credentials>: an AWS CLI profile name (AWS_PROFILE) or `env` (the ambient credential
chain as-is). Region: --region, else the AWS CLI profile's region, else
$AWS_REGION / $AWS_DEFAULT_REGION, else us-east-1.
"""
# subprocess calls in this file: argv lists, never a shell; arguments come from the operator (nosec / nosemgrep).
import argparse, os, re, shutil, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # -I drops the script directory
from sandbox_teardown import CREDENTIALS_HELP, credential_env, credential_mode, profile_region  # noqa: E402


def resolve_region(creds, region=None, environ=None):
    environ = os.environ if environ is None else environ
    if region:
        return region
    if credential_mode(creds) == "profile":
        region = profile_region(creds, environ)
    return region or environ.get("AWS_REGION") or environ.get("AWS_DEFAULT_REGION") or "us-east-1"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("build")
    ap.add_argument("--account", required=True, metavar="CREDENTIALS", help=CREDENTIALS_HELP)
    ap.add_argument("--region", help="default: the AWS CLI profile's region, $AWS_REGION, else us-east-1")
    ap.add_argument("--var", action="append", default=[], help="name=value (HCL value for lists, e.g. '[\"a\"]')")
    ap.add_argument("--json-out", help="write `terraform show -json` of the plan here (input to `sgea check --plan`)")
    a = ap.parse_args(argv)

    work = tempfile.mkdtemp(prefix="sgea-plan-")
    shutil.copytree(os.path.join(a.build, "terraform"), work, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".terraform", "*.tfstate*"))
    with open(os.path.join(work, "backend_override.tf"), "w") as f:
        f.write('terraform {\n  backend "local" {}\n}\n')
    env = credential_env(a.account, resolve_region(a.account, a.region), role=getattr(a, "role", "admin"))
    subprocess.run(["terraform", "init", "-input=false", "-no-color"], cwd=work, env=env, capture_output=True)  # nosec B603  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    var_args = [x for v in a.var for x in ("-var", v)]
    r = subprocess.run(["terraform", "plan", "-input=false", "-no-color", "-lock=false", "-refresh=false", "-out=tfplan",
                        *var_args], cwd=work, env=env, capture_output=True, text=True)  # nosec B603  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    log = r.stdout + r.stderr
    open(os.path.join(work, "plan.log"), "w").write(log)
    keep = [l for l in log.splitlines() if re.match(r"\s*(Error|Plan:)", l) or "error_message" in l]
    print("\n".join(keep) or log[-2000:])
    if a.json_out and r.returncode == 0:
        j = subprocess.run(["terraform", "show", "-json", "tfplan"], cwd=work, env=env, capture_output=True, text=True)  # nosec B603  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
        open(a.json_out, "w").write(j.stdout)
        print("plan json -> " + a.json_out)
    print("exit=%d  log=%s" % (r.returncode, os.path.join(work, "plan.log")))
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
