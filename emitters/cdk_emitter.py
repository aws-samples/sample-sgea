"""
SGEA CDK emitter — wrapper-seam design (ADR 0001).

Emits an AWS CDK (TypeScript) app whose stacks compose thin WRAPPER CONSTRUCTS
(emitters/cdk_app/, copied verbatim) mirroring the Terraform wrapper modules
one-to-one. Constructs use L1 (CloudFormation) types throughout, so the
synthesized template maps directly onto CFN properties; the experimental alpha
L2s are avoided.

The constructs implement NO control decisions. Everything they need is in
config.json: the resolved profile plus `_derived` (emitters/derived.py), the
same values the Terraform emitter bakes into HCL — so the two outputs cannot
drift. Customer environment inputs (VPC, subnets, org id, ...) come from CDK
context (`-c sgea:<key>=...`), mirroring the Terraform root variables.
"""
import json, os, shutil

try:
    from .derived import derive, pack_template
except ImportError:  # in-repo fallback import (sgea._load_emitters)
    from derived import derive, pack_template

APP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cdk_app")


def _w(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    return path


def emit(resolved, prof, outdir, root=None):
    written = []
    cdk = (resolved.get("emit", {}) or {}).get("cdk", {}) or {}
    lang = cdk.get("language", "typescript")
    pid = resolved["profile"]["id"]
    derived = derive(resolved, root)
    written.append(_w(os.path.join(outdir, "config.json"),
                      json.dumps(dict(resolved, _derived=derived), indent=2) + "\n"))

    if lang != "typescript":
        written.append(_w(os.path.join(outdir, "README.md"),
                          "# SGEA CDK (python) — not implemented\n\n`config.json` holds the resolved control "
                          "decisions; only the TypeScript app is implemented (backlog item 23).\n"))
        return written

    # Static construct library (no decisions in it) + pinned conformance pack templates.
    for base, _, files in os.walk(APP_DIR):
        for f in files:
            src = os.path.join(base, f)
            dst = os.path.join(outdir, os.path.relpath(src, APP_DIR))
            written.append(_w(dst, open(src).read()))
    lam = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lambda")
    for f in os.listdir(lam):
        if f.endswith(".py"):
            written.append(_w(os.path.join(outdir, "lambda", f), open(os.path.join(lam, f)).read()))
    for fname in derived["conformance_packs"].values():
        src = os.path.join(root or ".", "sources", "conformance-packs", fname)
        written.append(_w(os.path.join(outdir, "packs", fname), pack_template(root, fname)))

    pkg = {
        "name": "sgea-" + pid, "version": "0.1.0", "private": True, "bin": {"sgea": "bin/app.js"},
        "scripts": {"build": "tsc", "synth": "cdk synth", "deploy": "cdk deploy --all"},
        # Exact versions + the shipped package-lock.json (cdk_app/package-lock.json): `npm ci` installs the
        # same dependency tree every time (supply-chain pinning).
        "devDependencies": {"aws-cdk": "2.1145.0", "typescript": "5.9.3", "ts-node": "10.9.2", "@types/node": "22.20.5"},
        "dependencies": {"aws-cdk-lib": "2.273.0", "constructs": "10.8.1", "source-map-support": "0.5.21"},
    }
    written.append(_w(os.path.join(outdir, "package.json"), json.dumps(pkg, indent=2) + "\n"))
    lock_src = os.path.join(APP_DIR, "package-lock.json")
    if os.path.exists(lock_src):
        lock = json.load(open(lock_src))
        lock["name"] = pkg["name"]
        lock.setdefault("packages", {}).setdefault("", {})["name"] = pkg["name"]
        written.append(_w(os.path.join(outdir, "package-lock.json"), json.dumps(lock, indent=2) + "\n"))
    tsconfig = {"compilerOptions": {
        "target": "ES2022", "module": "commonjs", "lib": ["es2022"], "strict": True,
        "esModuleInterop": True, "skipLibCheck": True, "declaration": False,
        "noEmitOnError": True, "types": ["node"]},
        "exclude": ["node_modules", "cdk.out"]}
    written.append(_w(os.path.join(outdir, "tsconfig.json"), json.dumps(tsconfig, indent=2) + "\n"))
    # Official CDK feature flags: S3 server-access-log delivery by bucket policy (ACLs stay disabled).
    written.append(_w(os.path.join(outdir, "cdk.json"), json.dumps({
        "app": "npx ts-node --prefer-ts-exts bin/app.ts",
        "context": {"@aws-cdk/aws-s3:serverAccessLogsUseBucketPolicy": True},
    }, indent=2) + "\n"))

    readme = ("# SGEA CDK output — " + resolved["profile"]["name"] + "\n\n"
              "Wrapper-seam design (ADR 0001), driven by the same resolved + derived values as the "
              "Terraform output (`config.json`). Two stacks: `SgeaEnclaveLogReplica` (log-store replica, "
              "in `" + derived["replica_region"] + "`) and `SgeaEnclave` (primary, `" +
              resolved["regions"]["primary"] + "`).\n\n"
              "## Environment inputs (CDK context)\n\n"
              "Same as the Terraform root variables, e.g.:\n\n```\nnpx cdk synth -c sgea:env=prod "
              "-c sgea:orgId=o-xxxx -c sgea:perimeterCidrs=10.0.0.0/8 \\\n  -c sgea:vpcId=vpc-... "
              "-c sgea:endpointSubnetIds=subnet-a,subnet-b -c sgea:auroraSubnetIds=subnet-a,subnet-b ...\n```\n\n"
              "Org perimeter packs are skipped (with a synth warning) until `sgea:orgId` / perimeter inputs "
              "are set — they are never emitted empty.\n\n"
              "## Build & check\n```\nnpm install\nnpx cdk synth\nsgea check --out .. --cfn cdk.out/SgeaEnclave.template.json\n```\n")
    written.append(_w(os.path.join(outdir, "README.md"), readme))
    return written
