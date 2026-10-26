# Installing and running the SGEA CLI

The generator is a small Python package (one dependency: PyYAML). `baselines/`,
`profiles/` and `verticals/` are **your working data** — they are not bundled
into the install; the CLI finds them at the toolkit root.

## Install

```bash
# from the toolkit root (the directory containing pyproject.toml)
pipx install .            # isolated, recommended
# or
python -m pip install .   # into the current environment
# or, for development (editable):
python -m pip install -e ".[dev]"
```

Optional structural profile validation uses `jsonschema`:

```bash
python -m pip install ".[schema]"
```

If `jsonschema` is not installed, the CLI still runs every **semantic** check
(partition/geo coherence, HIPAA eligibility, region membership, scaffold
detection); only the extra JSON-Schema structural check is skipped.

Which emitters run: when the toolkit root contains `emitters/` (a checkout), the CLI uses that copy, so the
emitters and the `sources/` / `catalog/` data they read always come from the same checkout. The installed package
(complete, including the Lambda sources and the CDK app) is used when the toolkit root carries data only.

## Toolkit root discovery

The installed `sgea` command finds `baselines/` and `profiles/` by, in order:

1. `$SGEA_ROOT` if set,
2. the nearest parent of the current directory that contains both,
3. the directory the module lives in (in-repo use).

So run `sgea` from inside a toolkit checkout, or `export SGEA_ROOT=/path/to/toolkit`.

## Use

```bash
sgea --version
sgea list
sgea resolve --profile profiles/fedramp-moderate-hipaa.commercial.json
sgea export  --profile profiles/fedramp-moderate-hipaa.commercial.json --out build/
sgea verify  --out build/fedramp-moderate-hipaa-commercial
```

Scaffold (unverified) baselines — FedRAMP High, DoD IL2, DoD IL4, DoD IL5 — are refused by
`export` unless you pass `--allow-unverified`, and the output is then marked
non-production.

## Test

```bash
pytest -q                      # if pytest is installed
python tests/test_resolver.py  # no dependencies — standalone runner
```

The tests exercise the resolver and validator against the shipped baselines
and profiles: additive catalog union, allow-list replacement, HIPAA coherence,
GovCloud partition/geo coherence, and scaffold detection.

## Verify (the real IaC gate)

`sgea verify --out build/<profile-id>` runs the actual toolchains:

- **Terraform:** `terraform fmt -check`, `terraform init -backend=false`, `terraform validate`
  in `build/<profile-id>/terraform/`.
- **CDK:** `npm install`, `npx cdk synth` with placeholder VPC / subnet / security-group inputs
  (`VERIFY_CONTEXT` in `sgea.py` — format-valid ids that exist nowhere; verify never deploys), then a
  credential-free `sgea check` of the synthesized CloudFormation against the framework catalogs.

A toolchain that isn't installed is reported as **SKIP**, not failure. `verify`
exits non-zero only if a step ran and failed.

## Check (does the IaC meet the framework?)

`sgea check` evaluates a Terraform plan (`terraform show -json`) or synthesized
CDK templates against every required control in `catalog/<baseline>.json` for the
profile's baselines — SGEA-inferred AgentCore/Bedrock controls and the AWS Config
rules of the composed conformance packs — and fails (exit 5) on any gap.

```bash
python -I tools/sandbox_plan.py build/<profile-id> --account my-sandbox-profile \
    --var org_id=o-xxxx --var 'perimeter_cidrs=["10.0.0.0/8"]' --json-out plan.json
sgea check --out build/<profile-id> --plan plan.json
```

`tools/sandbox_plan.py` is read-only (`plan -refresh=false`, local state in a temp
dir). `--account` is an AWS CLI profile name, or `env` for the ambient credential chain;
`--region` defaults to the profile's region, then `$AWS_REGION`, then `us-east-1`.

Always also do a sandbox apply under the customer's own SCPs before production
([`docs/TESTING.md`](docs/TESTING.md)).

## Catalogs

`catalog/` is generated from `sources/` by `tools/build_catalog.py` (needs
`pip install ".[catalog]"` — openpyxl). The CLI reads the built JSON plus the SGEA-authored YAML in
`sources/inferred/` (rule dispositions, known findings).

The built catalogs are included, so you only need `build_catalog.py` to refresh them. The AWS pages and AWS Artifact
reports it reads are not redistributed with the toolkit; see the README, "Maintaining the source data".
