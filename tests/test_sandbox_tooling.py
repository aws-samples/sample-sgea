# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Tests for the sandbox tooling's credential handling (tools/sandbox_teardown.py, tools/sandbox_plan.py) and the
syntax of the sandbox shell scripts.

Runs two ways:
  - pytest:            pytest -q
  - no dependencies:   python tests/test_sandbox_tooling.py

No AWS calls and no credentials: subprocess and boto3 are replaced by fakes.
"""
import builtins, os, subprocess, sys, tempfile, types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
sys.path.insert(0, ROOT)
sys.path.insert(0, TOOLS)

import sandbox_teardown as td  # noqa: E402
import sandbox_plan  # noqa: E402

SHELL_SCRIPTS = ["examples/run_sandbox_test.sh", "tools/sandbox_matrix.sh", "tools/bootstrap_sdk.sh"]
A1, A2 = "1" * 12, "2" * 12          # two distinct 12-digit account ids (built, not written out)
CRED_MODES = ["sandbox", "env"]       # one <credentials> value per mode
AMBIENT = {"AWS_ACCESS_KEY_ID": "AKIDEXAMPLE", "AWS_SECRET_ACCESS_KEY": "secret", "AWS_SESSION_TOKEN": "tok",
           "AWS_REGION": "eu-west-1", "PATH": "/usr/bin"}


def _no_run(*a, **k):
    raise AssertionError("no subprocess expected for this credential mode")


class _Done:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def _aws_config(text):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "config")
    open(p, "w").write(text)
    return p


# ---- credential-mode selection ------------------------------------------------------------------
def test_mode_name_is_profile():
    for name in ("sandbox", "default", "my-org-admin", "envx", "ENV"):
        assert td.credential_mode(name) == "profile", name


def test_mode_env_is_ambient():
    assert td.credential_mode("env") == "env"


def test_mode_empty_is_rejected():
    for bad in ("", "   ", None):
        try:
            td.credential_mode(bad)
        except SystemExit as e:
            assert "profile" in str(e)
        else:
            raise AssertionError("accepted %r" % bad)


# ---- environment per mode -----------------------------------------------------------------------
def test_env_mode_keeps_ambient_credentials():
    env = td.credential_env("env", "us-east-1", environ=dict(AMBIENT), run=_no_run)
    assert env["AWS_ACCESS_KEY_ID"] == "AKIDEXAMPLE" and env["AWS_SESSION_TOKEN"] == "tok"
    assert "AWS_PROFILE" not in env
    assert env["AWS_REGION"] == env["AWS_DEFAULT_REGION"] == "us-east-1"


def test_env_mode_without_region_changes_nothing():
    assert td.credential_env("env", None, environ=dict(AMBIENT), run=_no_run) == AMBIENT


def test_profile_mode_sets_aws_profile_and_drops_static_keys():
    env = td.credential_env("sandbox", "us-east-1", environ=dict(AMBIENT), run=_no_run)
    assert env["AWS_PROFILE"] == "sandbox"
    for k in td.STATIC_KEYS:
        assert k not in env, k
    assert env["AWS_REGION"] == env["AWS_DEFAULT_REGION"] == "us-east-1"
    assert env["PATH"] == "/usr/bin"


def test_profile_mode_region_from_profile_when_not_given():
    cfg = _aws_config("[default]\nregion = ap-south-1\n[profile sandbox]\nregion = us-west-2\n[profile bare]\noutput = json\n")
    environ = dict(AMBIENT, AWS_CONFIG_FILE=cfg)
    assert td.credential_env("sandbox", None, environ=environ, run=_no_run)["AWS_REGION"] == "us-west-2"
    assert td.credential_env("default", None, environ=environ, run=_no_run)["AWS_REGION"] == "ap-south-1"
    # an explicit (resolved primary) region always wins over the profile's
    assert td.credential_env("sandbox", "us-east-1", environ=environ, run=_no_run)["AWS_REGION"] == "us-east-1"
    assert td.profile_region("bare", environ) is None and td.profile_region("missing", environ) is None


def test_plan_region_resolution():
    cfg = _aws_config("[profile sandbox]\nregion = us-west-2\n")
    environ = {"AWS_CONFIG_FILE": cfg}
    assert sandbox_plan.resolve_region("sandbox", "eu-central-1", environ) == "eu-central-1"
    assert sandbox_plan.resolve_region("sandbox", None, environ) == "us-west-2"
    assert sandbox_plan.resolve_region("other", None, dict(environ, AWS_REGION="eu-west-1")) == "eu-west-1"
    assert sandbox_plan.resolve_region("env", None, {"AWS_DEFAULT_REGION": "ca-central-1"}) == "ca-central-1"
    assert sandbox_plan.resolve_region("env", None, {}) == "us-east-1"


# ---- SDK directory ------------------------------------------------------------------------------
def test_sdk_dir_used_only_if_present():
    d = tempfile.mkdtemp()
    path = ["/x"]
    assert td.use_sdk_dir({"SGEA_BOTO": d}, path) == d and path == [d, "/x"]
    assert td.use_sdk_dir({"SGEA_BOTO": d}, path) == d and path == [d, "/x"]   # not inserted twice
    path = ["/x"]
    assert td.use_sdk_dir({"SGEA_BOTO": os.path.join(d, "missing")}, path) is None and path == ["/x"]


# ---- teardown account guard (all three modes) ---------------------------------------------------
def _fake_sdk(account, services=("sts", "bedrock-agentcore-control")):
    boto3 = types.ModuleType("boto3")
    sess = types.SimpleNamespace(get_available_services=lambda: list(services))
    boto3.session = types.SimpleNamespace(Session=lambda: sess)

    def client(name, **kw):
        assert name == "sts", "only sts may be called before the confirmation (got %s)" % name
        return types.SimpleNamespace(get_caller_identity=lambda: {"Account": account})
    boto3.client = client
    botocore = types.ModuleType("botocore")
    botocore.__version__, botocore.__file__ = "0.0-test", "/nowhere/botocore/__init__.py"
    return boto3, botocore


def _teardown(creds, cred_account, account_id, typed=None, services=("sts", "bedrock-agentcore-control")):
    """Run sandbox_teardown.main up to the guard; return the SystemExit message."""
    boto3, botocore = _fake_sdk(cred_account, services)
    saved_env, saved_mods = dict(os.environ), {k: sys.modules.get(k) for k in ("boto3", "botocore")}
    saved_input, saved_run, saved_attrs = builtins.input, td.subprocess.run, dict(vars(td))
    prompts = []
    try:
        sys.modules["boto3"], sys.modules["botocore"] = boto3, botocore
        os.environ["SGEA_BOTO"] = os.path.join(tempfile.mkdtemp(), "no-sdk-dir")
        builtins.input = lambda msg="": prompts.append(msg) or (typed if typed is not None else "")
        td.subprocess.run = _no_run
        try:
            td.main(["--account", creds, "--account-id", account_id])
        except SystemExit as e:
            return str(e), prompts
        raise AssertionError("teardown did not stop at the guard")
    finally:
        os.environ.clear(); os.environ.update(saved_env)
        for k, v in saved_mods.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
        builtins.input, td.subprocess.run = saved_input, saved_run
        vars(td).update(saved_attrs)


def test_teardown_refuses_wrong_account_in_every_mode():
    for creds in CRED_MODES:
        msg, prompts = _teardown(creds, A1, A2)
        assert msg == "refusing: credentials are for %s, not %s" % (A1, A2), (creds, msg)
        assert prompts == [], creds   # refused before the confirmation prompt


def test_teardown_requires_typed_account_id_in_every_mode():
    for creds in CRED_MODES:
        msg, prompts = _teardown(creds, A1, A1, typed=A1[:-1])
        assert msg == "aborted" and len(prompts) == 1 and A1 in prompts[0], (creds, msg)


def test_teardown_fails_before_credentials_without_agentcore_sdk():
    msg, prompts = _teardown("sandbox", A1, A1, services=("sts",))
    assert "bedrock-agentcore-control" in msg and "bootstrap_sdk.sh" in msg and prompts == []


# ---- distribution hygiene + shell syntax --------------------------------------------------------
def test_shell_scripts_parse():
    for f in SHELL_SCRIPTS:
        r = subprocess.run(["bash", "-n", os.path.join(ROOT, f)], capture_output=True, text=True)  # nosec B603 B607
        assert r.returncode == 0, "%s: %s" % (f, r.stderr)


def test_shell_usage_names_credentials():
    for f in ("examples/run_sandbox_test.sh", "tools/sandbox_matrix.sh"):
        s = open(os.path.join(ROOT, f)).read()
        assert "<credentials>" in s and 'CRED_KINDS="aws-profile | env"' in s and "<credentials: $CRED_KINDS>" in s, f


def _run():
    fns = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for n, f in fns:
        try:
            f(); passed += 1; print("  PASS  " + n)
        except Exception as e:  # noqa: BLE001
            failed += 1; print("  FAIL  " + n + "  -> " + repr(e))
    print("\n%d passed, %d failed, %d total" % (passed, failed, len(fns)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())


def test_run_sandbox_test_quota_preflight_snippet_runs():
    """The Python embedded in run_sandbox_test.sh's quota preflight must run against the current emitters."""
    import contextlib, io, re
    src = open(os.path.join(ROOT, "examples", "run_sandbox_test.sh")).read()
    code = re.search(r'NEED=\$\(python3 -c "\n(.*?)"\)', src, re.S).group(1)
    code = code.replace("$PROFILE", "profiles/fedramp-moderate-hitrust.commercial.json")
    out, cwd = io.StringIO(), os.getcwd()
    try:
        os.chdir(ROOT)
        with contextlib.redirect_stdout(out):
            exec(compile(code, "run_sandbox_test.sh:preflight", "exec"), {"__name__": "preflight"})  # nosec B102 - repo-local snippet under test
    finally:
        os.chdir(cwd)
    assert int(out.getvalue().strip()) >= 0
