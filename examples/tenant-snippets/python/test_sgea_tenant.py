# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Offline self-test for sgea_tenant (no AWS calls). Run: python3 -m pytest"""
import base64
import json
import os
import sys

os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("SGEA_MODEL_ID", "test-model")
os.environ.setdefault("SGEA_GUARDRAIL_ID", "test-guardrail")
os.environ.setdefault("SGEA_GUARDRAIL_VERSION", "1")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402
from botocore.stub import Stubber  # noqa: E402

import sgea_tenant  # noqa: E402


def _jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"


def test_caller_from_jwt_list_claim():
    assert sgea_tenant.caller_from_jwt("Bearer " + _jwt({"sub": "u-1", "cognito:groups": ["team-a", "b"]})) == ("u-1", "team-a")


def test_caller_from_jwt_string_and_custom_claim():
    assert sgea_tenant.caller_from_jwt(_jwt({"sub": "u-2", "team": "team-b"}), team_claim="team") == ("u-2", "team-b")


def test_caller_from_jwt_missing_or_bad():
    assert sgea_tenant.caller_from_jwt("Bearer " + _jwt({"sub": "u-3", "cognito:groups": 5})) == ("u-3", None)
    assert sgea_tenant.caller_from_jwt("Bearer not-a-jwt") == (None, None)
    assert sgea_tenant.caller_from_jwt("") == (None, None)


def test_log_outcome_drops_non_allow_listed(capsys):
    sgea_tenant.log_outcome("turn", {"status": "ok", "blocked": False, "answer_chars": 12,
                                     "prompt": "secret", "answer": "secret", "token": "x", "arguments": {}})
    line = json.loads(capsys.readouterr().out.strip())
    assert line == {"event": "turn", "status": "ok", "blocked": False, "answer_chars": 12}


def test_gateway_call_refuses_http(monkeypatch):
    monkeypatch.setenv("SGEA_GATEWAY_URL", "http://gateway.example.com/mcp")
    with pytest.raises(ValueError):
        sgea_tenant.gateway_call("tools/list", {}, "u", "t")


def _converse_response(stop, text):
    return {"output": {"message": {"role": "assistant", "content": [{"text": text}]}}, "stopReason": stop,
            "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2}, "metrics": {"latencyMs": 1}}


def _expected(prompt, meta=None):
    req = {"modelId": "test-model",
           "messages": [{"role": "user", "content": [{"guardContent": {"text": {"text": prompt}}}]}],
           "system": sgea_tenant.SYSTEM,
           "guardrailConfig": {"guardrailIdentifier": "test-guardrail", "guardrailVersion": "1", "trace": "enabled"}}
    if meta:
        req["requestMetadata"] = meta
    return req


def test_converse_builds_guard_content_and_metadata():
    with Stubber(sgea_tenant.runtime) as stub:
        stub.add_response("converse", _converse_response("end_turn", "hello"),
                          _expected("hi", {"sgea_user": "u-1", "sgea_team": "team-a"}))
        assert sgea_tenant.converse("hi", "u-1", "team-a") == {"answer": "hello", "blocked": False, "stopReason": "end_turn"}
        stub.assert_no_pending_responses()


def test_converse_omits_metadata_and_reports_block():
    with Stubber(sgea_tenant.runtime) as stub:
        stub.add_response("converse", _converse_response("guardrail_intervened", "Blocked by enclave."), _expected("bad"))
        out = sgea_tenant.converse("bad", None, "")
        assert out == {"answer": "Blocked by enclave.", "blocked": True, "stopReason": "guardrail_intervened"}


def test_record_turn_skips_without_memory(monkeypatch):
    monkeypatch.delenv("SGEA_MEMORY_ID", raising=False)
    assert sgea_tenant.record_turn("s" * 40, "actor", "q", "a") is None
