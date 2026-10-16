import copy
import json
import pytest
from cloud.core import (GUARDS, Denied, canonical, digest, decision,
                        build_transaction, validate_certificate)

NOW = 1791850000
RUN = "run-" + "a" * 32


def state():
    return {"run_id": RUN, "scenario": "primary-healthy", "mode": "FULL", "route": "primary",
            "route_revision": 1, "epoch": 1, "challenge": "nonce", "lease_until": NOW + 120,
            "conflict": False, "allow_degraded_writes": False,
            "contract_hash": "sha256:" + "a" * 64, "policy_hash": "policy"}


def canary():
    return {"run_id": RUN, "status": "PASS", "expires_at": NOW + 120, "epoch": 1,
            "route_revision": 1, "challenge": "nonce"}


def certificate(s=None, c=None):
    s, c = s or state(), c or canary()
    body = {k: s[k] for k in ("run_id", "scenario", "mode", "route", "route_revision",
                             "epoch", "challenge", "contract_hash", "policy_hash", "conflict")}
    body.update(issued_at=NOW, expires_at=NOW + 60, canary_digest=digest(c), decision=decision(s, c, NOW))
    return body


@pytest.mark.parametrize("field,value", [("mode", "DEGRADED"), ("route", "backup"),
    ("conflict", True), ("lease_until", NOW), ("mode", "UNKNOWN"), ("allow_degraded_writes", True)])
def test_never_resume_unsafe_state(field, value):
    s = state()
    s[field] = value
    assert not decision(s, canary(), NOW)["allowed"]


@pytest.mark.parametrize("field,value", [("status", "UNKNOWN"), ("expires_at", NOW + 2),
    ("epoch", 0), ("route_revision", 2), ("challenge", "other"), ("run_id", "other")])
def test_stale_or_wrong_canary_never_resume(field, value):
    c = canary()
    c[field] = value
    assert not decision(state(), c, NOW)["allowed"]


def test_current_valid_state_accepts_and_proof_replay_expires():
    validate_certificate(certificate(), state(), canary(), NOW)
    with pytest.raises(Denied, match="STALE"):
        validate_certificate(certificate(), state(), canary(), NOW + 11)


@pytest.mark.parametrize("field,value", [("run_id", "other"), ("route_revision", 2),
    ("epoch", 2), ("challenge", "old"), ("conflict", True), ("policy_hash", "other"),
    ("contract_hash", "other"), ("mode", "DEGRADED")])
def test_certificate_scope_and_generation_bound(field, value):
    body = certificate()
    body[field] = value
    with pytest.raises(Denied, match="BINDING"):
        validate_certificate(body, state(), canary(), NOW)


def records():
    out = {}
    for name in GUARDS:
        body = {"guard": name}
        if name == "SAFETY":
            body = {"body_digest": digest(certificate())}
        out[name] = {"run_id": RUN, "expires_at": NOW + 120,
                     "payload": canonical(body).decode(), "digest": digest(body)}
    return out


def test_transaction_is_fifteen_unique_atomic_records():
    tx = build_transaction("sandbox", RUN, records(), certificate(), NOW)
    assert len(tx["TransactItems"]) == 15
    identities = []
    for x in tx["TransactItems"]:
        action = next(iter(x.values()))
        key = action.get("Key", action.get("Item"))
        identities.append((key["PK"]["S"], key["SK"]["S"]))
    assert len(set(identities)) == 15
    assert tx["TransactItems"][-1]["Put"]["ConditionExpression"] == "attribute_not_exists(PK)"


@pytest.mark.parametrize("guard", GUARDS)
def test_expired_guard_prevents_transaction(guard):
    r = records()
    r[guard]["expires_at"] = NOW + 2
    with pytest.raises(Denied, match="EXPIRED"):
        build_transaction("sandbox", RUN, r, certificate(), NOW)


def test_digest_tampering_rejected():
    r = records()
    r["AUTH"]["payload"] = '{"decision":"ALLOW"}'
    with pytest.raises(Denied, match="DIGEST"):
        build_transaction("sandbox", RUN, r, certificate(), NOW)
