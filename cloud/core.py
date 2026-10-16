"""Pure fail-closed sandbox policy and exact-record DynamoDB transaction builder.

Cloud adaptation: uses KMS ECDSA rather than the reference Ed25519 format.
No compatibility claim with the v1.10 SafetyAttestation wire format.
"""
import hashlib
import json
from datetime import datetime, timezone

SCENARIOS = {
    "primary-healthy": "Primary nominal: commit one mock order across concurrent requests",
    "silent-monitor-death": "Silent monitor: switch to the authorized backup route",
    "backup-recovered": "Backup recovery: deny new orders during degraded operation",
    "untrusted-receipt": "Tampered proof: reject the modified certificate",
    "conflicting-evidence": "Evidence conflict: isolate new work",
}
GUARDS = ("AUTH", "POLICY", "CONTRACT", "CONTRACT_ACTIVE", "LEASE",
          "INCIDENT", "PROOF", "TRUST", "MODE", "ROUTE", "CANARY",
          "FRONTIER", "SAFETY")


class Denied(ValueError):
    pass


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(obj):
    return "sha256:" + hashlib.sha256(canonical(obj)).hexdigest()


def utc_now():
    return int(datetime.now(timezone.utc).timestamp())


def decision(state, canary, now):
    """Never infer FULL merely because a historical proof exists."""
    reasons = []
    if state.get("conflict") is not False:
        reasons.append("EVIDENCE_CONTRADICTION_OR_UNKNOWN")
    if state.get("mode") != "FULL" or state.get("route") != "primary":
        reasons.append("DEGRADED_BUSINESS_WRITES_FORBIDDEN")
    if state.get("allow_degraded_writes") is not False:
        reasons.append("CONTRACT_POLICY_INVALID")
    if state.get("lease_until", 0) <= now + 2:
        reasons.append("LEASE_EXPIRED")
    if (canary.get("status") != "PASS" or canary.get("expires_at", 0) <= now + 2
            or canary.get("route_revision") != state.get("route_revision")
            or canary.get("epoch") != state.get("epoch")
            or canary.get("challenge") != state.get("challenge")
            or canary.get("run_id") != state.get("run_id")):
        reasons.append("CANARY_INVALID_OR_STALE")
    return {"allowed": not reasons, "reasons": reasons}


def validate_certificate(body, state, canary, now):
    for field in ("run_id", "scenario", "mode", "route", "route_revision", "epoch",
                  "challenge", "contract_hash", "policy_hash", "conflict"):
        if body.get(field) != state.get(field):
            raise Denied("CERTIFICATE_STATE_BINDING:" + field)
    if body.get("canary_digest") != digest(canary):
        raise Denied("CANARY_DIGEST_MISMATCH")
    if (type(body.get("issued_at")) is not int or type(body.get("expires_at")) is not int
            or not body["issued_at"] <= now < body["expires_at"] - 2
            or now - body["issued_at"] > 10):
        raise Denied("CERTIFICATE_STALE_OR_FUTURE")
    current = decision(state, canary, now)
    if body.get("decision") != current:
        raise Denied("SIGNED_DECISION_MISMATCH")
    if not current["allowed"]:
        raise Denied(";".join(current["reasons"]))


def av(value):
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, int):
        return {"N": str(value)}
    if isinstance(value, str):
        return {"S": value}
    if value is None:
        return {"NULL": True}
    raise TypeError(type(value).__name__)


def build_transaction(table, run_id, records, body, now):
    """13 current-state CAS checks + claim CAS + unique mock order = 15 actions.

    Each guard is compared to its complete server-read canonical payload and
    digest. Deadline and run identity are checked by DynamoDB at commit time.
    The timestamp is supplied by the server; DynamoDB has no server-now primitive.
    """
    if set(records) != set(GUARDS):
        raise Denied("INCOMPLETE_GUARD_SET")
    tx = []
    for name in GUARDS:
        rec = records[name]
        if rec.get("run_id") != run_id or rec.get("expires_at", 0) <= now + 2:
            raise Denied("GUARD_EXPIRED_OR_SCOPE_INVALID:" + name)
        if rec.get("digest") != digest(json.loads(rec["payload"])):
            raise Denied("GUARD_DIGEST_INVALID:" + name)
        tx.append({"ConditionCheck": {
            "TableName": table, "Key": {"PK": av(name + "#" + run_id), "SK": av("STATE")},
            "ConditionExpression": "#p = :p AND #d = :d AND run_id = :r AND expires_at > :n",
            "ExpressionAttributeNames": {"#p": "payload", "#d": "digest"},
            "ExpressionAttributeValues": {":p": av(rec["payload"]), ":d": av(rec["digest"]),
                                          ":r": av(run_id), ":n": av(now + 2)},
        }})
    if json.loads(records["SAFETY"]["payload"])["body_digest"] != digest(body):
        raise Denied("SAFETY_INDEX_MISMATCH")
    tx.append({"Update": {
        "TableName": table, "Key": {"PK": av("CLAIM#" + run_id), "SK": av("STATE")},
        "UpdateExpression": "SET #s = :c",
        "ConditionExpression": "#s = :r AND run_id = :id AND expires_at > :n",
        "ExpressionAttributeNames": {"#s": "status"},
        "ExpressionAttributeValues": {":c": av("COMMITTED"), ":r": av("RESERVED"),
                                      ":id": av(run_id), ":n": av(now + 2)},
    }})
    tx.append({"Put": {
        "TableName": table,
        "Item": {"PK": av("ORDER#" + run_id), "SK": av("STATE"), "run_id": av(run_id),
                 "kind": av("MOCK_NO_PAYMENT"), "certificate_digest": av(digest(body)),
                 "created_at": av(now), "expires_at": av(now + 86400)},
        "ConditionExpression": "attribute_not_exists(PK)",
    }})
    return {"TransactItems": tx}
