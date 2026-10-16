"""Synthetic access-control laboratory. No external requests or customer data.

These are bounded defensive adaptations of disclosed incidents, not reconstructions
of undisclosed vulnerabilities. Every probe executes the same access handler before
and after a persisted policy change, including a legitimate-reader control.
"""
import copy
from cloud.core import digest

GATES = {
    "member_api": ("EDGE", "scoped_auth"),
    "app_members": ("NETWORK", "origin_allowlist"),
    "vendor_endpoint": ("COMPUTE", "device_isolation"),
    "document_gateway": ("DATA", "document_boundary"),
    "member_export": ("IDENTITY", "session_revocation"),
}
MOCK_RECORDS = ["SYNTHETIC-001", "SYNTHETIC-002", "SYNTHETIC-003"]


def baseline():
    return {
        "member_api": {"required_scope": "member:read", "anonymous_read": False},
        "app_members": {"allowed_origins": ["trusted-app.lab"]},
        "vendor_endpoint": {"quarantined_devices": ["vendor-pc.lab"], "vendor_access": False},
        "document_gateway": {"audiences": ["trusted-service.lab"], "external_download": False},
        "member_export": {"revoked_sessions": ["compromised-session.lab"], "bulk_export": False},
    }


def access(env, gate, actor, variant="A"):
    """Execute a tiny service request; a denial must actually return no records."""
    policy = env["security_policy"][gate]
    trusted = actor == "trusted-reader"
    if actor not in ("trusted-reader", "unscoped-client", "untrusted-origin", "compromised-device",
                     "external-document-reader", "revoked-session"):
        return {"status": 403, "records": []}
    expected_actor = dict(zip(GATES, ("unscoped-client", "untrusted-origin", "compromised-device",
                                   "external-document-reader", "revoked-session")))[gate]
    if not trusted and actor != expected_actor:
        return {"status": 403, "records": []}
    if gate == "member_api":
        scopes = ["member:read"] if trusted else []
        allowed = policy.get("anonymous_read", False) or policy.get("required_scope") is None or policy["required_scope"] in scopes
    elif gate == "app_members":
        origin = "trusted-app.lab" if trusted else "untrusted-origin.lab"
        allowed = origin in policy.get("allowed_origins", []) or "*" in policy.get("allowed_origins", [])
    elif gate == "vendor_endpoint":
        device = "service-pc.lab" if trusted else "vendor-pc.lab"
        allowed = device not in policy.get("quarantined_devices", []) and (trusted or policy.get("vendor_access", False))
    elif gate == "document_gateway":
        audience = "trusted-service.lab" if trusted else "external.lab"
        allowed = (audience in policy.get("audiences", []) or "*" in policy.get("audiences", [])) and (trusted or policy.get("external_download", False))
    else:
        session = "trusted-session.lab" if trusted else "compromised-session.lab"
        allowed = session not in policy.get("revoked_sessions", []) and (trusted or policy.get("bulk_export", False))
    if not allowed:
        return {"status": 403, "records": []}
    # Different challenges request a different synthetic record subset.
    index = sum(map(ord, variant)) % len(MOCK_RECORDS)
    return {"status": 200, "records": MOCK_RECORDS[index:]}


def challenges(env, gate, challenge):
    actor = dict(zip(GATES, ("unscoped-client", "untrusted-origin", "compromised-device",
                            "external-document-reader", "revoked-session")))[gate]
    attacks = [access(env, gate, actor, challenge + str(n)) for n in range(3)]
    legitimate = access(env, gate, "trusted-reader", challenge)
    return dict(denied=sum(r["status"] == 403 and not r["records"] for r in attacks),
                attempted=len(attacks), legitimate_read=legitimate["status"] == 200 and bool(legitimate["records"]))


def inject(env, gate):
    e = copy.deepcopy(env)
    unsafe = {
        "member_api": {"required_scope": None, "anonymous_read": True},
        "app_members": {"allowed_origins": ["*"]},
        "vendor_endpoint": {"quarantined_devices": [], "vendor_access": True},
        "document_gateway": {"audiences": ["*"], "external_download": True},
        "member_export": {"revoked_sessions": [], "bulk_export": True},
    }
    e["security_policy"][gate] = unsafe[gate]
    e["security_events"] = [dict(sequence=n, gate=gate, signal="SYNTHETIC_UNAUTHORIZED_READ",
                                 result=challenges(e, gate, "DETECT" + str(n))) for n in range(3)]
    return e


def evidence(env):
    return dict(events=copy.deepcopy(env["security_events"]),
                events_digest=digest(env["security_events"]), synthetic_only=True)
