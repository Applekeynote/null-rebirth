import copy
import pytest
from cloud import containment, healing, sandbox
from cloud.incidents import INCIDENTS
from cloud.core import Denied, digest
from tests_cloud.heal_fake import FakeRuntime
from tests_cloud.test_healing import to_verifying

SECURITY = [i for i in INCIDENTS if i.get("mode") == "containment"]


@pytest.mark.parametrize("incident", SECURITY, ids=lambda i: i["id"])
def test_denial_has_no_records_preserves_evidence_and_keeps_legitimate_read(incident):
    broken = sandbox.inject(sandbox.baseline(), incident["id"])
    gate = incident["fault"]
    assert containment.challenges(broken, gate, "BEFORE")["denied"] == 0
    saved = containment.evidence(broken)
    fixed, _ = sandbox.repair(broken, incident["runbook"])
    assert saved == containment.evidence(fixed)
    for challenge in ("AFTER", "DIFFERENT", "RETRY"):
        result = containment.challenges(fixed, gate, challenge)
        assert result == {"denied": 3, "attempted": 3, "legitimate_read": True}
    assert containment.access(fixed, gate, "unknown-principal")["records"] == []


@pytest.mark.parametrize("incident", SECURITY, ids=lambda i: i["id"])
def test_signature_requires_preserved_detection_evidence_and_persisted_dialogue(monkeypatch, incident):
    rt = FakeRuntime()
    state = to_verifying(rt, monkeypatch, incident["id"])
    evidence = copy.deepcopy(state["containment_evidence"])
    healing.attest(rt, state)
    normalized = healing.normalize(rt, state)
    assert normalized["verification"]["containment"]["denied"] == 3
    assert normalized["verification"]["evidence_preserved"]
    complete = healing.advance(rt, dict(run_id=state["run_id"], revision=normalized["revision"]))
    assert complete["containment_evidence"] == evidence
    assert {e["speaker"] for e in complete["dialogue"]} == {"PATCH", "LOG"}
    assert complete["dialogue"][-1]["text"] == complete["report"]
    assert any("not recovered" in e["text"] for e in complete["dialogue"])


def test_evidence_replacement_cannot_get_a_healthy_seal(monkeypatch):
    rt = FakeRuntime()
    state = to_verifying(rt, monkeypatch, SECURITY[0]["id"])
    env = rt.payload(state["run_id"], "WORKLOAD")
    env["security_events"] = []
    rt.record(state["run_id"], "WORKLOAD", env, healing.utc_now()+120, create=False)
    assert not healing.attest(rt, state)["body"]["healthy"]
    with pytest.raises(Denied):
        healing.normalize(rt, state)


@pytest.mark.parametrize("gate,policy", [
    ("member_api", {"required_scope":"ungranted:read", "anonymous_read":False}),
    ("app_members", {"allowed_origins":[]}),
    ("vendor_endpoint", {"quarantined_devices":["service-pc.lab", "vendor-pc.lab"], "vendor_access":False}),
    ("document_gateway", {"audiences":[], "external_download":False}),
    ("member_export", {"revoked_sessions":["trusted-session.lab", "compromised-session.lab"], "bulk_export":False}),
])
def test_blocking_everyone_is_not_successful_containment(gate, policy):
    env = sandbox.baseline()
    env["security_policy"][gate] = policy
    result = containment.challenges(env, gate, "CONTROL")
    assert result["denied"] == 3
    assert result["legitimate_read"] is False
    assert sandbox.probe(env)["failed"] == [gate]
