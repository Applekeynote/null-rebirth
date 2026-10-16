import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "source"))
from cloud import healing, sandbox, runtime
from cloud.incidents import INCIDENTS, CATALOG
from cloud.core import Denied, digest
from cloud.template import generate
from tests_cloud.heal_fake import FakeRuntime


@pytest.mark.parametrize("incident", INCIDENTS, ids=lambda i: i["id"])
def test_distinct_fault_changes_behavior_and_repair_restores_it(incident):
    good = sandbox.baseline()
    assert sandbox.probe(good)["healthy"]
    broken = sandbox.inject(good, incident["id"])
    observed = sandbox.probe(broken)
    assert observed["failed"] == [incident["fault"]]
    assert broken != good
    repaired, delta = sandbox.repair(broken, incident["runbook"])
    assert delta and broken != repaired and (good == repaired if incident.get("mode") != "containment" else repaired["security_policy"] == good["security_policy"])
    for challenge in ("A", "B", "C", "D"):
        assert sandbox.probe(repaired, challenge)["passed_count"] == sandbox.CHECK_TOTAL


def test_wrong_runbooks_and_untrusted_snapshots_fail_closed():
    for incident in INCIDENTS:
        env = sandbox.inject(sandbox.baseline(), incident["id"])
        for runbook in sandbox.RUNBOOKS:
            if runbook != incident["runbook"]:
                with pytest.raises(Denied):
                    sandbox.repair(env, runbook)
    for incident, field in (("lost-database", "snapshot"), ("deleted-tenant", "tenant_snapshot")):
        env = sandbox.inject(sandbox.baseline(), incident)
        env[field] = {"untrusted": True}
        with pytest.raises(Denied):
            sandbox.repair(env, CATALOG[incident]["runbook"])


def test_model_output_has_no_execution_authority():
    observed = sandbox.probe(sandbox.inject(sandbox.baseline(), "regex-exhaustion"))
    for plan in ({"runbook": "rm -rf /"}, {"runbook": "RESTORE_IDENTITY_QUOTA", "diagnosis": "wrong", "reason": "wrong"},
                 {"runbook": "ROLLBACK_WAF_RULE", "diagnosis": "ok", "reason": "ok", "command": "bash"}):
        with pytest.raises(Denied):
            sandbox.validate_plan(plan, observed)


def fake_model(rt, system, data, max_tokens=384):
    usage = {"model": "UNIT_TEST_FIXTURE", "inputTokens": 1, "outputTokens": 1}
    if "runbooks" in data:
        target = data["checks"][0]["id"]
        runbook = next(k for k, v in sandbox.RUNBOOKS.items() if v["target"] == target)
        return json.dumps(dict(runbook=runbook, diagnosis="The observed functional check failed.", reason="This runbook addresses the observed failure.")), usage
    return "I confirmed 25 passing checks after the scoped repair in the disposable lab.", usage


def to_verifying(rt, monkeypatch, incident="regex-exhaustion"):
    monkeypatch.setattr(healing, "model_call", fake_model)
    state = healing.start(rt, {"scenario": incident});run = state["run_id"]
    healing.observe(rt, {"run_id": run})
    while state["phase"] != "VERIFYING":
        state = healing.advance(rt, {"run_id": run, "revision": state["revision"]})
        if state["phase"] == "ANOMALY":
            healing.observe(rt, {"run_id": run})
    return state


@pytest.mark.parametrize("incident", list(CATALOG))
def test_workflow_requires_independent_signature_and_replay_is_idempotent(monkeypatch, incident):
    rt = FakeRuntime();state = to_verifying(rt, monkeypatch, incident);run = state["run_id"]
    old_revision = state["revision"]
    with pytest.raises(Denied):
        healing.normalize(rt, {"run_id": run})
    seal = healing.attest(rt, {"run_id": run})
    assert seal["body"]["healthy"]
    normalized = healing.normalize(rt, {"run_id": run})
    assert normalized["phase"] == "NORMALIZED"
    assert normalized["verification"]["kms_signature_verified"]
    tx_count = rt.transactions
    assert healing.normalize(rt, {"run_id": run}) == normalized
    assert rt.transactions == tx_count
    assert healing.advance(rt, {"run_id": run, "revision": old_revision}) == normalized
    complete = healing.advance(rt, {"run_id": run, "revision": normalized["revision"]})
    assert complete["phase"] == "COMPLETE" and complete["report"]
    assert [h["phase"] for h in complete["history"]] == ["NORMAL", "ANOMALY", "WARNING", "DIAGNOSING", "REPAIR_READY", "REPAIRING", "VERIFYING", "NORMALIZED", "REPORTING", "COMPLETE"]
    assert not any(name == "ORDER" for run, name in rt.items)


@pytest.mark.parametrize("tamper", ["signature", "workload", "scope", "expired"])
def test_tampering_or_stale_evidence_never_normalizes(monkeypatch, tamper):
    rt = FakeRuntime();state = to_verifying(rt, monkeypatch);run = state["run_id"]
    seal = healing.attest(rt, {"run_id": run})
    if tamper == "signature":
        rt.signature_valid = False
    elif tamper == "workload":
        rt.record(run, "WORKLOAD", sandbox.inject(sandbox.baseline(), "identity-quota"), healing.utc_now()+120, create=False)
    else:
        seal["body"]["run_id" if tamper == "scope" else "expires_at"] = "run-" + "f"*32 if tamper == "scope" else 1
        rt.record(run, "HEALSEAL", seal, healing.utc_now()+120, create=False)
    with pytest.raises(Denied):
        healing.normalize(rt, {"run_id": run})
    assert rt.payload(run, "HEAL")["phase"] == "VERIFYING"


def test_unavailable_ai_does_not_apply_a_fixed_fallback(monkeypatch):
    rt = FakeRuntime();state = healing.start(rt, {"scenario": "lost-database"});run=state["run_id"]
    state = healing.advance(rt, {"run_id": run, "revision": state["revision"]})
    healing.observe(rt, {"run_id": run})
    state = healing.advance(rt, {"run_id": run, "revision": state["revision"]})
    def unavailable(*a, **k):
        raise Denied("AI_UNAVAILABLE:AccessDeniedException")
    monkeypatch.setattr(healing, "model_call", unavailable)
    state = healing.advance(rt, {"run_id": run, "revision": state["revision"]})
    assert state["phase"] == "BLOCKED" and "verification" not in state
    assert rt.payload(run, "WORKLOAD")["database"] == {}
    assert rt.payload(run, "HEAL")["repair_capability"] == "ISSUED"


@pytest.mark.parametrize("correct_second", [True, False])
def test_rejected_model_plan_gets_bounded_feedback_without_repair(monkeypatch, correct_second):
    rt=FakeRuntime();state=healing.start(rt,{"scenario":"dns-withdrawal"});run=state["run_id"]
    state=healing.advance(rt,{"run_id":run,"revision":state["revision"]})
    healing.observe(rt,{"run_id":run})
    state=healing.advance(rt,{"run_id":run,"revision":state["revision"]})
    faulty=rt.payload(run,"WORKLOAD")
    calls=[]
    def proposing(rt, system, data, max_tokens=384):
        calls.append(copy.deepcopy(data))
        assert rt.payload(run,"WORKLOAD")==faulty
        if len(calls)>1:
            assert data["validator_feedback"]["failed_check_ids"]==["dns"]
            assert data["validator_feedback"]["rejected_target"]=="deployment"
        if correct_second and len(calls)>1:
            return fake_model(rt,system,data,max_tokens)
        return json.dumps(dict(runbook="RESTORE_PRODUCTION_ROUTE",diagnosis="Wrong proposal",reason="Wrong component match")),{"model":"UNIT_TEST_FIXTURE"}
    monkeypatch.setattr(healing,"model_call",proposing)
    state=healing.advance(rt,{"run_id":run,"revision":state["revision"]})
    assert rt.payload(run,"WORKLOAD")==faulty
    assert rt.payload(run,"HEAL")["repair_capability"]=="ISSUED"
    assert len(calls)==(2 if correct_second else 3)
    assert len(state["diagnosis_attempts"])==len(calls)
    assert state["phase"]==("REPAIR_READY" if correct_second else "BLOCKED")
    assert state["diagnosis_attempts"][0]["accepted"] is False
    assert len(state["ai_usage"])==len(calls)


def test_current_state_cas_rejects_replayed_repair(monkeypatch):
    rt=FakeRuntime();state=to_verifying(rt, monkeypatch);run=state["run_id"]
    stale=rt.get(run,"HEAL");body=rt.payload(run,"HEAL")
    healing.attest(rt,{"run_id":run});healing.normalize(rt,{"run_id":run})
    with pytest.raises(Denied,match="CAS_REJECTED"):
        healing.transition(rt,run,stale,body,"WARNING")


def test_budget_model_scope_and_no_infrastructure_mutation():
    r=generate()["Resources"]
    assert len(r)==32
    for role in ("RecoveryRole","ApiRole","BootstrapRole","WitnessRole","VerifierRole","CommitRole"):
        statements=r[role]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        assert all(not any(a.startswith(("ec2:","cloudformation:","iam:","scheduler:","s3:")) for a in s["Action"]) for s in statements)
        model=[s for s in statements if "bedrock:InvokeModel" in s["Action"]]
        assert len(model)==(1 if role=="RecoveryRole" else 0)
        if model:
            assert model[0]["Resource"]=={"Fn::Sub":"arn:${AWS::Partition}:bedrock:us-east-1::foundation-model/amazon.nova-micro-v1:0"}
    assert r["ShutdownSchedule"]["Properties"]["ScheduleExpression"]=="cron(0 20 1,2 12 ? 2026)"


def test_ai_cost_quota_is_consumed_before_model_request_and_cannot_be_bypassed(monkeypatch):
    rt=FakeRuntime();rt.counters["CONTROL#AI"]=600
    monkeypatch.setattr(healing.boto3,"client",lambda *a,**kw:pytest.fail("Quota exhausted but model invoked"))
    with pytest.raises(Denied,match="QUOTA_EXHAUSTED"):
        healing.model_call(rt,"system",{"checks":[]})
    assert rt.counters["CONTROL#AI"]==600


def test_model_request_is_bounded_and_partial_output_is_rejected(monkeypatch):
    rt=FakeRuntime();calls=[]
    def converse(**kwargs):
        calls.append(kwargs)
        return {"stopReason":"max_tokens","output":{"message":{"content":[{"text":"partial"}]}},"usage":{}}
    def client(service,**kwargs):
        assert service=="bedrock-runtime" and kwargs["region_name"]=="us-east-1"
        assert kwargs["config"].retries=={"total_max_attempts":1}
        return SimpleNamespace(converse=converse)
    monkeypatch.setattr(healing.boto3,"client",client)
    with pytest.raises(Denied,match="AI_RESPONSE_INCOMPLETE"):
        healing.model_call(rt,"system",{"checks":[]})
    assert calls[0]["modelId"]=="amazon.nova-micro-v1:0"
    assert calls[0]["inferenceConfig"]["maxTokens"]==384 and rt.counters["CONTROL#AI"]==1
    with pytest.raises(Denied,match="AI_INPUT_BUDGET_EXCEEDED"):
        healing.model_call(rt,"system",{"data":"x"*24001})
    assert len(calls)==1
