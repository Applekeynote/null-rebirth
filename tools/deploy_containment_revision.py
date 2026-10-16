"""Code-only update of the seven named artwork Lambdas; no IAM/S3/stack writes.

Run in the account's existing CloudShell working directory. The expected old
release is immutable; failures roll back functions already changed. The script
never outputs credentials and writes only a private local backup and evidence.
"""
import argparse
import base64
import hashlib
import io
import os
import json
import os
import time
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import boto3

PREFIX = "null-rebirth-v110"
ACCOUNT = os.environ.get("NR_ACCOUNT_ID", "NOT_CONFIGURED")
OLD = "e347ff9afb0f39c172f8b1a149f20d5bc113054a5ef3803aa42c43d1c21af5b4"
ROLES = ("bootstrap", "witness", "recovery", "verifier", "commit", "api", "janitor")
SESSION = boto3.Session(region_name="us-east-1")
LAM = SESSION.client("lambda")
CF = SESSION.client("cloudformation")
WORK = Path(__file__).resolve().parent
RECORD = WORK / "CONTAINMENT_RELEASE.json"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inventory():
    stack = CF.describe_stacks(StackName=PREFIX)["Stacks"][0]
    assert stack["StackStatus"] == "UPDATE_COMPLETE"
    template = CF.get_template(StackName=PREFIX)["TemplateBody"]
    resources = {x["LogicalResourceId"]: x["PhysicalResourceId"] for x in CF.list_stack_resources(StackName=PREFIX)["StackResourceSummaries"]}
    schedule = SESSION.client("scheduler").get_schedule(Name=PREFIX+"-shutdown")
    assert len(resources) == 32
    assert schedule["State"] == "ENABLED" and schedule["ScheduleExpression"] == "cron(0 20 1,2 12 ? 2026)"
    assert schedule["ScheduleExpressionTimezone"] == "Asia/Tokyo"
    return dict(resources=resources, template=template, schedule={k:schedule[k] for k in ("State", "ScheduleExpression", "ScheduleExpressionTimezone")}), stack


def deploy():
    assert SESSION.client("sts").get_caller_identity()["Account"] == ACCOUNT
    release = json.loads((WORK / "release.json").read_text())
    app = (WORK / "app.zip").read_bytes()
    assert sha(app) == release["sha256"] and release["before"] == OLD
    assert len(app) < 500000
    old_hash = base64.b64encode(bytes.fromhex(OLD)).decode()
    configurations = {r:LAM.get_function_configuration(FunctionName=PREFIX+"-"+r) for r in ROLES}
    assert all(c["CodeSha256"] == old_hash for c in configurations.values()), "Live version changed; stop for review"
    before, _ = inventory()
    location = LAM.get_function(FunctionName=PREFIX+"-api")["Code"]["Location"]
    with urlopen(location, timeout=30) as res:
        previous = res.read()
    assert sha(previous) == OLD
    allowed = {"cloud/containment.py", "cloud/incidents.py", "cloud/sandbox.py", "cloud/healing.py", "cloud/index.html", "cloud/bridge.css", "cloud/bridge.js"}
    with zipfile.ZipFile(io.BytesIO(previous)) as a, zipfile.ZipFile(io.BytesIO(app)) as b:
        assert set(b.namelist()) - set(a.namelist()) == {"cloud/containment.py"}
        assert not set(a.namelist()) - set(b.namelist())
        changed = {n for n in b.namelist() if n not in a.namelist() or b.read(n) != a.read(n)}
        assert changed == allowed, changed
    (WORK / "rollback-app.zip").write_bytes(previous)
    os.chmod(WORK / "rollback-app.zip", 0o600)
    result = dict(phase="DEPLOYING", account=ACCOUNT, before=OLD, after=release["sha256"], changed_files=sorted(changed), baseline=before, changed_functions=[])
    RECORD.write_text(json.dumps(result, indent=2))
    try:
        for role in ROLES:
            name = PREFIX+"-"+role
            LAM.update_function_code(FunctionName=name, ZipFile=app, RevisionId=configurations[role]["RevisionId"])
            result["changed_functions"].append(role)
            RECORD.write_text(json.dumps(result, indent=2))
            LAM.get_waiter("function_updated").wait(FunctionName=name)
            assert LAM.get_function_configuration(FunctionName=name)["CodeSha256"] == base64.b64encode(bytes.fromhex(release["sha256"])).decode()
            print("Updated " + role, flush=True)
        after, _ = inventory()
        assert before == after
        result.update(phase="DEPLOYED", iam_changes=0, new_resources=0, temporary_buckets=0)
    except Exception:
        for role in reversed(result["changed_functions"]):
            LAM.update_function_code(FunctionName=PREFIX+"-"+role, ZipFile=previous)
            LAM.get_waiter("function_updated").wait(FunctionName=PREFIX+"-"+role)
        result["phase"] = "ROLLED_BACK"
        RECORD.write_text(json.dumps(result, indent=2))
        raise
    RECORD.write_text(json.dumps(result, indent=2))
    print("DEPLOYED: unchanged IAM, 32 resources, shutdown schedule; no S3 staging", flush=True)


def verify():
    release = json.loads(RECORD.read_text())
    assert release["phase"] in ("DEPLOYED", "VERIFIED", "VERIFICATION_FAILED")
    live, stack = inventory()
    assert live == release["baseline"]
    url = next(x["OutputValue"] for x in stack["Outputs"] if x["OutputKey"] == "DemoUrl")
    # Reuse the existing artwork key in memory; do not transfer or print it.
    secret = LAM.get_function_configuration(FunctionName=PREFIX+"-api")["Environment"]["Variables"]["OPERATOR_TOKEN"]
    table = SESSION.resource("dynamodb").Table(PREFIX+"-state")
    def call(path="", data=None, authorized=True):
        headers = {"Content-Type":"application/json", "Origin":url.rstrip("/")}
        if authorized:
            headers["Authorization"] = "Bearer " + secret
        req = Request(url+path, headers=headers, data=json.dumps(data).encode() if data is not None else None)
        try:
            with urlopen(req, timeout=65) as res:
                return res.status, res.read().decode()
        except HTTPError as exc:
            return exc.code, exc.read().decode()
    def counter():
        item = table.get_item(Key={"PK":"CONTROL#AI","SK":"STATE"}, ConsistentRead=True).get("Item", {})
        return int(item.get("used", 0))
    used_before = counter()
    assert used_before <= 560, "Reserve enough calls; do not reset the lifetime quota"
    status, body = call("api/config")
    config = json.loads(body)
    assert status == 200 and len(config["incidents"]) == 25
    targets = [i for i in config["incidents"] if i.get("mode") == "containment"] + [next(i for i in config["incidents"] if i["id"] == "lost-database")]
    assert len(targets) == 6
    runs = []
    for incident in targets:
        code, body = call("api/heal", {"scenario":incident["id"]})
        state = json.loads(body)
        assert code == 200, (incident["id"], code)
        run = state["run_id"]
        snapshots = [state]
        for _ in range(15):
            if state["phase"] in ("COMPLETE", "BLOCKED"):
                break
            code, body = call("api/heal/step", {"run_id":run,"revision":state["revision"]})
            assert code == 200, (incident["id"], code)
            state = json.loads(body); snapshots.append(state)
        v = state.get("verification", {})
        passed = state["phase"] == "COMPLETE" and v.get("checks_passed") == v.get("checks_total") == 25 and v.get("kms_signature_verified") is True and state.get("report_engine") == "AMAZON_NOVA_MICRO"
        if incident.get("mode") == "containment":
            passed = passed and v.get("evidence_preserved") is True and v.get("containment") == dict(denied=3, attempted=3, legitimate_read=True)
        seal = table.get_item(Key={"PK":"HEALSEAL#"+run,"SK":"STATE"}, ConsistentRead=True).get("Item")
        assert table.get_item(Key={"PK":"ORDER#"+run,"SK":"STATE"}, ConsistentRead=True).get("Item") is None
        runs.append(dict(scenario=incident["id"], passed=bool(passed), result=state, snapshots=snapshots, attestation=json.loads(seal["payload"]) if seal else None))
        (WORK / "CONTAINMENT_VALIDATION.json").write_text(json.dumps(dict(runs=runs), indent=2))
        print(json.dumps(dict(scenario=incident["id"], phase=state["phase"], passed=bool(passed), error=state.get("error"))), flush=True)
    hashes = {r:LAM.get_function_configuration(FunctionName=PREFIX+"-"+r)["CodeSha256"] for r in ROLES}
    checks = dict(six_real_ai_cases=all(r["passed"] for r in runs), twenty_five_catalog_entries=len(config["incidents"])==25,
                  private_routes_denied=all(call(p,authorized=False)[0]==401 for p in ("api/config","api/heal","bridge.js","bridge.css","proof")),
                  unchanged_resources_template_shutdown=inventory()[0]==release["baseline"],
                  all_seven_code_hashes=all(v==base64.b64encode(bytes.fromhex(release["after"])).decode() for v in hashes.values()))
    key = next(x["OutputValue"] for x in stack["Outputs"] if x["OutputKey"] == "SigningKeyArn")
    report = dict(checked_at=int(time.time()), checks=checks, passed=all(checks.values()), runs=runs,
                  code_sha256=release["after"], model_calls_before=used_before, model_calls_after=counter(), model_limit=600,
                  signing_public_key_der_base64=base64.b64encode(SESSION.client("kms").get_public_key(KeyId=key)["PublicKey"]).decode(),
                  new_resources=0, iam_changes=0, temporary_buckets=0, shutdown=live["schedule"])
    (WORK / "CONTAINMENT_VALIDATION.json").write_text(json.dumps(report, indent=2))
    release["phase"] = "VERIFIED" if report["passed"] else "VERIFICATION_FAILED"
    RECORD.write_text(json.dumps(release, indent=2))
    with zipfile.ZipFile(WORK / "containment-evidence.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for p in (RECORD, WORK / "CONTAINMENT_VALIDATION.json"):
            z.write(p, p.name)
    print(json.dumps({k:v for k,v in report.items() if k not in ("runs", "signing_public_key_der_base64")}, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser();parser.add_argument("phase", choices=("deploy", "verify"))
    globals()[parser.parse_args().phase]()
