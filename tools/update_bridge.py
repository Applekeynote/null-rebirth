"""Same-scope UI/auth update. Review seven code changes before execution.

Run in the existing CloudShell work directory. Reuses the existing review key,
changes no roles/permissions, keeps deadline controls, removes staging storage.
"""
import argparse
import base64
import hashlib
import os
import json
import os
import secrets
import time
import zipfile
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from http.cookiejar import CookieJar
from urllib.request import build_opener, HTTPCookieProcessor

import boto3

PREFIX = "null-rebirth-v110"
REGION = "us-east-1"
STATE = Path(os.environ.get("NR_UPDATE_STATE", "bridge-update-state.json"))
REPORT = Path("BRIDGE_DEPLOYMENT_REPORT.json")
session = boto3.Session(region_name=REGION)
cf, s3 = session.client("cloudformation"), session.client("s3")


def save(state):
    STATE.write_text(json.dumps(state, indent=2))
    os.chmod(STATE, 0o600)


def baseline():
    iam = session.client("iam")
    policies = {}
    for role in ("bootstrap", "witness", "recovery", "verifier", "commit", "api", "janitor", "scheduler"):
        name = PREFIX + "-" + role + "-role"
        policies[name] = {p: iam.get_role_policy(RoleName=name, PolicyName=p)["PolicyDocument"]
            for p in iam.list_role_policies(RoleName=name)["PolicyNames"]}
    resources = {r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cf.list_stack_resources(StackName=PREFIX)["StackResourceSummaries"]}
    return {"iam_policy_sha256": hashlib.sha256(json.dumps(policies, sort_keys=True).encode()).hexdigest(),
            "physical_resources": resources}


def prepare():
    if STATE.exists():
        raise SystemExit("Existing update state; inspect before repeating")
    assert session.client("sts").get_caller_identity()["Account"] == os.environ.get("NR_ACCOUNT_ID", "NOT_CONFIGURED")
    stack = cf.describe_stacks(StackName=PREFIX)["Stacks"][0]
    assert stack["StackStatus"] == "UPDATE_COMPLETE"
    current = cf.get_template(StackName=PREFIX)["TemplateBody"]
    if isinstance(current, str):
        current = json.loads(current)
    wanted = json.loads(Path("template.json").read_text())
    assert current == wanted, "Template changed beyond code-only scope"
    key = json.loads(Path("deployment-secrets.json").read_text())["operator_token"]
    assert len(key) >= 32
    bucket = PREFIX + "-artifact-" + os.environ["NR_ACCOUNT_ID"] + "-bridge-" + secrets.token_hex(4)
    s3.create_bucket(Bucket=bucket)
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={"Rules": [{
        "ID": "expire-artifacts", "Filter": {"Prefix": ""}, "Status": "Enabled", "Expiration": {"Days": 1}}]})
    s3.upload_file("app.zip", bucket, "app.zip", ExtraArgs={"ServerSideEncryption": "AES256"})
    state = {"bucket": bucket, "changeset": "bridge-reviewed-" + secrets.token_hex(3),
             "old_api_hash": session.client("lambda").get_function_configuration(FunctionName=PREFIX + "-api")["CodeSha256"],
             "phase": "PREPARING", "code_sha256": hashlib.sha256(Path("app.zip").read_bytes()).hexdigest()}
    save(state)
    cf.create_change_set(StackName=PREFIX, ChangeSetName=state["changeset"], ChangeSetType="UPDATE",
        UsePreviousTemplate=True, Parameters=[{"ParameterKey": "ArtifactBucket", "ParameterValue": bucket},
        {"ParameterKey": "OperatorToken", "UsePreviousValue": True},
        {"ParameterKey": "ReserveConcurrency", "UsePreviousValue": True}], Capabilities=["CAPABILITY_NAMED_IAM"])
    cf.get_waiter("change_set_create_complete").wait(StackName=PREFIX, ChangeSetName=state["changeset"])
    review()


def review():
    state = json.loads(STATE.read_text())
    assert state["phase"] == "PREPARING"
    changes = cf.describe_change_set(StackName=PREFIX, ChangeSetName=state["changeset"])["Changes"]
    expected = {x.capitalize() + "Function" for x in ("bootstrap", "witness", "recovery", "verifier", "commit", "api", "janitor")}
    # CFN also propagates dynamic GetAtt references despite unchanged ARNs.
    indirect = {"AlarmInvokePermission": {("SourceArn", "UsageAlarm.Arn")},
                "ScheduleRole": {("Policies", "JanitorFunction.Arn")},
                "ShutdownSchedule": {("Target", "ScheduleRole.Arn"), ("Target", "JanitorFunction.Arn")},
                "UsageAlarm": {("AlarmActions", "JanitorFunction.Arn")}}
    assert {x["ResourceChange"]["LogicalResourceId"] for x in changes} == expected | set(indirect)
    for change in changes:
        c = change["ResourceChange"]
        assert c["Action"] == "Modify" and c["Replacement"] in ("False", "Conditional")
        name = c["LogicalResourceId"]
        if name in expected:
            assert c["Replacement"] == "False"
            assert all(d["Target"]["Name"] == "Code" for d in c["Details"])
        else:
            assert all(d["Evaluation"] == "Dynamic" and d["ChangeSource"] == "ResourceAttribute"
                and (d["Target"]["Name"], d["CausingEntity"]) in indirect[name] for d in c["Details"])
    state.update(phase="REVIEWED", changes=[x["ResourceChange"] for x in changes])
    state["baseline"] = baseline()
    save(state)
    print(json.dumps({"phase": state["phase"], "changes": [{k: x[k] for k in ("LogicalResourceId", "Action", "Replacement")} for x in state["changes"]]}), flush=True)


def execute():
    state = json.loads(STATE.read_text())
    assert state["phase"] == "REVIEWED"
    cf.execute_change_set(StackName=PREFIX, ChangeSetName=state["changeset"])
    state["phase"] = "UPDATING"
    save(state)
    cf.get_waiter("stack_update_complete").wait(StackName=PREFIX)
    state["phase"] = "UPDATE_COMPLETE"
    save(state)
    print("Bridge code update complete", flush=True)


def verify():
    state = json.loads(STATE.read_text())
    assert state["phase"] == "UPDATE_COMPLETE"
    stack = cf.describe_stacks(StackName=PREFIX)["Stacks"][0]
    url = next(x["OutputValue"] for x in stack["Outputs"] if x["OutputKey"] == "DemoUrl")
    domain = url.split("/")[2]
    key = json.loads(Path("deployment-secrets.json").read_text())["operator_token"]
    jar = CookieJar()
    opener = build_opener(HTTPCookieProcessor(jar))
    def request(path="", data=None, auth=False, origin=True, use_cookie=False):
        headers = {"Content-Type": "application/json"}
        if origin:
            headers["Origin"] = "https://" + domain
        if auth:
            headers["Authorization"] = "Bearer " + key
        req = Request(url + path, data=json.dumps(data).encode() if data is not None else None, headers=headers)
        try:
            res = (opener.open if use_cookie else urlopen)(req, timeout=70)
            return res.status, res.read().decode(), dict(res.headers)
        except HTTPError as exc:
            return exc.code, exc.read().decode(), dict(exc.headers)
    checks = {}
    code, body, _ = request()
    checks["anonymous_gate_only"] = code == 200 and "AUTHORIZE ACCESS" in body and "EXECUTE MISSION" not in body and key not in body
    checks["anonymous_config_denied"] = request("api/config")[0] == 401
    checks["anonymous_run_denied"] = request("api/run", {"scenario": "primary-healthy"})[0] == 401
    checks["wrong_key_denied"] = request("auth/login", {"key": "incorrect"})[0] == 401
    checks["cross_origin_login_denied"] = request("auth/login", {"key": "incorrect"}, origin=False)[0] == 403
    code, _, headers = request("auth/login", {"key": key}, use_cookie=True)
    checks["key_login_succeeds"] = code == 200 and bool(list(jar))
    checks["cookie_protected"] = all(x in headers.get("Set-Cookie", "") for x in ("Secure", "HttpOnly", "SameSite=Strict"))
    code, body, _ = request(use_cookie=True)
    checks["authorized_bridge"] = code == 200 and "EXECUTE MISSION" in body and "<html lang=\"en\">" in body and key not in body
    checks["authorized_config"] = request("api/config", use_cookie=True)[0] == 200
    checks["cross_origin_cookie_write_denied"] = request("api/run", {"scenario": "primary-healthy"}, origin=False, use_cookie=True)[0] == 403
    runs = []
    scenarios = ("primary-healthy", "silent-monitor-death", "backup-recovered", "untrusted-receipt", "conflicting-evidence")
    for scenario in scenarios:
        code, body, _ = request("api/run", {"scenario": scenario}, use_cookie=True)
        data = json.loads(body)
        assert code == 200, {"status": code, "body": body}
        count = data["order_count"]
        passed = count == (1 if scenario == "primary-healthy" else 0)
        if scenario == "untrusted-receipt":
            passed = passed and all(x.get("reason") == "SIGNATURE_INVALID" for x in data["commits"])
        if scenario == "conflicting-evidence":
            passed = passed and data["certificate"]["body"]["conflict"]
        runs.append({"scenario": scenario, "order_count": count, "commits": data["commits"], "passed": passed})
    checks["five_authenticated_scenarios"] = all(x["passed"] for x in runs)
    checks["logout_success"] = request("auth/logout", {}, use_cookie=True)[0] == 200
    checks["logout_blocks_config"] = request("api/config", use_cookie=True)[0] == 401
    hashes = {x: session.client("lambda").get_function_configuration(FunctionName=PREFIX + "-" + x)["CodeSha256"]
              for x in ("bootstrap", "witness", "recovery", "verifier", "commit", "api", "janitor")}
    expected = base64.b64encode(hashlib.sha256(Path("app.zip").read_bytes()).digest()).decode()
    checks["all_seven_code_hashes_match"] = all(x == expected for x in hashes.values())
    after = baseline()
    checks["iam_policies_unchanged"] = after["iam_policy_sha256"] == state["baseline"]["iam_policy_sha256"]
    checks["all_resource_ids_unchanged"] = after["physical_resources"] == state["baseline"]["physical_resources"]
    schedule = session.client("scheduler").get_schedule(Name=PREFIX + "-shutdown")
    checks["shutdown_unchanged"] = (schedule["State"] == "ENABLED" and schedule["ScheduleExpression"] == "cron(0 20 1,2 12 ? 2026)"
        and schedule["ScheduleExpressionTimezone"] == "Asia/Tokyo")
    s3.delete_object(Bucket=state["bucket"], Key="app.zip")
    s3.delete_bucket(Bucket=state["bucket"])
    checks["staging_bucket_removed"] = True
    state["phase"] = "VERIFIED"
    save(state)
    report = {"checked_at": int(time.time()), "stack": PREFIX, "stack_status": stack["StackStatus"], "url": url,
              "checks": checks, "scenarios": runs, "code_sha256": state["code_sha256"], "lambda_hashes": hashes,
              "passed": all(checks.values()), "auth": "Shared review key; 30-minute HttpOnly Secure SameSite=Strict session",
              "new_persistent_resources": 0, "iam_changes": 0}
    REPORT.write_text(json.dumps(report, indent=2))
    with zipfile.ZipFile("bridge-evidence.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.write(REPORT)
    print(json.dumps(report, indent=2), flush=True)
    assert report["passed"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("prepare", "review", "execute", "verify"))
    globals()[parser.parse_args().phase]()
