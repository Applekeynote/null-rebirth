"""Real AWS acceptance; produces scrubbed results, never prints operator token."""
import base64
import hashlib
import json
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

PREFIX = "null-rebirth-v110"
session = boto3.Session(region_name="us-east-1")
lam = session.client("lambda", config=Config(max_pool_connections=110,
    retries={"max_attempts": 1}, connect_timeout=5, read_timeout=90))
ddb = session.resource("dynamodb")
cf = session.client("cloudformation")


def invoke(role, data):
    try:
        out = lam.invoke(FunctionName=PREFIX + "-" + role,
                         Payload=json.dumps(data).encode())
        result = json.loads(out["Payload"].read())
        if out.get("FunctionError"):
            return {"error": result}
        result["aws_request_id"] = out["ResponseMetadata"]["RequestId"]
        return result
    except ClientError as exc:
        return {"api_error": exc.response["Error"]["Code"]}


def main():
    secret = json.loads(Path("deployment-secrets.json").read_text())
    stack = cf.describe_stacks(StackName=PREFIX)["Stacks"][0]
    outputs = {x["OutputKey"]: x["OutputValue"] for x in stack["Outputs"]}
    table = ddb.Table(outputs["StateTable"])
    url = outputs["DemoUrl"]
    report = {"environment": "REAL_AWS_SANDBOX_SYNTHETIC_FAULTS", "region": "us-east-1",
              "started_at_epoch": int(time.time()), "scenarios": [], "production_certified": False}
    for scenario in ("primary-healthy", "silent-monitor-death", "backup-recovered",
                     "untrusted-receipt", "conflicting-evidence"):
        request = urllib.request.Request(url + "api/run", data=json.dumps({"scenario": scenario}).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + secret["operator_token"]})
        with urllib.request.urlopen(request, timeout=100) as response:
            result = json.load(response)
        expected = 1 if scenario == "primary-healthy" else 0
        assert result["order_count"] == expected, (scenario, result)
        report["scenarios"].append(result)
        print(json.dumps({"scenario": scenario, "orders": result["order_count"],
                          "reasons": [c.get("reason", "COMMITTED") for c in result["commits"]]}))
    run = invoke("bootstrap", {"scenario": "primary-healthy"})["run_id"]
    invoke("witness", {"run_id": run})
    envelope = invoke("verifier", {"run_id": run})
    with ThreadPoolExecutor(max_workers=100) as pool:
        attempts = list(pool.map(lambda _: invoke("commit", {"run_id": run}), range(100)))
    committed = sum(x.get("committed") is True for x in attempts)
    item = table.get_item(Key={"PK": "ORDER#" + run, "SK": "STATE"}, ConsistentRead=True).get("Item")
    claim = table.get_item(Key={"PK": "CLAIM#" + run, "SK": "STATE"}, ConsistentRead=True)["Item"]
    assert committed == 1 and item and claim["status"] == "COMMITTED", (committed, attempts)
    report["concurrency"] = {"attempts": 100, "committed": committed, "stored_orders": int(bool(item)),
        "claim": claim["status"], "throttled": sum("api_error" in x for x in attempts), "responses": attempts}
    # Revoke one current guard after signing, and verify atomic rejection.
    run = invoke("bootstrap", {"scenario": "primary-healthy"})["run_id"]
    invoke("witness", {"run_id": run})
    invoke("verifier", {"run_id": run})
    table.update_item(Key={"PK": "POLICY#" + run, "SK": "STATE"},
                      UpdateExpression="SET expires_at = :zero", ExpressionAttributeValues={":zero": 0})
    revoked = invoke("commit", {"run_id": run})
    assert revoked.get("committed") is False
    assert not table.get_item(Key={"PK": "ORDER#" + run, "SK": "STATE"}, ConsistentRead=True).get("Item")
    report["revocation"] = revoked
    # Use IAM simulation: check permissions independent of application branches.
    iam = session.client("iam")
    account = session.client("sts").get_caller_identity()["Account"]
    tests = [("api", "kms:Sign", outputs["SigningKeyArn"], None),
             ("recovery", "kms:Sign", outputs["SigningKeyArn"], None),
             ("recovery", "dynamodb:PutItem", table.table_arn, "ORDER#" + run),
             ("witness", "dynamodb:PutItem", table.table_arn, "ORDER#" + run)]
    report["iam_boundary_simulation"] = []
    for role, action, resource, leading_key in tests:
        kwargs = {}
        if leading_key:
            kwargs["ContextEntries"] = [{"ContextKeyName": "dynamodb:LeadingKeys",
                                         "ContextKeyValues": [leading_key], "ContextKeyType": "stringList"}]
        answer = iam.simulate_principal_policy(PolicySourceArn="arn:aws:iam::" + account + ":role/" + PREFIX + "-" + role + "-role",
            ActionNames=[action], ResourceArns=[resource], **kwargs)["EvaluationResults"][0]
        assert answer["EvalDecision"] != "allowed", answer
        report["iam_boundary_simulation"].append({"role": role, "action": action, "decision": answer["EvalDecision"]})
    schedule = session.client("scheduler").get_schedule(Name=PREFIX + "-shutdown")
    assert schedule["State"] == "ENABLED" and schedule["ScheduleExpressionTimezone"] == "Asia/Tokyo"
    report["shutdown"] = {k: schedule[k] for k in ("Name", "State", "ScheduleExpression", "ScheduleExpressionTimezone")}
    key = session.client("kms").get_public_key(KeyId=outputs["SigningKeyArn"])
    Path("signing-public-key.der").write_bytes(key["PublicKey"])
    # This certificate can be independently verified offline after download.
    offline = {"certificate": report["scenarios"][0]["certificate"],
               "public_key_der_base64": base64.b64encode(key["PublicKey"]).decode()}
    Path("offline-proof.json").write_text(json.dumps(offline, indent=2))
    report["completed_at_epoch"] = int(time.time())
    report["all_assertions_passed"] = True
    Path("AWS_ACCEPTANCE_REPORT.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"result": "PASS", "concurrency": {k: v for k, v in report["concurrency"].items() if k != "responses"},
                      "shutdown": report["shutdown"]}, indent=2))


if __name__ == "__main__":
    main()
