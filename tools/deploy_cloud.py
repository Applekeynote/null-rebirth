"""CloudShell deployment, staged as prepare -> reviewed execute -> status.

No credentials leave CloudShell. Secret token is stored with mode 0600 and never
printed. The short-lived artifact bucket is private and removed after deployment.
"""
import argparse
import json
import os
import secrets
import time
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

PREFIX = "null-rebirth-v110"
REGION = "us-east-1"
STATE = Path("deployment-secrets.json")
session = boto3.Session(region_name=REGION)
cf = session.client("cloudformation")
s3 = session.client("s3")


def save(obj):
    STATE.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    os.chmod(STATE, 0o600)


def prepare():
    if STATE.exists():
        raise SystemExit("Deployment state already exists; use status and review it first.")
    account = session.client("sts").get_caller_identity()["Account"]
    bucket = PREFIX + "-artifact-" + account + "-" + secrets.token_hex(4)
    token = secrets.token_urlsafe(36)
    state = {"stack": PREFIX, "region": REGION, "bucket": bucket, "operator_token": token,
             "phase": "PREPARING", "changeset": "initial-reviewed"}
    save(state)
    s3.create_bucket(Bucket=bucket)
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={"Rules": [
        {"ID": "expire-artifacts", "Filter": {"Prefix": ""}, "Status": "Enabled", "Expiration": {"Days": 1},
         "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}}]})
    for name in ("app.zip", "template.json"):
        s3.upload_file(name, bucket, name, ExtraArgs={"ServerSideEncryption": "AES256"})
    cf.validate_template(TemplateURL="https://" + bucket + ".s3.us-east-1.amazonaws.com/template.json")
    settings = session.client("lambda").get_account_settings()["AccountLimit"]
    reserve = settings["ConcurrentExecutions"] >= 110
    out = cf.create_change_set(StackName=PREFIX, ChangeSetName=state["changeset"], ChangeSetType="CREATE",
        TemplateURL="https://" + bucket + ".s3.us-east-1.amazonaws.com/template.json",
        Parameters=[{"ParameterKey": "ArtifactBucket", "ParameterValue": bucket},
                    {"ParameterKey": "OperatorToken", "ParameterValue": token},
                    {"ParameterKey": "ReserveConcurrency", "ParameterValue": str(reserve).lower()}],
        Capabilities=["CAPABILITY_NAMED_IAM"], Tags=[{"Key": "Project", "Value": PREFIX},
                                                     {"Key": "ExpiresAt", "Value": "2026-12-01"}])
    state.update(phase="AWAITING_EXECUTION_APPROVAL", stack_id=out["StackId"], change_set_id=out["Id"], reserve=reserve)
    save(state)
    print(json.dumps({"prepared": True, "region": REGION, "reserved_concurrency": reserve,
                      "stack": PREFIX, "change_set_id": out["Id"], "resource_count": len(json.loads(Path('template.json').read_text())["Resources"])}))


def cleanup_bucket(state):
    bucket = state["bucket"]
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys = [{"Key": x["Key"]} for x in page.get("Contents", [])]
            if keys:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
        s3.delete_bucket(Bucket=bucket)
        state["artifact_bucket_deleted"] = True
        save(state)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            state["artifact_bucket_deleted"] = True
            save(state)
        else:
            raise


def execute():
    state = json.loads(STATE.read_text())
    change = cf.describe_change_set(ChangeSetName=state["change_set_id"])
    if change["Status"] != "CREATE_COMPLETE" or change["ExecutionStatus"] != "AVAILABLE":
        raise SystemExit(json.dumps({k: change.get(k) for k in ("Status", "StatusReason", "ExecutionStatus")}))
    cf.execute_change_set(ChangeSetName=state["change_set_id"])
    state["phase"] = "DEPLOYING"
    save(state)
    print("Deployment started. Use status to inspect completion.")


def status():
    state = json.loads(STATE.read_text())
    stack = cf.describe_stacks(StackName=state["stack_id"])["Stacks"][0]
    out = {"status": stack["StackStatus"], "outputs": stack.get("Outputs", [])}
    events = cf.describe_stack_events(StackName=state["stack_id"])["StackEvents"]
    out["recent_events"] = [{"resource": x["LogicalResourceId"], "status": x["ResourceStatus"],
                             "reason": x.get("ResourceStatusReason", "")} for x in events[:12]]
    if stack["StackStatus"] in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "DELETE_COMPLETE"):
        cleanup_bucket(state)
        out["artifact_bucket_deleted"] = True
        Path("deployment-result.json").write_text(json.dumps(out, indent=2, default=str))
    print(json.dumps(out, indent=2, default=str))


def review():
    state = json.loads(STATE.read_text())
    result = cf.describe_change_set(ChangeSetName=state["change_set_id"])
    print(json.dumps({"status": result["Status"], "reason": result.get("StatusReason"),
        "changes": [{"action": x["ResourceChange"]["Action"],
                     "id": x["ResourceChange"]["LogicalResourceId"],
                     "type": x["ResourceChange"]["ResourceType"]} for x in result.get("Changes", [])]}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["prepare", "review", "execute", "status"])
    {"prepare": prepare, "review": review, "execute": execute, "status": status}[parser.parse_args().action]()
