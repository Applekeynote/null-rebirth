"""Run from AWS CloudShell after Dec 1 to verify and finish this project only."""
import os
import json
import time
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

PREFIX = "null-rebirth-v110"
ACCOUNT = os.environ.get("NR_ACCOUNT_ID", "NOT_CONFIGURED")
DEADLINE = 1796122800
s = boto3.Session(region_name="us-east-1")


def main():
    assert int(time.time()) >= DEADLINE, "Cleanup is restricted to the shutdown window"
    assert s.client("sts").get_caller_identity()["Account"] == ACCOUNT
    cf = s.client("cloudformation")
    report = {"project": PREFIX, "account": ACCOUNT, "region": "us-east-1"}
    try:
        stack = cf.describe_stacks(StackName=PREFIX)["Stacks"][0]
        report["stack_before"] = stack["StackStatus"]
        if stack["StackStatus"] != "DELETE_COMPLETE":
            assert {t["Key"]: t["Value"] for t in stack["Tags"]}.get("Project") == PREFIX
            cf.delete_stack(StackName=PREFIX)
            cf.get_waiter("stack_delete_complete").wait(StackName=stack["StackId"])
    except ClientError as exc:
        if "does not exist" not in str(exc):
            raise
    iam = s.client("iam")
    role = PREFIX + "-janitor-role"
    try:
        for policy in iam.list_role_policies(RoleName=role)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role, PolicyName=policy)
        iam.delete_role(RoleName=role)
    except iam.exceptions.NoSuchEntityException:
        pass
    lam = s.client("lambda")
    functions = [f["FunctionName"] for p in lam.get_paginator("list_functions").paginate()
                 for f in p["Functions"] if f["FunctionName"].startswith(PREFIX + "-")]
    ddb = s.client("dynamodb")
    tables = [n for p in ddb.get_paginator("list_tables").paginate()
              for n in p["TableNames"] if n.startswith(PREFIX + "-")]
    logs = s.client("logs").describe_log_groups(logGroupNamePrefix="/aws/lambda/" + PREFIX + "-")["logGroups"]
    alarms = s.client("cloudwatch").describe_alarms(AlarmNamePrefix=PREFIX + "-")["MetricAlarms"]
    schedules = s.client("scheduler").list_schedules(NamePrefix=PREFIX + "-")["Schedules"]
    report.update(functions_remaining=functions, tables_remaining=tables,
                  log_groups_remaining=[g["logGroupName"] for g in logs],
                  alarms_remaining=[a["AlarmName"] for a in alarms],
                  schedules_remaining=[a["Name"] for a in schedules])
    assert not any((functions, tables, logs, alarms, schedules)), report
    key = os.environ["NR_KMS_KEY_ID"]
    try:
        state = s.client("kms").describe_key(KeyId=key)["KeyMetadata"]["KeyState"]
        if state != "PendingDeletion":
            s.client("kms").schedule_key_deletion(KeyId=key, PendingWindowInDays=7)
        report["kms_state"] = "PendingDeletion"
    except s.client("kms").exceptions.NotFoundException:
        report["kms_state"] = "DELETED"
    report["completed_at"] = int(time.time())
    report["all_assertions_passed"] = True
    Path("DEADLINE_CLEANUP_REPORT.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
