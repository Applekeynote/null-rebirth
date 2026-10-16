"""Create a disposable private copy, run its own janitor, verify deletion.

This tests CloudFormation's permission/dependency deletion behavior before the
real deadline. Only the named rehearsal stack is disposable. Main app is untouched.
"""
import json
import secrets
import time
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

MAIN = "null-rebirth-v110"
TEST = "null-rebirth-teardown-check"
session = boto3.Session(region_name="us-east-1")
cf = session.client("cloudformation")
s3 = session.client("s3")


def main():
    template = json.loads(Path("template.json").read_text().replace(MAIN, TEST))
    # Exercise URL/alarm deletion too, while requiring AWS IAM authentication.
    # No anonymous/public endpoint is created in this disposable stack.
    template["Resources"]["ApiUrl"]["Properties"]["AuthType"] = "AWS_IAM"
    for key in ("ApiUrlPermission", "ApiInvokePermission"):
        template["Resources"].pop(key)
    template["Outputs"].pop("DemoUrl")
    account = session.client("sts").get_caller_identity()["Account"]
    bucket = TEST + "-" + account + "-" + secrets.token_hex(4)
    report = {"test_stack": TEST, "main_stack": MAIN, "bucket": bucket,
              "private_url_auth": "AWS_IAM", "includes_alarm_and_url_deletion": True,
              "created_at": int(time.time()), "disposable": True}
    Path("TEARDOWN_REHEARSAL.json").write_text(json.dumps(report, indent=2))
    s3.create_bucket(Bucket=bucket)
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={"Rules": [{
        "ID": "expire", "Filter": {"Prefix": ""}, "Status": "Enabled", "Expiration": {"Days": 1}}]})
    s3.upload_file("app.zip", bucket, "app.zip", ExtraArgs={"ServerSideEncryption": "AES256"})
    s3.put_object(Bucket=bucket, Key="template.json", Body=json.dumps(template).encode(), ServerSideEncryption="AES256")
    out = cf.create_stack(StackName=TEST, TemplateURL="https://" + bucket + ".s3.us-east-1.amazonaws.com/template.json",
        Parameters=[{"ParameterKey": "ArtifactBucket", "ParameterValue": bucket},
                    {"ParameterKey": "OperatorToken", "ParameterValue": secrets.token_urlsafe(36)},
                    {"ParameterKey": "ReserveConcurrency", "ParameterValue": "false"}],
        Capabilities=["CAPABILITY_NAMED_IAM"], Tags=[{"Key": "Project", "Value": TEST}])
    report["stack_id"] = out["StackId"]
    Path("TEARDOWN_REHEARSAL.json").write_text(json.dumps(report, indent=2))
    print("Creating disposable private rehearsal stack.", flush=True)
    cf.get_waiter("stack_create_complete").wait(StackName=TEST, WaiterConfig={"Delay": 10, "MaxAttempts": 45})
    outputs = cf.describe_stacks(StackName=TEST)["Stacks"][0]["Outputs"]
    key = next(x["OutputValue"] for x in outputs if x["OutputKey"] == "SigningKeyArn")
    report["signing_key_arn"] = key
    out = session.client("lambda").invoke(FunctionName=TEST + "-janitor", Payload=b'{"alarmData":{"test":"DISPOSABLE_TEARDOWN_REHEARSAL"}}')
    report["janitor_result"] = json.loads(out["Payload"].read())
    report["janitor_function_error"] = out.get("FunctionError")
    print(json.dumps({"janitor_result": report["janitor_result"]}), flush=True)
    try:
        cf.get_waiter("stack_delete_complete").wait(StackName=report["stack_id"], WaiterConfig={"Delay": 10, "MaxAttempts": 45})
        report["stack_deleted"] = True
    except Exception as exc:
        report["stack_deleted"] = False
        report["deletion_error"] = str(exc)
        report["failed_events"] = [{"resource": x["LogicalResourceId"], "reason": x.get("ResourceStatusReason")}
            for x in cf.describe_stack_events(StackName=report["stack_id"])["StackEvents"] if x["ResourceStatus"] == "DELETE_FAILED"]
    report["key_state"] = session.client("kms").describe_key(KeyId=key)["KeyMetadata"]["KeyState"]
    # The deletion caller must retain its permissions until CFN has finished.
    # These free IAM controls are removed by the operator after stack completion.
    if report["stack_deleted"]:
        iam = session.client("iam")
        role = TEST + "-janitor-role"
        for policy in iam.list_role_policies(RoleName=role)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role, PolicyName=policy)
        iam.delete_role(RoleName=role)
        report["retained_cleanup_identity_removed"] = True
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": x["Key"]} for x in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)
    report["artifact_bucket_deleted"] = True
    report["finished_at"] = int(time.time())
    Path("TEARDOWN_REHEARSAL.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2), flush=True)
    if not report["stack_deleted"] or report["key_state"] != "PendingDeletion":
        raise SystemExit("Teardown rehearsal failed: repair permissions before final delivery.")


if __name__ == "__main__":
    main()
