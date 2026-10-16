"""Generate a reviewable CloudFormation template; does not call AWS."""
import json
from pathlib import Path

PREFIX = "null-rebirth-v110"
ROLES = ("bootstrap", "witness", "recovery", "verifier", "commit", "api", "janitor")


def ref(x):
    return {"Ref": x}


def sub(x):
    return {"Fn::Sub": x}


def arn(x):
    return {"Fn::GetAtt": [x, "Arn"]}


def statement(actions, resource, condition=None):
    s = {"Effect": "Allow", "Action": actions, "Resource": resource}
    if condition:
        s["Condition"] = condition
    return s


def data_permission(actions, prefixes):
    return statement(actions, arn("StateTable"), {
        "ForAllValues:StringLike": {"dynamodb:LeadingKeys": [x + "#run-*" for x in prefixes]},
        "Null": {"dynamodb:LeadingKeys": "false"}})


def generate():
    r = {}
    tags = [{"Key": "Project", "Value": PREFIX}, {"Key": "ExpiresAt", "Value": "2026-12-01"}]
    for name, suffix in (("StateTable", "state"), ("AuditTable", "audit")):
        r[name] = {"Type": "AWS::DynamoDB::Table", "DeletionPolicy": "Delete",
                   "UpdateReplacePolicy": "Delete", "Properties": {
            "TableName": PREFIX + "-" + suffix, "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": k, "AttributeType": "S"} for k in ("PK", "SK")],
            "KeySchema": [{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}],
            "TimeToLiveSpecification": {"AttributeName": "expires_at", "Enabled": True},
            "OnDemandThroughput": {"MaxReadRequestUnits": 100, "MaxWriteRequestUnits": 100},
            "Tags": tags,
        }}
    r["SigningKey"] = {"Type": "AWS::KMS::Key", "DeletionPolicy": "Delete", "Properties": {
        "Description": "NULL REBIRTH sandbox-only ECDSA proof signer; expires Dec 1 2026",
        "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY", "PendingWindowInDays": 7,
        "KeyPolicy": {"Version": "2012-10-17", "Statement": [{"Sid": "EnableIAM",
            "Effect": "Allow", "Principal": {"AWS": sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:root")},
            "Action": "kms:*", "Resource": "*"}]}, "Tags": tags}}
    read_names = ["AUTH", "POLICY", "CONTRACT", "CONTRACT_ACTIVE", "LEASE", "INCIDENT",
                  "PROOF", "TRUST", "MODE", "ROUTE", "CANARY", "FRONTIER", "SAFETY", "CERTIFICATE", "CAPABILITY"]
    seed_names = ["AUTH", "POLICY", "CONTRACT", "CONTRACT_ACTIVE", "LEASE", "INCIDENT",
                  "TRUST", "MODE", "ROUTE", "CAPABILITY", "CLAIM"]
    permissions = {
        "bootstrap": [data_permission(["dynamodb:PutItem"], seed_names),
                      statement(["dynamodb:UpdateItem"], arn("StateTable"), {
                          "ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["CONTROL#QUOTA"]},
                          "Null": {"dynamodb:LeadingKeys": "false"}})],
        "witness": [data_permission(["dynamodb:GetItem"], ["INCIDENT"]),
                    data_permission(["dynamodb:PutItem"], ["CANARY"])],
        "recovery": [data_permission(["dynamodb:GetItem"], ["INCIDENT", "CANARY", "CAPABILITY", "ROUTE", "MODE", "LEASE"]),
                     data_permission(["dynamodb:UpdateItem"], ["INCIDENT", "CAPABILITY", "ROUTE", "MODE", "LEASE"])],
        "verifier": [data_permission(["dynamodb:GetItem"], ["INCIDENT", "CANARY"]),
                     data_permission(["dynamodb:PutItem"], ["PROOF", "FRONTIER", "SAFETY", "CERTIFICATE"]),
                     statement(["kms:Sign"], arn("SigningKey"))],
        "commit": [data_permission(["dynamodb:GetItem", "dynamodb:ConditionCheckItem"], read_names),
                   data_permission(["dynamodb:UpdateItem"], ["CLAIM"]),
                   data_permission(["dynamodb:PutItem"], ["ORDER"]),
                   statement(["kms:Verify"], arn("SigningKey"))],
        "api": [data_permission(["dynamodb:GetItem"], ["ORDER"]),
                statement(["dynamodb:Query"], arn("AuditTable")),
                statement(["lambda:InvokeFunction"], [sub("arn:${AWS::Partition}:lambda:${AWS::Region}:${AWS::AccountId}:function:" + PREFIX + "-" + x)
                    for x in ROLES if x not in ("api", "janitor")])],
        "janitor": [],
    }
    # The lab reuses the existing table and workers. Each permission is bounded
    # to run-scoped lab records. AI receives no infrastructure mutation rights.
    permissions["bootstrap"].append(data_permission(["dynamodb:PutItem"], ["HEAL", "WORKLOAD"]))
    permissions["witness"] += [data_permission(["dynamodb:GetItem"], ["HEAL", "WORKLOAD"]),
                               data_permission(["dynamodb:PutItem"], ["HEALCHECK"])]
    permissions["recovery"] += [
        data_permission(["dynamodb:GetItem"], ["HEAL", "WORKLOAD", "HEALCHECK"]),
        data_permission(["dynamodb:UpdateItem"], ["HEAL", "WORKLOAD"]),
        statement(["dynamodb:UpdateItem"], arn("StateTable"), {
            "ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["CONTROL#AI"]},
            "Null": {"dynamodb:LeadingKeys": "false"}}),
        statement(["bedrock:InvokeModel"], sub("arn:${AWS::Partition}:bedrock:us-east-1::foundation-model/amazon.nova-micro-v1:0"))]
    permissions["verifier"] += [data_permission(["dynamodb:GetItem"], ["HEAL", "WORKLOAD"]),
                                data_permission(["dynamodb:PutItem"], ["HEALSEAL"])]
    permissions["commit"] += [data_permission(["dynamodb:GetItem", "dynamodb:ConditionCheckItem"], ["HEAL", "WORKLOAD", "HEALSEAL"]),
                              data_permission(["dynamodb:UpdateItem"], ["HEAL"])]
    permissions["api"].append(data_permission(["dynamodb:GetItem"], ["HEAL"]))
    for role in ROLES:
        id = role.capitalize()
        role_id = id + "Role"
        function_name = PREFIX + "-" + role
        policies = list(permissions[role])
        if role != "janitor":
            policies.append(statement(["dynamodb:PutItem"], arn("AuditTable")))
        policies.append(statement(["logs:CreateLogStream", "logs:PutLogEvents"],
            sub("arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/" + function_name + ":*")))
        r[role_id] = {"Type": "AWS::IAM::Role", "Properties": {
            "RoleName": function_name + "-role", "AssumeRolePolicyDocument": {
                "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                                                       "Action": "sts:AssumeRole"}]},
            "Policies": [{"PolicyName": "sandbox", "PolicyDocument": {"Version": "2012-10-17", "Statement": policies}}],
            "Tags": tags}}
        r[id + "Log"] = {"Type": "AWS::Logs::LogGroup", "DeletionPolicy": "Delete", "Properties": {
            "LogGroupName": "/aws/lambda/" + function_name, "RetentionInDays": 3, "Tags": tags}}
        variables = {"ROLE": role, "PREFIX": PREFIX, "TABLE": ref("StateTable"),
                     "AUDIT_TABLE": ref("AuditTable"), "SIGNING_KEY": arn("SigningKey")}
        if role == "api":
            variables["OPERATOR_TOKEN"] = ref("OperatorToken")
        props = {"FunctionName": function_name, "Runtime": "python3.12", "Handler": "cloud.runtime.handler",
                 "Role": arn(role_id), "Timeout": 60 if role == "api" else (45 if role == "recovery" else 30),
                 "MemorySize": 128, "Architectures": ["arm64"],
                 "Environment": {"Variables": variables},
                 "Code": {"S3Bucket": ref("ArtifactBucket"), "S3Key": "app.zip"}, "Tags": tags}
        # Reduced-quota new accounts cannot reserve while leaving 100 unreserved.
        props["ReservedConcurrentExecutions"] = {"Fn::If": ["CanReserve", 2 if role in ("commit", "witness") else 1, {"Ref": "AWS::NoValue"}]}
        r[id + "Function"] = {"Type": "AWS::Lambda::Function", "DependsOn": [id + "Log"], "Properties": props}
    # App uses conditional append; runtime roles lack UpdateItem/DeleteItem.
    # PutItem can overwrite if a writer is compromised: not WORM storage.
    # Janitor may only delete this named stack and the resources with its prefix.
    janitor_statements = [
        statement(["cloudformation:DeleteStack", "cloudformation:DescribeStacks", "cloudformation:DescribeStackEvents",
                   "cloudformation:ListStackResources", "cloudformation:DescribeStackResource"],
                  sub("arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/" + PREFIX + "/*")),
        statement(["lambda:PutFunctionConcurrency", "lambda:DeleteFunctionConcurrency", "lambda:DeleteFunction",
                   "lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:RemovePermission",
                   "lambda:DeleteFunctionUrlConfig", "lambda:GetFunctionUrlConfig", "lambda:GetPolicy"],
                  sub("arn:${AWS::Partition}:lambda:${AWS::Region}:${AWS::AccountId}:function:" + PREFIX + "-*")),
        statement(["dynamodb:DeleteTable", "dynamodb:DescribeTable"], [arn("StateTable"), arn("AuditTable")]),
        statement(["kms:ScheduleKeyDeletion", "kms:DescribeKey"], arn("SigningKey")),
        statement(["logs:DeleteLogGroup"], sub("arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/" + PREFIX + "-*")),
        statement(["iam:DeleteRole", "iam:GetRole", "iam:DeleteRolePolicy", "iam:GetRolePolicy", "iam:ListRolePolicies",
                   "iam:ListAttachedRolePolicies", "iam:DetachRolePolicy"],
                  sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:role/" + PREFIX + "-*")),
        statement(["scheduler:DeleteSchedule", "scheduler:GetSchedule"],
                  sub("arn:${AWS::Partition}:scheduler:${AWS::Region}:${AWS::AccountId}:schedule/default/" + PREFIX + "-*")),
        statement(["cloudwatch:DeleteAlarms", "cloudwatch:DescribeAlarms"],
                  sub("arn:${AWS::Partition}:cloudwatch:${AWS::Region}:${AWS::AccountId}:alarm:" + PREFIX + "-*")),
        statement(["iam:PassRole"], sub("arn:${AWS::Partition}:iam::${AWS::AccountId}:role/" + PREFIX + "-*"),
                  {"StringEquals": {"iam:PassedToService": "scheduler.amazonaws.com"}}),
    ]
    r["JanitorPolicy"] = {"Type": "AWS::IAM::Policy", "Properties": {
        "PolicyName": "delete-only-this-sandbox", "Roles": [ref("JanitorRole")],
        "PolicyDocument": {"Version": "2012-10-17", "Statement": janitor_statements}}}
    # CloudFormation uses the caller's temporary credentials to delete the stack.
    # Removing this caller's policy mid-deletion revokes later Delete* calls.
    # Retain only the free, project-scoped cleanup identity; remove it separately
    # after DELETE_COMPLETE. All metered resources remain DeletionPolicy Delete.
    r["JanitorRole"]["DeletionPolicy"] = "Retain"
    r["JanitorPolicy"]["DeletionPolicy"] = "Retain"
    r["JanitorRole"]["UpdateReplacePolicy"] = "Retain"
    r["JanitorPolicy"]["UpdateReplacePolicy"] = "Retain"
    r["ScheduleRole"] = {"Type": "AWS::IAM::Role", "Properties": {
        "RoleName": PREFIX + "-scheduler-role", "AssumeRolePolicyDocument": {
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")}}}]},
        "Policies": [{"PolicyName": "invoke-janitor", "PolicyDocument": {"Version": "2012-10-17",
            "Statement": [statement(["lambda:InvokeFunction"], arn("JanitorFunction"))]}}]}}
    r["ShutdownSchedule"] = {"Type": "AWS::Scheduler::Schedule", "DependsOn": ["JanitorPolicy"], "Properties": {
        "Name": PREFIX + "-shutdown", "ScheduleExpression": "cron(0 20 1,2 12 ? 2026)",
        "ScheduleExpressionTimezone": "Asia/Tokyo", "FlexibleTimeWindow": {"Mode": "OFF"},
        "State": "ENABLED", "Target": {"Arn": arn("JanitorFunction"), "RoleArn": arn("ScheduleRole"),
            "Input": "{}", "RetryPolicy": {"MaximumEventAgeInSeconds": 3600, "MaximumRetryAttempts": 5}}}}
    r["ApiUrl"] = {"Type": "AWS::Lambda::Url", "Properties": {
        "TargetFunctionArn": ref("ApiFunction"), "AuthType": "NONE", "InvokeMode": "BUFFERED"}}
    r["ApiUrlPermission"] = {"Type": "AWS::Lambda::Permission", "Properties": {
        "FunctionName": ref("ApiFunction"), "Action": "lambda:InvokeFunctionUrl", "Principal": "*", "FunctionUrlAuthType": "NONE"}}
    r["ApiInvokePermission"] = {"Type": "AWS::Lambda::Permission", "Properties": {
        "FunctionName": ref("ApiFunction"), "Action": "lambda:InvokeFunction", "Principal": "*", "InvokedViaFunctionUrl": True}}
    # An hourly request surge triggers a cost circuit breaker, not a billing cap.
    r["UsageAlarm"] = {"Type": "AWS::CloudWatch::Alarm", "Properties": {
        "AlarmName": PREFIX + "-request-circuit-breaker", "Namespace": "AWS/Lambda", "MetricName": "Invocations",
        "Dimensions": [{"Name": "FunctionName", "Value": ref("ApiFunction")}],
        "Statistic": "Sum", "Period": 3600, "EvaluationPeriods": 1, "Threshold": 1000,
        "ComparisonOperator": "GreaterThanThreshold", "TreatMissingData": "notBreaching",
        "AlarmActions": [arn("JanitorFunction")]}}
    r["AlarmInvokePermission"] = {"Type": "AWS::Lambda::Permission", "Properties": {
        "FunctionName": ref("JanitorFunction"), "Action": "lambda:InvokeFunction",
        "Principal": "lambda.alarms.cloudwatch.amazonaws.com", "SourceAccount": ref("AWS::AccountId"),
        "SourceArn": arn("UsageAlarm")}}
    return {"AWSTemplateFormatVersion": "2010-09-09",
        "Description": "NULL REBIRTH AWS sandbox - target USD5 - automatic deletion Dec1 2026 JST",
        "Parameters": {"ArtifactBucket": {"Type": "String"},
                       "OperatorToken": {"Type": "String", "NoEcho": True, "MinLength": 32},
                       "ReserveConcurrency": {"Type": "String", "Default": "true", "AllowedValues": ["true", "false"]}},
        "Conditions": {"CanReserve": {"Fn::Equals": [ref("ReserveConcurrency"), "true"]}},
        "Resources": r,
        "Outputs": {"DemoUrl": {"Value": {"Fn::GetAtt": ["ApiUrl", "FunctionUrl"]}},
                    "SigningKeyArn": {"Value": arn("SigningKey")}, "StateTable": {"Value": ref("StateTable")},
                    "AuditTable": {"Value": ref("AuditTable")},
                    "ShutdownJST": {"Value": "2026-12-01 20:00 Asia/Tokyo"}}}


if __name__ == "__main__":
    Path("dist").mkdir(exist_ok=True)
    Path("dist/template.json").write_text(json.dumps(generate(), indent=2), encoding="utf-8")
