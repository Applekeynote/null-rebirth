"""Prepare/review/execute this specific lab update in the existing CloudShell.

Preparation never executes the change set. Six existing roles gain narrowly
scoped lab data permissions; Recovery alone gains one Nova Micro invocation.
No new persistent resources, credential changes, or shutdown changes.
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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import boto3

PREFIX="null-rebirth-v110"
ACCOUNT=os.environ.get("NR_ACCOUNT_ID", "NOT_CONFIGURED")
REGION="us-east-1"
STATE=Path(os.environ.get("NR_HEAL_STATE","healing-update-state.json"))
REPORT=Path("HEALING_DEPLOYMENT_REPORT.json")
ROLES=("bootstrap","witness","recovery","verifier","commit","api","janitor")
session=boto3.Session(region_name=REGION)
cf,s3=session.client("cloudformation"),session.client("s3")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(state):
    STATE.write_text(json.dumps(state,indent=2))
    os.chmod(STATE,0o600)


def current_template():
    t=cf.get_template(StackName=PREFIX)["TemplateBody"]
    return json.loads(t) if isinstance(t,str) else t


def physical():
    return {r["LogicalResourceId"]:r["PhysicalResourceId"] for r in cf.list_stack_resources(StackName=PREFIX)["StackResourceSummaries"]}


def static_review(old,new):
    assert set(old)==set(new)
    for key in set(old)-{"Resources"}:
        assert old[key]==new[key],key
    assert set(old["Resources"])==set(new["Resources"]) and len(new["Resources"])==32
    allowed_roles={x.capitalize()+"Role" for x in ROLES if x!="janitor"}
    additions={}
    for name,before in old["Resources"].items():
        after=new["Resources"][name]
        if before==after:
            continue
        b,a=json.loads(json.dumps(before)),json.loads(json.dumps(after))
        if name in allowed_roles:
            bpol=b["Properties"].pop("Policies");apol=a["Properties"].pop("Policies")
            assert b==a and len(bpol)==len(apol)==1
            bs=bpol[0]["PolicyDocument"]["Statement"];ass=apol[0]["PolicyDocument"]["Statement"]
            assert all(s in ass for s in bs),"Existing authority changed"
            added=[s for s in ass if s not in bs]
            assert added
            for s in added:
                assert s["Effect"]=="Allow"
                assert set(s["Action"])<= {"dynamodb:PutItem","dynamodb:GetItem","dynamodb:UpdateItem","dynamodb:ConditionCheckItem","bedrock:InvokeModel"}
                if "bedrock:InvokeModel" in s["Action"]:
                    assert name=="RecoveryRole" and s["Resource"]=={"Fn::Sub":"arn:${AWS::Partition}:bedrock:us-east-1::foundation-model/amazon.nova-micro-v1:0"}
                else:
                    assert s["Resource"]=={"Fn::GetAtt":["StateTable","Arn"]}
                    cond=s["Condition"]
                    keys=cond.get("ForAllValues:StringLike",cond.get("ForAllValues:StringEquals"))["dynamodb:LeadingKeys"]
                    assert all(k in {"HEAL#run-*","WORKLOAD#run-*","HEALCHECK#run-*","HEALSEAL#run-*","CONTROL#AI"} for k in keys)
            additions[name]=added
        elif name=="RecoveryFunction":
            assert b["Properties"].pop("Timeout")==30 and a["Properties"].pop("Timeout")==45 and b==a
        else:
            raise AssertionError("Unexpected static change: "+name)
    assert set(additions)==allowed_roles
    return additions


def prepare():
    assert not STATE.exists(),"Inspect existing update state before repeating"
    assert session.client("sts").get_caller_identity()["Account"]==ACCOUNT
    assert cf.describe_stacks(StackName=PREFIX)["Stacks"][0]["StackStatus"]=="UPDATE_COMPLETE"
    old,new=current_template(),json.loads(Path("template.json").read_text())
    additions=static_review(old,new)
    key=json.loads(Path("deployment-secrets.json").read_text())["operator_token"]
    with zipfile.ZipFile("app.zip") as z:
        assert not any("test" in n or ".token" in n or "secrets" in n for n in z.namelist())
        assert all(key.encode() not in z.read(n) for n in z.namelist())
    stack=cf.describe_stacks(StackName=PREFIX)["Stacks"][0]
    rollback_bucket=next(p["ParameterValue"] for p in stack["Parameters"] if p["ParameterKey"]=="ArtifactBucket")
    assert rollback_bucket.startswith(PREFIX+"-artifact-"+ACCOUNT+"-")
    fn=session.client("lambda").get_function(FunctionName=PREFIX+"-api")
    with urlopen(fn["Code"]["Location"],timeout=30) as response:
        previous_app=response.read()
    assert base64.b64encode(hashlib.sha256(previous_app).digest()).decode()==fn["Configuration"]["CodeSha256"]
    # The prior staging bucket was removed. Recreate only this exact named,
    # private artifact bucket so CloudFormation can roll back the code update.
    owned={b["Name"] for b in s3.list_buckets()["Buckets"]}
    assert rollback_bucket not in owned,"Inspect existing rollback artifact bucket before proceeding"
    s3.create_bucket(Bucket=rollback_bucket)
    s3.put_public_access_block(Bucket=rollback_bucket,PublicAccessBlockConfiguration={"BlockPublicAcls":True,"IgnorePublicAcls":True,"BlockPublicPolicy":True,"RestrictPublicBuckets":True})
    s3.put_bucket_lifecycle_configuration(Bucket=rollback_bucket,LifecycleConfiguration={"Rules":[{"ID":"expire-rollback","Filter":{"Prefix":""},"Status":"Enabled","Expiration":{"Days":1}}]})
    s3.put_object(Bucket=rollback_bucket,Key="app.zip",Body=previous_app,ServerSideEncryption="AES256")
    bucket=PREFIX+"-artifact-"+ACCOUNT+"-healing-"+secrets.token_hex(4)
    s3.create_bucket(Bucket=bucket)
    s3.put_public_access_block(Bucket=bucket,PublicAccessBlockConfiguration={"BlockPublicAcls":True,"IgnorePublicAcls":True,"BlockPublicPolicy":True,"RestrictPublicBuckets":True})
    s3.put_bucket_lifecycle_configuration(Bucket=bucket,LifecycleConfiguration={"Rules":[{"ID":"expire-artifacts","Filter":{"Prefix":""},"Status":"Enabled","Expiration":{"Days":1}}]})
    s3.upload_file("app.zip",bucket,"app.zip",ExtraArgs={"ServerSideEncryption":"AES256"})
    state=dict(phase="PREPARING",bucket=bucket,rollback_bucket=rollback_bucket,changeset="healing-reviewed-"+secrets.token_hex(3),
        code_sha256=sha(Path("app.zip").read_bytes()),template_sha256=sha(Path("template.json").read_bytes()),
        baseline_resources=physical(),permission_additions=additions)
    save(state)
    Path("HEALING_BASELINE_TEMPLATE.json").write_text(json.dumps(old,indent=2))
    cf.create_change_set(StackName=PREFIX,ChangeSetName=state["changeset"],ChangeSetType="UPDATE",
        TemplateBody=json.dumps(new,separators=(",",":")),Parameters=[{"ParameterKey":"ArtifactBucket","ParameterValue":bucket},
        {"ParameterKey":"OperatorToken","UsePreviousValue":True},{"ParameterKey":"ReserveConcurrency","UsePreviousValue":True}],Capabilities=["CAPABILITY_NAMED_IAM"])
    cf.get_waiter("change_set_create_complete").wait(StackName=PREFIX,ChangeSetName=state["changeset"])
    review()


def review():
    state=json.loads(STATE.read_text());assert state["phase"]=="PREPARING"
    changes=[x["ResourceChange"] for x in cf.describe_change_set(StackName=PREFIX,ChangeSetName=state["changeset"])["Changes"]]
    allowed={x.capitalize()+"Function" for x in ROLES}|set(state["permission_additions"])|{"AlarmInvokePermission","ScheduleRole","ShutdownSchedule","UsageAlarm"}
    assert all(c["LogicalResourceId"] in allowed and c["Action"]=="Modify" and c["Replacement"] in ("False","Conditional") for c in changes)
    assert {x.capitalize()+"Function" for x in ROLES}|set(state["permission_additions"]) <= {c["LogicalResourceId"] for c in changes}
    state.update(phase="REVIEWED",changes=changes);save(state)
    report=dict(account=ACCOUNT,region=REGION,stack=PREFIX,phase="REVIEWED_NOT_EXECUTED",
        code_sha256=state["code_sha256"],template_sha256=state["template_sha256"],new_persistent_resources=0,
        changed_existing_roles=6,permission_additions=state["permission_additions"],
        changes=[{k:c[k] for k in ("LogicalResourceId","Action","Replacement")} for c in changes],
        model="amazon.nova-micro-v1:0",ai_model_call_limit=600,ai_output_token_limit=384,
        shutdown="2026-12-01 20:00 Asia/Tokyo; retry Dec2",target_usd=5,maximum_requested_usd=60)
    Path("HEALING_CHANGE_REVIEW.json").write_text(json.dumps(report,indent=2))
    with zipfile.ZipFile("healing-review-evidence.zip","w",zipfile.ZIP_DEFLATED) as z:
        z.write("HEALING_CHANGE_REVIEW.json")
    print(json.dumps({k:v for k,v in report.items() if k!="permission_additions"},indent=2),flush=True)


def execute():
    state=json.loads(STATE.read_text());assert state["phase"]=="REVIEWED"
    assert sha(Path("app.zip").read_bytes())==state["code_sha256"]
    assert sha(Path("template.json").read_bytes())==state["template_sha256"]
    cf.execute_change_set(StackName=PREFIX,ChangeSetName=state["changeset"])
    state["phase"]="UPDATING";save(state)
    cf.get_waiter("stack_update_complete").wait(StackName=PREFIX)
    state["phase"]="UPDATE_COMPLETE";save(state)
    print("Healing update complete",flush=True)


def cleanup():
    state=json.loads(STATE.read_text())
    if state.get("staging_removed"):
        return
    assert state["bucket"].startswith(PREFIX+"-artifact-"+ACCOUNT+"-healing-")
    owned={b["Name"] for b in s3.list_buckets()["Buckets"]}
    for bucket in {state["bucket"],state["rollback_bucket"]}:
        assert bucket.startswith(PREFIX+"-artifact-"+ACCOUNT+"-")
        if bucket not in owned:
            continue
        s3.delete_object(Bucket=bucket,Key="app.zip");s3.delete_bucket(Bucket=bucket)
    state["staging_removed"]=True;save(state)


def verify():
    state=json.loads(STATE.read_text());assert state["phase"] in ("UPDATE_COMPLETE","DEPLOYED_AI_PENDING","VERIFIED","DEPLOYED_TEST_FAILED")
    stack=cf.describe_stacks(StackName=PREFIX)["Stacks"][0]
    url=next(x["OutputValue"] for x in stack["Outputs"] if x["OutputKey"]=="DemoUrl")
    key=json.loads(Path("deployment-secrets.json").read_text())["operator_token"]
    def request(path="",data=None,auth=False):
        headers={"Content-Type":"application/json","Origin":url.rstrip("/")}
        if auth:headers["Authorization"]="Bearer "+key
        req=Request(url+path,headers=headers,data=json.dumps(data).encode() if data is not None else None)
        try:
            with urlopen(req,timeout=65) as res:
                return res.status,res.read().decode()
        except HTTPError as exc:
            return exc.code,exc.read().decode()
    checks={}
    checks["anonymous_login_gate"]=request()[0]==200 and "AUTHORIZE ACCESS" in request()[1]
    checks["all_private_routes_denied"]=all(request(p)[0]==401 for p in ("api/config","api/heal","bridge.js","bridge.css","proof"))
    code,html=request(auth=True);checks["english_bridge"]=code==200 and "RUN INCIDENT" in html and '<html lang="en">' in html and key not in html
    code,config=request("api/config",auth=True);config=json.loads(config)
    checks["twenty_incident_sources"]=code==200 and len(config["incidents"])==20 and len({i["id"] for i in config["incidents"]})==20
    runs=[];ai_pending=False
    signing_key=next(x["OutputValue"] for x in stack["Outputs"] if x["OutputKey"]=="SigningKeyArn")
    public_key=base64.b64encode(session.client("kms").get_public_key(KeyId=signing_key)["PublicKey"]).decode()
    def verify_incident(incident):
        table=boto3.Session(region_name=REGION).resource("dynamodb").Table(PREFIX+"-state")
        code,body=request("api/heal",{"scenario":incident["id"]},True);result=json.loads(body)
        assert code==200,{"scenario":incident["id"],"status":code,"response":result}
        snapshots=[result];run=result["run_id"]
        while result["phase"] not in ("COMPLETE","BLOCKED"):
            code,body=request("api/heal/step",{"run_id":run,"revision":result["revision"]},True);result=json.loads(body)
            assert code==200,{"scenario":incident["id"],"status":code,"response":result}
            snapshots.append(result)
            time.sleep(.25)
        passed=result["phase"]=="COMPLETE" and result.get("verification",{}).get("kms_signature_verified") is True and result["verification"]["checks_passed"]==20 and 2<=len(result.get("ai_usage",[]))<=4 and all(u["model"]=="amazon.nova-micro-v1:0" for u in result["ai_usage"]) and result.get("report_engine")=="AMAZON_NOVA_MICRO"
        seal=table.get_item(Key={"PK":"HEALSEAL#"+run,"SK":"STATE"},ConsistentRead=True).get("Item")
        order=table.get_item(Key={"PK":"ORDER#"+run,"SK":"STATE"},ConsistentRead=True).get("Item")
        assert order is None,"Healing created a business order"
        entry=dict(scenario=incident["id"],passed=passed,result=result,snapshots=snapshots,
            attestation=json.loads(seal["payload"]) if seal else None,orders_created=0)
        Path("healing-case-"+incident["id"]+".json").write_text(json.dumps(entry,indent=2))
        print(json.dumps({"scenario":incident["id"],"phase":result["phase"],"passed":passed,"error":result.get("error")}),flush=True)
        return entry
    with ThreadPoolExecutor(max_workers=2) as pool:
        runs=list(pool.map(verify_incident,config["incidents"]))
    ai_pending=any(r["result"].get("error","").startswith("AI_UNAVAILABLE:AccessDenied") for r in runs)
    checks["twenty_live_ai_repairs"]=len(runs)==20 and all(r["passed"] for r in runs)
    expected=base64.b64encode(hashlib.sha256(Path("app.zip").read_bytes()).digest()).decode()
    hashes={x:session.client("lambda").get_function_configuration(FunctionName=PREFIX+"-"+x)["CodeSha256"] for x in ROLES}
    checks["seven_code_hashes_match"]=all(x==expected for x in hashes.values())
    checks["all_32_resource_ids_unchanged"]=physical()==state["baseline_resources"]
    checks["template_matches"]=current_template()==json.loads(Path("template.json").read_text())
    iam=session.client("iam");wanted=json.loads(Path("template.json").read_text())["Resources"]
    # Compare the exact evaluated leading keys/actions and direct model ARN.
    live={x:iam.get_role_policy(RoleName=PREFIX+"-"+x+"-role",PolicyName="sandbox")["PolicyDocument"] for x in ROLES if x!="janitor"}
    model_statements=[s for s in live["recovery"]["Statement"] if "bedrock:InvokeModel" in s["Action"]]
    checks["recovery_model_is_exactly_scoped"]=len(model_statements)==1 and model_statements[0]["Resource"]=="arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-micro-v1:0"
    checks["other_workers_have_no_model_access"]=all("bedrock:InvokeModel" not in s["Action"] for x,p in live.items() if x!="recovery" for s in p["Statement"])
    schedule=session.client("scheduler").get_schedule(Name=PREFIX+"-shutdown")
    checks["shutdown_unchanged"]=schedule["State"]=="ENABLED" and schedule["ScheduleExpression"]=="cron(0 20 1,2 12 ? 2026)" and schedule["ScheduleExpressionTimezone"]=="Asia/Tokyo"
    cleanup();state=json.loads(STATE.read_text());checks["staging_removed"]=state["staging_removed"]
    state["phase"]="VERIFIED" if all(checks.values()) else "DEPLOYED_AI_PENDING" if ai_pending else "DEPLOYED_TEST_FAILED";save(state)
    report=dict(checked_at=int(time.time()),account=ACCOUNT,stack=PREFIX,stack_status=stack["StackStatus"],url=url,
        checks=checks,passed=all(checks.values()),ai_pending=ai_pending,runs=runs,
        signing_public_key_der_base64=public_key,
        code_sha256=state["code_sha256"],lambda_hashes=hashes,new_persistent_resources=0,changed_existing_roles=6,
        ai_model="amazon.nova-micro-v1:0",deadline="2026-12-01 20:00 Asia/Tokyo")
    REPORT.write_text(json.dumps(report,indent=2));Path("HEALING_DEPLOYED_TEMPLATE.json").write_text(json.dumps(current_template(),indent=2))
    with zipfile.ZipFile("healing-deployment-evidence.zip","w",zipfile.ZIP_DEFLATED) as z:
        for n in (REPORT,"HEALING_DEPLOYED_TEMPLATE.json","HEALING_CHANGE_REVIEW.json"):
            z.write(n)
    print(json.dumps({"phase":state["phase"],"checks":checks,"ai_pending":ai_pending},indent=2),flush=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("phase",choices=("prepare","review","execute","verify","cleanup"))
    globals()[parser.parse_args().phase]()
