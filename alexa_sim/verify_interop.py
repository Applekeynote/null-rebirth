"""Independent official-SDK client plus explicit 2025-11-25 transport checks."""
import asyncio,json,site
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
root=Path(__file__).resolve().parents[1]
if (root/'.mcpdeps').exists():site.addsitedir(str(root/'.mcpdeps'))
from mcp import Client
URL='http://127.0.0.1:8768/mcp/'
def rpc(body,origin=None):
    headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2025-11-25'}
    if origin:headers['Origin']=origin
    with urlopen(Request(URL,data=json.dumps(body).encode(),headers=headers),timeout=20) as r:return json.load(r)
async def main():
    init=rpc({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'nr-explicit-2025-client','version':'1'}}})
    assert init['result']['protocolVersion']=='2025-11-25'
    async with Client(URL,mode='legacy',read_timeout_seconds=30) as c:
        listing=await c.list_tools();names=[t.name for t in listing.tools];assert len(names)==7
        results={}
        for name in ['get_recovery_status','inspect_proof_frontier','plan_missing_evidence','inspect_resume_gate']:
            r=await c.call_tool(name,{});assert not r.is_error
            data=r.structured_content
            if data is None:data=json.loads(next(x.text for x in r.content if hasattr(x,'text')))
            assert isinstance(data,dict) and data
            results[name]=data
        assert results['get_recovery_status']['checks_total']==25
        assert results['inspect_proof_frontier']['effects_performed']==0
        assert results['plan_missing_evidence']['effects_performed']==0
        assert results['inspect_resume_gate']['business_order_created'] is False
        bad=await c.call_tool('inspect_proof_frontier',{'scenario':'../../etc/passwd'});assert bad.is_error
        blocked=await c.call_tool('confirm_recovery',{'run_id':'run-'+'0'*32,'confirmation_id':'invalid'});assert blocked.is_error
    try:rpc({'jsonrpc':'2.0','id':1,'method':'ping'},'https://untrusted.invalid')
    except HTTPError as e:assert e.code==403
    else:raise AssertionError('Untrusted Origin was accepted')
    out={'sdk':'mcp 2.3.0','protocol':'2025-11-25','transport':'Streamable HTTP / JSON','tools':names,'read_results':results,'invalid_scenario_rejected':True,'unconfirmed_repair_rejected':True,'untrusted_origin_rejected':True,'actual_echo_tested':False}
    (root/'evidence/aws/ALEXA_MCP_INTEROP.json').write_text(json.dumps(out,indent=2),encoding='utf8')
    print(json.dumps({k:v for k,v in out.items() if k!='read_results'}))
if __name__=='__main__':asyncio.run(main())
