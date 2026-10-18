import asyncio,json,time
import pytest
from alexa_sim import server

class Request:
    headers={'origin':server.ORIGIN,'x-nr-session':server.WEB_TOKEN}
    def __init__(self,body=None,query=None):self.body=body or {};self.query_params=query or {}
    async def json(self):return self.body

@pytest.mark.anyio
async def test_monitoring_writes_require_the_local_session(monkeypatch):
    request=Request();request.headers={}
    for route in [server.experiment,server.review,server.cancel_conversations]:
        response=await route(request)
        assert response.status_code==403

@pytest.mark.anyio
async def test_duplicate_start_does_not_create_another_aws_run(monkeypatch):
    server.conversations.clear();calls=[]
    async def tool(name,args):
        calls.append(name)
        return {'run_id':'run-'+'a'*32,'started_at':time.time(),'fault_due_at':time.time()+180,'fault_delay_seconds':180,'phase':'NORMAL'}
    monkeypatch.setattr(server,'call_tool',tool)
    request=Request({'thread_id':'e'*32,'scenario':'sourcenext-api'})
    one=await server.experiment(request);two=await server.experiment(request)
    assert one.status_code==200 and two.status_code==400 and calls==['start_incident_lab']
    ctx=server.conversations['e'*32];ctx['task'].cancel()
    await asyncio.gather(ctx['task'],return_exceptions=True);server.conversations.clear()

@pytest.mark.anyio
async def test_waiting_poll_uses_cached_baseline_without_aws_calls(monkeypatch):
    server.conversations.clear();ctx=server.conversation_context('e'*32)
    ctx.update(cached={'run_id':'saved','phase':'NORMAL'},monitor={'status':'WAITING'},pending=None)
    monkeypatch.setattr(server.lab,'state',lambda *args:pytest.fail('Waiting must not poll AWS'))
    response=await server.state(Request(query={'thread_id':'e'*32}))
    assert response.status_code==200 and json.loads(response.body)['monitor']['status']=='WAITING'
    server.conversations.clear()

@pytest.mark.anyio
@pytest.mark.parametrize('rejected',[False,True])
async def test_confirmation_exposes_progress_and_restores_rejected_review(monkeypatch,rejected):
    server.conversations.clear();ctx=server.conversation_context('f'*32)
    rid=ctx['run_id'];entered=asyncio.Event();release=asyncio.Event()
    ctx.update(pending={'state':{'run_id':rid},'confirmation_id':'one-use'},monitor={'status':'REPAIR_READY'},cached={'phase':'REPAIR_READY'})
    current={'run_id':rid,'scenario':'sourcenext-api','phase':'REPAIRING','revision':5}
    monkeypatch.setattr(server.lab,'state',lambda *args:dict(current))
    async def tool(name,args):
        assert ctx['monitor']['status']=='REPAIRING'
        entered.set();await release.wait()
        if rejected:
            current['phase']='REPAIR_READY'
            raise ValueError('Expired confirmation')
        return {**current,'phase':'COMPLETE'}
    monkeypatch.setattr(server,'call_tool',tool)
    task=asyncio.create_task(server.chat(Request({'thread_id':'f'*32,'message':'Confirm the repair'})))
    await entered.wait()
    response=await server.state(Request(query={'thread_id':'f'*32}))
    assert json.loads(response.body)['phase']=='REPAIRING'
    release.set();result=await task
    assert result.status_code==(400 if rejected else 200)
    assert ctx['monitor']['status']==('REPAIR_READY' if rejected else 'COMPLETE')
    assert ctx['pending'] is None
    server.conversations.clear()
