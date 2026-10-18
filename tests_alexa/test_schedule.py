import asyncio
from types import SimpleNamespace
import pytest
from alexa_sim import server

@pytest.mark.anyio
async def test_scheduler_waits_then_diagnoses_once_without_repair(monkeypatch):
    calls=[]
    async def tool(name,args):
        calls.append((name,args))
        return {'state':{'run_id':'run-'+'1'*32,'phase':'REPAIR_READY'},'confirmation_id':'private','confirmation_expires_at':999}
    monkeypatch.setattr(server,'call_tool',tool)
    ctx={'run_id':'run-'+'1'*32,'lock':asyncio.Lock(),'monitor':{'status':'WAITING'},'pending':None}
    task=asyncio.create_task(server.automatic_incident(ctx,.04))
    await asyncio.sleep(.01)
    assert calls==[] and ctx['monitor']['status']=='WAITING'
    await task
    assert [c[0] for c in calls]==['prepare_recovery']
    assert ctx['monitor']['status']=='REPAIR_READY' and ctx['pending']['confirmation_id']=='private'
    assert 'confirmation_id' not in server.monitor_view(ctx)

@pytest.mark.anyio
async def test_cancelled_waiting_thread_does_not_inject(monkeypatch):
    async def tool(*args):pytest.fail('A cancelled timer must not call MCP')
    monkeypatch.setattr(server,'call_tool',tool)
    ctx={'lock':asyncio.Lock(),'monitor':{'status':'CANCELLED'}}
    await server.automatic_incident(ctx,0)

@pytest.mark.anyio
async def test_diagnosis_failure_never_claims_repair(monkeypatch):
    async def tool(*args):raise ValueError('Upstream failed')
    monkeypatch.setattr(server,'call_tool',tool)
    ctx={'run_id':'example','lock':asyncio.Lock(),'monitor':{'status':'WAITING'},'pending':None}
    await server.automatic_incident(ctx,0)
    assert ctx['monitor']['status']=='FAILED' and ctx['pending'] is None
