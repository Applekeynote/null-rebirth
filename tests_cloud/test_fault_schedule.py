import pytest
from cloud import healing,sandbox
from tests_cloud.heal_fake import FakeRuntime

@pytest.mark.parametrize('draw',[0,180])
def test_persisted_random_deadline_cannot_be_fast_forwarded(monkeypatch,draw):
    clock=[1792300000]
    monkeypatch.setattr(healing,'utc_now',lambda:clock[0])
    monkeypatch.setattr(healing.secrets,'randbelow',lambda n:draw if n==181 else pytest.fail('Unexpected range'))
    rt=FakeRuntime();s=healing.start(rt,{'scenario':'lost-database'});rid=s['run_id']
    assert s['fault_delay_seconds']==120+draw and s['fault_due_at']==clock[0]+120+draw
    stored=rt.get(rid,'HEAL');workload=rt.payload(rid,'WORKLOAD')
    for moment in [clock[0],s['fault_due_at']-1]:
        clock[0]=moment
        assert healing.advance(rt,{'run_id':rid,'revision':0})==s
        assert rt.get(rid,'HEAL')==stored and rt.payload(rid,'WORKLOAD')==workload
        assert rt.counters.get('CONTROL#AI',0)==0
    clock[0]=s['fault_due_at']
    broken=healing.advance(rt,{'run_id':rid,'revision':0})
    assert broken['phase']=='ANOMALY' and broken['revision']==1
    assert not sandbox.probe(rt.payload(rid,'WORKLOAD'))['healthy']
    assert healing.advance(rt,{'run_id':rid,'revision':0})==broken
    assert sum(e[1]=='HEAL_ANOMALY' for e in rt.events)==1
