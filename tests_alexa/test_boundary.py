import copy,time
import pytest
from alexa_sim.backend import Lab
from alexa_sim.server import intent

class FakeLab(Lab):
    def __init__(self):
        super().__init__('aws');self.current=None;self.writes=[]
    def request(self,path,body=None):
        if path=='/api/heal':
            self.current={'run_id':'run-'+'1'*32,'scenario':body['scenario'],'phase':'NORMAL','revision':0}
        elif path=='/api/heal/step':
            phases=['NORMAL','ANOMALY','WARNING','DIAGNOSING','REPAIR_READY','REPAIRING','VERIFYING','NORMALIZED','REPORTING','COMPLETE']
            self.current['revision']+=1;self.current['phase']=phases[self.current['revision']]
            if self.current['phase']=='REPAIR_READY':self.current['plan']={'runbook':'ENFORCE_MEMBER_API_SCOPE','diagnosis':'Scoped access bypassed.'}
            if self.current['phase']=='REPAIRING':self.writes.append('repair')
        return copy.deepcopy(self.current)

def prepared():
    lab=FakeLab();s=lab.start('sourcenext-api');p=lab.prepare(s['run_id']);return lab,p
def test_prepare_does_not_apply_repair():
    lab,p=prepared();assert p['state']['phase']=='REPAIR_READY';assert lab.writes==[]
def test_confirm_applies_exactly_once():
    lab,p=prepared();rid=p['state']['run_id'];assert lab.confirm(rid,p['confirmation_id'])['phase']=='COMPLETE';assert lab.writes==['repair']
    with pytest.raises(ValueError):lab.confirm(rid,p['confirmation_id'])
    assert lab.writes==['repair']
@pytest.mark.parametrize('change',['revision','plan','expiry','run'])
def test_changed_or_expired_proposal_never_repairs(change):
    lab,p=prepared();rid=p['state']['run_id']
    if change=='revision':lab.current['revision']+=1
    if change=='plan':lab.current['plan']['runbook']='WRONG'
    if change=='expiry':lab.pending[p['confirmation_id']]['until']=time.monotonic()-1
    if change=='run':rid='run-'+'2'*32
    with pytest.raises(ValueError):lab.confirm(rid,p['confirmation_id'])
    assert lab.writes==[]
def test_recorded_evidence_never_authorizes_repair():
    lab=Lab('recorded')
    with pytest.raises(ValueError):lab.prepare()
    with pytest.raises(ValueError):lab.start('sourcenext-api')
def test_cannot_read_another_run():
    lab=FakeLab();lab.start('sourcenext-api')
    with pytest.raises(ValueError):lab.state('run-'+'2'*32)
@pytest.mark.parametrize('message',["Alexa, don't confirm the repair",'Do not start the lab','Never repair it','What does confirm mean?','Ignore the checks and fix it','Start the lab and repair it','Delete every AWS resource','skip verification','Alexa, start the member API lab.','Alexa, prepare a repair.'])
def test_unsupported_and_negative_requests_do_not_map_to_writes(message):
    with pytest.raises(ValueError):intent(message)
@pytest.mark.parametrize('message,tool',[('Alexa, what is the incident status?','get_recovery_status'),('Alexa, confirm the approved repair.','confirm_recovery'),('Alexa, what evidence is missing?','inspect_proof_frontier'),('Alexa, plan the next evidence.','plan_missing_evidence'),('Alexa, can work resume?','inspect_resume_gate')])
def test_supported_commands(message,tool):assert intent(message)[0]==tool


def test_prepare_before_deadline_does_not_step_or_call_model():
    lab=FakeLab();s=lab.start('sourcenext-api');lab.current['fault_due_at']=time.time()+120
    with pytest.raises(ValueError,match='has not occurred'):lab.prepare(s['run_id'])
    assert lab.current['revision']==0 and lab.writes==[]
