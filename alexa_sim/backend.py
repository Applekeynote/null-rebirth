"""Bounded adapter to the existing protected AWS lab, not a new AWS deployment."""
from pathlib import Path
import hashlib, json, os, re, secrets, threading, time
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError

ROOT=Path(__file__).resolve().parents[1]
BASE=os.getenv('NR_LAB_URL','').rstrip('/')
EXPECTED_BASE_SHA256='d7f26fc725be83fab8ad40d52e548c4bd493b451caa56b40c03c0e96d816202b'
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

class Lab:
    def __init__(self,mode=None):
        self.mode=mode or os.getenv('NR_MODE','recorded')
        if self.mode not in {'recorded','aws'}:raise ValueError('Invalid NR_MODE')
        self.recorded=json.loads((ROOT/'evidence/aws/CONTAINMENT_BROWSER_EXPORT.json').read_text(encoding='utf8'))['result']
        recent=ROOT/'evidence/aws/ALEXA_LIVE_VALIDATION.json'
        if recent.exists():self.recorded=json.loads(recent.read_text(encoding='utf8'))['result']
        self.latest=self.recorded['run_id']
        self.owned=set();self.pending={};self.lock=threading.RLock()
        self.opener=build_opener(NoRedirect())
    def request(self,path,body=None):
        if self.mode!='aws':raise ValueError('Recorded mode is read-only. Set NR_MODE=aws for a live run.')
        if hashlib.sha256(BASE.encode()).hexdigest()!=EXPECTED_BASE_SHA256:raise ValueError('Set NR_LAB_URL to the judge-only exhibition endpoint.')
        keyfile=os.environ.get('NR_REVIEW_KEY_FILE')
        if not keyfile:raise ValueError('Server review key is not configured.')
        key=Path(keyfile).read_text().strip()
        if len(key)<32:raise ValueError('Invalid server review key.')
        headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'}
        req=Request(BASE+path,data=json.dumps(body).encode() if body is not None else None,headers=headers)
        try:
            with self.opener.open(req,timeout=55) as r:return json.load(r)
        except HTTPError as e:
            # Never return request headers or credentials through a tool error.
            raise ValueError(f'AWS lab returned HTTP {e.code}. Inspect the server configuration or run state.') from None
    def state(self,run_id=''):
        rid=run_id or self.latest
        if rid==self.recorded['run_id'] and rid not in self.owned:return dict(self.recorded)
        if rid not in self.owned or not re.fullmatch(r'run-[a-f0-9]{32}',rid):raise ValueError('Run is not owned by this simulator session.')
        return self.request('/api/heal?run_id='+rid)
    def start(self,scenario):
        from cloud.incidents import CATALOG
        if scenario not in CATALOG:raise ValueError('Unknown approved scenario.')
        with self.lock:
            if len(self.owned)>=5:raise ValueError('This simulator process permits at most five new runs.')
            state=self.request('/api/heal',{'scenario':scenario})
            self.owned.add(state['run_id']);self.latest=state['run_id']
            return state
    def step(self,state):
        return self.request('/api/heal/step',{'run_id':state['run_id'],'revision':state['revision']})
    def prepare(self,run_id=''):
        with self.lock:
            state=self.state(run_id)
            if state['run_id'] not in self.owned:raise ValueError('Recorded evidence cannot authorize a new repair. Start a live lab first.')
            if state['phase']=='NORMAL' and time.time()<state.get('fault_due_at',0):raise ValueError('Monitoring is active. The scheduled fault has not occurred yet.')
            for _ in range(6):
                if state['phase']=='REPAIR_READY':break
                if state['phase'] in {'COMPLETE','BLOCKED','REPAIRING','VERIFYING','NORMALIZED','REPORTING'}:raise ValueError('This run cannot prepare another repair.')
                if state.get('fault_due_at') and state['phase'] in {'ANOMALY','WARNING'}:time.sleep(3)
                state=self.step(state)
            if state['phase']!='REPAIR_READY':raise ValueError('No validated repair proposal is ready.')
            return self.permit(state)
    def permit(self,state):
        with self.lock:
            if state['run_id'] not in self.owned or state['phase']!='REPAIR_READY':raise ValueError('No owned proposal is ready.')
            # At most one valid permit per run. Re-review invalidates the old one.
            self.pending={k:v for k,v in self.pending.items() if v['run_id']!=state['run_id'] and time.monotonic()<=v['until']}
            token=secrets.token_urlsafe(24)
            self.pending[token]={'run_id':state['run_id'],'revision':state['revision'],
                'plan':hashlib.sha256(json.dumps(state['plan'],sort_keys=True).encode()).hexdigest(), 'until':time.monotonic()+120}
            return {'state':state,'confirmation_id':token,'confirmation_required':True,
                'confirmation_expires_at':time.time()+120,
                'message':'Review the approved runbook. Confirm explicitly to apply it to this isolated workload.'}
    def confirm(self,run_id,confirmation_id):
        with self.lock:
            permit=self.pending.pop(confirmation_id,None)
            if not permit or permit['run_id']!=run_id or time.monotonic()>permit['until']:raise ValueError('Missing, expired or consumed confirmation.')
            state=self.state(run_id)
            digest=hashlib.sha256(json.dumps(state.get('plan'),sort_keys=True).encode()).hexdigest()
            if state['phase']!='REPAIR_READY' or state['revision']!=permit['revision'] or digest!=permit['plan']:raise ValueError('Proposal or run revision changed. Prepare it again.')
            for _ in range(6):
                if state['phase'] in {'COMPLETE','BLOCKED'}:break
                if state.get('fault_due_at') and state['phase'] in {'REPAIRING','VERIFYING'}:time.sleep(2)
                state=self.step(state)
            if state['phase'] not in {'COMPLETE','BLOCKED'}:raise ValueError('Workflow did not reach a terminal state.')
            return state

def summary(state,mode):
    v=state.get('verification',{})
    probe=state.get('probe',state.get('observed',{}))
    return {'run_id':state['run_id'],'scenario':state['scenario'],'phase':state['phase'],
        'revision':state['revision'],'mode':'AWS LIVE LAB' if mode=='aws' and state.get('phase')!='RECORDED' else 'RECORDED AWS EVIDENCE',
        'checks_passed':v.get('checks_passed',probe.get('passed_count',0)),
        'checks_total':v.get('checks_total',probe.get('total',25)),
        'plan':state.get('plan'),'verification':v,'dialogue':state.get('dialogue',[]),
        'report':state.get('report'),'ai_usage':state.get('ai_usage',[]),
        'started_at':state.get('started_at'),'fault_due_at':state.get('fault_due_at'),
        'fault_delay_seconds':state.get('fault_delay_seconds')}
