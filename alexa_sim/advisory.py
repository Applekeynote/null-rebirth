"""Original Proof Frontier/PAP reference calculations. Read-only synthetic inputs."""
from datetime import datetime,timedelta,timezone
from rpp_v15.proof_frontier import POLICIES,VerifiedFact,assess,safe_mode
from rpp_v16.acquisition_planner import Probe,plan_acquisition

CASES={'primary-healthy','silent-monitor-death','backup-recovered','untrusted-receipt','conflicting-evidence'}
def evaluate(scenario):
    if scenario not in CASES:raise ValueError('Unknown reference case.')
    now=datetime(2026,10,12,4,0,tzinfo=timezone.utc);scope='reference/incident/operation';contract='sha256:'+'f'*64
    atoms={a for p in POLICIES for g in p.obligations for a in g.one_of}
    x={a:VerifiedFact(a,'PASS',True,scope,contract,now+timedelta(minutes=2),'sha256:'+'a'*64) for a in atoms}
    def set_(a,status,auth=True):x[a]=VerifiedFact(a,status,auth,scope,contract,now+timedelta(minutes=2),'sha256:'+'a'*64)
    set_('original_route_failed','UNKNOWN');set_('incident_monitor_failed','FAIL');set_('degraded_writes_contract_allowed','FAIL')
    if scenario in {'silent-monitor-death','backup-recovered','untrusted-receipt'}:
        set_('incident_monitor_failed','PASS');set_('primary_pipeline_fresh','FAIL');set_('original_route_healthy','FAIL');set_('original_route_failed','PASS')
    if scenario=='silent-monitor-death':
        set_('lease_current','FAIL');set_('backup_pipeline_fresh_authorized','UNKNOWN');set_('evidence_source_authenticated','UNKNOWN')
    if scenario=='untrusted-receipt':set_('backup_pipeline_fresh_authorized','PASS',False)
    if scenario=='conflicting-evidence':set_('original_route_failed','PASS')
    return assess(x,as_of=now,scope=scope,contract_hash=contract)
def frontier(scenario='silent-monitor-death'):
    out=evaluate(scenario)
    return {'scenario':scenario,'source':'SYNTHETIC REFERENCE MODEL','effects_performed':0,'actual_authorization':False,'safe_mode':safe_mode(out),
        'decisions':{k:{'status':v.status,'missing_proof_frontier':v.missing_proof_frontier,'blocking_failed_atoms':v.blocking_failed_atoms} for k,v in out.items()}}
def acquisition(scenario='silent-monitor-death'):
    out=evaluate(scenario);atoms={a for v in out.values() for g in v.missing_groups for a in g}
    catalog={a:Probe(a,2+i%5,120+i%4*80,700000) for i,a in enumerate(sorted(atoms))}
    plan=plan_acquisition(out,catalog,budget=12,desired_actions=('read_own_order','repair_primary_monitor','new_mock_order','issue_full_history','issue_degraded_history'))
    return {'source':'SYNTHETIC REFERENCE MODEL','effects_performed':0,'actual_authorization':False,'cost_basis':'ILLUSTRATIVE UNITS, NOT AWS PRICES',
        'budget_used':plan.budget_used,'status':plan.status,'recommendations':[{'atom':r.atom,'cost_units':r.cost_units,'potential_actions':r.potential_actions} for r in plan.recommendations]}
