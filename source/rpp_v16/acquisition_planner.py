"""Risk-weighted Proof Acquisition Planner (PAP) — never an authorization source.

Chooses which read-only evidence probe might unlock the largest number of missing
clauses per stated cost. Costs/probabilities are user-declared modelling assumptions,
not measured cloud facts. No probe performs any network call or repair.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping
from rpp_v15.proof_frontier import GateResult, POLICIES, FrontierError

@dataclass(frozen=True)
class Probe:
    atom:str
    cost_units:int
    latency_ms:int
    pass_probability_ppm:int # assumption, NOT empirical calibration
    read_only:bool=True

@dataclass(frozen=True)
class ProbeRecommendation:
    atom:str; cost_units:int; latency_ms:int; assumed_probability_ppm:int
    potential_actions:tuple[str,...]
    uncovered_clauses:int

@dataclass(frozen=True)
class AcquisitionPlan:
    recommendations:tuple[ProbeRecommendation,...]
    budget_used:int
    status:str='COUNTERFACTUAL_READ_ONLY_NO_AUTHORIZATION'
    effects_performed:int=0


def plan_acquisition(results:Mapping[str,GateResult],probes:Mapping[str,Probe],*,
      budget:int,desired_actions:tuple[str,...],max_probes:int=5)->AcquisitionPlan:
    if type(budget) is not int or budget<0 or type(max_probes) is not int or not 0<=max_probes<=10:
        raise FrontierError('INVALID_ACQUISITION_BUDGET')
    whitelist={a for p in POLICIES for g in p.obligations for a in g.one_of}
    actions={p.name for p in POLICIES}
    if not desired_actions or set(desired_actions)-actions:
        raise FrontierError('UNAPPROVED_TARGET_ACTION')
    for key,p in probes.items():
        if (key!=p.atom or key not in whitelist or not p.read_only or type(p.cost_units) is not int
            or p.cost_units<=0 or type(p.latency_ms) is not int or p.latency_ms<0
            or type(p.pass_probability_ppm) is not int or not 0<=p.pass_probability_ppm<=1_000_000):
            raise FrontierError('UNAPPROVED_OR_INVALID_PROBE')
    # Known failures and evidence contradictions are never "solved" by observing more.
    pending={name:list(results[name].missing_groups) for name in desired_actions
             if results[name].status=='PROOF_MISSING'}
    chosen=[];spent=0;available=set(probes)
    while pending and len(chosen)<max_probes:
        scores=[]
        for atom in available:
            p=probes[atom]
            if spent+p.cost_units>budget:continue
            affected=tuple(sorted(name for name,groups in pending.items()
                      if any(atom in group for group in groups)))
            coverage=sum(sum(atom in group for group in groups) for groups in pending.values())
            # A zero-probability or zero-positive-utility probe must not spend budget.
            if not affected or not coverage or p.pass_probability_ppm == 0:continue
            # Prefer expected clause coverage / cost; deterministic tie breaks.
            score=(coverage*p.pass_probability_ppm/p.cost_units, len(affected),
                   -p.latency_ms, -p.cost_units)
            scores.append((score,atom,affected,coverage))
        if not scores:break
        _,atom,affected,coverage=max(scores,key=lambda x:(x[0],x[1]))
        p=probes[atom]
        chosen.append(ProbeRecommendation(atom,p.cost_units,p.latency_ms,p.pass_probability_ppm,affected,coverage))
        spent+=p.cost_units;available.remove(atom)
        # A selected probe is a *hypothetical success*, not evidence of a real PASS.
        pending={name:[g for g in groups if atom not in g] for name,groups in pending.items()}
        pending={name:groups for name,groups in pending.items() if groups}
    return AcquisitionPlan(tuple(chosen),spent)
