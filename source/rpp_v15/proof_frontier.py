"""Evidence-to-Authority Frontier (EAF), a bounded *advisory* proof planner.

New work must still pass independent authenticated gateway and atomic DB checks.
Never accept a caller-provided EvidenceFact as self-authenticating evidence.
This module expects observations from an authenticated evidence verification layer.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from itertools import product
import json
import re
from typing import Mapping, Sequence


class FrontierError(ValueError):
    pass


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise FrontierError('AWARE_UTC_TIME_REQUIRED')
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class VerifiedFact:
    atom: str
    state: str  # PASS, FAIL or UNKNOWN
    source_authenticated: bool
    scope: str
    contract_hash: str
    valid_until: datetime
    evidence_digest: str

    def normalized_state(self, now: datetime, scope: str, contract_hash: str) -> str:
        # If an observation is stale or untrusted it is UNKNOWN, never a PASS.
        if (not self.source_authenticated or self.scope != scope or
            self.contract_hash != contract_hash or not re.fullmatch(r'sha256:[0-9a-f]{64}', self.evidence_digest) or
            now >= _utc(self.valid_until)):
            return 'UNKNOWN'
        if self.state not in {'PASS', 'FAIL', 'UNKNOWN'}:
            return 'UNKNOWN'
        return self.state


@dataclass(frozen=True)
class Obligation:
    # An OR group. Different groups are combined with AND.
    one_of: tuple[str, ...]

    def __post_init__(self):
        if not self.one_of or any(not a or not isinstance(a, str) for a in self.one_of):
            raise FrontierError('INVALID_OBLIGATION')


@dataclass(frozen=True)
class ActionPolicy:
    name: str
    obligations: tuple[Obligation, ...]


@dataclass(frozen=True)
class GateResult:
    action: str
    eligible: bool
    status: str
    # Candidate evidence acquisition ONLY; never permission to perform repair.
    missing_proof_frontier: tuple[str, ...]
    blocking_failed_atoms: tuple[str, ...]
    missing_groups: tuple[tuple[str, ...], ...]
    evidence_digest: str


# Preapproved, static policy. Cannot be authored/expanded by LLM at runtime.
POLICIES: tuple[ActionPolicy, ...] = (
    ActionPolicy('read_own_order', tuple(map(Obligation, (
        ('authenticated',), ('owner_matches',), ('tenant_matches',),
        ('policy_active',), ('read_scope_valid',),
    )))),
    ActionPolicy('repair_primary_monitor', tuple(map(Obligation, (
        ('recovery_admin_authenticated',), ('tenant_matches',), ('policy_active',),
        ('incident_monitor_failed',), ('original_route_failed',), ('capability_issued_valid',),
        ('backup_precanary_fresh',), ('fence_current',), ('runbook_rb001_approved',),
    )))),
    ActionPolicy('new_mock_order', tuple(map(Obligation, (
        ('authenticated',), ('owner_matches',), ('tenant_matches',),
        ('policy_active',), ('write_scope_valid',), ('contract_approved',),
        ('authorization_current',), ('lease_current',), ('idempotency_guard',),
        ('primary_pipeline_fresh', 'backup_pipeline_fresh_authorized'),
        ('primary_pipeline_fresh', 'degraded_writes_contract_allowed'),
    )))),
    ActionPolicy('issue_full_history', tuple(map(Obligation, (
        ('evidence_source_authenticated',), ('audit_complete',), ('authorization_proven',),
        ('business_proven',), ('independent_verifier_pass',),
        ('primary_pipeline_fresh',), ('original_route_healthy',),
    )))),
    ActionPolicy('issue_degraded_history', tuple(map(Obligation, (
        ('evidence_source_authenticated',), ('audit_complete',), ('authorization_proven',),
        ('business_proven',), ('independent_verifier_pass',),
        ('original_route_failed',), ('backup_pipeline_fresh_authorized',),
    )))),
)


def _policy_hash(policies: Sequence[ActionPolicy]) -> str:
    value = [{'action': p.name, 'obligations': [list(g.one_of) for g in p.obligations]} for p in policies]
    return 'sha256:' + sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


POLICY_HASH = _policy_hash(POLICIES)


def _atoms(policies: Sequence[ActionPolicy]) -> set[str]:
    return {atom for p in policies for group in p.obligations for atom in group.one_of}


def _observed(facts: Mapping[str, VerifiedFact], now: datetime, scope: str, contract_hash: str,
              policies: Sequence[ActionPolicy]) -> dict[str, str]:
    known = _atoms(policies)
    for supplied_key, fact in facts.items():
        if supplied_key not in known or not isinstance(fact, VerifiedFact):
            raise FrontierError('UNKNOWN_OR_INVALID_FACT_ATOM')
        # Critical: caller dictionary keys must NEVER re-label a cryptographic claim.
        if fact.atom != supplied_key:
            raise FrontierError('FACT_ATOM_BINDING_MISMATCH')
    return {a: facts[a].normalized_state(now, scope, contract_hash) if a in facts else 'UNKNOWN'
            for a in known}


def _minimal_unknown_plan(groups: Sequence[Obligation], states: Mapping[str, str],
                          costs: Mapping[str, int]) -> tuple[str, ...]:
    """Find minimum-cost set of UNKNOWN atoms covering all still-unsatisfied OR clauses.

    FAIL atoms are excluded: collecting more evidence does not fix known bad state.
    If no UNKNOWN alternative can satisfy a group, return no proposed proof plan.
    """
    candidates = []
    for group in groups:
        if any(states[a] == 'PASS' for a in group.one_of):
            continue
        viable = tuple(sorted(a for a in group.one_of if states[a] == 'UNKNOWN'))
        if not viable:
            return ()
        candidates.append(viable)
    if not candidates:
        return ()
    # Bound enumeration; safety must not rely on combinatorial explosion.
    count = 1
    for option in candidates:
        count *= len(option)
        if count > 4096:
            raise FrontierError('FRONTIER_SEARCH_BUDGET_EXCEEDED')
    options = (tuple(sorted(set(choice))) for choice in product(*candidates))
    unique = set(options)
    return min(unique, key=lambda x: (sum(costs.get(a, 1) for a in x), len(x), x))


def assess(facts: Mapping[str, VerifiedFact], *, as_of: datetime, scope: str, contract_hash: str,
           policies: Sequence[ActionPolicy] = POLICIES, acquisition_costs: Mapping[str, int] | None = None,
           conflict_latched: bool = False) -> dict[str, GateResult]:
    """A *non-authoritative* snapshot explanation; does not invoke effects or issue tokens."""
    now = _utc(as_of)
    if not scope or not re.fullmatch(r'sha256:[0-9a-f]{64}', contract_hash):
        raise FrontierError('INVALID_SCOPE_OR_CONTRACT')
    costs = acquisition_costs or {}
    if any(type(v) is not int or v <= 0 for v in costs.values()):
        raise FrontierError('INVALID_COST')
    if tuple(policies) != POLICIES:
        raise FrontierError('POLICY_NOT_PREAPPROVED')
    states = _observed(facts, now, scope, contract_hash, policies)
    contradictory = tuple(sorted({a for pair in (
        ('original_route_failed', 'original_route_healthy'),
        ('original_route_failed', 'primary_pipeline_fresh'),
    ) if all(states[a] == 'PASS' for a in pair) for a in pair}))
    if conflict_latched:
        contradictory = tuple(sorted(set(contradictory) | {'EVIDENCE_CONFLICT_LATCHED'}))
    result = {}
    for policy in policies:
        missing_groups = tuple(group.one_of for group in policy.obligations
                               if not any(states[a] == 'PASS' for a in group.one_of))
        known_failed = tuple(sorted({a for group in policy.obligations
                                     if all(states[a] == 'FAIL' for a in group.one_of)
                                     for a in group.one_of}))
        eligible = not missing_groups and not contradictory
        missing = () if eligible or known_failed or contradictory else _minimal_unknown_plan(policy.obligations, states, costs)
        status = ('EVIDENCE_CONTRADICTION' if contradictory else
                  'PRELIMINARY_ELIGIBLE' if eligible else
                  'BLOCKED_BY_KNOWN_FAILURE' if known_failed else 'PROOF_MISSING')
        # Digest is an explanation identity, not a signed security certificate.
        body = {'action': policy.name, 'policy': _policy_hash(policies), 'states': states,
                'scope': scope, 'contract_hash': contract_hash, 'as_of': now.isoformat(),
                'eligible': eligible, 'missing': missing, 'known_failed': known_failed}
        explanation_digest = 'sha256:' + sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        result[policy.name] = GateResult(policy.name, eligible, status, tuple(missing),
                                         contradictory or known_failed, missing_groups, explanation_digest)
    return result


def counterfactual(facts: Mapping[str, VerifiedFact], proposed_observations: Mapping[str, VerifiedFact], *,
                   as_of: datetime, scope: str, contract_hash: str) -> dict:
    """What-if *only*: candidate snapshots cannot authorize actions or claim new facts.

    Known verified FAIL cannot be silently promoted to PASS; legitimate repair requires
    a new independently authenticated event and a separate post-repair evidence horizon.
    """
    existing = _observed(facts, _utc(as_of), scope, contract_hash, POLICIES)
    for atom, fact in proposed_observations.items():
        if atom not in _atoms(POLICIES) or fact.atom != atom:
            raise FrontierError('UNKNOWN_OR_MISMATCHED_ATOM')
        if existing[atom] == 'FAIL' and fact.normalized_state(_utc(as_of),scope,contract_hash) == 'PASS':
            raise FrontierError('CANNOT_WHATIF_AWAY_VERIFIED_FAILURE')
    original = assess(facts, as_of=as_of, scope=scope, contract_hash=contract_hash)
    projected = dict(facts)
    projected.update(proposed_observations)
    hypothetical = assess(projected, as_of=as_of, scope=scope, contract_hash=contract_hash)
    return {
        'kind': 'COUNTERFACTUAL_ONLY_NEVER_AUTHORIZATION',
        'policy_hash': POLICY_HASH,
        'baseline': {k: {'status': v.status, 'missing_proof': list(v.missing_proof_frontier)} for k,v in original.items()},
        'hypothetical': {k: {'status': v.status, 'missing_proof': list(v.missing_proof_frontier)} for k,v in hypothetical.items()},
        'gained_actions': sorted(k for k,v in hypothetical.items() if v.eligible and not original[k].eligible),
        'assumed_atoms': sorted(proposed_observations),
        'effects_performed': 0,
    }


def safe_mode(results: Mapping[str, GateResult]) -> str:
    """Advisory maximum action class; actual gateway must recheck all conditions."""
    if results['new_mock_order'].eligible: return 'ACTIVE_CANDIDATE'
    if results['repair_primary_monitor'].eligible: return 'RECOVERY_ONLY_CANDIDATE'
    if results['read_own_order'].eligible: return 'READ_ONLY_CANDIDATE'
    return 'QUARANTINED_CANDIDATE'
