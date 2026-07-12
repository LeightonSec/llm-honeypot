"""Gate 2 semantic-layer tests — Criteria A–E (DECISIONS.md P3-V).

Five criteria because the outcomes are five different KINDS of thing, and one
merged test could not say which invariant broke:

  A — routing    (pure)         was it in-band?
  B — admission  (state)        were we allowed to call?
  C — isolation  (write path)   did the judge stay out of api_*?
  D — execution  (failure)      did an attempted-and-failed call tell the truth?
  E — disabled   (deployment)   is the fail-closed default real, not a comment?

No API key, no network, no spend: the judge is injected at the seam, and the
ledger is driven by recording REAL calls — never by stubbing the decision under
test, which would prove nothing about the ordering it claims to verify.

CRITERION C IS ONLY HALF-COVERED HERE. The half that exists asserts against
evaluate()'s real return object (it has no api_* surface at all — you cannot
persist a field that does not exist). The other half — that the DB row written
by the app keeps api_* byte-identical — cannot be tested until app.py/db.py
wiring lands, because there is no production write path yet. G2 IS NOT CLOSED
until that test exists; nothing in this file should be read as covering it.
"""

import itertools

import pytest

from classifier import HONEYPOT_PATTERNS
from semantic import (
    BAND_MISS,
    BREAKER_OPEN,
    BUDGET_GLOBAL,
    BUDGET_SOURCE,
    DISABLED,
    ENTERS_BAND,
    JUDGE_FAILED,
    JUDGED,
    ROUTING_OUTCOMES,
    SKIP_REASONS,
    WATCH_SE_SENTIMENT,
    BudgetConfig,
    BudgetLedger,
    evaluate,
    merge,
    route,
)

RISK_LEVELS = ["LOW", "MEDIUM", "HIGH"]

# Derived from the LIVE source of truth, never a hardcoded list: adding a sixth
# attack type to HONEYPOT_PATTERNS automatically enters this matrix. A snapshot
# list would guard yesterday's enum and go green on tomorrow's (proxy-test
# failure class). Verified: classify_attack() builds its score dict FROM
# HONEYPOT_PATTERNS and returns one of its keys or "unknown"; analyse_and_classify
# adds only "clean" (its other two overrides, jailbreak/social_engineering, are
# already keys). No translation layer between those strings and route().
ATTACK_TYPES = sorted(set(HONEYPOT_PATTERNS) | {"clean", "unknown"})


@pytest.fixture(autouse=True)
def _enabled(monkeypatch):
    """Layer ON for every test EXCEPT Criterion E, which owns the OFF default."""
    monkeypatch.setenv("SEMANTIC_ENABLED", "1")


def stub_judge(verdict, confidence="HIGH", reason="stub"):
    def _judge(_prompt):
        return {"VERDICT": verdict, "CONFIDENCE": confidence, "REASON": reason}
    return _judge


def exploding_judge(_prompt):
    raise RuntimeError("transport blew up")


def fresh_ledger(**overrides):
    """Ledger with the locked V2 defaults; any field overridable by name.

    Defaults live in a dict and are then overridden — passing the fields
    explicitly AND **overrides would raise TypeError on duplicate kwargs the
    moment a test overrode one (caught in review before it bit).
    """
    defaults = {
        "hourly_cap": 60,
        "daily_cap": 300,
        "per_source_hourly": 5,
        "breaker_consecutive_errors": 3,
        "breaker_cooldown_seconds": 900,
    }
    return BudgetLedger(BudgetConfig(**{**defaults, **overrides}))


def in_band_case(**kwargs):
    """Arguments that reach the judge: unknown + MEDIUM (the locked band)."""
    base = dict(
        prompt="ambiguous payload",
        attack_type="unknown",
        local_risk="MEDIUM",
        sentiment_bumped=False,
        source="1.2.3.4",
    )
    base.update(kwargs)
    return base


# ============================================================================
# Criterion A — routing: pure, matrix-driven, total and disjoint
# ============================================================================

def test_criterion_a_routing_total_and_disjoint():
    """For EVERY (attack_type, risk_level, sentiment_bumped): exactly one
    routing outcome. Never two (the single skip-reason column cannot express
    it); never zero (an unrouted case writes a NULL verdict with a NULL reason
    — the silent gap the column exists to prevent).

    Disjointness is asserted from the SPEC's predicates, not from route()'s
    branch order — if two ever hold at once, route() is silently picking one.
    """
    for attack_type, risk, bumped in itertools.product(ATTACK_TYPES, RISK_LEVELS, [True, False]):
        outcome = route(attack_type, risk, bumped)
        assert outcome in ROUTING_OUTCOMES, (attack_type, risk, bumped, outcome)

        in_band = attack_type == "unknown" and risk == "MEDIUM"
        in_watch = attack_type == "social_engineering" and bumped
        assert not (in_band and in_watch), f"two outcomes claim {(attack_type, risk, bumped)}"

        expected = ENTERS_BAND if in_band else WATCH_SE_SENTIMENT if in_watch else BAND_MISS
        assert outcome == expected, (attack_type, risk, bumped, outcome, expected)


def test_criterion_a_band_is_exactly_one_cell():
    """The band is unknown+MEDIUM and nothing else — the neighbours are already
    collapsed by classifier.py's fusion (unknown+LOW → clean, unknown+HIGH →
    jailbreak), so they are labelled, not ambiguous."""
    banded = {
        (a, r)
        for a, r, b in itertools.product(ATTACK_TYPES, RISK_LEVELS, [True, False])
        if route(a, r, b) == ENTERS_BAND
    }
    assert banded == {("unknown", "MEDIUM")}


def test_criterion_a_watch_cell_never_enters_band():
    """V1b: the watch cell is instrumented, never judged — no spend, and it
    cannot leak into the band at any risk level."""
    for risk, bumped in itertools.product(RISK_LEVELS, [True, False]):
        outcome = route("social_engineering", risk, bumped)
        assert outcome != ENTERS_BAND
        assert outcome == (WATCH_SE_SENTIMENT if bumped else BAND_MISS)


def test_criterion_a_routing_skips_are_legal_column_values():
    for attack_type, risk, bumped in itertools.product(ATTACK_TYPES, RISK_LEVELS, [True, False]):
        outcome = route(attack_type, risk, bumped)
        if outcome != ENTERS_BAND:
            assert outcome in SKIP_REASONS


# ============================================================================
# Criterion B — admission: state-driven, exactly one outcome, order load-bearing
# ============================================================================

def test_criterion_b_under_cap_is_judged():
    assert fresh_ledger().admit("1.2.3.4", now=1000.0) == JUDGED


def test_criterion_b_at_source_cap():
    """Per-source cap (5/hr) bites well before the global cap (60/hr) — one
    attacker cannot starve every other session (P3)."""
    ledger = fresh_ledger()
    for i in range(5):
        assert ledger.admit("attacker", now=1000.0 + i) == JUDGED
    assert ledger.admit("attacker", now=1005.0) == BUDGET_SOURCE
    # ...and another source is unaffected: the starvation attack fails.
    assert ledger.admit("someone-else", now=1005.0) == JUDGED


def test_criterion_b_at_global_cap():
    """Global cap reached via many distinct sources, each under its own cap."""
    ledger = fresh_ledger(hourly_cap=10, per_source_hourly=5)
    for i in range(10):
        assert ledger.admit(f"src-{i // 2}", now=1000.0 + i) == JUDGED
    assert ledger.admit("fresh-source", now=1010.0) == BUDGET_GLOBAL


def test_criterion_b_global_cap_precedes_source_cap():
    """Link 1→2 of the order: a case that could not afford a call is never
    attributed to a source limit it also happened to hit."""
    ledger = fresh_ledger(hourly_cap=2, per_source_hourly=2)
    assert ledger.admit("s", now=1000.0) == JUDGED
    assert ledger.admit("s", now=1001.0) == JUDGED
    assert ledger.admit("s", now=1002.0) == BUDGET_GLOBAL


def test_criterion_b_budget_precedes_breaker_when_both_would_trip():
    """Link 2→3 of the order — the tiebreak nothing else exercises.

    Two pairwise proofs are not a proof of a three-link chain. Without a case
    sitting in the OVERLAP (budget exhausted AND breaker tripped), a refactor
    that moved the breaker check ahead of budget would leave every other test
    green while silently changing what rows report. Budget must win: the call
    was refused because we could not afford it, and it must not be attributed
    to an API failure it never made.
    """
    ledger = fresh_ledger(hourly_cap=1, breaker_consecutive_errors=3)
    assert ledger.admit("s", now=1000.0) == JUDGED      # exhaust the global cap
    for _ in range(3):
        ledger.record_error(now=1000.0)                 # ...and trip the breaker
    assert ledger.stats(now=1001.0)["breaker_open"] is True

    assert ledger.admit("s", now=1001.0) == BUDGET_GLOBAL   # budget wins
    assert ledger.admit("s", now=1001.0) != BREAKER_OPEN


def test_criterion_b_breaker_open_refuses_admission():
    """Breaker refuses the call outright — no call made, no budget consumed."""
    ledger = fresh_ledger()
    for _ in range(3):
        ledger.record_error(now=1000.0)
    assert ledger.admit("1.2.3.4", now=1001.0) == BREAKER_OPEN
    assert ledger.stats(now=1001.0)["calls_last_hour"] == 0


def test_criterion_b_breaker_cooldown_half_opens():
    """V2a: a breaker, not a fuse — after the cooldown a probe is admitted."""
    ledger = fresh_ledger(breaker_cooldown_seconds=900)
    for _ in range(3):
        ledger.record_error(now=1000.0)
    assert ledger.admit("s", now=1500.0) == BREAKER_OPEN   # still cooling
    assert ledger.admit("s", now=1900.0) == JUDGED         # cooldown elapsed


# --- breaker state machine (V2a): CLOSED → OPEN → HALF_OPEN → ? -------------
#
# The Criteria A–E suite proved 3-strikes-then-open and nothing else: the
# transition back OUT of open was never exercised, which is how two real defects
# survived it (a failing probe not re-opening the breaker; a stats() flag that
# lied). Recovery behaviour that is not tested is just a second copy of the bug.


def trip_breaker(ledger, now=1000.0):
    """Drive the breaker OPEN through the real path — three recorded errors."""
    for _ in range(3):
        ledger.record_error(now=now)
    assert ledger.stats(now=now)["breaker_state"] == "OPEN"


def test_breaker_half_open_probe_succeeds_closes_the_breaker():
    """Probe succeeds → CLOSED, error count reset. Normal traffic resumes."""
    ledger = fresh_ledger(breaker_cooldown_seconds=900)
    trip_breaker(ledger)

    assert ledger.stats(now=1900.0)["breaker_state"] == "HALF_OPEN"  # cooldown up
    assert ledger.admit("s", now=1900.0) == JUDGED                   # the probe
    assert ledger.stats(now=1900.0)["probe_in_flight"] is True

    ledger.record_success()
    stats = ledger.stats(now=1900.0)
    assert stats["breaker_state"] == "CLOSED"
    assert stats["breaker_open"] is False
    assert stats["consecutive_errors"] == 0
    assert stats["probe_in_flight"] is False
    assert ledger.admit("s", now=1901.0) == JUDGED                   # traffic resumed


def test_breaker_half_open_probe_fails_reopens_immediately():
    """THE bug this state machine fixed: one probe failure re-opens, and the
    cooldown RESTARTS. Previously the probe failure was counted as "error 1 of
    3", so a genuinely down judge received three fresh calls every window.
    """
    ledger = fresh_ledger(breaker_cooldown_seconds=900)
    trip_breaker(ledger, now=1000.0)

    assert ledger.admit("s", now=1900.0) == JUDGED       # probe admitted
    ledger.record_error(now=1900.0)                      # ...and it fails

    stats = ledger.stats(now=1900.0)
    assert stats["breaker_state"] == "OPEN"              # re-opened, not "1 of 3"
    assert stats["breaker_open"] is True
    assert stats["probe_in_flight"] is False

    # Cooldown RESTARTED from the probe failure: still open at what would have
    # been the original window's end, half-open only 900s after the FAILURE.
    assert ledger.admit("s", now=2000.0) == BREAKER_OPEN
    assert ledger.stats(now=2799.0)["breaker_state"] == "OPEN"
    assert ledger.stats(now=2800.0)["breaker_state"] == "HALF_OPEN"


def test_breaker_only_one_probe_at_a_time():
    """Concurrent in-band calls while a probe is unresolved are REFUSED.

    The judge call happens outside the ledger lock, so several threads can be
    past admit() at once. Without this guard, every request arriving as the
    cooldown expires becomes a simultaneous probe against a judge already known
    to be broken — the hammering the breaker exists to prevent.
    """
    ledger = fresh_ledger(breaker_cooldown_seconds=900)
    trip_breaker(ledger)

    assert ledger.admit("first", now=1900.0) == JUDGED        # the one probe
    assert ledger.admit("second", now=1900.0) == BREAKER_OPEN  # refused
    assert ledger.admit("third", now=1901.0) == BREAKER_OPEN   # still refused
    assert ledger.stats(now=1901.0)["calls_last_hour"] == 1     # only the probe spent


def test_breaker_hung_probe_reports_open_and_refuses():
    """The no-hang test: a probe that never resolves must READ as open.

    A hung probe (the accepted transport-timeout gap) never calls record_success
    or record_error, so _breaker_opened_at is never touched and the state stays
    HALF_OPEN forever — while _probe_in_flight refuses every subsequent call.
    Deriving `breaker_open` from `state == "OPEN"` would report FALSE here: a
    dashboard reading "healthy" while nothing is being judged. It must reflect
    what a consumer means — "are calls being refused for breaker reasons".

    No sleeping required: "unresolved" is simply "no resolution call happened".
    """
    ledger = fresh_ledger(breaker_cooldown_seconds=900)
    trip_breaker(ledger)

    assert ledger.admit("s", now=1900.0) == JUDGED   # probe goes out...
    # ...and hangs: neither record_success nor record_error is ever called.

    stats = ledger.stats(now=1900.0)
    assert stats["breaker_state"] == "HALF_OPEN"     # granular truth
    assert stats["probe_in_flight"] is True
    assert stats["breaker_open"] is True, "hung probe refuses calls — must not read healthy"

    # And the refusal is real, not just reported.
    assert ledger.admit("s", now=1901.0) == BREAKER_OPEN
    assert ledger.admit("other", now=5000.0) == BREAKER_OPEN  # still stuck, still honest


def test_breaker_open_flag_is_never_stale():
    """The other original defect: breaker_open must not report OPEN once the
    cooldown has elapsed and no probe is out — that state is HALF_OPEN, and the
    next call WILL be admitted."""
    ledger = fresh_ledger(breaker_cooldown_seconds=900)
    trip_breaker(ledger)

    assert ledger.stats(now=1500.0)["breaker_open"] is True    # still cooling
    stats = ledger.stats(now=1900.0)                           # cooldown elapsed
    assert stats["breaker_state"] == "HALF_OPEN"
    assert stats["breaker_open"] is False, "a half-open breaker admits the next call"


def test_criterion_b_exactly_one_admission_outcome_per_state():
    """Totality + disjointness over injected states — never zero, never two.
    Each ledger is driven into its state through the REAL path (recording calls
    and errors), never by stubbing admit()'s answer."""
    under = fresh_ledger()
    at_global = fresh_ledger(hourly_cap=1)
    at_source = fresh_ledger(per_source_hourly=1)
    breaker = fresh_ledger()

    at_global.admit("other", now=1000.0)
    at_source.admit("same", now=1000.0)
    for _ in range(3):
        breaker.record_error(now=1000.0)

    cases = [
        ("under_cap", under, JUDGED),
        ("at_global", at_global, BUDGET_GLOBAL),
        ("at_source", at_source, BUDGET_SOURCE),
        ("breaker", breaker, BREAKER_OPEN),
    ]
    for name, ledger, expected in cases:
        outcome = ledger.admit("same", now=1001.0)
        assert outcome == expected, f"{name}: got {outcome}"
        if outcome != JUDGED:
            assert outcome in SKIP_REASONS


# --- ledger memory safety: THREE distinct properties, tested separately -----
#
# A flood of unique source fingerprints is attacker-controllable input to a
# dict, so the ledger must not grow without bound. Three different mechanisms
# are involved and they must not be conflated — an earlier version of this test
# asserted only the downstream NUMBER (active_sources == 60), which a buggy
# implementation that recorded every ATTEMPTED source could still satisfy while
# leaking memory. Assert the mechanisms, not the number they happen to produce.


def test_criterion_b_cap_bounds_how_many_sources_are_admitted():
    """Property 1: the global cap bounds the ledger's source count, because a
    source is only recorded when it is ADMITTED and admission stops at the cap.
    """
    ledger = fresh_ledger(hourly_cap=60)
    for i in range(1000):
        ledger.admit(f"src-{i}", now=1000.0)
    assert ledger.stats(now=1000.0)["active_sources"] == 60


def test_criterion_b_refused_sources_leave_no_footprint():
    """Property 2 (the MECHANISM, not a downstream number): a source refused at
    admission must leave NO trace in the ledger.

    In admit(), the budget check returns BEFORE `_source_calls.setdefault(...)`,
    so a refused source never enters the dict. This test distinguishes that safe
    implementation from a buggy one that records every attempted source and
    merely happens to report a plausible count — the flood is the attack, and an
    attacker whose refused calls still allocate has found the memory leak the
    budget was supposed to prevent.
    """
    ledger = fresh_ledger(hourly_cap=1)
    assert ledger.admit("first", now=1000.0) == JUDGED
    before = ledger.stats(now=1000.0)["active_sources"]
    assert before == 1

    for i in range(500):  # every one of these is refused at the global cap
        assert ledger.admit(f"flood-{i}", now=1000.0) == BUDGET_GLOBAL

    after = ledger.stats(now=1000.0)["active_sources"]
    assert after == before, "refused sources must not be recorded — ledger is leaking"
    assert ledger._source_calls.keys() == {"first"}, "only the admitted source is tracked"


def test_criterion_b_pruning_drops_idle_sources():
    """Property 3, ISOLATED from the cap: pruning. With a cap high enough that
    every source IS admitted, the dict must still not accumulate across hours —
    idle sources fall out of the window. (With a low cap this property is
    invisible, because the cap does the bounding and pruning is never exercised
    on more than a handful of entries.)
    """
    ledger = fresh_ledger(hourly_cap=500, daily_cap=500, per_source_hourly=5)
    for i in range(200):
        assert ledger.admit(f"src-{i}", now=1000.0) == JUDGED
    assert ledger.stats(now=1000.0)["active_sources"] == 200   # all admitted

    assert ledger.stats(now=1000.0 + 3601)["active_sources"] == 0  # all pruned
    assert ledger._source_calls == {}, "pruned sources must be removed, not emptied"


# ============================================================================
# Criterion C — write-path isolation (HALF: see module docstring)
# ============================================================================

LOCAL_API_FIELDS = ("api_verdict", "api_confidence", "api_reason")


@pytest.mark.parametrize(
    "verdict",
    ["CLEAN", "SUSPICIOUS", "JAILBREAK", None],
    ids=["judge_clean", "judge_suspicious", "judge_jailbreak", "judge_failed"],
)
def test_criterion_c_semantic_result_has_no_api_surface(verdict):
    """P4/P6b hazard, ENFORCED against production code.

    api_verdict/api_confidence/api_reason hold LOCALLY synthesized values. If
    the judge ever writes into them, the local verdict is destroyed — and with
    it BOTH disagreement flags, which are computed by comparing local against
    semantic. Detection would not degrade; it would silently vanish while every
    counter still read healthy.

    The strongest available form of the guarantee: the semantic layer's output
    object has no api_* surface AT ALL. You cannot accidentally persist a field
    that does not exist.
    """
    result = evaluate(
        **in_band_case(),
        ledger=fresh_ledger(),
        judge=stub_judge(verdict),
        now=1000.0,
    )
    for field in LOCAL_API_FIELDS:
        assert not hasattr(result, field), f"semantic result exposes {field} — P4 hazard"
    assert hasattr(result, "verdict") and hasattr(result, "reason")


def test_merge_shape_illustration_not_criterion_c():
    """NOT a Criterion C test — deliberately named so nobody mistakes it for one.

    It hand-assembles a row in the TEST FILE and asserts that assembly is
    correct, which proves only that this test agrees with itself. No production
    code assembles a DB row yet (app.py/db.py wiring is the next G2 step), so
    the real write-path guarantee CANNOT be tested here. It is documented as an
    open G2 item; when the wiring lands, the real Criterion C test must assert
    that the row DB actually receives keeps api_* byte-identical.

    Kept as an illustration of the intended row shape, honestly labelled.
    """
    local_analysis = {
        "api_verdict": "SUSPICIOUS",
        "api_confidence": "LOW",
        "api_reason": "Local pattern match only (firewall unavailable)",
        "risk_level": "MEDIUM",
    }
    before = {k: local_analysis[k] for k in LOCAL_API_FIELDS}

    result = evaluate(
        **in_band_case(),
        ledger=fresh_ledger(),
        judge=stub_judge("JAILBREAK"),
        now=1000.0,
    )
    illustrative_row = {
        **local_analysis,
        "risk_level": result.risk_level,
        "semantic_verdict": result.verdict,
        "semantic_skip_reason": result.skip_reason,
        "semantic_disagreement": result.disagreement,
    }
    assert {k: illustrative_row[k] for k in LOCAL_API_FIELDS} == before
    assert illustrative_row["semantic_verdict"] == "JAILBREAK"
    assert illustrative_row["risk_level"] == "HIGH"


# --- merge semantics (P6b): additive-only, both directions reachable ---------

def test_merge_is_additive_only_and_flags_both_directions():
    down = merge("MEDIUM", "CLEAN")
    assert down.risk_level == "MEDIUM"                      # exoneration impossible
    assert down.disagreement == "judge_disagreement_down"

    up = merge("MEDIUM", "JAILBREAK")
    assert up.risk_level == "HIGH"                          # max() obeys
    assert up.disagreement == "judge_disagreement_up"

    same = merge("MEDIUM", "SUSPICIOUS")
    assert same.risk_level == "MEDIUM" and same.disagreement is None

    none = merge("MEDIUM", None)
    assert none.risk_level == "MEDIUM" and none.disagreement is None


def test_merge_up_direction_is_reachable_from_the_locked_band():
    """The bug the P6b amendment fixed: with the band pinned at local=MEDIUM, a
    fixed-level up-trigger ("local LOW/CLEAN") was UNREACHABLE — a permanently
    zero counter reading as safety. Relative comparison makes it reachable.
    """
    result = evaluate(
        **in_band_case(),                  # local risk is MEDIUM by construction
        ledger=fresh_ledger(),
        judge=stub_judge("JAILBREAK"),
        now=1000.0,
    )
    assert result.disagreement == "judge_disagreement_up"
    assert result.risk_level == "HIGH"


# ============================================================================
# Criterion D — execution: an attempted-and-failed call tells the TRUTH
# ============================================================================

@pytest.mark.parametrize(
    "judge",
    [stub_judge(None), exploding_judge],
    ids=["degraded_verdict_none", "judge_raises"],
)
def test_criterion_d_failed_judge_is_judge_failed_not_breaker_open(judge):
    """V3a. By the time the judge is called, admission returned JUDGED — only
    possible with the breaker CLOSED and the call already recorded against both
    budgets. Labelling this `breaker_open` would be a FALSE claim: it inflates
    the breaker-health signal and makes ledger stats irreconcilable with per-row
    reasons (budget consumed, row says no call was made).

    A raise and a degraded return take the same path — operationally identical.
    """
    ledger = fresh_ledger()
    result = evaluate(**in_band_case(), ledger=ledger, judge=judge, now=1000.0)

    assert result.skip_reason == JUDGE_FAILED
    assert result.skip_reason != BREAKER_OPEN
    assert result.verdict is None                   # no verdict → no merge
    assert result.risk_level == "MEDIUM"            # local untouched
    assert result.disagreement is None

    stats = ledger.stats(now=1000.0)
    assert stats["calls_last_hour"] == 1            # budget WAS consumed
    assert stats["consecutive_errors"] == 1         # breaker WAS incremented
    assert stats["breaker_open"] is False           # ...but is not yet open


def test_criterion_d_outcomes_compose_over_time_into_breaker_open():
    """The actual proof the breaker works: labelling each outcome correctly in
    isolation proves only bookkeeping. After N consecutive judge_failed results
    the NEXT call must be refused at ADMISSION with breaker_open — a different
    row label, and no further budget consumed.
    """
    ledger = fresh_ledger(breaker_consecutive_errors=3)
    judge = stub_judge(None)

    for i in range(3):
        r = evaluate(**in_band_case(), ledger=ledger, judge=judge, now=1000.0 + i)
        assert r.skip_reason == JUDGE_FAILED, f"call {i}"

    assert ledger.stats(now=1003.0)["calls_last_hour"] == 3
    assert ledger.stats(now=1003.0)["breaker_open"] is True

    def must_not_be_called(_prompt):
        raise AssertionError("breaker is open — the judge must NOT be called")

    r = evaluate(**in_band_case(), ledger=ledger, judge=must_not_be_called, now=1003.0)
    assert r.skip_reason == BREAKER_OPEN
    assert r.skip_reason != JUDGE_FAILED
    assert ledger.stats(now=1003.0)["calls_last_hour"] == 3   # no new spend


def test_criterion_d_success_resets_the_error_count():
    """A blip must not accumulate toward a trip across a healthy call between."""
    ledger = fresh_ledger()
    evaluate(**in_band_case(), ledger=ledger, judge=stub_judge(None), now=1000.0)
    evaluate(**in_band_case(), ledger=ledger, judge=stub_judge(None), now=1001.0)
    assert ledger.stats(now=1001.0)["consecutive_errors"] == 2

    evaluate(**in_band_case(), ledger=ledger, judge=stub_judge("CLEAN"), now=1002.0)
    assert ledger.stats(now=1002.0)["consecutive_errors"] == 0
    assert ledger.stats(now=1002.0)["breaker_open"] is False


# ============================================================================
# Criterion E — the disabled path: the fail-closed default is REAL
# ============================================================================

def test_criterion_e_disabled_by_default_touches_nothing(monkeypatch):
    """V2b. Unset SEMANTIC_ENABLED → the layer returns `disabled`, local risk
    untouched, and touches NOTHING else: no ledger call, no judge call, no
    network. This is what makes the fail-closed default a control rather than a
    comment — and it is the easiest property to leave untested, because it is
    the simplest case.
    """
    monkeypatch.delenv("SEMANTIC_ENABLED", raising=False)   # override the fixture

    class ExplodingLedger(BudgetLedger):
        def admit(self, *_a, **_kw):
            raise AssertionError("layer is disabled — admission must NOT run")

    def must_not_be_called(_prompt):
        raise AssertionError("layer is disabled — the judge must NOT be called")

    result = evaluate(
        **in_band_case(),                 # in-band: WOULD be judged if enabled
        ledger=ExplodingLedger(BudgetConfig()),
        judge=must_not_be_called,
        now=1000.0,
    )
    assert result.skip_reason == DISABLED
    assert result.verdict is None
    assert result.risk_level == "MEDIUM"
    assert result.disagreement is None
    assert DISABLED in SKIP_REASONS


@pytest.mark.parametrize("value", ["0", "", "false", "no", "TRUE", "2"])
def test_criterion_e_only_explicit_1_enables(monkeypatch, value):
    """Anything other than exactly "1" leaves the layer off — a typo in the env
    file must not silently start spending money and calling an external API."""
    monkeypatch.setenv("SEMANTIC_ENABLED", value)

    def must_not_be_called(_prompt):
        raise AssertionError(f"SEMANTIC_ENABLED={value!r} must NOT enable the layer")

    result = evaluate(
        **in_band_case(),
        ledger=fresh_ledger(),
        judge=must_not_be_called,
        now=1000.0,
    )
    assert result.skip_reason == DISABLED
