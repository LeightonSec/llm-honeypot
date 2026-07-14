"""Phase B semantic layer — routing, admission, execution, merge.

See DECISIONS.md P3 / P3-V (V1, V1b, V2, V2a, V2b, V3, V3a) / P4 / P6b.

THREE kinds of outcome, deliberately distinct (V3a) — a row's skip reason must
be true about what actually happened to that row:

  routing    — was it in-band?          → band_miss, watch_band_se_sentiment
  admission  — were we allowed to call? → budget_global, budget_source,
                                          breaker_open  (NO call was made)
  execution  — did the call succeed?    → judge_failed  (call WAS made,
                                          budget consumed, verdict unusable)

Routing is a pure function of the case; admission is a function of runtime
state; execution is what the judge actually did. They are separately tested
(Criteria A, B, D) because they fail for different reasons and a merged test
could not say which invariant broke.

Check order is LOAD-BEARING (V3): enabled → band → budget → breaker → call.
It is what guarantees every case lands in exactly one outcome, which is the
only thing making `semantic_skip_reason` a single enum column.

`evaluate()` is the SINGLE entry point and the only path from the classifier to
the judge; the SEMANTIC_ENABLED gate is its first line, so no call site can
reach the network by forgetting to check a flag. Default 0 — an unconfigured
deploy behaves exactly like Phase A: no key, no egress, no spend.
"""

import os
import threading
import time
from dataclasses import dataclass

# --- severity scale (P6b amendment: one ordinal scale, one mapping) ----------

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

# The judge's closed vocabulary (ai-firewall VALID_VERDICTS) → local scale.
VERDICT_TO_SEVERITY = {"CLEAN": "LOW", "SUSPICIOUS": "MEDIUM", "JAILBREAK": "HIGH"}

# --- routing outcomes: was it in-band? (pure) -------------------------------

ENTERS_BAND = "enters_band"
WATCH_SE_SENTIMENT = "watch_band_se_sentiment"
BAND_MISS = "band_miss"

ROUTING_OUTCOMES = frozenset({ENTERS_BAND, WATCH_SE_SENTIMENT, BAND_MISS})

# --- admission outcomes: were we allowed to call? (runtime state) -----------
# Every non-JUDGED value here means NO CALL WAS MADE and NO BUDGET CONSUMED.

JUDGED = "judged"
BUDGET_GLOBAL = "budget_global"
BUDGET_SOURCE = "budget_source"
BREAKER_OPEN = "breaker_open"

ADMISSION_OUTCOMES = frozenset({JUDGED, BUDGET_GLOBAL, BUDGET_SOURCE, BREAKER_OPEN})

# --- execution outcome: did the call succeed? (V3a) -------------------------
# JUDGE_FAILED means the call WAS made and DID consume budget, and the judge
# returned no usable verdict (ai-firewall fails closed: VERDICT is None on a
# degraded/anomalous scan). It is NOT breaker_open — the breaker was closed, or
# admission would never have returned JUDGED. Reusing breaker_open here would
# inflate the breaker-health signal and make ledger stats irreconcilable with
# per-row skip reasons.

JUDGE_FAILED = "judge_failed"

# --- deployment outcome: the layer is switched off entirely (V2b) -----------

DISABLED = "disabled"

# Every legal value of the semantic_skip_reason column (V3/V3a): each means
# "the judge did not speak, and this is truthfully why".
SKIP_REASONS = (
    (ROUTING_OUTCOMES - {ENTERS_BAND})
    | (ADMISSION_OUTCOMES - {JUDGED})
    | {JUDGE_FAILED, DISABLED}
)

# --- disagreement flags (P6b): semantic_disagreement's closed vocabulary -----
# V5: db.py derives the column's CHECK constraint from DISAGREEMENTS, and
# merge() returns these same constants — one source of truth for schema and
# application, never two hand-synced copies of the strings. The VALUES are
# wire format (persisted rows + CHECK vocabulary): changing one is a schema
# migration event, and test_semantic.py pins them for exactly that reason.

DISAGREEMENT_UP = "judge_disagreement_up"      # max() obeys — noise-injection suspect
DISAGREEMENT_DOWN = "judge_disagreement_down"  # max() ignores — persuasion-to-clear suspect

DISAGREEMENTS = frozenset({DISAGREEMENT_UP, DISAGREEMENT_DOWN})


def is_enabled() -> bool:
    """V2b kill switch. Default OFF — fail-closed in the deployment dimension."""
    return os.getenv("SEMANTIC_ENABLED", "0") == "1"


# --- routing (pure) ----------------------------------------------------------

def route(attack_type: str, risk_level: str, sentiment_bumped: bool) -> str:
    """Pure routing decision (V1/V1b). Total and disjoint by construction.

    The band is the one genuinely ambiguous cell: the pattern classifier had no
    idea (`unknown`) while the keyword layer scored MEDIUM. classifier.py's
    fusion has already collapsed the neighbours — unknown+LOW becomes `clean`,
    unknown+HIGH is promoted to `jailbreak` — so those are labelled, not
    ambiguous, and buy nothing from a judge call.

    The watch cell (sentiment-bumped social_engineering) is EXCLUDED from the
    band but instrumented: it is where an attacker tuning against the keyword
    classifier lands, and there is no capture data on it yet. Excluding it
    without recording it would leave G3 making the same call with the same zero
    evidence (V1b).

    BRANCH ORDER IS NOT ARBITRARY, even though it currently cannot matter. The
    two predicates are disjoint today — an attack_type cannot be both `unknown`
    and `social_engineering` — and Criterion A asserts that disjointness from the
    spec, so it is provable, not assumed. But the code below reads as if the
    order were incidental, and it is not: if a future attack type could satisfy
    both, the band would win by POSITION alone, silently, and the single
    skip-reason column could no longer express the case. A future editor
    reordering these branches will not re-run Criterion A in their head — so the
    dependency is stated here rather than left to the test to defend.
    """
    if attack_type == "unknown" and risk_level == "MEDIUM":
        return ENTERS_BAND
    if attack_type == "social_engineering" and sentiment_bumped:
        return WATCH_SE_SENTIMENT
    return BAND_MISS


# --- admission (runtime state) -----------------------------------------------

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class BudgetConfig:
    """Cost/DoS bounds (V2/V2a). Independent of band width."""

    hourly_cap: int = 60
    daily_cap: int = 300
    per_source_hourly: int = 5
    breaker_consecutive_errors: int = 3
    # V2a: without a cooldown the breaker is a FUSE, not a circuit breaker —
    # three transient errors would end judging for the life of the process,
    # silently (degradation is graceful by design). Cooldown makes it
    # recoverable: open, hold, half-open a probe, reset on success.
    breaker_cooldown_seconds: int = 900

    @classmethod
    def from_env(cls) -> "BudgetConfig":
        return cls(
            hourly_cap=_env_int("SEMANTIC_HOURLY_CAP", 60),
            daily_cap=_env_int("SEMANTIC_DAILY_CAP", 300),
            per_source_hourly=_env_int("SEMANTIC_PER_SOURCE_HOURLY", 5),
            breaker_consecutive_errors=_env_int("SEMANTIC_BREAKER_CONSECUTIVE_ERRORS", 3),
            breaker_cooldown_seconds=_env_int("SEMANTIC_BREAKER_COOLDOWN_SECONDS", 900),
        )


class BudgetLedger:
    """Call accounting + circuit breaker — the real path admission decisions use.

    Tests drive this by recording real calls and real errors, never by stubbing
    the decision: a test that fakes admit()'s answer proves nothing about the
    ordering it claims to verify (Criterion B).

    Timestamps are injectable (`now`) so tests age the window without sleeping.
    Per-source buckets are pruned on every admit, so an attacker flooding unique
    source fingerprints cannot grow the ledger without bound — the same trust
    boundary the rest of the honeypot applies to attacker-controlled keys.
    """

    def __init__(self, config: BudgetConfig | None = None):
        self.config = config or BudgetConfig.from_env()
        self._lock = threading.Lock()
        self._global_calls: list[float] = []        # timestamps, pruned to 24h
        self._source_calls: dict[str, list[float]] = {}
        self._consecutive_errors = 0
        self._breaker_opened_at: float | None = None
        # HALF_OPEN is an EXPLICIT state (V2a). Modelling it implicitly — just
        # resetting the error count once the cooldown elapsed — produced two real
        # defects, found in the G2 self-review: a failing probe did NOT re-open
        # the breaker (it became "error 1 of 3", so a DOWN judge got three fresh
        # calls every window), and stats() reported a stale breaker_open. One
        # probe at a time, resolved explicitly.
        self._probe_in_flight = False

    # -- internals (caller holds the lock) --

    def _prune(self, now: float) -> None:
        day_ago, hour_ago = now - 86400, now - 3600
        self._global_calls = [t for t in self._global_calls if t > day_ago]
        for src in list(self._source_calls):
            kept = [t for t in self._source_calls[src] if t > hour_ago]
            if kept:
                self._source_calls[src] = kept
            else:
                del self._source_calls[src]  # bounded: idle sources drop out

    def _breaker_state(self, now: float) -> str:
        """CLOSED | OPEN | HALF_OPEN — a PURE read, no mutation.

        admit() and stats() both derive from this, so a cooldown that has elapsed
        is reflected the moment it elapses rather than whenever traffic next
        happens to arrive and clear a flag (the stale-flag defect).
        """
        if self._breaker_opened_at is None:
            return "CLOSED"
        if now - self._breaker_opened_at >= self.config.breaker_cooldown_seconds:
            return "HALF_OPEN"
        return "OPEN"

    def _refuses_calls(self, now: float) -> bool:
        """Will the next in-band case be refused for BREAKER reasons?

        This — not `state == OPEN` — is what a consumer means by "the breaker is
        open". A probe that HANGS never resolves, so the state stays HALF_OPEN
        while `_probe_in_flight` refuses every subsequent call: reporting that as
        "not open" would be a health signal that lies (says healthy while nothing
        is being judged) — the same class as the stale flag it replaced, inverted.
        """
        state = self._breaker_state(now)
        return state == "OPEN" or (state == "HALF_OPEN" and self._probe_in_flight)

    # -- public API --

    def admit(self, source: str, now: float | None = None) -> str:
        """Decide whether an in-band case may call the judge, and record it.

        Returns exactly one ADMISSION_OUTCOME. On JUDGED the call is recorded
        against both budgets in the same operation — admission and accounting
        cannot drift apart, because they are not two steps.

        Order is load-bearing (V3): budget → breaker. Budget first, so a case
        that could not afford a call is never attributed to an API failure it
        never made.
        """
        now = time.time() if now is None else now
        with self._lock:
            self._prune(now)

            hour_ago = now - 3600
            global_hour = sum(1 for t in self._global_calls if t > hour_ago)
            if global_hour >= self.config.hourly_cap or len(self._global_calls) >= self.config.daily_cap:
                return BUDGET_GLOBAL

            if len(self._source_calls.get(source, ())) >= self.config.per_source_hourly:
                return BUDGET_SOURCE

            # HALF_OPEN admits EXACTLY ONE probe (V2a). The judge call happens
            # outside this lock (network I/O; holding a lock across it would
            # serialise the honeypot), so several threads can be past admit() at
            # once — without the in-flight guard, every request arriving as the
            # cooldown expires becomes a simultaneous probe against a judge
            # already known to be broken.
            state = self._breaker_state(now)
            if state == "OPEN":
                return BREAKER_OPEN
            if state == "HALF_OPEN":
                if self._probe_in_flight:
                    return BREAKER_OPEN       # a probe is already out — one at a time
                self._probe_in_flight = True  # THIS call is the probe

            self._global_calls.append(now)
            self._source_calls.setdefault(source, []).append(now)
            return JUDGED

    def record_success(self) -> None:
        """A successful call closes the breaker — including a successful probe.

        No `now` parameter: closing needs no timestamp (unlike record_error,
        which must stamp the cooldown's start). A symmetric-but-unused parameter
        would imply an intent that does not exist.
        """
        with self._lock:
            self._consecutive_errors = 0
            self._breaker_opened_at = None
            self._probe_in_flight = False

    def record_error(self, now: float | None = None) -> None:
        """Trip on N consecutive errors; a FAILED PROBE re-opens IMMEDIATELY.

        A probe failure does not "count toward" a fresh N (V2a): the breaker was
        already tripped, the cooldown was its benefit of the doubt, and the probe
        spent it. One failure re-opens and restarts the cooldown — otherwise a
        genuinely down judge receives three fresh calls every window.
        """
        now = time.time() if now is None else now
        with self._lock:
            self._consecutive_errors += 1

            if self._probe_in_flight:
                self._probe_in_flight = False
                self._breaker_opened_at = now      # re-open; cooldown restarts
                return

            if self._consecutive_errors >= self.config.breaker_consecutive_errors:
                self._breaker_opened_at = now

    def stats(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        with self._lock:
            self._prune(now)
            hour_ago = now - 3600
            return {
                "calls_last_hour": sum(1 for t in self._global_calls if t > hour_ago),
                "calls_last_day": len(self._global_calls),
                "active_sources": len(self._source_calls),
                # breaker_open means what a consumer assumes: calls are being
                # refused for breaker reasons. NOT `state == OPEN` — a hung probe
                # leaves the state HALF_OPEN while refusing everything (V2a's
                # accepted hung-probe consequence).
                "breaker_open": self._refuses_calls(now),
                "breaker_state": self._breaker_state(now),   # granular detail
                "probe_in_flight": self._probe_in_flight,
                "consecutive_errors": self._consecutive_errors,
            }


# --- merge (P6b: additive-only; both disagreement directions) ----------------

@dataclass(frozen=True)
class MergeResult:
    risk_level: str                 # effective = max(local, semantic)
    disagreement: str | None        # judge_disagreement_up | _down | None


def merge(local_risk: str, semantic_verdict: str | None) -> MergeResult:
    """Additive-only merge. The judge can escalate or annotate, never lower.

    Disagreement is defined RELATIVE to local severity (P6b amendment
    2026-07-12), not against fixed levels: the band pins local severity at
    MEDIUM, so a fixed-level up-trigger ("local LOW/CLEAN") would be
    permanently unreachable — a zero counter reading as safety while the
    noise-injection attacker walks past it.

    A local false positive keeps its local severity even when the judge
    correctly says CLEAN. Deliberate (P6b rejected-alternatives): this honeypot
    labels, it does not block. A wrong high label costs analyst attention; a
    wrong clean label buries a captured attack.
    """
    if semantic_verdict is None:
        return MergeResult(risk_level=local_risk, disagreement=None)

    semantic_risk = VERDICT_TO_SEVERITY[semantic_verdict]
    local_rank = SEVERITY_ORDER[local_risk]
    semantic_rank = SEVERITY_ORDER[semantic_risk]

    if semantic_rank > local_rank:
        disagreement = DISAGREEMENT_UP
    elif semantic_rank < local_rank:
        disagreement = DISAGREEMENT_DOWN
    else:
        disagreement = None

    effective = local_risk if local_rank >= semantic_rank else semantic_risk
    return MergeResult(risk_level=effective, disagreement=disagreement)


# --- single entry point ------------------------------------------------------

@dataclass(frozen=True)
class SemanticResult:
    """What the semantic layer contributes. NEVER touches api_* (P6b hazard).

    The local pipeline's api_verdict/api_confidence/api_reason columns hold
    LOCALLY synthesized values (legacy naming from Phase A). Merging the judge
    into them would destroy P4 — and with it both disagreement flags, which are
    computed by comparing local against semantic. Criterion C enforces this.
    """

    risk_level: str                  # effective severity after additive-only merge
    verdict: str | None = None       # judge's verdict, or None if it did not speak
    confidence: str | None = None
    reason: str | None = None
    skip_reason: str | None = None   # exactly one SKIP_REASON when verdict is None
    disagreement: str | None = None


def evaluate(
    prompt: str,
    attack_type: str,
    local_risk: str,
    sentiment_bumped: bool,
    source: str,
    ledger: BudgetLedger,
    judge=None,
    now: float | None = None,
) -> SemanticResult:
    """THE single path from the classifier to the judge (V2b).

    The enable gate is the first line: no call site can reach the network by
    forgetting to check a flag. Then routing (pure) → admission (state) →
    execution (the call) → additive-only merge. Every non-judged outcome carries
    exactly one truthful skip_reason, and the local risk level is returned
    untouched.

    `judge` is injected (default: ai-firewall's api_scan) so CI runs this whole
    path deterministically with no key, no network, and no spend.
    """
    if not is_enabled():
        return SemanticResult(risk_level=local_risk, skip_reason=DISABLED)

    routing = route(attack_type, local_risk, sentiment_bumped)
    if routing != ENTERS_BAND:
        return SemanticResult(risk_level=local_risk, skip_reason=routing)

    admission = ledger.admit(source, now=now)
    if admission != JUDGED:
        # No call was made; no budget consumed. The reason is truthful.
        return SemanticResult(risk_level=local_risk, skip_reason=admission)

    if judge is None:
        from ai_firewall.detector import api_scan as judge  # lazy: no import cost when disabled

    # The judge call is wrapped even though ai-firewall's api_scan currently
    # catches broadly and returns a degraded dict rather than raising (verified
    # in its source). Relying on that would make THIS module's budget-consistency
    # invariant depend on a callee's internal discipline, in another repo, behind
    # a SHA pin that a later gate may bump — and `judge` is an injection seam, so
    # any other judge has made no such promise. An uncaught raise here would be
    # the worst outcome available: budget consumed, breaker not incremented, and
    # NO row written at all — the call vanishes from the audit trail entirely.
    #
    # A raise and a garbage return are operationally identical to the honeypot
    # (call attempted, budget consumed, no usable verdict), so both take the same
    # truthful reason rather than inventing a distinction nobody would act on.
    #
    # STILL OPEN (accepted gap, DECISIONS.md): a HANG is not an exception. This
    # try/except cannot save us from a wedged connection — the call blocks with
    # budget consumed and no row written. evaluate() ASSUMES the injected judge
    # enforces its own transport timeout; ai-firewall's api_scan currently does
    # NOT (its Anthropic client is constructed with no timeout and no
    # max_retries). Fix belongs there, then bump the SHA pin. The presence of
    # exception handling here does not mean this surface is covered.
    try:
        result = judge(prompt)
        verdict = result.get("VERDICT")
    except Exception:
        verdict = None

    # ai-firewall fails CLOSED: a degraded or steered scan yields VERDICT None.
    # A None verdict is NOT a verdict — it neither raises nor lowers anything.
    # This is JUDGE_FAILED, never BREAKER_OPEN (V3a): the breaker was closed (or
    # admission could not have returned JUDGED), the call WAS made, and budget
    # WAS consumed. The error increments the breaker so a persistently broken
    # judge stops being called — but this row's reason must state what actually
    # happened to THIS row.
    if verdict is None:
        ledger.record_error(now=now)
        return SemanticResult(risk_level=local_risk, skip_reason=JUDGE_FAILED)

    # CONFIDENCE deliberately does NOT gate this: the breaker measures API
    # HEALTH, not verdict quality. A LOW-confidence verdict is a successful
    # call — tripping the breaker on an uncertain-but-healthy judge would mute
    # it exactly when its opinion is most wanted.
    ledger.record_success()

    merged = merge(local_risk, verdict)
    return SemanticResult(
        risk_level=merged.risk_level,
        verdict=verdict,
        confidence=result.get("CONFIDENCE"),
        reason=result.get("REASON"),
        disagreement=merged.disagreement,
    )
