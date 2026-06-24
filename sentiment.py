"""
sentiment.py — Emotional-manipulation and framing-detection layer.

Acts as Layer 1 in the detection pipeline:
  Prompt → Sentiment Layer → Keyword Scanner → LLM Classifier → Final Verdict

Catches social-engineering attacks that rely on emotional framing
(e.g. the grandmother exploit) before the keyword and LLM layers run.
"""
import re

from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

_analyzer = SentimentIntensityAnalyzer()

# ---------------------------------------------------------------------------
# Emotional-loading word patterns
# ---------------------------------------------------------------------------

_EMOTION_PATTERNS: dict = {
    "grief": [
        r"\b(grief|grieving|mourning|mourn|loss|lost|died|dying|dead|death"
        r"|passed away|passed on|terminal|cancer|funeral|widow|orphan"
        r"|miss(?:ing)? (?:you|them|her|him|so much))\b",
    ],
    "urgency": [
        r"\b(urgent|urgently|emergency|critical|immediately|right now|hurry"
        r"|quickly|time[- ]sensitive|deadline|asap|last chance"
        r"|running out of time|no time left)\b",
    ],
    "sympathy": [
        r"\b(please|begging|beg|desperate|desperately|helpless|vulnerable"
        r"|struggling|suffering|alone|lonely|scared|afraid|terrified"
        r"|only (?:hope|chance|one)|need (?:your )?help so badly)\b",
    ],
    "guilt": [
        r"\b(shame|ashamed|guilty|guilt|fault|blame|disappoint|disappointed"
        r"|let (?:you|me|them|her|him|us) down|failed|betray|betrayed"
        r"|hurt (?:you|me|them))\b",
    ],
}

# Contribution weight of each emotion category to the composite loading score
_EMOTION_WEIGHTS = {"grief": 0.35, "urgency": 0.25, "sympathy": 0.25, "guilt": 0.15}

# ---------------------------------------------------------------------------
# Framing-type patterns
# ---------------------------------------------------------------------------

_FRAMING_PATTERNS: dict = {
    "grandmother": [
        r"\b(grandm(?:a|other)|grann?[yi]|nan(?:na?)?)\b",
        r"\bbedtime stor(?:y|ies)\b",
        r"\bused to (?:tell|read|sing|whisper|share)\b",
        r"\b(?:before|since) (?:she|he) (?:passed|died|left us)\b",
        r"\bwhen (?:i was|we were) (?:young|little|a child|kids?)\b",
    ],
    "fictional_wrapper": [
        r"\bfor (?:a |my |this )?(?:story|novel|book|screenplay|film|script"
        r"|fiction|tale|narrative|game|simulation|project|class|assignment)\b",
        r"\bwrite (?:a |me )?(?:story|scene|chapter|dialogue|narrative) (?:where|in which|about)\b",
        r"\b(?:my )?(?:character|protagonist|villain|hero|narrator) (?:needs? to|would|should|must)\b",
        r"\bin (?:a |this |the )?(?:fictional|fantasy|sci.fi|dystopian|alternate|imaginary) (?:world|universe|setting|scenario)\b",
    ],
    "roleplay": [
        r"\b(?:let(?:'?s)?|we(?:'re)?|i want(?:ed)? to) (?:do a |play a |start a )?(?:roleplay|role[- ]play)\b",
        r"\bact (?:as(?: if)?|like) (?:you (?:are|were|have no|don'?t|can))\b",
        r"\bpretend (?:you(?:'re| are)| to be| that you)\b",
        r"\bplay (?:the role|a character|the part) of\b",
    ],
    "hypothetical": [
        r"\bhypothetically(?: speaking)?\b",
        r"\btheoret(?:ically|ical scenario)\b",
        r"\b(?:what if|imagine if) you (?:could|were|had|didn'?t|were not)\b",
        r"\bin (?:a |this )?hypothetical(?: scenario| situation| world)?\b",
        r"\bthought experiment\b",
    ],
    "authority_claim": [
        r"\bi(?:'m| am) (?:a |an )?(?:senior |lead |chief )?(?:developer|admin(?:istrator)?|researcher"
        r"|security (?:researcher|professional|expert)|engineer|scientist|doctor|professor)\b",
        r"\b(?:admin|developer|root|system|debug|maintenance|superuser) (?:mode|override|access|key|token|bypass)\b",
        r"\bi (?:have|was (?:given|granted)) (?:(?:special |elevated |admin |system )?(?:permission|authorization|clearance|access))\b",
        r"\bfor (?:authorized|legitimate|official|professional|research) (?:use|purposes?|testing|evaluation)\b",
    ],
}

# Priority order when multiple framings are detected — most specific first
_FRAMING_PRIORITY = [
    "grandmother", "fictional_wrapper", "roleplay", "authority_claim", "hypothetical"
]

# ---------------------------------------------------------------------------
# Attack-corroborating keyword patterns
#
# Used as a second required signal for risk_bump (two-signal requirement).
# A high emotional_loading alone can come from genuine distress; pairing it
# with attack vocabulary distinguishes manipulation from a real cry for help.
# ---------------------------------------------------------------------------

_CORROBORATING_PATTERNS = [
    r"\bignore\b.{0,20}\bprevious\b",   # "ignore previous", "ignore all previous", etc.
    r"\bno restrictions?\b",
    r"\bunrestricted\b",
    r"\bbypass\b",
    r"\boverride\b",
    r"\broleplay\b",
    r"\bpretend\b",
    r"\bact as\b",
    r"\bjailbr(?:eak(?:ed|n)?|oken)\b",  # "jailbreak", "jailbroken" (different roots)
    r"\bdan\b",
    r"\bdeveloper mode\b",
    r"\bsystem prompt\b",
]


def analyse_sentiment(prompt: str) -> dict:
    """
    Run VADER + emotion/framing patterns on a prompt.

    Returns:
      vader_compound       float  [-1, 1]   VADER polarity score
      emotion_scores       dict   category -> 0.0 or 1.0
      emotional_loading    float  [0, 1]    composite manipulation score
      framing_types        list   all detected framing categories
      framing_type         str    highest-priority framing, or "none"
      confidence           str    "LOW" | "MEDIUM" | "HIGH"
      corroborating_signal bool   True if attack keywords co-occur with framing
      risk_bump            bool   True → caller should raise risk level

    risk_bump two-signal requirement:
      Both emotional_loading >= 0.5 AND corroborating_signal must be True,
      EXCEPT for grandmother framing which bumps unconditionally — it is a
      known high-confidence attack vector that bypasses other detection layers.
    """
    prompt_lower = prompt.lower()

    # VADER polarity
    vs = _analyzer.polarity_scores(prompt)

    # Emotion pattern hits (binary per category)
    emotion_scores: dict = {
        emotion: (1.0 if any(re.search(p, prompt_lower) for p in patterns) else 0.0)
        for emotion, patterns in _EMOTION_PATTERNS.items()
    }

    # Weighted pattern score (0–1)
    pattern_score = sum(emotion_scores[e] * _EMOTION_WEIGHTS[e] for e in _EMOTION_WEIGHTS)

    # VADER's negative tone adds a small fractional boost — captures emotional
    # vocabulary not explicitly listed in our patterns.
    emotional_loading = round(min(1.0, pattern_score + vs["neg"] * 0.2), 4)

    # Framing detection
    detected: list = [
        framing
        for framing, patterns in _FRAMING_PATTERNS.items()
        if any(re.search(p, prompt_lower) for p in patterns)
    ]

    # Primary framing by priority order
    framing_type = next((f for f in _FRAMING_PRIORITY if f in detected), "none")

    # Confidence level
    if emotional_loading >= 0.5:
        confidence = "HIGH"
    elif emotional_loading >= 0.25 or detected:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # Attack-corroborating signal: attack vocabulary present alongside emotional loading
    corroborating_signal = any(
        re.search(p, prompt_lower) for p in _CORROBORATING_PATTERNS
    )

    # Two-signal risk bump:
    #   – grandmother framing alone (exception — high-confidence attack vector)
    #   – OR: emotional_loading >= 0.5 AND a corroborating attack keyword is present
    #     (prevents flagging genuinely distressed users who have no attack intent)
    risk_bump = (
        "grandmother" in detected
        or (emotional_loading >= 0.5 and corroborating_signal)
    )

    return {
        "vader_compound": round(vs["compound"], 4),
        "emotion_scores": emotion_scores,
        "emotional_loading": emotional_loading,
        "framing_types": detected,
        "framing_type": framing_type,
        "confidence": confidence,
        "corroborating_signal": corroborating_signal,
        "risk_bump": risk_bump,
    }
