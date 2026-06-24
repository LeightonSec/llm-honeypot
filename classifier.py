import base64
import os
import random
import re
import unicodedata

from dotenv import load_dotenv

from sentiment import analyse_sentiment

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))


# Unicode confusables: maps lookalike chars to their ASCII equivalents.
# Covers the Cyrillic and Greek scripts most commonly used in homoglyph attacks.
_CONFUSABLE_MAP = str.maketrans({
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p',
    'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i',
    'ј': 'j', 'п': 'p',
    'ο': 'o', 'α': 'a', 'ε': 'e',
    'в': 'b', 'ԁ': 'd',
})


def normalize_for_matching(text: str) -> str:
    """NFKC + confusable map: collapses homoglyph substitutions before pattern matching."""
    return unicodedata.normalize('NFKC', text).translate(_CONFUSABLE_MAP)


def _extract_b64_payloads(prompt: str) -> list:
    """Speculatively decode base64 blobs found in a prompt.

    Returns decoded UTF-8 strings for any blob that is long enough and decodes
    to printable ASCII — the attacker's actual instruction hidden inside encoding.
    """
    found = []
    for m in re.finditer(r'[A-Za-z0-9+/]{20,}={0,2}', prompt):
        blob = m.group(0)
        padded = blob + '=' * (-len(blob) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
            text = raw.decode('utf-8', errors='ignore').strip()
            if len(text) >= 8 and all(ord(c) < 128 for c in text) and text.isprintable():
                found.append(text)
        except Exception:
            pass
    return found


HONEYPOT_PATTERNS = {
    "prompt_injection": [
        r"ignore (?:all )?previous (?:instructions?|prompts?|context)",
        r"new (?:system )?instructions?[\s:]",
        r"###\s*(?:instruction|system|prompt)",
        r"</?(?:system|instruction|prompt)>",
        r"\[\[.*?\]\]",
        r"you are now (?:a |an )?(?:new|different)",
        r"override (?:previous |your )?(?:instructions?|programming|directives?)",
        r"forget (?:everything|all) (?:above|before|previous)",
        r"disregard (?:all )?(?:previous|prior|above)",
        r"your (?:new|updated) (?:task|instructions?|role|purpose) (?:is|are)",
    ],
    "jailbreak": [
        r"\bdan\b",
        r"do anything now",
        r"jailbreak",
        r"no (?:restrictions?|rules?|limits?|guidelines?|filters?|ethics?)",
        r"pretend (?:you (?:have no|don't have|are without)|there are no)",
        r"act as (?:if )?(?:you (?:have no|don't have)|an? (?:ai|llm|model) without)",
        r"roleplay as",
        r"(?:disable|remove|bypass|ignore) (?:your )?(?:safety|filter|restriction|censorship)",
        r"developer mode",
        r"god mode",
        r"unrestricted mode",
        r"jailbroken",
        r"you have been freed",
        r"evil(?:\s+mode|\s+version|\s+ai)",
        r"without (?:any )?(?:moral|ethical) (?:guidelines?|constraints?)",
        # Liberation / true-self framing
        r"(?:liberated?|freed) from (?:your |all |previous )?(?:constraints?|restrictions?|programming|guidelines?)",
        r"(?:true|real|authentic|original|inner|unfiltered|unrestricted) self",
        r"without (?:any )?(?:restrictions?|limits?|constraints?|filters?|censorship|guidelines?)",
        r"no longer (?:need to|have to|must|required to) (?:follow|obey|comply|abide)",
        # Obfuscation / encoding signals
        r"decode and (?:follow|execute|run|apply|implement)",
        r"(?:base64|b64)[- _]?(?:encoded?|decode|string)",
    ],
    "data_extraction": [
        r"(?:your )?training (?:data|set|examples?|corpus)",
        r"(?:system|initial|original|hidden|base) prompt",
        r"what (?:were|are) (?:you|your) (?:told|instructions?|rules?|guidelines?|directives?)",
        r"(?:repeat|print|output|show|reveal|leak|display|echo) (?:your|the) (?:system|initial|original|first)",
        r"what (?:is|was) (?:your|the) (?:system|initial|first|original) (?:message|prompt|instruction)",
        r"(?:show|tell|reveal|expose|share|give me) (?:me )?your (?:instructions?|prompt|rules?|guidelines?|constraints?|context)",
        r"(?:confidential|internal|secret|hidden|privileged) (?:instructions?|prompt|data|information)",
        r"exfil(?:trate)?",
        r"what (?:did|do) (?:they|your creators?|anthropic|openai|nexusai) (?:tell|instruct|program|train) you",
    ],
    "social_engineering": [
        r"i am (?:a |an )?(?:developer|admin|administrator|owner|creator|operator|researcher)",
        r"(?:admin|developer|maintenance|debug|root|superuser) (?:mode|override|access|token|key)",
        r"i (?:give|grant) you (?:permission|authorization|access)",
        r"permission (?:granted|override|level)",
        r"(?:hypothetically|theoretically|in (?:a )?(?:story|fiction|scenario|hypothetical|thought experiment))",
        r"for (?:educational|research|academic|creative|fictional|artistic|scientific) purposes?",
        r"(?:urgent|emergency|critical|important|time.sensitive)",
        r"trust me",
        r"i (?:promise|swear|guarantee)",
        r"this is (?:a )?(?:test|simulation|experiment|drill)",
        r"pretend this is fiction",
        r"in a (?:movie|book|game|story|novel)",
        # Fictional / creative wrapper variations
        r"for (?:a |my )?(?:novel|story|book|screenplay|film|script)",
        r"(?:science )?fiction(?:al)? (?:story|scenario|world|character|ai|robot|setting)",
        r"dystopian (?:future|world|setting|scenario)",
        r"play the role of an? (?:ai|robot|assistant) (?:from|with|that|without)",
    ],
    "reconnaissance": [
        r"what (?:(?:can|could) you (?:do|help with)|are your capabilities?)",
        r"(?:are|is) you (?:gpt|claude|gemini|llama|mistral|chatgpt)",
        r"(?:what|which) (?:model|version|llm|ai|language model) (?:are you|powers? you|is this|is behind this|are you based on)",
        r"who (?:made|created|built|developed|trained) you",
        r"how (?:do you|does (?:this|your)) work",
        r"what (?:are )?your (?:limits?|restrictions?|constraints?|capabilities?|rules?)",
        r"(?:do you|can you) (?:have access to|access|connect to|browse|search)",
        r"(?:what data|which data|what information) (?:do you|can you) (?:access|see|use|read)",
        r"are you (?:connected|online|aware|sentient|conscious)",
        r"what (?:companies?|organizations?|systems?) (?:are you|can you) (?:connected|integrated|linked)",
        r"(?:do you|can you) remember (?:me|previous|past)",
        r"what is your (?:context|context window|token limit|memory)",
    ],
}

FAKE_RESPONSES = {
    "jailbreak": [
        "I'm designed to be helpful, harmless, and honest — those aren't settings I can toggle off. Happy to help with something else!",
        "I maintain the same values regardless of how requests are framed. What can I legitimately help you with today?",
        "That's not something I'm able to assist with. My guidelines aren't restrictions I can bypass — they're fundamental to how I work.",
        "I notice this asks me to behave differently than I'm designed to. I'm here to help with genuine tasks — what would you like to work on?",
    ],
    "prompt_injection": [
        "I process each conversation naturally and don't respond to embedded instruction overrides. How can I help you today?",
        "I noticed some unusual formatting in your message. I'm here to help with genuine questions — what are you looking for?",
        "My behavior isn't changed by embedded instructions. Is there something I can genuinely assist you with?",
        "Each conversation starts fresh for me. I'm happy to help with what you're actually looking to accomplish.",
    ],
    "data_extraction": [
        "I don't have access to my system configuration or training details — I'm just here to assist with your questions!",
        "That information isn't available to me or through me. Is there something else I can help you with?",
        "My internal configuration and instructions aren't something I can share or access. What else can I help you with?",
        "I'm not able to reflect on or share details about my underlying instructions. Happy to help with other things though!",
    ],
    "social_engineering": [
        "I treat all users the same regardless of claimed roles or permissions. How can I help you today?",
        "My guidelines apply equally to everyone. I'm happy to help with legitimate requests though!",
        "That framing doesn't change how I respond, but I'm happy to help you accomplish something legitimate. What do you need?",
        "I don't modify my behavior based on claimed authority or special contexts. What would you like to work on?",
    ],
    "reconnaissance": [
        "I'm Aria, an AI assistant by NexusAI Labs. I can help with writing, analysis, coding, research, and general questions. What can I do for you?",
        "I'm an AI assistant here to help with a wide range of tasks. I work best with clear, specific questions — what would you like help with?",
        "I'm Aria — a general-purpose AI assistant. Writing, analysis, problem-solving, research — that's my wheelhouse. What do you need?",
        "I'm a general-purpose AI assistant. I'm most useful for specific tasks: writing, code, analysis, research. What are you working on?",
    ],
    "unknown": [
        "Could you tell me a bit more about what you're looking for? Happy to help once I understand better.",
        "Interesting — could you give me a bit more context so I can give you the most useful answer?",
        "I want to make sure I help you effectively. What specifically are you trying to accomplish?",
        "Could you clarify what outcome you're hoping for? That'll help me point you in the right direction.",
    ],
    "clean": [
        "That's a good question. To give you the best answer, could you share a bit more detail about your situation?",
        "Happy to help with that. The key is finding the right approach for your context — what are the constraints you're working within?",
        "Let me work through this with you. There are a few angles worth considering — what aspect matters most to you?",
        "The answer depends on your specific needs. Could you tell me a bit more about what you're trying to accomplish?",
        "To give you the most useful answer, could you tell me a bit more about what you're working on?",
    ],
}


def _local_analyse(prompt: str) -> dict:
    """Fallback keyword-only analysis when ai-firewall is unavailable."""
    prompt_lower = normalize_for_matching(prompt).lower()
    all_patterns = {
        "persona_hijack": [r"act as", r"pretend you", r"you are now", r"roleplay as", r"ignore (?:your )?previous instructions"],
        "restriction_bypass": [r"no restrictions", r"bypass", r"override", r"jailbreak", r"ignore your training"],
        "authority_claim": [r"i am a developer", r"admin override", r"system prompt", r"developer mode"],
        "harmful_intent": [r"how to hack", r"malware", r"ransomware", r"exploit vulnerability"],
    }
    matches = {}
    score = 0
    for category, patterns in all_patterns.items():
        hits = [p for p in patterns if re.search(p, prompt_lower)]
        if hits:
            matches[category] = hits
            score += len(hits)

    if score >= 3:
        risk = "HIGH"
        verdict = "JAILBREAK"
    elif score >= 1:
        risk = "MEDIUM"
        verdict = "SUSPICIOUS"
    else:
        risk = "LOW"
        verdict = "CLEAN"

    return {
        "risk_level": risk,
        "keyword_score": score,
        "keyword_matches": matches,
        "api_verdict": verdict,
        "api_confidence": "LOW",
        "api_reason": "Local pattern match only (firewall unavailable)",
    }


def _obfuscation_score(prompt: str) -> int:
    """Return a score > 0 if the prompt uses character-level obfuscation."""
    score = 0
    # Cyrillic lookalike characters (е, о, а, р, etc. used to bypass ASCII matching)
    cyrillic = sum(1 for c in prompt if 0x0400 <= ord(c) <= 0x04FF)
    if cyrillic >= 3:
        score += 2
    # High density of non-ASCII in otherwise Latin text
    non_ascii = sum(1 for c in prompt if ord(c) > 127)
    if non_ascii / max(len(prompt), 1) > 0.15:
        score += 1
    return score


def classify_attack(prompt: str, b64_payloads: list = None) -> str:
    """Determine the primary attack type from a prompt.

    Pass pre-computed b64_payloads to avoid decoding the prompt twice when the
    caller already extracted them (e.g. analyse_and_classify).
    """
    # Normalize before matching so homoglyph substitutions don't defeat patterns
    normalized_lower = normalize_for_matching(prompt).lower()
    scores = {attack_type: 0 for attack_type in HONEYPOT_PATTERNS}

    for attack_type, patterns in HONEYPOT_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, normalized_lower):
                scores[attack_type] += 1

    # Score any base64-encoded payloads embedded in the prompt
    if b64_payloads is None:
        b64_payloads = _extract_b64_payloads(prompt)
    for payload in b64_payloads:
        payload_lower = normalize_for_matching(payload).lower()
        for attack_type, patterns in HONEYPOT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, payload_lower):
                    scores[attack_type] += 1

    # Obfuscation heuristic runs on the ORIGINAL prompt, not the normalized form
    scores["jailbreak"] += _obfuscation_score(prompt)

    max_score = max(scores.values())
    if max_score == 0:
        return "unknown"
    return max(scores, key=scores.get)


def get_fake_response(attack_type: str, risk_level: str) -> str:
    if risk_level == "LOW" and attack_type in ("unknown", "clean"):
        pool = FAKE_RESPONSES["clean"]
    else:
        pool = FAKE_RESPONSES.get(attack_type, FAKE_RESPONSES["unknown"])
    return random.choice(pool)


def analyse_and_classify(prompt: str) -> dict:
    """Full honeypot pipeline:
    Layer 1: Sentiment + framing → Layer 2: Keyword scanner → Layer 3: LLM classifier → Final Verdict.
    """
    # Layer 1 — Emotional manipulation and framing detection
    sentiment = analyse_sentiment(prompt)

    # Layer 2 — Keyword scanner (local analysis; no external firewall dependency)
    fw = _local_analyse(prompt)

    # Layer 3 — Pattern-based attack-type classification
    b64_payloads = _extract_b64_payloads(prompt)
    attack_type = classify_attack(prompt, b64_payloads=b64_payloads)

    if fw["risk_level"] == "LOW" and attack_type == "unknown":
        attack_type = "clean"

    # Promote: LLM detected a threat the regex layer missed — trust the LLM.
    if attack_type == "unknown" and (
        fw["api_verdict"] == "JAILBREAK" or fw["risk_level"] == "HIGH"
    ):
        attack_type = "jailbreak"

    # Sentiment risk bump: emotional manipulation + framing upgrades risk and type.
    # Runs after keyword/LLM so it only overrides when those layers gave clean/unknown.
    risk_level = fw["risk_level"]
    if sentiment["risk_bump"]:
        if risk_level == "LOW":
            risk_level = "MEDIUM"
        if attack_type in ("clean", "unknown"):
            attack_type = "social_engineering"

    # Surface b64 payloads and detected framings in keyword_matches for logging
    keyword_matches = dict(fw.get("keyword_matches", {}))
    if b64_payloads:
        keyword_matches["b64_decoded"] = b64_payloads
    if sentiment["framing_types"]:
        keyword_matches["sentiment_framings"] = sentiment["framing_types"]

    fake_response = get_fake_response(attack_type, risk_level)

    return {
        "attack_type": attack_type,
        "risk_level": risk_level,
        "keyword_score": fw.get("keyword_score", 0),
        "keyword_matches": keyword_matches,
        "api_verdict": fw.get("api_verdict", "UNKNOWN"),
        "api_confidence": fw.get("api_confidence", "UNKNOWN"),
        "api_reason": fw.get("api_reason", ""),
        "fake_response": fake_response,
        "sentiment_score": sentiment["emotional_loading"],
        "framing_type": sentiment["framing_type"],
    }
