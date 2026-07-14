from typing import Any

from pydantic import BaseModel, Field, field_validator


class ChatRequest(BaseModel):
    prompt: str = Field(..., max_length=4000)


class AttackFilter(BaseModel):
    limit: int = 50
    offset: int = 0

    @field_validator("limit", mode="before")
    @classmethod
    def clamp_limit(cls, v: object) -> int:
        try:
            return max(0, min(int(v), 500))
        except (ValueError, TypeError):
            raise ValueError("limit must be an integer")

    @field_validator("offset", mode="before")
    @classmethod
    def clamp_offset(cls, v: object) -> int:
        try:
            return max(0, int(v))
        except (ValueError, TypeError):
            raise ValueError("offset must be an integer")


class AnalysisRecord(BaseModel):
    fake_response: str = ""
    attack_type: str = "unknown"
    risk_level: str = "LOW"
    keyword_score: int = 0
    keyword_matches: dict[str, Any] = {}
    api_verdict: str = "UNKNOWN"
    api_confidence: str = "UNKNOWN"
    api_reason: str = ""
    flags: dict[str, Any] = {}
    sentiment_score: float = 0.0
    framing_type: str = "none"
    # Phase B semantic layer (V3/V5). NULL until the wiring populates them.
    # The closed vocabularies are enforced by CHECK constraints in db.py,
    # derived from semantic.py's constants — deliberately NOT duplicated here
    # as Literal types, so there is exactly one enforcement point below the
    # app layer and out-of-vocabulary values fail loud (IntegrityError), not
    # silently reset to a blank record by the ValidationError fallback.
    semantic_verdict: str | None = None
    semantic_skip_reason: str | None = None
    semantic_disagreement: str | None = None

    model_config = {"extra": "ignore"}
