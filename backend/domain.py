from dataclasses import asdict, dataclass
from typing import List, Optional


@dataclass
class ParsedLog:
    line_no: int
    timestamp: Optional[str]
    source_ip: str
    severity: str
    event_type: str
    raw_log: str
    features: List[float]

    def to_dict(self):
        return asdict(self)


@dataclass
class ScoredEvent:
    line_no: int
    timestamp: Optional[str]
    source_ip: str
    severity: str
    event_type: str
    risk_score: float
    verdict: str
    explanation: str
    model_source: str
    model_error: Optional[str]
    raw_log: str
    features: List[float]

    def to_dict(self):
        return asdict(self)
