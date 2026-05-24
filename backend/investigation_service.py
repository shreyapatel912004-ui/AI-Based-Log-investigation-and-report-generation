from typing import Dict

from .log_parser import LogParser
from .repository import LogRepository
from .scoring import EventScoringService
from .summary import InvestigationSummary


class InvestigationService:
    SUMMARY_LIMIT = 10000

    def __init__(
        self,
        parser: LogParser,
        scoring_service: EventScoringService,
        repository: LogRepository,
        summary_builder: InvestigationSummary,
    ):
        self.parser = parser
        self.scoring_service = scoring_service
        self.repository = repository
        self.summary_builder = summary_builder

    def ingest(self, logs: str, case_id: int, log_type: str = "generic") -> Dict:
        parsed_logs = self.parser.parse(logs, log_type=log_type)
        events = self.scoring_service.score_events(parsed_logs)
        self.repository.save_events(case_id, events)
        event_dicts = [event.to_dict() for event in events]
        return {"summary": self.summary_builder.build(event_dicts), "events": event_dicts}

    def search(self, case_id: int, filters: Dict, limit: int = 250) -> Dict:
        matching_events = self.repository.query_events(case_id, filters, max(limit, self.SUMMARY_LIMIT))
        return {
            "summary": self.summary_builder.build(matching_events),
            "events": matching_events[:limit],
        }
