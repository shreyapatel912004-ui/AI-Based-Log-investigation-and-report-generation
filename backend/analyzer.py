from .log_parser import LogParser
from .scoring import CompositeRiskScorer, EventClassifier, EventScoringService, HeuristicRiskScorer, LstmRiskScorer
from .summary import InvestigationSummary


def build_default_analyzer():
    parser = LogParser()
    scorer = CompositeRiskScorer(LstmRiskScorer(), HeuristicRiskScorer())
    scoring_service = EventScoringService(scorer, EventClassifier())
    return parser, scoring_service, InvestigationSummary()


def parse_logs(logs: str):
    parser, scoring_service, _ = build_default_analyzer()
    return [scoring_service.score_event(parsed_log).to_dict() for parsed_log in parser.parse(logs)]


def summarize_events(events):
    return InvestigationSummary().build(events)


def analyze_logs(logs: str):
    events = parse_logs(logs)
    return {"summary": summarize_events(events), "events": events}
