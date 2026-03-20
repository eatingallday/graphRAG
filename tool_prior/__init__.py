from .schema import (
    ToolPrior,
    DetectionCapability,
    DetectionMethod,
    SignalPolarity,
    TaintRelevance,
    AnalysisDepth,
    DetectionFamily,
    EvidenceType,
    Granularity,
    FPRisk,
)
from .prior_store import save_prior, load_prior, save_all, load_all
from .finding_schema import NormalizedFinding


def extract_tool_prior(*args, **kwargs):
    from .extractor import extract_tool_prior as _extract_tool_prior
    return _extract_tool_prior(*args, **kwargs)


def extract_all(*args, **kwargs):
    from .extractor import extract_all as _extract_all
    return _extract_all(*args, **kwargs)


def parse_report(*args, **kwargs):
    from .finding_parser import parse_report as _parse_report
    return _parse_report(*args, **kwargs)


def detect_tool(*args, **kwargs):
    from .finding_parser import detect_tool as _detect_tool
    return _detect_tool(*args, **kwargs)

__all__ = [
    "ToolPrior",
    "DetectionCapability",
    "DetectionMethod",
    "SignalPolarity",
    "TaintRelevance",
    "AnalysisDepth",
    "DetectionFamily",
    "EvidenceType",
    "Granularity",
    "FPRisk",
    "extract_tool_prior",
    "extract_all",
    "save_prior",
    "load_prior",
    "save_all",
    "load_all",
    "NormalizedFinding",
    "parse_report",
    "detect_tool",
]
