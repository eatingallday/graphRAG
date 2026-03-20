"""
Unified finding schema for normalizing different SAST tool outputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NormalizedFinding:
    """One parsed finding from any SAST tool, normalized to a common shape."""

    # Identity
    tool_name: str
    rule_id: str
    title: str
    description: str = ""

    # Severity
    severity: str = "info"  # critical | high | medium | low | info
    original_severity: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: str = ""

    # Location
    file_path: str = ""
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    method_signature: str = ""
    class_name: str = ""
    component_name: str = ""

    # Evidence
    code_snippet: str = ""
    matched_string: str = ""
    affected_components: list[str] = field(default_factory=list)
    call_path: list[str] = field(default_factory=list)

    # Context
    category: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    reference_urls: list[str] = field(default_factory=list)
    recommendation: str = ""

    # Tool-specific
    confidence: Optional[float] = None
    signal_polarity: str = "vulnerability"  # vulnerability | hardening_present | observation
