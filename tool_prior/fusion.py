"""
Capability-aware weighted fusion of normalized SAST findings.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

from .finding_schema import NormalizedFinding
from .schema import DetectionCapability, ToolPrior

_DEPTH_WEIGHT = {
    "taint_analysis": 1.0,
    "inter_procedural": 0.85,
    "intra_procedural": 0.70,
    "external_result_ingest": 0.65,
    "constant_backtrack": 0.60,
    "api_presence": 0.40,
    "manifest_parse": 0.35,
    "syntax_only": 0.20,
}

_FP_DISCOUNT = {"low": 0.05, "medium": 0.20, "high": 0.40}
_SEVERITY_WEIGHT = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.3,
    "info": 0.1,
}


@dataclass
class FusedFinding:
    """One finding after capability-aware fusion."""

    id: str
    tool_name: str
    rule_id: str
    title: str
    description: str = ""

    severity: str = "info"
    file_path: str = ""
    line_number: Optional[int] = None
    method_signature: str = ""
    class_name: str = ""
    component_name: str = ""
    code_snippet: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    affected_components: list[str] = field(default_factory=list)
    signal_polarity: str = "vulnerability"

    matched_capability_id: str = ""
    capability_taint_relevance: str = "low"
    capability_fp_risk: str = "medium"
    capability_analysis_depth: str = ""

    fused_score: float = 0.0
    score_breakdown: dict = field(default_factory=dict)
    corroboration_count: int = 1

    alignment: dict = field(default_factory=dict)


def _enum_value(value) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _generate_id(tool: str, rule_id: str, title: str) -> str:
    digest = hashlib.md5(f"{tool}:{rule_id}:{title}".encode("utf-8")).hexdigest()[:4]
    return f"{tool}_{rule_id}_{digest}"


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (text or "").lower()).strip("_") or "unknown"


def _best_analysis_depth(cap: DetectionCapability) -> tuple[str, float]:
    if not cap.detection_methods:
        return ("unknown", 0.3)
    best_depth = "unknown"
    best_weight = 0.3
    for method in cap.detection_methods:
        depth = _enum_value(method.depth)
        weight = _DEPTH_WEIGHT.get(depth, 0.3)
        if weight > best_weight:
            best_depth = depth
            best_weight = weight
    return best_depth, best_weight


def capability_strength(cap: DetectionCapability | None) -> tuple[str, float]:
    if cap is None:
        return ("no_capability_match", 0.25)
    return _best_analysis_depth(cap)


def evidence_strength(finding: NormalizedFinding) -> tuple[str, float]:
    if (finding.method_signature or "").strip():
        return ("method_level", 1.0)
    if (finding.class_name or "").strip():
        return ("class_level", 0.6)
    if (finding.component_name or "").strip() or finding.affected_components:
        return ("component_level", 0.5)
    if finding.file_path and finding.line_number is not None:
        return ("file_line_level", 0.45)
    if (finding.file_path or "").strip():
        return ("file_level", 0.3)
    return ("description_only", 0.15)


def reliability(cap: DetectionCapability | None) -> float:
    if cap is None:
        return 1.0 - _FP_DISCOUNT["medium"]
    fp_risk = _enum_value(cap.fp_risk)
    return 1.0 - _FP_DISCOUNT.get(fp_risk, _FP_DISCOUNT["medium"])


def severity_weight(severity: str) -> float:
    return _SEVERITY_WEIGHT.get((severity or "").lower(), 0.3)


def match_capability(
    finding: NormalizedFinding,
    prior: ToolPrior | None,
) -> DetectionCapability | None:
    if prior is None:
        return None

    slug = _slugify(finding.rule_id)

    for cap in prior.capabilities:
        if finding.rule_id in cap.native_rule_ids:
            return cap

    for cap in prior.capabilities:
        if cap.capability_id == slug:
            return cap

    for cap in prior.capabilities:
        if slug in cap.capability_id or cap.capability_id in slug:
            return cap

    if finding.cwe_ids:
        wanted = set(finding.cwe_ids)
        best_cap = None
        best_depth = -1.0
        for cap in prior.capabilities:
            if not (set(cap.cwe_ids) & wanted):
                continue
            _, depth = _best_analysis_depth(cap)
            if depth > best_depth:
                best_cap = cap
                best_depth = depth
        return best_cap

    return None


def apply_corroboration_boost(
    findings: list[FusedFinding],
    boost_per_tool: float = 0.08,
    max_boost: float = 0.25,
) -> None:
    from collections import defaultdict

    groups: dict[tuple[str, str], list[FusedFinding]] = defaultdict(list)
    for finding in findings:
        cwe = finding.cwe_ids[0] if finding.cwe_ids else "no_cwe"
        loc = finding.component_name or finding.class_name or "no_loc"
        groups[(cwe, loc)].append(finding)

    for group in groups.values():
        tools = {f.tool_name for f in group}
        tool_count = len(tools)
        if tool_count <= 1:
            continue
        boost = min(boost_per_tool * (tool_count - 1), max_boost)
        for finding in group:
            finding.corroboration_count = tool_count
            finding.fused_score = min(1.0, finding.fused_score + boost)
            finding.score_breakdown["corroboration_boost"] = boost


def fuse_findings(
    findings: list[NormalizedFinding],
    priors: list[ToolPrior],
) -> list[FusedFinding]:
    prior_map = {prior.tool_name.lower(): prior for prior in priors}
    fused_results: list[FusedFinding] = []

    for finding in findings:
        prior = prior_map.get((finding.tool_name or "").lower())
        cap = match_capability(finding, prior)

        depth_name, cap_weight = capability_strength(cap)
        evidence_level, evidence_weight = evidence_strength(finding)
        rel = reliability(cap)
        sev_weight = severity_weight(finding.severity)

        score = cap_weight * evidence_weight * rel * sev_weight
        score = max(0.0, min(1.0, score))

        fused_results.append(
            FusedFinding(
                id=_generate_id(finding.tool_name, finding.rule_id, finding.title),
                tool_name=finding.tool_name,
                rule_id=finding.rule_id,
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                file_path=finding.file_path,
                line_number=finding.line_number,
                method_signature=finding.method_signature,
                class_name=finding.class_name,
                component_name=finding.component_name,
                code_snippet=finding.code_snippet,
                cwe_ids=list(finding.cwe_ids),
                affected_components=list(finding.affected_components),
                signal_polarity=finding.signal_polarity,
                matched_capability_id=cap.capability_id if cap else "",
                capability_taint_relevance=_enum_value(cap.taint_relevance) if cap else "low",
                capability_fp_risk=_enum_value(cap.fp_risk) if cap else "medium",
                capability_analysis_depth=depth_name,
                fused_score=score,
                score_breakdown={
                    "capability_strength": cap_weight,
                    "capability_depth": depth_name,
                    "evidence_strength": evidence_weight,
                    "evidence_level": evidence_level,
                    "reliability": rel,
                    "severity_weight": sev_weight,
                },
            )
        )

    apply_corroboration_boost(fused_results)
    fused_results.sort(key=lambda x: x.fused_score, reverse=True)
    return fused_results
