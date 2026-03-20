"""
Extract ToolPrior instances from structured Markdown reports under tools_intro/.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .prior_store import save_all
from .schema import (
    AnalysisDepth,
    DetectionCapability,
    DetectionFamily,
    DetectionMethod,
    EvidenceType,
    FPRisk,
    Granularity,
    SignalPolarity,
    TaintRelevance,
    ToolPrior,
)

_SECTION_RE = re.compile(r"^##\s+(\d+)\.\s+(.+?)\s*$", re.MULTILINE)
_TITLE_RE = re.compile(r"^#\s+Tool Prior Analysis:\s*(.+?)\s*$", re.MULTILINE)
_CWE_RE = re.compile(r"CWE-\d+")
_YEAR_RE = re.compile(r"(20\d{2})")
_RULE_PREFIX_RE = re.compile(r"^\s*Rule\s+(\d+)\s*:\s*(.+)$", re.IGNORECASE)
_INLINE_CODE_RE = re.compile(r"`([^`]+)`")
_CATEGORY_BULLET_RE = re.compile(r"^\s*-\s*Category(?: family)?:\s*(.+)$", re.MULTILINE)

_DETECTION_MATCHERS: list[tuple[tuple[str, ...], DetectionFamily]] = [
    (("manifest attribute", "manifest xpath", "manifest dom", "manifest parsing", "xml dom"), DetectionFamily.MANIFEST_ATTRIBUTE_CHECK),
    (("manifest permission", "permission membership", "permission extraction"), DetectionFamily.MANIFEST_PERMISSION_CHECK),
    (("exported", "intent-filter", "component export"), DetectionFamily.MANIFEST_COMPONENT_EXPORT),
    (("network-security-config", "network security config"), DetectionFamily.NETWORK_SECURITY_CONFIG_PARSE),
    (("regex", "grep", "pattern match", "keyword search"), DetectionFamily.REGEX_TEXT_SCAN),
    (("dex string", "string table", "string scan"), DetectionFamily.DEX_STRING_SCAN),
    (("smali invocation", "smali opcode"), DetectionFamily.SMALI_INVOCATION_PATTERN),
    (("api-call xref", "xref search", "androguard xref", "api method cross-reference"), DetectionFamily.API_CALL_XREF),
    (("java ast", "java pattern"), DetectionFamily.JAVA_AST_MATCH),
    (("jimple",), DetectionFamily.JIMPLE_PATTERN),
    (("constant backtrack", "register backtrace", "constant propagation", "constant trace"), DetectionFamily.CONSTANT_ARG_TRACE),
    (("class-hierarchy", "subclass", "interface-impl", "interface implementation"), DetectionFamily.CLASS_HIERARCHY_CHECK),
    (("backward slice", "backward def-use", "saaf"), DetectionFamily.BACKWARD_DEF_USE_SLICE),
    (("flowdroid", "source-sink", "taint analysis"), DetectionFamily.FLOWDROID_TAINT),
    (("ifds",), DetectionFamily.IFDS_CONSTANT_PROPAGATION),
    (("forward intent taint",), DetectionFamily.FORWARD_INTENT_TAINT),
    (("certificate", "signing", "apksig"), DetectionFamily.CERTIFICATE_PARSE),
    (("elf", "checksec", "lief", "native binary"), DetectionFamily.BINARY_METADATA_INSPECT),
    (("entropy",), DetectionFamily.STRING_ENTROPY_SCAN),
    (("library fingerprint", "library version", "package-family"), DetectionFamily.LIBRARY_FINGERPRINT),
    (("apk file inventory", "duplicate dex", "apk structural"), DetectionFamily.APK_FILE_INVENTORY),
    (("external tool", "consumes another tool", "ingestion"), DetectionFamily.EXTERNAL_TAINT_INGEST),
]

_EVIDENCE_MATCHERS: list[tuple[tuple[str, ...], EvidenceType]] = [
    (("file path", "file paths", "path"), EvidenceType.FILE_PATH),
    (("line number", "line numbers"), EvidenceType.LINE_NUMBER),
    (("method signature", "method qualname", "caller method"), EvidenceType.METHOD_SIGNATURE),
    (("class name", "class"), EvidenceType.CLASS_NAME),
    (("component name", "activity name", "receiver name", "provider name"), EvidenceType.COMPONENT_NAME),
    (("code snippet", "statement text", "matching line"), EvidenceType.CODE_SNIPPET),
    (("call path", "caller", "src -> dst"), EvidenceType.CALL_PATH),
    (("permission",), EvidenceType.PERMISSION_NAME),
    (("manifest attribute", "manifest setting"), EvidenceType.MANIFEST_ATTRIBUTE),
    (("constant", "resolved value"), EvidenceType.CONSTANT_VALUE),
    (("url", "domain", "host"), EvidenceType.DOMAIN_SCOPE),
    (("certificate",), EvidenceType.CERTIFICATE_INFO),
    (("library",), EvidenceType.LIBRARY_INFO),
    (("description only",), EvidenceType.DESCRIPTION_ONLY),
    (("score", "cvss"), EvidenceType.SCORE),
    (("source-sink pair",), EvidenceType.SOURCE_SINK_PAIR),
    (("taint path",), EvidenceType.TAINT_PATH),
]

_GRANULARITY_MATCHERS: list[tuple[tuple[str, ...], Granularity]] = [
    (("app", "app-wide"), Granularity.APP),
    (("manifest", "manifest entry"), Granularity.MANIFEST_ENTRY),
    (("component", "activity", "receiver", "provider", "service"), Granularity.COMPONENT),
    (("class",), Granularity.CLASS),
    (("method", "callsite"), Granularity.METHOD),
    (("statement", "instruction"), Granularity.STATEMENT),
    (("file + line", "file+line", "file line", "line"), Granularity.FILE_LINE),
    (("resource", "xml resource"), Granularity.RESOURCE_ENTRY),
    (("library", "native library"), Granularity.LIBRARY),
]


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return slug or "capability"


def _normalize_tool_name(raw_name: str) -> str:
    name = _slugify(raw_name).replace("_framework", "")
    aliases = {
        "mob_sf": "mobsf",
        "androbugs": "androbugs",
        "apk_hunt": "apkhunt",
        "super_android_analyzer": "super",
    }
    return aliases.get(name, name)


def _split_sections(text: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    matches = list(_SECTION_RE.finditer(text))
    for i, match in enumerate(matches):
        key = match.group(1)
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        sections[key] = text[start:end].strip()
    return sections


def _split_table_row(row: str) -> list[str]:
    # Keep literal pipes inside inline code spans intact.
    chars = list(row.rstrip("\n"))
    in_code = False
    for idx, ch in enumerate(chars):
        if ch == "`":
            in_code = not in_code
        elif ch == "|" and in_code:
            chars[idx] = "\u0000"
    safe = "".join(chars).strip().strip("|")
    return [cell.strip().replace("\u0000", "|") for cell in safe.split("|")]


def _is_separator_row(row: str) -> bool:
    return bool(re.fullmatch(r"\s*\|?[\s:\-\|]+\|?\s*", row))


def _extract_tables(text: str) -> list[tuple[list[str], list[list[str]]]]:
    lines = text.splitlines()
    i = 0
    tables: list[tuple[list[str], list[list[str]]]] = []
    while i < len(lines) - 1:
        if "|" not in lines[i] or "|" not in lines[i + 1]:
            i += 1
            continue
        if not _is_separator_row(lines[i + 1]):
            i += 1
            continue
        header = _split_table_row(lines[i])
        i += 2
        rows: list[list[str]] = []
        while i < len(lines) and "|" in lines[i]:
            row = lines[i].strip()
            if not row:
                break
            if _is_separator_row(row):
                i += 1
                continue
            cells = _split_table_row(row)
            if any(cell for cell in cells):
                rows.append(cells)
            i += 1
        tables.append((header, rows))
    return tables


def _parse_overview(section: str, title_tool_name: str) -> dict:
    raw = {
        "tool_name": _normalize_tool_name(title_tool_name),
        "repo_url": "",
        "implementation_languages": [],
        "last_maintained": "",
        "maintenance_status": "stale",
    }
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("-"):
            continue
        if ":" not in line:
            continue
        key, value = line[1:].split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "repository":
            raw["repo_url"] = value
        elif key == "language":
            chunks = re.split(r",|;|\band\b", value)
            raw["implementation_languages"] = [c.strip(" `") for c in chunks if c.strip()]
        elif key == "last maintained":
            raw["last_maintained"] = value

    last_maintained = raw["last_maintained"].lower()
    if "archiv" in last_maintained:
        raw["maintenance_status"] = "archived"
    elif "active" in last_maintained:
        raw["maintenance_status"] = "active"
    else:
        year_match = _YEAR_RE.search(last_maintained)
        if year_match:
            year = int(year_match.group(1))
            raw["maintenance_status"] = "active" if year >= 2024 else "stale"
        else:
            raw["maintenance_status"] = "stale"
    return raw


def _extract_cwe_ids(text: str) -> list[str]:
    return sorted(set(_CWE_RE.findall(text)))


def _infer_depth(family: DetectionFamily) -> AnalysisDepth:
    if family in {DetectionFamily.REGEX_TEXT_SCAN, DetectionFamily.DEX_STRING_SCAN, DetectionFamily.STRING_ENTROPY_SCAN}:
        return AnalysisDepth.SYNTAX_ONLY
    if family in {
        DetectionFamily.MANIFEST_ATTRIBUTE_CHECK,
        DetectionFamily.MANIFEST_PERMISSION_CHECK,
        DetectionFamily.MANIFEST_COMPONENT_EXPORT,
        DetectionFamily.NETWORK_SECURITY_CONFIG_PARSE,
    }:
        return AnalysisDepth.MANIFEST_PARSE
    if family in {DetectionFamily.API_CALL_XREF, DetectionFamily.SMALI_INVOCATION_PATTERN}:
        return AnalysisDepth.API_PRESENCE
    if family in {DetectionFamily.CONSTANT_ARG_TRACE}:
        return AnalysisDepth.CONSTANT_BACKTRACK
    if family in {DetectionFamily.JAVA_AST_MATCH, DetectionFamily.CLASS_HIERARCHY_CHECK}:
        return AnalysisDepth.INTRA_PROCEDURAL
    if family in {
        DetectionFamily.JIMPLE_PATTERN,
        DetectionFamily.BACKWARD_DEF_USE_SLICE,
        DetectionFamily.IFDS_CONSTANT_PROPAGATION,
    }:
        return AnalysisDepth.INTER_PROCEDURAL
    if family in {DetectionFamily.FLOWDROID_TAINT, DetectionFamily.FORWARD_INTENT_TAINT}:
        return AnalysisDepth.TAINT_ANALYSIS
    if family in {DetectionFamily.EXTERNAL_TAINT_INGEST}:
        return AnalysisDepth.EXTERNAL_RESULT_INGEST
    return AnalysisDepth.API_PRESENCE


def _family_target_artifact(family: DetectionFamily) -> str:
    if family in {
        DetectionFamily.MANIFEST_ATTRIBUTE_CHECK,
        DetectionFamily.MANIFEST_PERMISSION_CHECK,
        DetectionFamily.MANIFEST_COMPONENT_EXPORT,
        DetectionFamily.NETWORK_SECURITY_CONFIG_PARSE,
    }:
        return "manifest_xml"
    if family in {DetectionFamily.DEX_STRING_SCAN, DetectionFamily.API_CALL_XREF}:
        return "dalvik"
    if family in {DetectionFamily.SMALI_INVOCATION_PATTERN}:
        return "smali"
    if family in {DetectionFamily.JAVA_AST_MATCH, DetectionFamily.REGEX_TEXT_SCAN}:
        return "decompiled_java"
    if family in {DetectionFamily.JIMPLE_PATTERN, DetectionFamily.IFDS_CONSTANT_PROPAGATION}:
        return "jimple"
    if family in {DetectionFamily.FLOWDROID_TAINT, DetectionFamily.FORWARD_INTENT_TAINT}:
        return "flowdroid"
    if family in {DetectionFamily.CERTIFICATE_PARSE, DetectionFamily.BINARY_METADATA_INSPECT}:
        return "apk_binary"
    return "mixed"


def _map_detection_methods(text: str) -> list[DetectionMethod]:
    lower = text.lower()
    seen: set[DetectionFamily] = set()
    methods: list[DetectionMethod] = []
    for needles, family in _DETECTION_MATCHERS:
        if any(needle in lower for needle in needles):
            if family in seen:
                continue
            seen.add(family)
            methods.append(
                DetectionMethod(
                    family=family,
                    depth=_infer_depth(family),
                    target_artifact=_family_target_artifact(family),
                )
            )
    if not methods:
        methods.append(
            DetectionMethod(
                family=DetectionFamily.REGEX_TEXT_SCAN,
                depth=AnalysisDepth.SYNTAX_ONLY,
                target_artifact="decompiled_text",
                notes="fallback mapping",
            )
        )
    return methods


def _map_evidence_types(text: str) -> list[EvidenceType]:
    lower = text.lower()
    items: list[EvidenceType] = []
    for needles, value in _EVIDENCE_MATCHERS:
        if any(needle in lower for needle in needles):
            items.append(value)
    if not items:
        return [EvidenceType.DESCRIPTION_ONLY]
    return list(dict.fromkeys(items))


def _map_granularity(text: str) -> list[Granularity]:
    lower = text.lower()
    items: list[Granularity] = []
    for needles, value in _GRANULARITY_MATCHERS:
        if any(needle in lower for needle in needles):
            items.append(value)
    if not items:
        return [Granularity.APP]
    return list(dict.fromkeys(items))


def _split_values(cell: str) -> list[str]:
    cleaned = re.sub(r"[`*]", "", cell)
    parts = re.split(r"/|,|;|\bor\b|\|", cleaned)
    return [p.strip() for p in parts if p.strip()]


def _parse_native_rule_ids(tool_name: str, category: str, vector_cell: str) -> tuple[str, list[str]]:
    native_rule_ids: list[str] = []
    clean_category = category.strip()

    if tool_name == "speck":
        m = _RULE_PREFIX_RE.match(category)
        if m:
            native_rule_ids.append(f"rule_{m.group(1)}")
            clean_category = m.group(2).strip()

    if vector_cell:
        for match in _INLINE_CODE_RE.findall(vector_cell):
            for token in match.split(","):
                token = token.strip()
                if token:
                    native_rule_ids.append(token)

    if not native_rule_ids and vector_cell:
        for token in vector_cell.split(","):
            token = token.strip(" `")
            if token and re.search(r"[A-Za-z0-9_-]", token):
                native_rule_ids.append(token)

    return clean_category, sorted(set(native_rule_ids))


def _infer_signal_polarity(category: str, severity_values: list[str]) -> SignalPolarity:
    text = f"{category} {' '.join(severity_values)}".lower()
    if "observational" in text or "inventory" in text or "fingerprint" in text:
        return SignalPolarity.OBSERVATION
    positive_only = {"ok", "good", "secure"}
    if severity_values and all(v.lower() in positive_only for v in severity_values):
        return SignalPolarity.HARDENING_PRESENT
    return SignalPolarity.VULNERABILITY


def _infer_fp_risk(methods: list[DetectionMethod]) -> FPRisk:
    families = {m.family for m in methods}
    if DetectionFamily.FLOWDROID_TAINT in families or DetectionFamily.IFDS_CONSTANT_PROPAGATION in families:
        return FPRisk.LOW
    if families & {
        DetectionFamily.REGEX_TEXT_SCAN,
        DetectionFamily.DEX_STRING_SCAN,
        DetectionFamily.SAME_FILE_COOCCURRENCE,
    }:
        return FPRisk.HIGH
    return FPRisk.MEDIUM


def _parse_capability_tables(section: str, tool_name: str) -> list[DetectionCapability]:
    capabilities: list[DetectionCapability] = []
    slug_counter: defaultdict[str, int] = defaultdict(int)

    for header, rows in _extract_tables(section):
        normalized = [h.strip().lower() for h in header]
        if "category" not in normalized:
            continue
        if "detection method" not in normalized or "evidence type" not in normalized:
            continue

        col_idx = {name: idx for idx, name in enumerate(normalized)}
        has_vector_col = "main vector ids" in col_idx

        for row in rows:
            if len(row) < len(header):
                row = row + [""] * (len(header) - len(row))
            category = row[col_idx["category"]].strip()
            if not category:
                continue

            vector_cell = row[col_idx["main vector ids"]] if has_vector_col else ""
            category, native_rule_ids = _parse_native_rule_ids(tool_name, category, vector_cell)
            cwe_cell = row[col_idx["cwe"]] if "cwe" in col_idx else ""
            method_cell = row[col_idx["detection method"]]
            granularity_cell = row[col_idx["granularity"]] if "granularity" in col_idx else ""
            severity_cell = row[col_idx["severity"]] if "severity" in col_idx else ""
            evidence_cell = row[col_idx["evidence type"]] if "evidence type" in col_idx else ""

            methods = _map_detection_methods(method_cell)
            severity_values = _split_values(severity_cell)
            granularity = _map_granularity(granularity_cell)
            evidence = _map_evidence_types(evidence_cell)
            cwe_ids = _extract_cwe_ids(cwe_cell)

            base_slug = _slugify(f"{tool_name}_{category}")
            slug_counter[base_slug] += 1
            capability_id = base_slug if slug_counter[base_slug] == 1 else f"{base_slug}_{slug_counter[base_slug]}"

            analysis_scope = sorted(
                {
                    "manifest" if g in {Granularity.MANIFEST_ENTRY, Granularity.COMPONENT} else
                    "method" if g in {Granularity.METHOD, Granularity.STATEMENT} else
                    "file" if g == Granularity.FILE_LINE else
                    "app"
                    for g in granularity
                }
            )

            capabilities.append(
                DetectionCapability(
                    capability_id=capability_id,
                    category=category,
                    cwe_ids=cwe_ids,
                    signal_polarity=_infer_signal_polarity(category, severity_values),
                    detection_methods=methods,
                    analysis_scope=analysis_scope,
                    granularity=granularity,
                    evidence_types=evidence,
                    severity_values=severity_values,
                    fp_risk=_infer_fp_risk(methods),
                    native_rule_ids=native_rule_ids,
                )
            )

    return capabilities


def _extract_bullet_field(block: str, field_name: str) -> str:
    pattern = re.compile(
        rf"^\s*-\s*{re.escape(field_name)}:\s*(.+?)(?=^\s*-\s*[A-Z][^:\n]*:|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(block)
    if not match:
        return ""
    value = match.group(1).strip()
    lines = [line.strip() for line in value.splitlines()]
    return " ".join(line for line in lines if line)


def _parse_bullet_categories(head: str, block: str) -> list[str]:
    categories = [token.strip() for token in _INLINE_CODE_RE.findall(head) if token.strip()]
    if not categories:
        categories = [part.strip() for part in head.split(",") if part.strip()]

    # Some family blocks enumerate concrete vulnerability codes below the heading.
    for code in re.findall(r"^\s*-\s*`([A-Z0-9_/-]+)`\s*$", block, re.MULTILINE):
        categories.append(code.strip())

    return sorted(set(cat for cat in categories if cat))


def _parse_capability_bullets(section: str, tool_name: str) -> list[DetectionCapability]:
    capabilities: list[DetectionCapability] = []
    matches = list(_CATEGORY_BULLET_RE.finditer(section))
    slug_counter: defaultdict[str, int] = defaultdict(int)

    for idx, match in enumerate(matches):
        head = match.group(1).strip()
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(section)
        block = section[start:end]

        categories = _parse_bullet_categories(head, block)
        if not categories:
            continue

        cwe_text = _extract_bullet_field(block, "CWE")
        method_text = _extract_bullet_field(block, "Detection method")
        granularity_text = _extract_bullet_field(block, "Detection granularity")
        severity_text = _extract_bullet_field(block, "Severity classification")
        evidence_text = _extract_bullet_field(block, "Evidence provided")

        methods = _map_detection_methods(method_text)
        granularity = _map_granularity(granularity_text)
        evidence = _map_evidence_types(evidence_text)
        cwe_ids = _extract_cwe_ids(cwe_text)
        severity_values = _split_values(severity_text)

        for category in categories:
            base_slug = _slugify(f"{tool_name}_{category}")
            slug_counter[base_slug] += 1
            capability_id = (
                base_slug
                if slug_counter[base_slug] == 1
                else f"{base_slug}_{slug_counter[base_slug]}"
            )

            analysis_scope = sorted(
                {
                    "manifest" if g in {Granularity.MANIFEST_ENTRY, Granularity.COMPONENT} else
                    "method" if g in {Granularity.METHOD, Granularity.STATEMENT} else
                    "file" if g == Granularity.FILE_LINE else
                    "app"
                    for g in granularity
                }
            )

            capabilities.append(
                DetectionCapability(
                    capability_id=capability_id,
                    category=category,
                    cwe_ids=cwe_ids,
                    signal_polarity=_infer_signal_polarity(category, severity_values),
                    detection_methods=methods,
                    analysis_scope=analysis_scope,
                    granularity=granularity,
                    evidence_types=evidence,
                    severity_values=severity_values,
                    fp_risk=_infer_fp_risk(methods),
                    native_rule_ids=[],
                )
            )

    return capabilities


def _parse_architecture(section: str) -> dict:
    lower = section.lower()
    input_formats: list[str] = []
    intermediate_representations: list[str] = []
    decomp_tools: list[str] = []

    input_map = {
        "apk": "apk",
        "aab": "aab",
        "apks": "apks",
        "xapk": "xapk",
        "source": "source",
        "java source": "java_source",
        "smali": "smali",
        "jar": "jar",
        "aar": "aar",
        ".so": "so",
    }
    ir_map = {
        "dalvik": "dalvik",
        "dex": "dalvik",
        "jimple": "jimple",
        "java ast": "java_ast",
        "decompiled java": "decompiled_java",
        "smali": "smali",
        "manifest": "manifest_xml",
        "sqlite": "sqlite_index",
    }
    for needle, val in input_map.items():
        if needle in lower:
            input_formats.append(val)
    for needle, val in ir_map.items():
        if needle in lower:
            intermediate_representations.append(val)
    for tool in ("jadx", "apktool", "dex2jar", "cfr", "jd-cmd"):
        if tool in lower:
            decomp_tools.append(tool)

    return {
        "input_formats": sorted(set(input_formats)),
        "intermediate_representations": sorted(set(intermediate_representations)),
        "requires_decompilation": bool(decomp_tools or "decompil" in lower),
        "decompilation_tools": sorted(set(decomp_tools)),
    }


def _parse_output_format(section: str) -> dict:
    lower = section.lower()
    output_formats = []
    for fmt in ("json", "txt", "text", "xml", "html", "pdf", "sarif"):
        if re.search(rf"\b{re.escape(fmt)}\b", lower):
            output_formats.append("txt" if fmt == "text" else fmt)

    raw_levels = re.findall(r"`([^`]+)`", section)
    severity_set: set[str] = set()
    for item in raw_levels:
        low = item.lower()
        if low in {"critical", "high", "medium", "low", "warning", "notice", "info", "ok", "good", "secure", "na"}:
            severity_set.add(low)
    if "critical" in lower and not severity_set:
        severity_set.update(["critical", "warning", "info"])

    no_conf = bool(re.search(r"\bno\b.{0,25}\bconfidence", lower))
    has_confidence = ("confidence" in lower) and not no_conf
    has_numeric = "cvss" in lower or "numeric risk score" in lower
    supports_positive = any(token in lower for token in ("good", "secure", "ok"))

    return {
        "output_formats": sorted(set(output_formats)),
        "severity_scheme": sorted(severity_set),
        "has_confidence_score": has_confidence,
        "has_numeric_risk_score": has_numeric,
        "supports_positive_controls": supports_positive,
    }


def _looks_like_schema_field(text: str) -> bool:
    """
    Detect schema-feedback bullets like `tool_name: str` that are not tool quirks.
    """
    low = text.lower()
    if re.search(r"`\s*[a-z_][a-z0-9_]*\s*:\s*[^`]+`", text):
        return True
    if re.fullmatch(r"`[a-z0-9_/-]+`", text.strip()):
        return True
    if re.search(r"\b[a-z_][a-z0-9_]*\s*:\s*(str|int|float|bool|list|dict|literal|datetime)\b", low):
        return True
    return False


def _is_quirk_candidate(text: str) -> bool:
    """
    Keep only high-signal implementation quirks; drop schema/taxonomy bullets.
    """
    low = text.lower()
    if not text:
        return False

    schema_terms = (
        "essential fields",
        "suggested",
        "schema",
        "enum",
        "shape",
        "findingprofile",
        "detectionmethodprimary",
        "analysisscope",
        "granularity",
        "evidencefield",
        "suggested enums",
        "suggested enum/taxonomy",
        "fields a naive schema",
    )
    if any(term in low for term in schema_terms):
        return False
    if _looks_like_schema_field(text):
        return False

    quirk_terms = (
        "bug",
        "broken",
        "stale",
        "inconsistent",
        "orphaned",
        "wrong",
        "failed",
        "failure",
        "brittle",
        "unreliable",
        "todo",
        "commented out",
        "disabled",
        "mismatch",
        "issue",
        "heuristic",
        "false-positive",
        "false positive",
    )
    return any(term in low for term in quirk_terms)


def _parse_strengths_limitations(section6: str, section7: str) -> dict:
    strengths: list[str] = []
    limitations: list[str] = []
    known_quirks: list[str] = []

    mode = ""
    for raw in section6.splitlines():
        line = raw.strip()
        low = line.lower()
        if low.startswith("- strengths"):
            mode = "strengths"
            continue
        if low.startswith("- limitations") or low.startswith("- limitation"):
            mode = "limitations"
            continue
        if line.startswith("- ") and mode in {"strengths", "limitations"}:
            text = line[2:].strip()
            if text:
                if mode == "strengths":
                    strengths.append(text)
                else:
                    limitations.append(text)

    taint_match = re.search(r"taint relevance\s*:\s*(high|medium|low)", section6, re.IGNORECASE)
    taint = TaintRelevance.LOW
    if taint_match:
        taint = TaintRelevance(taint_match.group(1).lower())

    for raw in section7.splitlines():
        line = raw.strip()
        if line.startswith("- "):
            item = line[2:].strip()
            if _is_quirk_candidate(item):
                known_quirks.append(item)
                if len(known_quirks) >= 10:
                    break

    issue_text = f"{section6}\n{section7}".lower()
    if any(token in issue_text for token in ("broken", "bug", "inconsistent", "orphaned", "stale", "archived")):
        reliability = "low"
    elif "active" in issue_text and "limitation" not in issue_text:
        reliability = "high"
    else:
        reliability = "medium"

    return {
        "overall_strengths": strengths,
        "overall_limitations": limitations,
        "taint_relevance": taint,
        "implementation_reliability": reliability,
        "known_quirks": known_quirks,
    }


def extract_tool_prior(md_path: str) -> ToolPrior:
    """Parse one tool analysis Markdown file into ToolPrior."""
    text = Path(md_path).read_text(encoding="utf-8")
    title_match = _TITLE_RE.search(text)
    title_name = title_match.group(1).strip() if title_match else Path(md_path).stem

    sections = _split_sections(text)
    overview = _parse_overview(sections.get("1", ""), title_name)
    tool_name = overview["tool_name"]

    section2 = sections.get("2", "")
    capabilities = _parse_capability_tables(section2, tool_name)
    capabilities.extend(_parse_capability_bullets(section2, tool_name))
    architecture = _parse_architecture(sections.get("3", ""))
    output = _parse_output_format(sections.get("5", ""))
    assessment = _parse_strengths_limitations(sections.get("6", ""), sections.get("7", ""))

    # Apply tool-level taint default and known quirks to capabilities.
    for cap in capabilities:
        cap.taint_relevance = assessment["taint_relevance"]
        if assessment["known_quirks"]:
            cap.known_quirks = list(dict.fromkeys(cap.known_quirks + assessment["known_quirks"]))

    return ToolPrior(
        tool_name=tool_name,
        repo_url=overview["repo_url"],
        implementation_languages=overview["implementation_languages"],
        last_maintained=overview["last_maintained"],
        maintenance_status=overview["maintenance_status"],
        input_formats=architecture["input_formats"],
        intermediate_representations=architecture["intermediate_representations"],
        requires_decompilation=architecture["requires_decompilation"],
        decompilation_tools=architecture["decompilation_tools"],
        capabilities=capabilities,
        output_formats=output["output_formats"],
        severity_scheme=output["severity_scheme"],
        has_confidence_score=output["has_confidence_score"],
        has_numeric_risk_score=output["has_numeric_risk_score"],
        supports_positive_controls=output["supports_positive_controls"],
        taint_relevance=assessment["taint_relevance"],
        overall_strengths=assessment["overall_strengths"],
        overall_limitations=assessment["overall_limitations"],
        implementation_reliability=assessment["implementation_reliability"],
        extracted_at=datetime.now(timezone.utc).isoformat(),
        extraction_source="codex_report",
    )


def extract_all(tools_intro_dir: str) -> list[ToolPrior]:
    """Parse all tool_prior_analysis_*.md files in a directory."""
    root = Path(tools_intro_dir)
    md_files = sorted(root.glob("tool_prior_analysis_*.md"))
    return [extract_tool_prior(str(path)) for path in md_files]


if __name__ == "__main__":
    here = Path(__file__).resolve()
    tools_intro_dir = here.parents[2] / "tools_intro"
    output_dir = here.parent / "priors"
    output_dir.mkdir(parents=True, exist_ok=True)

    priors = extract_all(str(tools_intro_dir))
    paths = save_all(priors, str(output_dir))
    for path in paths:
        print(f"Wrote: {path}")
