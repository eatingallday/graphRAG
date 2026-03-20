"""
ToolPrior Schema — Unified design synthesized from 11 SAST tool analysis reports.

This module defines the data structures for representing a SAST tool's
"capability profile" (Tool Prior). Each ToolPrior captures:
  - What vulnerability categories the tool can detect
  - How it detects them (detection methods)
  - What evidence it provides
  - Known strengths, blind spots, and false-positive risks
  - How relevant its output is to downstream taint/graph reasoning

Design principles:
  1. Capability-centric: the core unit is a DetectionCapability, not a "rule"
  2. Detection methods are structured, not flat enums (all 11 reports agree)
  3. Signal polarity is explicit: vulnerability vs hardening vs observation
  4. Taint relevance is per-tool AND per-capability
  5. No mandatory confidence_score field (none of the 11 tools have calibrated confidence)
  6. Implementation reliability is tracked separately from claimed capability
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ─────────────────── Enums ───────────────────

class SignalPolarity(str, Enum):
    """What kind of signal does this capability produce?"""
    VULNERABILITY = "vulnerability"           # reports a weakness/vuln
    HARDENING_PRESENT = "hardening_present"   # reports a defense is present (MobSF "good", SPECK "ok")
    HARDENING_MISSING = "hardening_missing"   # reports absence of a defense (negative check)
    OBSERVATION = "observation"               # informational, not a verdict (trueseeing fingerprints, API inventory)
    COMPLIANCE = "compliance"                 # compliance/guideline check (MobSF NIAP, APKHunt MASVS)


class TaintRelevance(str, Enum):
    """How relevant is this tool/capability to data-flow / taint analysis?"""
    HIGH = "high"       # tool does real interprocedural taint (JAADAS flowdroid mode)
    MEDIUM = "medium"   # partial taint or useful taint priors (AUSERA, Marvin SAAF)
    LOW = "low"         # pattern matching only, but output can seed taint reasoning


class AnalysisDepth(str, Enum):
    """How deep is the analysis behind this capability?"""
    SYNTAX_ONLY = "syntax_only"                   # regex/grep/string match (APKHunt, Super)
    MANIFEST_PARSE = "manifest_parse"              # XML DOM/XPath attribute checks
    API_PRESENCE = "api_presence"                   # detects API call exists, no flow
    CONSTANT_BACKTRACK = "constant_backtrack"       # traces constant args to API calls (AndroBugs, Marvin SAAF, trueseeing)
    INTRA_PROCEDURAL = "intra_procedural"          # method-local flow/state tracking (QARK WebView defaults)
    INTER_PROCEDURAL = "inter_procedural"          # cross-method/class analysis (JAADAS IFDS)
    TAINT_ANALYSIS = "taint_analysis"              # full source-sink taint (JAADAS/SPECK FlowDroid)
    EXTERNAL_RESULT_INGEST = "external_result_ingest"  # consumes another tool's output (AUSERA)


class DetectionFamily(str, Enum):
    """Primary detection mechanism family."""
    # Manifest / config
    MANIFEST_ATTRIBUTE_CHECK = "manifest_attribute_check"
    MANIFEST_PERMISSION_CHECK = "manifest_permission_check"
    MANIFEST_COMPONENT_EXPORT = "manifest_component_export"
    NETWORK_SECURITY_CONFIG_PARSE = "network_security_config_parse"
    CONFIG_XML_PARSE = "config_xml_parse"

    # APK / binary level
    APK_FILE_INVENTORY = "apk_file_inventory"
    CERTIFICATE_PARSE = "certificate_parse"
    BINARY_METADATA_INSPECT = "binary_metadata_inspect"  # ELF checksec (MobSF)

    # Code pattern matching
    REGEX_TEXT_SCAN = "regex_text_scan"              # grep-style over source (APKHunt, Super)
    DEX_STRING_SCAN = "dex_string_scan"              # string table scan (AndroBugs)
    SMALI_INVOCATION_PATTERN = "smali_invocation_pattern"  # Smali opcode/invoke matching (trueseeing, droidstatx)
    API_CALL_XREF = "api_call_xref"                 # API method cross-reference (AndroBugs)
    JAVA_AST_MATCH = "java_ast_match"               # Java AST node matching (QARK)
    JIMPLE_PATTERN = "jimple_pattern"                # Soot Jimple body matching (AUSERA, JAADAS)

    # Deeper analysis
    CONSTANT_ARG_TRACE = "constant_arg_trace"        # backward trace to resolve constant args
    CLASS_HIERARCHY_CHECK = "class_hierarchy_check"   # interface impl / subclass check
    BACKWARD_DEF_USE_SLICE = "backward_def_use_slice" # SAAF-style backward slicing (Marvin)
    IFDS_CONSTANT_PROPAGATION = "ifds_constant_propagation"  # interprocedural (JAADAS)
    FLOWDROID_TAINT = "flowdroid_taint"              # FlowDroid source-sink (JAADAS, SPECK)
    FORWARD_INTENT_TAINT = "forward_intent_taint"    # custom intent taint (JAADAS)

    # Cross-artifact
    CROSS_ARTIFACT_HEURISTIC = "cross_artifact_heuristic"  # manifest + code combined
    SAME_FILE_COOCCURRENCE = "same_file_cooccurrence"      # two regex in same file (Super)
    LIBRARY_FINGERPRINT = "library_fingerprint"            # library presence/version (Marvin, trueseeing)

    # Enrichment
    EXTERNAL_TAINT_INGEST = "external_taint_ingest"   # FlowDroid/IccTA result consumption (AUSERA)
    STRING_ENTROPY_SCAN = "string_entropy_scan"       # secret detection (MobSF)
    RESOURCE_LABEL_MAPPING = "resource_label_mapping"  # UI label enrichment (AUSERA)


class EvidenceType(str, Enum):
    """What evidence does the tool provide with a finding?"""
    COMPONENT_NAME = "component_name"
    METHOD_SIGNATURE = "method_signature"
    CLASS_NAME = "class_name"
    FILE_PATH = "file_path"
    LINE_NUMBER = "line_number"
    CODE_SNIPPET = "code_snippet"
    CALL_PATH = "call_path"             # caller -> callee chain
    SOURCE_SINK_PAIR = "source_sink_pair"
    TAINT_PATH = "taint_path"           # full source-to-sink path
    MANIFEST_ATTRIBUTE = "manifest_attribute"
    PERMISSION_NAME = "permission_name"
    MATCHED_STRING = "matched_string"
    CONSTANT_VALUE = "constant_value"    # resolved constant (crypto key, cipher mode, etc.)
    DOMAIN_SCOPE = "domain_scope"
    CERTIFICATE_INFO = "certificate_info"
    LIBRARY_INFO = "library_info"
    EXPLOIT_METADATA = "exploit_metadata"  # QARK exploit APK
    WIDGET_LABEL = "widget_label"          # UI enrichment (AUSERA)
    DESCRIPTION_ONLY = "description_only"
    SCORE = "score"                        # numeric risk score


class Granularity(str, Enum):
    """At what level does the tool report findings?"""
    APP = "app"
    MANIFEST_ENTRY = "manifest_entry"
    COMPONENT = "component"
    CLASS = "class"
    METHOD = "method"
    STATEMENT = "statement"        # instruction/statement level
    FILE_LINE = "file_line"
    RESOURCE_ENTRY = "resource_entry"
    LIBRARY = "library"


class FPRisk(str, Enum):
    """False positive risk level for a capability."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ─────────────────── Core Data Structures ───────────────────

@dataclass
class DetectionMethod:
    """
    Structured representation of HOW a capability detects issues.
    All 11 reports agree: a single enum is insufficient.
    Many capabilities combine multiple methods (e.g., manifest + code check).
    """
    family: DetectionFamily
    depth: AnalysisDepth
    target_artifact: str = ""        # e.g., "manifest_xml", "decompiled_java", "smali", "jimple"
    target_apis: list[str] = field(default_factory=list)  # specific APIs targeted
    uses_sdk_condition: bool = False  # gated by minSdk/targetSdk
    uses_default_inference: bool = False  # flags absence of secure config (QARK WebView)
    notes: str = ""


@dataclass
class DetectionCapability:
    """
    One vulnerability/security category that a tool can detect.
    This is the core unit of the ToolPrior schema.
    """
    # Identity
    capability_id: str                 # unique ID within this tool
    category: str                      # human-readable category name
    subcategories: list[str] = field(default_factory=list)  # subtypes if applicable

    # Classification
    cwe_ids: list[str] = field(default_factory=list)
    signal_polarity: SignalPolarity = SignalPolarity.VULNERABILITY

    # Detection
    detection_methods: list[DetectionMethod] = field(default_factory=list)
    analysis_scope: list[str] = field(default_factory=list)  # ["manifest", "method", "cross_file", etc.]
    granularity: list[Granularity] = field(default_factory=list)

    # Evidence
    evidence_types: list[EvidenceType] = field(default_factory=list)
    severity_values: list[str] = field(default_factory=list)  # tool-native severity labels

    # Reliability assessment
    taint_relevance: TaintRelevance = TaintRelevance.LOW
    fp_risk: FPRisk = FPRisk.MEDIUM
    blind_spots: list[str] = field(default_factory=list)
    known_quirks: list[str] = field(default_factory=list)  # implementation bugs, swapped labels, etc.
    native_rule_ids: list[str] = field(default_factory=list)  # tool-native rule IDs

    # Activation conditions
    enabled_by_default: bool = True
    requires_external_input: bool = False     # needs another tool's output (AUSERA)
    api_level_conditions: list[str] = field(default_factory=list)  # e.g., "minSdk <= 16"


@dataclass
class ToolPrior:
    """
    Complete capability profile for one SAST tool.
    This is the top-level data structure persisted and used by the online module.
    """
    # ── Tool identity ──
    tool_name: str
    tool_version: str = ""
    repo_url: str = ""
    implementation_languages: list[str] = field(default_factory=list)
    last_maintained: str = ""        # ISO date string or "archived"
    maintenance_status: str = ""     # "active", "stale", "archived"

    # ── Analysis architecture ──
    input_formats: list[str] = field(default_factory=list)    # ["apk", "java_source", "smali", etc.]
    intermediate_representations: list[str] = field(default_factory=list)  # ["dalvik", "jimple", "java_ast", etc.]
    requires_decompilation: bool = False
    decompilation_tools: list[str] = field(default_factory=list)  # ["jadx", "apktool", "cfr", etc.]

    # ── Capabilities (the core) ──
    capabilities: list[DetectionCapability] = field(default_factory=list)

    # ── Output characteristics ──
    output_formats: list[str] = field(default_factory=list)   # ["json", "txt", "html", "xml", etc.]
    severity_scheme: list[str] = field(default_factory=list)   # tool-native severity levels
    has_confidence_score: bool = False
    has_numeric_risk_score: bool = False
    supports_positive_controls: bool = False  # can report "defense is present" (MobSF, SPECK)

    # ── Tool-level assessment ──
    taint_relevance: TaintRelevance = TaintRelevance.LOW
    overall_strengths: list[str] = field(default_factory=list)
    overall_limitations: list[str] = field(default_factory=list)
    implementation_reliability: str = "medium"  # "high", "medium", "low"

    # ── For online module weighting ──
    confidence_weight: float = 0.5   # initial weight, updated by feedback loop (0.0 - 1.0)
    # Per-CWE weights can be derived from capabilities, but we also store
    # aggregated overrides from feedback here:
    cwe_weight_overrides: dict[str, float] = field(default_factory=dict)

    # ── Metadata ──
    prior_version: str = "1.0"       # schema version
    extracted_at: str = ""           # ISO timestamp of when this prior was generated
    extraction_source: str = ""      # "codex_report", "manual", "llm_agent", etc.
