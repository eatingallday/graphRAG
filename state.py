"""
LangGraph shared state — the "working memory" passed between nodes.
"""
from typing import TypedDict, Optional


class AnalysisState(TypedDict):
    # ── Input ────────────────────────────────────────────────────────────────
    apk_name:     str
    analysis_dir: Optional[str]  # APK 产物目录路径，供 ui_semantic_agent 等读取文件系统的 agent 使用
    sast_reports_dir: Optional[str]
    manifest_xml: str
    app_smali:    dict   # {class_name: smali_content}
    app_java:     dict   # {class_name: java_content} (may be empty)

    # ── Agent results ─────────────────────────────────────────────────────────
    manifest_result:    Optional[dict]
    # keys: exported_providers, attack_surface, root_path_protected,
    #        vulnerability, confidence

    taint_result:       Optional[dict]
    # keys: sources, sinks, susi_confidence, needs_semantic_analysis,
    #        susi_path

    semantic_result:    Optional[dict]
    # keys: semantic_findings, revised_paths, confidence_updated

    flowdroid_result:   Optional[dict]
    # keys: intra_paths (list), raw_xml_path, status

    ui_semantic_result: Optional[dict]
    # keys: total_views (int), sensitive_views (list[dict]), status (str)

    icc_bridge_result:  Optional[dict]
    # keys: cross_paths (list), status

    validation_result:  Optional[dict]
    # keys: cypher_queries, final_verdict, exploitable, evidence_chain

    sast_prior_result: Optional[dict]
    # keys: status, tools_loaded, stats, method_hints, component_hints,
    #        fused_findings_summary

    # ── Output ────────────────────────────────────────────────────────────────
    final_report: Optional[str]
