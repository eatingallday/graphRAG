"""
Node: SAST Tool Prior Fusion (lightweight deterministic version).
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from neo4j import GraphDatabase

from config import NEO4J_PASSWORD, NEO4J_URI, NEO4J_USER, TOOL_PRIORS_DIR
from state import AnalysisState
from tool_prior.alignment import align_findings
from tool_prior.finding_parser import detect_tool, parse_report
from tool_prior.fusion import FusedFinding, fuse_findings
from tool_prior.prior_store import load_all as load_priors
from utils.debug_logger import trace_event


def _ingest_reports(reports_dir: str) -> tuple[list, list[str]]:
    from tool_prior.finding_schema import NormalizedFinding

    all_findings: list[NormalizedFinding] = []
    tools_loaded: list[str] = []
    report_dir = Path(reports_dir)

    if not report_dir.exists():
        print(f"[sast_prior_node] Warning: reports dir not found: {reports_dir}")
        return all_findings, tools_loaded

    for file_path in sorted(report_dir.iterdir()):
        if file_path.name.startswith(".") or file_path.is_dir():
            continue
        try:
            tool = detect_tool(str(file_path))
            findings = parse_report(str(file_path), tool)
            all_findings.extend(findings)
            if tool not in tools_loaded:
                tools_loaded.append(tool)
            print(f"[sast_prior_node]   {file_path.name}: {len(findings)} findings ({tool})")
        except Exception as exc:
            print(f"[sast_prior_node]   Skip {file_path.name}: {exc}")

    return all_findings, tools_loaded


def _write_provenance(driver, fused: list[FusedFinding]) -> int:
    count = 0
    with driver.session() as session:
        for finding in fused:
            alignment = finding.alignment or {}
            session.run(
                """
                MERGE (sf:SASTFinding {id: $id})
                SET sf.tool_name = $tool,
                    sf.rule_id = $rule_id,
                    sf.title = $title,
                    sf.severity = $severity,
                    sf.fused_score = $score,
                    sf.signal_polarity = $polarity,
                    sf.cwe_ids = $cwes,
                    sf.capability_id = $cap_id,
                    sf.capability_taint_relevance = $tr,
                    sf.capability_analysis_depth = $depth,
                    sf.alignment_status = $al_st,
                    sf.alignment_method = $al_method,
                    sf.matched_node_type = $al_node_type,
                    sf.matched_node_id = $al_node_id,
                    sf.method_signature = $method_sig,
                    sf.class_name = $class_name,
                    sf.component_name = $component_name,
                    sf.corroboration_count = $corr,
                    sf.description = $desc
                """,
                id=finding.id,
                tool=finding.tool_name,
                rule_id=finding.rule_id,
                title=finding.title,
                severity=finding.severity,
                score=finding.fused_score,
                polarity=finding.signal_polarity,
                cwes=finding.cwe_ids,
                cap_id=finding.matched_capability_id,
                tr=finding.capability_taint_relevance,
                depth=finding.capability_analysis_depth,
                al_st=alignment.get("status", "unmatched"),
                al_method=alignment.get("alignment_method") or "",
                al_node_type=alignment.get("matched_node_type") or "",
                al_node_id=alignment.get("matched_node_id") or "",
                method_sig=finding.method_signature,
                class_name=finding.class_name,
                component_name=finding.component_name,
                corr=finding.corroboration_count,
                desc=(finding.description or "")[:500],
            )
            count += 1

            node_id = alignment.get("matched_node_id")
            if alignment.get("status") in ("aligned", "candidate") and node_id:
                node_type = alignment.get("matched_node_type")
                if node_type == "Component":
                    session.run(
                        """
                        MATCH (sf:SASTFinding {id:$sfid}), (c:Component {name:$nid})
                        MERGE (sf)-[:IMPLICATES]->(c)
                        """,
                        sfid=finding.id,
                        nid=node_id,
                    )
                elif node_type == "Method":
                    session.run(
                        """
                        MATCH (sf:SASTFinding {id:$sfid}), (m:Method {sig:$nid})
                        MERGE (sf)-[:IMPLICATES]->(m)
                        """,
                        sfid=finding.id,
                        nid=node_id,
                    )

    return count


def _enrich_aligned_nodes(driver, fused: list[FusedFinding]) -> int:
    from collections import defaultdict

    groups = defaultdict(list)
    for finding in fused:
        alignment = finding.alignment or {}
        if alignment.get("status") != "aligned":
            continue
        node_type = alignment.get("matched_node_type")
        node_id = alignment.get("matched_node_id")
        if node_type and node_id:
            groups[(node_type, node_id)].append(finding)

    enriched_nodes = 0
    with driver.session() as session:
        for (node_type, node_id), findings in groups.items():
            max_score = max(f.fused_score for f in findings)
            all_cwes = sorted({cwe for f in findings for cwe in f.cwe_ids})
            all_tools = sorted({f.tool_name for f in findings})
            finding_count = len(findings)

            if node_type == "Component":
                session.run(
                    """
                    MATCH (c:Component {name: $nid})
                    SET c.sast_fused_score = $score,
                        c.sast_cwes = $cwes,
                        c.sast_tools_flagged = $tools,
                        c.sast_finding_count = $count
                    """,
                    nid=node_id,
                    score=max_score,
                    cwes=all_cwes,
                    tools=all_tools,
                    count=finding_count,
                )
            elif node_type == "Method":
                session.run(
                    """
                    MATCH (m:Method {sig: $nid})
                    SET m.sast_fused_score = $score,
                        m.sast_cwes = $cwes,
                        m.sast_tools_flagged = $tools,
                        m.sast_finding_count = $count
                    """,
                    nid=node_id,
                    score=max_score,
                    cwes=all_cwes,
                    tools=all_tools,
                    count=finding_count,
                )
            else:
                continue

            for finding in findings:
                if node_type == "Component":
                    session.run(
                        """
                        MATCH (c:Component {name:$nid}), (sf:SASTFinding {id:$sfid})
                        MERGE (c)-[:EVIDENCED_BY]->(sf)
                        """,
                        nid=node_id,
                        sfid=finding.id,
                    )
                elif node_type == "Method":
                    session.run(
                        """
                        MATCH (m:Method {sig:$nid}), (sf:SASTFinding {id:$sfid})
                        MERGE (m)-[:EVIDENCED_BY]->(sf)
                        """,
                        nid=node_id,
                        sfid=finding.id,
                    )

            enriched_nodes += 1

    return enriched_nodes


def _write_hints(fused: list[FusedFinding], driver) -> dict:
    sink_cwes = {"CWE-200", "CWE-532", "CWE-312", "CWE-319", "CWE-921"}
    source_cwes = {"CWE-926", "CWE-927", "CWE-925"}

    method_hints = []
    component_hints = []
    hints_written = 0

    with driver.session() as session:
        for finding in fused:
            alignment = finding.alignment or {}
            if alignment.get("status") not in ("aligned", "candidate"):
                continue

            node_type = alignment.get("matched_node_type")
            node_id = alignment.get("matched_node_id")
            if not node_id:
                continue

            if node_type == "Method" and finding.capability_taint_relevance in ("high", "medium"):
                cwe_set = set(finding.cwe_ids)
                if cwe_set & sink_cwes:
                    hint_type = "potential_sink"
                elif cwe_set & source_cwes:
                    hint_type = "potential_source"
                else:
                    hint_type = "potential_taint_relevant"

                session.run(
                    """
                    MATCH (m:Method {sig: $sig})
                    WHERE m.sast_hint_score IS NULL OR m.sast_hint_score < $score
                    SET m.sast_taint_hint = $hint,
                        m.sast_hint_score = $score,
                        m.sast_hint_tool = $tool
                    """,
                    sig=node_id,
                    hint=hint_type,
                    score=finding.fused_score,
                    tool=finding.tool_name,
                )
                method_hints.append(
                    {
                        "sig": node_id,
                        "hint_type": hint_type,
                        "score": finding.fused_score,
                        "tool": finding.tool_name,
                    }
                )
                hints_written += 1
                continue

            priority = "high" if finding.fused_score > 0.3 else "medium"
            hint_text = f"SAST({finding.tool_name}) flagged for {finding.title}"
            if node_type == "Component":
                session.run(
                    """
                    MATCH (c:Component {name: $nid})
                    WHERE c.sast_search_priority IS NULL
                          OR ($priority = 'high' AND c.sast_search_priority <> 'high')
                    SET c.sast_search_priority = $priority,
                        c.sast_hint_text = $hint
                    """,
                    nid=node_id,
                    priority=priority,
                    hint=hint_text[:500],
                )
            elif node_type == "Method":
                session.run(
                    """
                    MATCH (m:Method {sig: $nid})
                    WHERE m.sast_search_priority IS NULL
                          OR ($priority = 'high' AND m.sast_search_priority <> 'high')
                    SET m.sast_search_priority = $priority,
                        m.sast_hint_text = $hint
                    """,
                    nid=node_id,
                    priority=priority,
                    hint=hint_text[:500],
                )
            else:
                continue

            component_hints.append(
                {
                    "target": node_id,
                    "node_type": node_type or "",
                    "fused_score": finding.fused_score,
                    "cwes": finding.cwe_ids,
                    "hint_text": hint_text,
                }
            )
            hints_written += 1

    return {
        "method_hints": method_hints,
        "component_hints": component_hints,
        "hints_written": hints_written,
    }


def run_sast_prior_node(state: AnalysisState) -> dict:
    print("[sast_prior_node] Starting SAST Tool Prior Fusion ...")

    reports_dir = state.get("sast_reports_dir", "")
    trace_event(
        "sast_prior_start",
        {"reports_dir": reports_dir, "apk_name": state.get("apk_name", "")},
        agent="sast_prior_node",
    )
    if not reports_dir:
        print("[sast_prior_node] No sast_reports_dir, skipping.")
        trace_event("sast_prior_skipped", {"reason": "missing_reports_dir"}, agent="sast_prior_node")
        return {"sast_prior_result": {"status": "skipped"}}

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        all_findings, tools_loaded = _ingest_reports(reports_dir)
        print(
            f"[sast_prior_node] Ingested {len(all_findings)} findings from {len(tools_loaded)} tools"
        )
        if not all_findings:
            trace_event(
                "sast_prior_no_findings",
                {"tools_loaded": tools_loaded},
                agent="sast_prior_node",
            )
            return {"sast_prior_result": {"status": "no_findings", "tools_loaded": tools_loaded}}

        priors = load_priors(TOOL_PRIORS_DIR)
        fused = fuse_findings(all_findings, priors)
        if fused:
            print(
                f"[sast_prior_node] Fused {len(fused)} findings, top score: {fused[0].fused_score:.3f}"
            )
        else:
            print("[sast_prior_node] Fused 0 findings")

        align_findings(fused, driver)
        aligned = sum(1 for f in fused if (f.alignment or {}).get("status") == "aligned")
        candidate = sum(1 for f in fused if (f.alignment or {}).get("status") == "candidate")
        unmatched = sum(1 for f in fused if (f.alignment or {}).get("status") == "unmatched")
        print(
            "[sast_prior_node] Alignment: "
            f"aligned={aligned}, candidate={candidate}, unmatched={unmatched}"
        )

        provenance_nodes = _write_provenance(driver, fused)
        print(f"[sast_prior_node] Wrote {provenance_nodes} SASTFinding provenance nodes")

        enriched_nodes = _enrich_aligned_nodes(driver, fused)
        print(f"[sast_prior_node] Enriched {enriched_nodes} HPG nodes")

        hint_result = _write_hints(fused, driver)
        print(
            "[sast_prior_node] Hints written: "
            f"{hint_result['hints_written']} "
            f"(method_hints={len(hint_result['method_hints'])}, "
            f"component_hints={len(hint_result['component_hints'])})"
        )
        trace_event(
            "sast_prior_done",
            {
                "tools_loaded": tools_loaded,
                "total_findings": len(all_findings),
                "total_fused": len(fused),
                "aligned": aligned,
                "candidate": candidate,
                "unmatched": unmatched,
                "provenance_nodes": provenance_nodes,
                "enriched_nodes": enriched_nodes,
                "hints_written": hint_result["hints_written"],
            },
            agent="sast_prior_node",
        )
    finally:
        driver.close()

    return {
        "sast_prior_result": {
            "status": "success",
            "tools_loaded": tools_loaded,
            "stats": {
                "total_findings": len(all_findings),
                "total_fused": len(fused),
                "aligned": aligned,
                "candidate": candidate,
                "unmatched": unmatched,
                "provenance_nodes": provenance_nodes,
                "enriched_nodes": enriched_nodes,
                "hints_written": hint_result["hints_written"],
            },
            "method_hints": hint_result["method_hints"],
            "component_hints": hint_result["component_hints"],
            "fused_findings_summary": [
                {
                    "id": finding.id,
                    "tool": finding.tool_name,
                    "title": finding.title,
                    "score": round(finding.fused_score, 3),
                    "depth": finding.capability_analysis_depth,
                    "alignment": (finding.alignment or {}).get("status"),
                    "node": (finding.alignment or {}).get("matched_node_id"),
                }
                for finding in fused[:50]
            ],
        }
    }
