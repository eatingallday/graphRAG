"""
FlowDroid Node — Layer A: intra-component taint analysis.

Runs FlowDroid as a subprocess, parses the XML output,
and writes IntraPath nodes + HAS_INTRA_PATH edges to Neo4j.

Falls back to dynamic synthetic IntraPath (built from taint_agent's
sources/sinks) if FlowDroid fails or produces no results.
"""
import os
import re
import sys
import subprocess
import xml.etree.ElementTree as ET
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD,
    ANDROID_PLATFORMS, FLOWDROID_JAR, OUTPUT_DIR
)
from neo4j import GraphDatabase
from state import AnalysisState
from utils.debug_logger import log_file_output, trace_event

import glob as _glob

os.makedirs(OUTPUT_DIR, exist_ok=True)

SOOT_SIG_RE = re.compile(
    r"<[\w.]+:\s+[\w.\[\]]+\s+\w+\([^)]*\)>"
)


# ── APK discovery ────────────────────────────────────────────────────────────

def _find_apk(analysis_dir: str) -> str | None:
    """
    Find the .apk file from analysis_dir.
    Convention: APK sits in the parent directory of analysis/.
    e.g. Ghera/<type>/<name>/<name>.apk  with analysis/ alongside it.
    """
    parent = os.path.dirname(analysis_dir.rstrip("/"))
    apks = _glob.glob(os.path.join(parent, "*.apk"))
    if apks:
        return apks[0]
    # Also check analysis_dir itself (edge case)
    apks = _glob.glob(os.path.join(analysis_dir, "*.apk"))
    return apks[0] if apks else None


# ── SuSi XML validator ────────────────────────────────────────────────────────

def validate_susi(susi_path: str) -> tuple[bool, list[str]]:
    invalid = []
    if not os.path.exists(susi_path):
        return False, [f"File not found: {susi_path}"]
    with open(susi_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("<"):
                sig = line.split("->")[0].strip()
                if not SOOT_SIG_RE.match(sig):
                    invalid.append(line)
    return len(invalid) == 0, invalid


# ── FlowDroid XML parser ──────────────────────────────────────────────────────

def parse_flowdroid_xml(xml_path: str) -> list[dict]:
    if not os.path.exists(xml_path):
        return []
    try:
        tree = ET.parse(xml_path)
        results = []
        for result in tree.findall(".//Result"):
            sink_elem = result.find("Sink")
            sink_stmt = sink_elem.get("Statement", "") if sink_elem is not None else ""
            sink_method = sink_elem.get("Method", "") if sink_elem is not None else ""
            for src in result.findall(".//Source"):
                src_stmt   = src.get("Statement", "")
                src_method = src.get("Method", "")
                path_elems = [p.get("Statement", "") for p in result.findall(".//PathElement")]
                results.append({
                    "id":     f"intra_{len(results)}",
                    "source": src_method or src_stmt,
                    "sink":   sink_method or sink_stmt,
                    "path":   path_elems,
                    "layer":  "A",
                    "confidence": 0.9,
                })
        return results
    except ET.ParseError as e:
        print(f"[flowdroid_node] XML parse error: {e}")
        return []


# ── Dynamic synthetic fallback ────────────────────────────────────────────────

def _synthetic_intra_paths_from_taint(state: AnalysisState) -> list[dict]:
    """
    Build synthetic IntraPath from taint_agent's discovered sources and sinks.
    Pairs each source with each sink within the same component to form
    candidate intra-component paths.
    """
    taint = state.get("taint_result") or {}
    sources = taint.get("sources", [])
    sinks = taint.get("sinks", [])

    if not sources or not sinks:
        print("[flowdroid_node] No sources or sinks from taint_agent — no synthetic paths.")
        return []

    # Extract component name from Soot sig: <com.foo.Bar: ...> → com.foo.Bar
    def _comp(sig: str) -> str:
        m = re.match(r"<([\w.$]+):", sig)
        return m.group(1) if m else ""

    paths = []
    idx = 0
    for src in sources:
        src_sig = src if isinstance(src, str) else src.get("sig", "")
        if not src_sig:
            continue
        src_comp = _comp(src_sig)
        for sink in sinks:
            sink_sig = sink if isinstance(sink, str) else sink.get("sig", "")
            if not sink_sig:
                continue
            # Pair sources and sinks — prefer same-component, but also allow cross
            paths.append({
                "id": f"intra_synthetic_{idx}",
                "source": src_sig,
                "sink": sink_sig,
                "path": [f"Synthetic: {src_sig} → {sink_sig}"],
                "layer": "A",
                "confidence": 0.70 if _comp(sink_sig) == src_comp else 0.50,
                "synthetic": True,
            })
            idx += 1

    # Cap at 20 pairs to avoid explosion
    if len(paths) > 20:
        paths.sort(key=lambda p: p["confidence"], reverse=True)
        paths = paths[:20]

    print(f"[flowdroid_node] Built {len(paths)} synthetic IntraPath from taint sources/sinks.")
    return paths


# ── Neo4j write ───────────────────────────────────────────────────────────────

def _write_intra_paths_to_neo4j(intra_paths: list[dict]):
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as s:
            for p in intra_paths:
                isrc = "Synthetic" if p.get("synthetic") else "FlowDroid"
                s.run("""
                    MERGE (ip:IntraPath {id:$id})
                    SET ip.source=$src, ip.sink=$sink,
                        ip.path=$path,
                        ip.layer="A", ip.confidence=$conf,
                        ip.synthetic=$synth, ip.inference_source=$isrc
                """, id=p["id"], src=p["source"], sink=p["sink"],
                     path=p.get("path", []),
                     conf=p.get("confidence", 0.9),
                     synth=p.get("synthetic", False),
                     isrc=isrc)

                # Link source Method → IntraPath via HAS_INTRA_PATH
                # Match by sig (exact) or by name extracted from sig
                src_sig = p["source"]
                name_m = re.search(r":\s+[\w.\[\]]+\s+(\w+)\(", src_sig)
                src_name = name_m.group(1) if name_m else ""

                if SOOT_SIG_RE.match(src_sig):
                    s.run("""
                        MATCH (m:Method {sig:$sig}), (ip:IntraPath {id:$id})
                        MERGE (m)-[:HAS_INTRA_PATH]->(ip)
                    """, sig=src_sig, id=p["id"])
                elif src_name:
                    s.run("""
                        MATCH (m:Method {name:$name}), (ip:IntraPath {id:$id})
                        MERGE (m)-[:HAS_INTRA_PATH]->(ip)
                    """, name=src_name, id=p["id"])

        print(f"[flowdroid_node] Wrote {len(intra_paths)} IntraPath nodes to Neo4j.")
        trace_event(
            "flowdroid_intra_written",
            {"count": len(intra_paths), "sample_ids": [p.get("id") for p in intra_paths[:10]]},
            agent="flowdroid_node",
        )
    finally:
        driver.close()


# ── Main node function ────────────────────────────────────────────────────────

def run_flowdroid(state: AnalysisState) -> dict:
    susi_path   = os.path.join(OUTPUT_DIR, "SourcesAndSinks.txt")
    xml_out     = os.path.join(OUTPUT_DIR, "flowdroid_results.xml")

    # Resolve APK path dynamically from analysis_dir
    analysis_dir = state.get("analysis_dir", "")
    apk_path = _find_apk(analysis_dir) if analysis_dir else None
    trace_event(
        "flowdroid_start",
        {
            "analysis_dir": analysis_dir,
            "apk_path": apk_path,
            "susi_path": susi_path,
            "xml_out": xml_out,
        },
        agent="flowdroid_node",
    )

    def _fallback(status: str, extra: dict | None = None):
        intra_paths = _synthetic_intra_paths_from_taint(state)
        _write_intra_paths_to_neo4j(intra_paths)
        result = {"intra_paths": intra_paths, "status": status}
        if extra:
            result.update(extra)
        trace_event(
            "flowdroid_fallback",
            {"status": status, "extra": extra or {}, "intra_count": len(intra_paths)},
            agent="flowdroid_node",
        )
        return {"flowdroid_result": result}

    # 1. Validate SuSi XML
    valid, invalid = validate_susi(susi_path)
    log_file_output(susi_path, label="susi_sources_sinks", agent="flowdroid_node")
    if not valid:
        print(f"[flowdroid_node] WARNING: Invalid Soot signatures found: {invalid}")
        print("[flowdroid_node] Falling back to synthetic IntraPath.")
        trace_event("flowdroid_susi_invalid", {"invalid_lines": invalid}, agent="flowdroid_node")
        return _fallback("synthetic_fallback")

    # 2. Check APK exists
    if not apk_path:
        print(f"[flowdroid_node] APK file not found near {analysis_dir}. Using synthetic fallback.")
        return _fallback("apk_missing")

    # 3. Check JAR exists
    if not os.path.exists(FLOWDROID_JAR):
        print(f"[flowdroid_node] FlowDroid JAR not found at {FLOWDROID_JAR}. Using synthetic fallback.")
        return _fallback("jar_missing")

    # 4. Run FlowDroid
    cmd = [
        "java",
        "--add-opens", "java.base/java.lang=ALL-UNNAMED",
        "--add-opens", "java.base/java.util=ALL-UNNAMED",
        "--add-opens", "java.base/java.io=ALL-UNNAMED",
        "--add-opens", "java.base/sun.nio.cs=ALL-UNNAMED",
        "-Xmx4g",
        "-jar", FLOWDROID_JAR,
        "-a", apk_path,
        "-p", ANDROID_PLATFORMS,
        "-s", susi_path,
        "-o", xml_out,
    ]

    print(f"[flowdroid_node] Running FlowDroid: {' '.join(cmd)}")
    trace_event("flowdroid_command", {"cmd": cmd}, agent="flowdroid_node")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        print(f"[flowdroid_node] FlowDroid exit code: {proc.returncode}")
        if proc.stdout:
            print(f"[flowdroid_node] stdout (last 500 chars): ...{proc.stdout[-500:]}")
        if proc.stderr:
            print(f"[flowdroid_node] stderr (last 500 chars): ...{proc.stderr[-500:]}")

        if proc.returncode != 0:
            print("[flowdroid_node] FlowDroid failed. Using synthetic fallback.")
            trace_event(
                "flowdroid_failed",
                {"returncode": proc.returncode, "stderr_tail": proc.stderr[-1000:]},
                agent="flowdroid_node",
            )
            return _fallback("flowdroid_failed", {"stderr": proc.stderr[-1000:]})

    except subprocess.TimeoutExpired:
        print("[flowdroid_node] FlowDroid timed out. Using synthetic fallback.")
        return _fallback("timeout")
    except FileNotFoundError:
        print("[flowdroid_node] java not found. Using synthetic fallback.")
        return _fallback("java_not_found")

    # 5. Parse output
    intra_paths = parse_flowdroid_xml(xml_out)
    log_file_output(xml_out, label="flowdroid_xml", agent="flowdroid_node")
    if not intra_paths:
        print("[flowdroid_node] FlowDroid produced no results. Using synthetic fallback.")
        return _fallback("no_results_synthetic")

    print(f"[flowdroid_node] FlowDroid found {len(intra_paths)} intra paths.")
    _write_intra_paths_to_neo4j(intra_paths)
    trace_event(
        "flowdroid_success",
        {"intra_count": len(intra_paths), "xml_out": xml_out},
        agent="flowdroid_node",
    )
    return {"flowdroid_result": {"intra_paths": intra_paths, "status": "success", "raw_xml_path": xml_out}}
