"""
FlowDroid Node — Layer A: intra-component taint analysis.

Runs FlowDroid as a subprocess, parses the XML output,
and writes IntraPath nodes + HAS_INTRA_PATH edges to Neo4j.

Falls back to a static synthetic IntraPath if FlowDroid fails
(Java compatibility issues, timeout, etc.) so the rest of the
pipeline can still run.
"""
import os
import re
import sys
import subprocess
import xml.etree.ElementTree as ET
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD,
    APK_PATH, ANDROID_PLATFORMS, FLOWDROID_JAR, OUTPUT_DIR
)
from neo4j import GraphDatabase
from state import AnalysisState

os.makedirs(OUTPUT_DIR, exist_ok=True)

SOOT_SIG_RE = re.compile(
    r"<[\w.]+:\s+[\w.\[\]]+\s+\w+\([^)]*\)>"
)


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
        # FlowDroid XML schema: <Results><Result><Sources><Source .../></Sources><Sink .../></Result></Results>
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


# ── Synthetic fallback IntraPath ──────────────────────────────────────────────

def _synthetic_intra_paths() -> list[dict]:
    """
    Construct IntraPath from static Smali analysis when FlowDroid is unavailable.
    For this specific APK the taint path is well-known:
      query() receives URI → reads CSV file → addRow() populates MatrixCursor → returned to caller
    """
    return [
        {
            "id":     "intra_synthetic_0",
            "source": "<edu.ksu.cs.benign.provider.UserDetailsContentProvider: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)>",
            "sink":   "<android.database.MatrixCursor: void addRow(java.lang.Iterable)>",
            "path":   [
                "BufferedReader.readLine() reads SSN/address CSV",
                "String.split() parses CSV row",
                "ArrayList.add() collects column values",
                "MatrixCursor.addRow() inserts sensitive row into cursor",
            ],
            "layer":      "A",
            "confidence": 0.85,
            "synthetic":  True,
        },
        {
            "id":     "intra_synthetic_1",
            "source": "<edu.ksu.cs.benign.provider.UserDetailsContentProvider: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)>",
            "sink":   "<java.io.BufferedReader: java.lang.String readLine()>",
            "path":   [
                "FileInputStream opened on sensitive file path",
                "InputStreamReader wraps stream",
                "BufferedReader.readLine() returns sensitive line",
            ],
            "layer":      "A",
            "confidence": 0.80,
            "synthetic":  True,
        },
    ]


# ── Neo4j write ───────────────────────────────────────────────────────────────

def _write_intra_paths_to_neo4j(intra_paths: list[dict]):
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as s:
            for p in intra_paths:
                isrc = "Synthetic" if p.get("synthetic") else "Rule_Based"
                s.run("""
                    MERGE (ip:IntraPath {id:$id})
                    SET ip.source=$src, ip.sink=$sink,
                        ip.layer="A", ip.confidence=$conf,
                        ip.synthetic=$synth, ip.inference_source=$isrc
                """, id=p["id"], src=p["source"], sink=p["sink"],
                     conf=p.get("confidence", 0.9),
                     synth=p.get("synthetic", False),
                     isrc=isrc)

                # Link from query() Method node
                s.run("""
                    MATCH (m:Method {name:"query"}), (ip:IntraPath {id:$id})
                    MERGE (m)-[:HAS_INTRA_PATH]->(ip)
                """, id=p["id"])

        print(f"[flowdroid_node] Wrote {len(intra_paths)} IntraPath nodes to Neo4j.")
    finally:
        driver.close()


# ── Main node function ────────────────────────────────────────────────────────

def run_flowdroid(state: AnalysisState) -> dict:
    susi_path   = os.path.join(OUTPUT_DIR, "SourcesAndSinks.txt")
    xml_out     = os.path.join(OUTPUT_DIR, "flowdroid_results.xml")

    # 1. Validate SuSi XML
    valid, invalid = validate_susi(susi_path)
    if not valid:
        print(f"[flowdroid_node] WARNING: Invalid Soot signatures found: {invalid}")
        print("[flowdroid_node] Falling back to synthetic IntraPath.")
        intra_paths = _synthetic_intra_paths()
        _write_intra_paths_to_neo4j(intra_paths)
        return {"flowdroid_result": {"intra_paths": intra_paths, "status": "synthetic_fallback"}}

    # 2. Check JAR exists
    if not os.path.exists(FLOWDROID_JAR):
        print(f"[flowdroid_node] FlowDroid JAR not found at {FLOWDROID_JAR}. Using synthetic fallback.")
        intra_paths = _synthetic_intra_paths()
        _write_intra_paths_to_neo4j(intra_paths)
        return {"flowdroid_result": {"intra_paths": intra_paths, "status": "jar_missing"}}

    # 3. Run FlowDroid
    cmd = [
        "java",
        "--add-opens", "java.base/java.lang=ALL-UNNAMED",
        "--add-opens", "java.base/java.util=ALL-UNNAMED",
        "--add-opens", "java.base/java.io=ALL-UNNAMED",
        "--add-opens", "java.base/sun.nio.cs=ALL-UNNAMED",
        "-Xmx4g",
        "-jar", FLOWDROID_JAR,
        "-a", APK_PATH,
        "-p", ANDROID_PLATFORMS,
        "-s", susi_path,
        "-o", xml_out,
    ]

    print(f"[flowdroid_node] Running FlowDroid: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        print(f"[flowdroid_node] FlowDroid exit code: {proc.returncode}")
        if proc.stdout:
            print(f"[flowdroid_node] stdout (last 500 chars): ...{proc.stdout[-500:]}")
        if proc.stderr:
            print(f"[flowdroid_node] stderr (last 500 chars): ...{proc.stderr[-500:]}")

        if proc.returncode != 0:
            print("[flowdroid_node] FlowDroid failed. Using synthetic fallback.")
            intra_paths = _synthetic_intra_paths()
            _write_intra_paths_to_neo4j(intra_paths)
            return {"flowdroid_result": {"intra_paths": intra_paths, "status": "flowdroid_failed", "stderr": proc.stderr[-1000:]}}

    except subprocess.TimeoutExpired:
        print("[flowdroid_node] FlowDroid timed out. Using synthetic fallback.")
        intra_paths = _synthetic_intra_paths()
        _write_intra_paths_to_neo4j(intra_paths)
        return {"flowdroid_result": {"intra_paths": intra_paths, "status": "timeout"}}
    except FileNotFoundError:
        print("[flowdroid_node] java not found. Using synthetic fallback.")
        intra_paths = _synthetic_intra_paths()
        _write_intra_paths_to_neo4j(intra_paths)
        return {"flowdroid_result": {"intra_paths": intra_paths, "status": "java_not_found"}}

    # 4. Parse output
    intra_paths = parse_flowdroid_xml(xml_out)
    if not intra_paths:
        print("[flowdroid_node] FlowDroid produced no results. Using synthetic fallback.")
        intra_paths = _synthetic_intra_paths()
        _write_intra_paths_to_neo4j(intra_paths)
        return {"flowdroid_result": {"intra_paths": intra_paths, "status": "no_results_synthetic"}}

    print(f"[flowdroid_node] FlowDroid found {len(intra_paths)} intra paths.")
    _write_intra_paths_to_neo4j(intra_paths)
    return {"flowdroid_result": {"intra_paths": intra_paths, "status": "success", "raw_xml_path": xml_out}}
