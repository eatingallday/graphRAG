"""
Entry point for the LangGraph + Neo4j GraphRAG analysis pipeline.

Usage:
    cd analysis-pipeline
    python main.py

Pre-requisites:
    - Neo4j running: docker run -d --name neo4j-ghera -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password123 neo4j:5
    - conda activate graph-vuls
    - APK decompiled into ../analysis/  (done via apktool)
"""
import os
import sys
import time

# Add pipeline root to path so all modules resolve correctly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, ANALYSIS_DIR, OUTPUT_DIR
from hpg.builder import build_hpg
from utils.file_loader import load_apk_artifacts


def wait_for_neo4j(max_retries: int = 10, delay: float = 3.0):
    """Poll until Neo4j is accepting connections."""
    from neo4j import GraphDatabase
    from neo4j.exceptions import ServiceUnavailable

    for i in range(max_retries):
        try:
            driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
            driver.verify_connectivity()
            driver.close()
            print(f"[main] Neo4j is ready ({NEO4J_URI})")
            return
        except (ServiceUnavailable, Exception) as e:
            print(f"[main] Waiting for Neo4j... ({i+1}/{max_retries}) — {e}")
            time.sleep(delay)
    raise RuntimeError("Neo4j did not become ready in time. Check: docker ps")


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=" * 60)
    print("  LangGraph + Neo4j GraphRAG — Android APK Security Analysis")
    print("=" * 60)

    # Step 1: Verify Neo4j connectivity
    wait_for_neo4j()

    # Step 2: Load APK artifacts from analysis/ directory
    print("\n[main] Loading APK artifacts ...")
    manifest_xml, app_smali, app_java = load_apk_artifacts(ANALYSIS_DIR)
    print(f"[main] Loaded manifest ({len(manifest_xml)} chars), "
          f"{len(app_smali)} smali files, {len(app_java)} java files")

    # Step 3: Build initial HPG in Neo4j
    print("\n[main] Building initial HPG in Neo4j ...")
    build_hpg(smali_map=app_smali)
    print("[main] HPG construction complete. Visit http://localhost:7474 to inspect.")

    # Step 4: Run LangGraph pipeline
    print("\n[main] Starting LangGraph pipeline ...")
    from graph import app

    initial_state = {
        "apk_name":         "InadequatePathPermission-InformationExposure-Lean-benign",
        "manifest_xml":     manifest_xml,
        "app_smali":        app_smali,
        "app_java":         app_java,
        "manifest_result":  None,
        "taint_result":     None,
        "semantic_result":  None,
        "flowdroid_result": None,
        "icc_bridge_result":None,
        "validation_result":None,
        "final_report":     None,
    }

    final_state = app.invoke(initial_state)

    # Step 5: Print summary
    print("\n" + "=" * 60)
    print("  ANALYSIS COMPLETE")
    print("=" * 60)

    val = final_state.get("validation_result") or {}
    print(f"\nExploitable : {val.get('exploitable', 'N/A')}")
    print(f"Severity    : {val.get('severity', 'N/A')}")
    print(f"CWE         : {val.get('cwe', 'N/A')}")
    print(f"\nVerdict:\n{val.get('final_verdict', 'N/A')}")

    report_path = os.path.join(OUTPUT_DIR, "report.md")
    dump_path   = os.path.join(OUTPUT_DIR, "state_dump.json")
    print(f"\nReport  : {report_path}")
    print(f"Dump    : {dump_path}")
    print(f"Neo4j   : http://localhost:7474")

    return final_state


if __name__ == "__main__":
    main()
