"""
Entry point for the LangGraph + Neo4j GraphRAG analysis pipeline.

Usage:
    python main.py                                              # 使用 config.py 默认路径
    python main.py --apk analysis/ActivityCommunication1       # 相对路径
    python main.py --apk /abs/path --output /abs/output

Pre-requisites:
    - Neo4j running: docker run -d --name neo4j-ghera -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password123 neo4j:5
    - conda activate graph-vuls
    - APK decompiled into analysis/<apk_name>/apktool/ and analysis/<apk_name>/jadx/
"""
import os
import sys
import time
import argparse

# Add pipeline root to path so all modules resolve correctly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, ANALYSIS_DIR, OUTPUT_DIR


def parse_args():
    parser = argparse.ArgumentParser(description="Android APK Security Analysis Pipeline")
    parser.add_argument("--apk", default=None,
                        help="APK 分析目录（含 apktool/ 和 jadx/ 子目录）")
    parser.add_argument("--output", default=None,
                        help="输出目录（默认: analysis-pipeline/output/）")
    return parser.parse_args()


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
    raise RuntimeError("Neo4j did not become ready. Check: docker ps")


def main():
    args = parse_args()
    analysis_dir = os.path.abspath(args.apk)    if args.apk    else ANALYSIS_DIR
    output_dir   = os.path.abspath(args.output) if args.output else OUTPUT_DIR
    apk_name     = os.path.basename(analysis_dir)

    os.makedirs(output_dir, exist_ok=True)

    print("=" * 60)
    print("  LangGraph + Neo4j GraphRAG — Android APK Security Analysis")
    print(f"  Target : {analysis_dir}")
    print(f"  APK    : {apk_name}")
    print("=" * 60)

    # Step 1: Verify Neo4j connectivity
    wait_for_neo4j()

    from utils.file_loader import load_apk_artifacts
    from hpg.builder import build_hpg

    # Step 2: Load APK artifacts from analysis/ directory
    print("\n[main] Loading APK artifacts ...")
    manifest_xml, app_smali, app_java = load_apk_artifacts(analysis_dir)
    print(f"[main] Loaded: {len(app_smali)} smali, {len(app_java)} java files")

    # Step 3: Build initial HPG in Neo4j
    print("\n[main] Building HPG in Neo4j ...")
    build_hpg(analysis_dir=analysis_dir, smali_map=app_smali)

    # Step 4: Run LangGraph pipeline
    print("\n[main] Starting LangGraph pipeline ...")
    from graph import app

    initial_state = {
        "apk_name":           apk_name,
        "analysis_dir":       analysis_dir,
        "manifest_xml":       manifest_xml,
        "app_smali":          app_smali,
        "app_java":           app_java,
        "manifest_result":    None,
        "ui_semantic_result": None,
        "taint_result":       None,
        "semantic_result":    None,
        "flowdroid_result":   None,
        "icc_bridge_result":  None,
        "validation_result":  None,
        "final_report":       None,
    }

    final_state = app.invoke(initial_state)

    # Step 5: Print summary
    print("\n" + "=" * 60)
    print("  ANALYSIS COMPLETE")
    print("=" * 60)

    val = final_state.get("validation_result") or {}
    print(f"\nExploitable : {val.get('exploitable', 'N/A')}")
    print(f"Verdict     :\n{val.get('final_verdict', 'N/A')}")
    print(f"\nReport : {os.path.join(output_dir, 'report.md')}")
    print(f"Neo4j  : http://localhost:7474")

    return final_state


if __name__ == "__main__":
    main()
