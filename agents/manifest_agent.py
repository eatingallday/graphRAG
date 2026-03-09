"""
Node 1: Manifest Agent
- Calls Qwen to analyze AndroidManifest.xml
- Writes Component node attributes to Neo4j (shared blackboard)
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, PROMPTS_DIR
from utils.llm_client import llm_call
from neo4j import GraphDatabase
from state import AnalysisState


def _load_prompt(name: str) -> str:
    path = os.path.join(PROMPTS_DIR, name)
    with open(path, encoding="utf-8") as f:
        return f.read()


def run_manifest_agent(state: AnalysisState) -> dict:
    print("[manifest_agent] Analyzing AndroidManifest.xml ...")

    system = _load_prompt("manifest_system.md")
    user   = f"分析以下 AndroidManifest.xml，识别权限配置漏洞：\n\n{state['manifest_xml']}"

    result = llm_call(system, user, json_mode=True)
    print(f"[manifest_agent] LLM result: {result}")

    # ── Write to Neo4j (shared blackboard) ───────────────────────────────
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as s:
            for provider_name in result.get("exported_providers", []):
                # Use short name (last segment)
                short = provider_name.split(".")[-1]
                s.run("""
                    MATCH (c:Component {name:$name})
                    SET c.vuln_description    = $vuln,
                        c.root_path_protected = $rpp,
                        c.analysis_confidence = $conf
                """,
                name=short,
                vuln=result.get("vulnerability", ""),
                rpp=result.get("root_path_protected", False),
                conf=result.get("confidence", 0.0))
                print(f"[manifest_agent] Updated Neo4j for component: {short}")
    finally:
        driver.close()

    return {"manifest_result": result}
