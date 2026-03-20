"""
Node 3: Semantic Agent (conditionally triggered)
- Reads low-confidence taint paths from Neo4j
- Calls Qwen to do deeper semantic analysis of Smali
- Updates TaintPath / Method confidence in Neo4j
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, PROMPTS_DIR, load_graph_description
from utils.llm_client import llm_call
from neo4j import GraphDatabase
from state import AnalysisState


def _load_prompt(name: str) -> str:
    path = os.path.join(PROMPTS_DIR, name)
    with open(path, encoding="utf-8") as f:
        return f.read()


def run_semantic_agent(state: AnalysisState) -> dict:
    print("[semantic_agent] Running semantic analysis ...")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as s:
            uncertain = s.run(
                "MATCH (m:Method) WHERE m.confidence < 0.7 AND m.taint_role <> 'unknown' "
                "RETURN m.sig AS sig, m.taint_role AS role, m.confidence AS conf"
            ).data()
    finally:
        driver.close()

    print(f"[semantic_agent] Uncertain methods: {uncertain}")

    provider_key   = "edu/ksu/cs/benign/provider/UserDetailsContentProvider"
    provider_smali = state["app_smali"].get(provider_key, "")

    system = _load_prompt("semantic_system.md") + "\n\n" + load_graph_description()
    user = (
        f"需要语义分析确认以下不确定点：\n{uncertain}\n\n"
        f"ContentProvider Smali 代码：\n{provider_smali}"
    )

    result = llm_call(
        system,
        user,
        json_mode=True,
        agent_name="semantic_agent",
        trace_label="semantic_resolution",
    )
    print(f"[semantic_agent] Semantic findings: {result.get('semantic_findings', '')[:200]}")

    # Update confidence in Neo4j
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as s:
            for path_info in result.get("revised_paths", []):
                if "id" in path_info:
                    s.run(
                        "MATCH (m:Method {sig:$sig}) SET m.confidence=$conf",
                        sig=path_info["id"], conf=path_info.get("confidence", 0.8)
                    )
    finally:
        driver.close()

    return {"semantic_result": result}
