"""
Node 4: Path Validation Agent — GraphRAG core (Layer C).

Uses Text2CypherRetriever to issue natural language queries against the HPG,
then synthesizes results into a final exploitability verdict.

This is the primary GraphRAG contribution of the paper:
  Natural Language → Cypher → Neo4j → Structured Evidence → LLM Verdict
"""
import os
import sys
import httpx
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import (
    NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD,
    QWEN_MODEL, QWEN_BASE_URL, QWEN_API_KEY, PROMPTS_DIR
)
from hpg.schema import HPG_SCHEMA
from utils.llm_client import llm_call
from neo4j import GraphDatabase
from neo4j_graphrag.llm import OpenAILLM
from neo4j_graphrag.retrievers import Text2CypherRetriever
from state import AnalysisState


def _load_prompt(name: str) -> str:
    path = os.path.join(PROMPTS_DIR, name)
    with open(path, encoding="utf-8") as f:
        return f.read()


# Few-shot examples for Text2Cypher — must be list[str] in Q/A format
_EXAMPLES = [
    (
        "Question: 哪些 ContentProvider 没有保护根路径\n"
        "Answer: MATCH (c:Component {type:'provider', exported:true}) "
        "WHERE c.root_path_protected = false RETURN c.name, c.authority, c.vuln_description"
    ),
    (
        "Question: query() 方法是否访问包含 SSN 的敏感污点路径\n"
        "Answer: MATCH (m:Method {name:'query'})-[:HAS_INTRA_PATH]->(ip:IntraPath) "
        "RETURN m.sig, ip.source, ip.sink, ip.confidence"
    ),
    (
        "Question: 是否存在从 ContentProvider 到敏感数据的跨组件路径\n"
        "Answer: MATCH (ip:IntraPath)-[:ESCALATED_TO]->(cp:CrossPath) "
        "RETURN cp.entry_component, cp.attack_vector, cp.confidence"
    ),
    (
        "Question: 已知路径权限配置是什么\n"
        "Answer: MATCH (c:Component)-[:HAS_PATH_PERMISSION]->(pp:PathPermission) "
        "RETURN c.name, pp.pathPrefix, pp.readPermission"
    ),
]

# Validation queries to issue
VALIDATION_QUERIES = [
    "该 ContentProvider 的根路径是否可被外部无权限应用访问？",
    "query() 方法是否存在污点路径指向 SSN 或其他敏感数据？",
    "现有的 path-permission 配置能否防止根路径被绕过？",
    "是否存在完整的跨组件攻击路径（CrossPath）？",
]


def run_validation_agent(state: AnalysisState) -> dict:
    print("[validation_agent] Starting GraphRAG path validation (Layer C) ...")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    # Initialize Text2CypherRetriever with Qwen
    # socksio must be installed for SOCKS proxy support: pip install "httpx[socks]"
    llm = OpenAILLM(
        model_name=QWEN_MODEL,
        base_url=QWEN_BASE_URL,
        api_key=QWEN_API_KEY,
    )

    retriever = Text2CypherRetriever(
        driver=driver,
        llm=llm,
        neo4j_schema=HPG_SCHEMA,
        examples=_EXAMPLES,
    )

    # Direct fallback queries for high-importance checks (Text2Cypher may generate wrong Cypher)
    _DIRECT_QUERIES: dict[str, str] = {
        "query() 方法是否存在污点路径指向 SSN 或其他敏感数据？": (
            "MATCH (m:Method {name:'query'})-[:ACCESSES]->(sc:StringConst) "
            "WHERE sc.sensitivity IN ['HIGH', 'MEDIUM'] "
            "RETURN m.name, m.sig, sc.value, sc.sensitivity"
        ),
    }

    cypher_results = []
    for query in VALIDATION_QUERIES:
        print(f"[validation_agent] Query: {query}")
        # Try Text2Cypher first; fall back to direct query if result is empty
        try:
            result = retriever.search(query_text=query)
            answer = [str(item) for item in (result.items or [])]
            print(f"[validation_agent] Text2Cypher answer ({len(answer)} items)")
        except Exception as e:
            print(f"[validation_agent] Text2Cypher query failed: {e}")
            answer = []

        # Fallback: use direct Cypher if we got no answer and have one defined
        if not answer and query in _DIRECT_QUERIES:
            print(f"[validation_agent] Using direct Cypher fallback for: {query}")
            try:
                with driver.session() as s:
                    rows = s.run(_DIRECT_QUERIES[query]).data()
                    answer = [str(r) for r in rows]
                print(f"[validation_agent] Direct query answer ({len(answer)} items)")
            except Exception as e:
                print(f"[validation_agent] Direct query also failed: {e}")
                answer = [f"ERROR: {e}"]

        print(f"[validation_agent] Final answer: {answer}")
        cypher_results.append({"query": query, "answer": answer})

    driver.close()

    # ── Synthesize verdict with LLM ───────────────────────────────────────
    system = _load_prompt("validation_system.md")
    user = (
        f"GraphRAG 查询结果：\n"
        + "\n".join(
            f"Q: {r['query']}\nA: {r['answer']}" for r in cypher_results
        )
        + "\n\n请综合以上证据，给出最终安全结论（JSON）。"
    )

    verdict = llm_call(system, user, json_mode=True)
    print(f"[validation_agent] Final verdict: exploitable={verdict.get('exploitable')}")

    return {
        "validation_result": {
            "cypher_queries": cypher_results,
            "final_verdict":  verdict.get("final_verdict", ""),
            "exploitable":    verdict.get("exploitable", False),
            "severity":       verdict.get("severity", "UNKNOWN"),
            "attack_scenario":verdict.get("attack_scenario", ""),
            "evidence_chain": verdict.get("evidence_chain", []),
            "cwe":            verdict.get("cwe", ""),
        }
    }
