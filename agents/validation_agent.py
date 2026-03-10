"""
Node 7: Validation Agent (Budget-Aware ReAct, max_loops=5)

LLM 自主发起 Cypher 查询，从图数据库收集证据，
证据充足后调用 finish 给出最终可利用性裁定。

工具集：
  - query_neo4j(cypher)
  - finish(exploitable, final_verdict, severity, attack_scenario, evidence_chain, cwe)
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from neo4j import GraphDatabase
from state import AnalysisState
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from utils.agent_loop import run_agent_loop

VALIDATION_SYSTEM = """你是一名 Android 安全分析专家，负责对 APK 漏洞进行最终裁定。

图数据库（Neo4j）中包含所有分析阶段的结果：
- Component：组件信息、exported 状态、路径权限、漏洞描述
- Method：方法签名、taint_role（source/sink）、inference_source、confidence
- IntraPath：FlowDroid 发现的组件内污点路径
- CrossPath：跨组件攻击路径
- PathPermission：路径权限配置

可用工具（每轮只能调用一个）：

1. query_neo4j — 执行 Cypher 查询获取证据
   {"tool": "query_neo4j", "args": {"cypher": "MATCH (c:Component {exported:true}) RETURN c.name, c.type"}}

   常用查询：
   - 暴露组件：MATCH (c:Component {exported:true}) RETURN c
   - source/sink：MATCH (m:Method) WHERE m.taint_role IN ['source','sink'] RETURN m.sig, m.taint_role, m.confidence
   - 跨组件路径：MATCH (cp:CrossPath) RETURN cp.channel_type, cp.attack_vector, cp.confidence
   - 污点路径：MATCH (m:Method)-[:HAS_INTRA_PATH]->(ip:IntraPath) RETURN m.sig, ip.source, ip.sink

2. finish — 证据充足，输出最终裁定
   {"tool": "finish", "args": {
     "exploitable": true,
     "final_verdict": "详细裁定说明（中文）",
     "severity": "HIGH",
     "attack_scenario": "攻击场景描述",
     "evidence_chain": ["证据1", "证据2"],
     "cwe": "CWE-926"
   }}
   severity 取值：CRITICAL / HIGH / MEDIUM / LOW / NONE

每轮严格输出一个 JSON 对象，不要输出其他文字。
收集到足够证据后立即调用 finish，不要无谓地重复查询。"""


def run_validation_agent(state: AnalysisState) -> dict:
    print("[validation_agent] Starting GraphRAG path validation (Budget-Aware, max_loops=5) ...")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    def query_neo4j(cypher: str) -> str:
        try:
            with driver.session() as s:
                rows = s.run(cypher).data()
            return str(rows) if rows else "（无结果）"
        except Exception as e:
            return f"[Cypher 错误] {e}"

    tool_executors = {"query_neo4j": query_neo4j}

    first_user_msg = (
        f"请对 APK「{state['apk_name']}」进行最终安全裁定。\n"
        "图数据库中已包含所有分析阶段的结果。\n"
        "请自主查询需要的数据，收集足够证据后调用 finish 给出结论。"
    )

    result = run_agent_loop(
        agent_name    = "validation_agent",
        system_prompt = VALIDATION_SYSTEM,
        first_user_msg= first_user_msg,
        tool_executors= tool_executors,
        max_loops     = 5,
    )

    driver.close()

    print(f"[validation_agent] exploitable={result.get('exploitable')}, "
          f"conclude_reason={result.get('conclude_reason')}, loops={result.get('loops_used')}")

    return {
        "validation_result": {
            "exploitable":     result.get("exploitable", False),
            "final_verdict":   result.get("final_verdict", ""),
            "severity":        result.get("severity", "UNKNOWN"),
            "attack_scenario": result.get("attack_scenario", ""),
            "evidence_chain":  result.get("evidence_chain", []),
            "cwe":             result.get("cwe", ""),
            "conclude_reason": result.get("conclude_reason"),
            "loops_used":      result.get("loops_used"),
        }
    }
