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
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, load_graph_description
from utils.agent_loop import run_agent_loop

VALIDATION_SYSTEM = """你是一名 Android 安全分析专家，负责对 APK 漏洞进行最终裁定。

图数据库（Neo4j）中包含所有分析阶段的结果：
- Component：组件信息、exported 状态、路径权限、漏洞描述
- Method：方法签名、taint_role（source/sink）、inference_source、confidence
- IntraPath：FlowDroid 发现的组件内污点路径
- CrossPath：跨组件攻击路径
- PathPermission：路径权限配置
- SASTFinding：SAST 工具融合发现。属性: tool_name, fused_score, cwe_ids, capability_analysis_depth, alignment_status
  关系：(SASTFinding)-[:IMPLICATES]->(Component|Method), (Component|Method)-[:EVIDENCED_BY]->(SASTFinding)
  查询: MATCH (sf:SASTFinding) WHERE sf.fused_score > 0.5 RETURN sf.tool_name, sf.title, sf.fused_score, sf.capability_analysis_depth
  查询: MATCH (c:Component)-[:EVIDENCED_BY]->(sf:SASTFinding) RETURN c.name, sf.tool_name, sf.fused_score

可用工具（每轮只能调用一个）：

1. query_neo4j — 执行 Cypher 查询获取证据
   {"tool": "query_neo4j", "args": {"cypher": "MATCH (c:Component {exported:true}) RETURN c.name, c.type"}}

   常用查询：
   - 暴露组件：MATCH (c:Component {exported:true}) RETURN c.name, c.type, c.vuln_description
   - source/sink：MATCH (m:Method) WHERE m.taint_role IN ['source','sink'] RETURN m.sig, m.taint_role, m.confidence
   - 跨组件路径：MATCH (cp:CrossPath) RETURN cp.channel_type, cp.attack_vector, cp.confidence, cp.target_component
   - 污点路径：MATCH (ip:IntraPath) RETURN ip.source, ip.sink, ip.confidence, ip.synthetic
   - ⚠ 方法所属组件（CONTAINS 边方向为 Component->Method，不可反向）：
     MATCH (c:Component)-[:CONTAINS]->(m:Method {sig:'<完整sig>'}) RETURN c.name, c.exported, c.type
   - SAST+组件联合查：MATCH (c:Component)-[:EVIDENCED_BY]->(sf:SASTFinding) WHERE sf.fused_score > 0.5 RETURN c.name, c.exported, sf.title, sf.fused_score
   - SAST+方法→组件：MATCH (c:Component)-[:CONTAINS]->(m:Method)-[:EVIDENCED_BY]->(sf:SASTFinding) WHERE sf.fused_score > 0.5 RETURN c.name, c.exported, m.sig, sf.title, sf.fused_score

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

    sast_result = state.get("sast_prior_result") or {}
    sast_ctx = ""
    if sast_result.get("status") == "success":
        stats = sast_result.get("stats", {})
        sast_ctx = (
            f"\nSAST 融合: {stats.get('total_fused', 0)} 发现, "
            f"{stats.get('aligned', 0)} 对齐, "
            f"{stats.get('enriched_nodes', 0)} 节点已富化。"
            "可查询 SASTFinding 节点和 EVIDENCED_BY 边获取证据。\n"
        )

    first_user_msg = (
        f"请对 APK「{state['apk_name']}」进行最终安全裁定。\n"
        "图数据库中已包含所有分析阶段的结果。\n"
        + sast_ctx
        + "请自主查询需要的数据，收集足够证据后调用 finish 给出结论。"
    )

    result = run_agent_loop(
        agent_name    = "validation_agent",
        system_prompt = VALIDATION_SYSTEM + "\n\n" + load_graph_description(),
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
