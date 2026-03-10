"""
Node 1: Manifest Agent (Budget-Aware ReAct, max_loops=3)

LLM 每轮输出 {"tool": "工具名", "args": {...}}，引擎解析执行后把结果
注入下一轮的历史记录，直到 LLM 调用 finish 或达到 max_loops。

工具集：
  - query_neo4j(cypher)
  - read_manifest_section(component_name)
  - update_component_risk(name, vuln, confidence)
  - finish(exported_providers, vulnerability, root_path_protected, confidence)
"""
import os
import sys
import xml.etree.ElementTree as ET
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from neo4j import GraphDatabase
from state import AnalysisState
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from utils.agent_loop import run_agent_loop

ANDROID_NS = "http://schemas.android.com/apk/res/android"

MANIFEST_SYSTEM = """你是一名 Android 安全专家，专门分析 AndroidManifest.xml 中的权限配置漏洞。

任务：找出 exported=true 的组件、ContentProvider 的路径权限绕过风险，并给出最终结论。

可用工具（每轮只能调用一个）：

1. query_neo4j — 查询图数据库中的组件数据
   {"tool": "query_neo4j", "args": {"cypher": "MATCH (c:Component) RETURN c"}}

2. read_manifest_section — 提取指定组件的完整 XML 片段
   {"tool": "read_manifest_section", "args": {"component_name": "UserDetailsContentProvider"}}

3. update_component_risk — 把风险写回图数据库
   {"tool": "update_component_risk", "args": {"name": "组件短名", "vuln": "漏洞描述", "confidence": 0.9}}

4. finish — 分析完成，输出最终结论
   {"tool": "finish", "args": {
     "exported_providers": ["com.example.MyProvider"],
     "vulnerability": "漏洞描述",
     "root_path_protected": false,
     "confidence": 0.9
   }}

规则：
- 每轮严格输出一个 JSON 对象，不要输出其他文字
- 证据充足后立即调用 finish，不要拖延"""


def run_manifest_agent(state: AnalysisState) -> dict:
    print("[manifest_agent] Starting manifest analysis (Budget-Aware, max_loops=3) ...")

    manifest_xml = state["manifest_xml"]
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    # ── 工具闭包 ──────────────────────────────────────────────────────────

    def query_neo4j(cypher: str) -> str:
        try:
            with driver.session() as s:
                rows = s.run(cypher).data()
            return str(rows) if rows else "（无结果）"
        except Exception as e:
            return f"[Cypher 错误] {e}"

    def read_manifest_section(component_name: str) -> str:
        try:
            root = ET.fromstring(manifest_xml)
            app  = root.find("application")
            if app is None:
                return "（未找到 <application> 元素）"
            for tag in ("activity", "service", "provider", "receiver"):
                for elem in app.findall(tag):
                    full  = elem.get(f"{{{ANDROID_NS}}}name", "")
                    short = full.split(".")[-1]
                    if component_name in (full, short):
                        return ET.tostring(elem, encoding="unicode")
            return f"（未找到组件 {component_name!r}）"
        except Exception as e:
            return f"[解析错误] {e}"

    def update_component_risk(name: str, vuln: str, confidence: float) -> str:
        try:
            with driver.session() as s:
                s.run(
                    "MATCH (c:Component {name:$name}) "
                    "SET c.vuln_description=$vuln, c.analysis_confidence=$conf",
                    name=name, vuln=vuln, conf=confidence,
                )
            return f"已更新 {name} 的风险属性"
        except Exception as e:
            return f"[写入错误] {e}"

    tool_executors = {
        "query_neo4j":           query_neo4j,
        "read_manifest_section": read_manifest_section,
        "update_component_risk": update_component_risk,
    }

    manifest_preview = manifest_xml[:3000] + ("..." if len(manifest_xml) > 3000 else "")
    first_user_msg = (
        f"请分析以下 AndroidManifest.xml，识别权限配置漏洞。\n\n"
        f"Manifest（前 3000 字符）：\n{manifest_preview}\n\n"
        f"Neo4j 中已有组件骨架数据，可用 query_neo4j 查询。"
    )

    result = run_agent_loop(
        agent_name    = "manifest_agent",
        system_prompt = MANIFEST_SYSTEM,
        first_user_msg= first_user_msg,
        tool_executors= tool_executors,
        max_loops     = 3,
    )

    driver.close()

    # ── 把 finish 结果写回 Neo4j ──────────────────────────────────────────
    driver2 = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver2.session() as s:
            for provider_name in result.get("exported_providers", []):
                short = provider_name.split(".")[-1]
                s.run(
                    "MATCH (c:Component {name:$name}) "
                    "SET c.vuln_description=$vuln, "
                    "    c.root_path_protected=$rpp, "
                    "    c.analysis_confidence=$conf",
                    name=short,
                    vuln=result.get("vulnerability", ""),
                    rpp=result.get("root_path_protected", False),
                    conf=result.get("confidence", 0.0),
                )
                print(f"[manifest_agent] Updated Neo4j for: {short}")
    finally:
        driver2.close()

    print(f"[manifest_agent] Done. conclude_reason={result.get('conclude_reason')}, "
          f"loops={result.get('loops_used')}")
    return {"manifest_result": result}
