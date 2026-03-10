"""
Node 2: Taint Agent (Budget-Aware ReAct, max_loops=5)

流程：
  1. 规则预分类（框架 API 黑名单，Rule_Based，置信度 0.95）→ 直接写 Neo4j
  2. Budget-Aware ReAct 循环：LLM 用工具自主探索，补充额外 source/sink
  3. 合并两层结果，写 SuSi XML
"""
import os
import re
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from neo4j import GraphDatabase
from state import AnalysisState
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, OUTPUT_DIR
from utils.agent_loop import run_agent_loop

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Smali type helpers ────────────────────────────────────────────────────────

_CLASS_RE  = re.compile(r"\.class .+? ([\w/$]+);")
_METHOD_RE = re.compile(
    r"\.method (?:public |private |protected |static |final |abstract |bridge |synthetic )*"
    r"(\w+)\(([^)]*)\)([\w/[\];$]+)"
)
_CALL_RE = re.compile(
    r"invoke-\w+ \{[^}]*\}, ([\w/$]+);->(\w+)\(([^)]*)\)([\w/\[\];]+)"
)
_SMALI_TO_JAVA = {
    "V": "void", "Z": "boolean", "B": "byte", "C": "char",
    "S": "short", "I": "int",  "J": "long", "F": "float", "D": "double",
}


def _smali_type(t: str) -> str:
    if t in _SMALI_TO_JAVA:
        return _SMALI_TO_JAVA[t]
    if t.startswith("["):
        return _smali_type(t[1:]) + "[]"
    if t.startswith("L") and t.endswith(";"):
        return t[1:-1].replace("/", ".")
    return t


def _smali_params(params: str) -> str:
    if not params:
        return ""
    parts, i = [], 0
    while i < len(params):
        if params[i] == "[":
            j = i + 1
            while j < len(params) and params[j] == "[":
                j += 1
            if j < len(params) and params[j] == "L":
                try:
                    end = params.index(";", j) + 1
                    parts.append(_smali_type(params[i:end]))
                    i = end
                except ValueError:
                    i = j + 1
            else:
                parts.append(_smali_type(params[i:j+1]))
                i = j + 1
        elif params[i] == "L":
            try:
                end = params.index(";", i) + 1
                parts.append(_smali_type(params[i:end]))
                i = end
            except ValueError:
                i += 1
        else:
            parts.append(_smali_type(params[i]))
            i += 1
    return ",".join(parts)


# ── 框架 API 黑名单（Rule_Based 预分类）─────────────────────────────────────

_FRAMEWORK_SOURCES = {
    "<android.telephony.TelephonyManager: java.lang.String getDeviceId()>",
    "<android.telephony.TelephonyManager: java.lang.String getSubscriberId()>",
    "<android.telephony.TelephonyManager: java.lang.String getLine1Number()>",
    "<android.telephony.TelephonyManager: java.lang.String getSimSerialNumber()>",
    "<android.location.Location: double getLatitude()>",
    "<android.location.Location: double getLongitude()>",
    "<android.app.Activity: android.content.Intent getIntent()>",
    "<android.content.Intent: java.lang.String getStringExtra(java.lang.String)>",
    "<android.content.Intent: android.os.Bundle getExtras()>",
    "<android.os.Bundle: java.lang.String getString(java.lang.String)>",
    "<android.accounts.AccountManager: android.accounts.Account[] getAccounts()>",
    "<android.content.SharedPreferences: java.lang.String getString(java.lang.String,java.lang.String)>",
    "<android.database.Cursor: java.lang.String getString(int)>",
    "<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)>",
}

_FRAMEWORK_SINKS = {
    "<android.util.Log: int d(java.lang.String,java.lang.String)>",
    "<android.util.Log: int e(java.lang.String,java.lang.String)>",
    "<android.util.Log: int i(java.lang.String,java.lang.String)>",
    "<android.util.Log: int v(java.lang.String,java.lang.String)>",
    "<android.util.Log: int w(java.lang.String,java.lang.String)>",
    "<android.telephony.SmsManager: void sendTextMessage(java.lang.String,java.lang.String,java.lang.String,android.app.PendingIntent,android.app.PendingIntent)>",
    "<android.app.Activity: void setResult(int,android.content.Intent)>",
    "<android.content.Intent: android.content.Intent putExtra(java.lang.String,java.lang.String)>",
    "<java.io.FileOutputStream: void write(byte[])>",
    "<java.io.FileOutputStream: void write(byte[],int,int)>",
    "<java.io.PrintWriter: void println(java.lang.String)>",
    "<java.net.HttpURLConnection: java.io.OutputStream getOutputStream()>",
    "<android.content.Context: void sendBroadcast(android.content.Intent)>",
    "<android.content.ClipboardManager: void setPrimaryClip(android.content.ClipData)>",
}

_SKIP_FRAMEWORK_CLASSES = {
    "java.lang.Object", "java.lang.String", "java.lang.StringBuilder",
    "java.lang.Integer", "java.lang.Boolean", "java.lang.Long",
    "java.lang.Float", "java.lang.Double", "java.lang.Math", "java.lang.System",
}


def extract_framework_api_calls(smali_map: dict) -> set[str]:
    app_prefixes = set()
    for key in smali_map:
        parts = key.replace("/", ".").split(".")
        if len(parts) >= 2:
            app_prefixes.add(".".join(parts[:2]))
    framework_calls: set[str] = set()
    for smali_text in smali_map.values():
        for m in _CALL_RE.finditer(smali_text):
            cls    = m.group(1).replace("/", ".")
            name   = m.group(2)
            params = m.group(3)
            ret    = m.group(4)
            if any(cls.startswith(p) for p in app_prefixes):
                continue
            if cls in _SKIP_FRAMEWORK_CLASSES:
                continue
            framework_calls.add(
                f"<{cls}: {_smali_type(ret)} {name}({_smali_params(params)})>"
            )
    return framework_calls


# ── UI-Inferred source boost ─────────────────────────────────────────────────

def _boost_from_ui_sensitivity(session, smali_map: dict) -> list[str]:
    """Mark methods that read HIGH-sensitivity UI views as sources.

    Queries READS_UI edges in Neo4j. If the method also calls getText()
    (i.e., actually reads user input from the view), mark it as a source
    with confidence=0.90 and inference_source='UI_Inferred'.

    Returns list of newly boosted source sigs.
    """
    rows = session.run("""
        MATCH (m:Method)-[:READS_UI]->(uv:UIView)
        WHERE uv.sensitivity_label IN ['HIGH', 'MEDIUM']
          AND m.taint_role <> 'source'
        RETURN m.sig AS sig, m.name AS name, m.class AS cls,
               uv.sensitivity_label AS ui_sens, uv.view_id AS vid
    """).data()

    if not rows:
        return []

    boosted = []
    for row in rows:
        sig, cls_name = row["sig"], row["cls"]
        # Verify the method actually reads the view content (getText, etc.)
        # by checking its Smali body for getText/toString calls
        smali_key = cls_name.replace(".", "/")
        smali_text = smali_map.get(smali_key, "")
        if not smali_text:
            # Try suffix match
            for k in smali_map:
                if k.endswith(smali_key.split("/")[-1]):
                    smali_text = smali_map[k]
                    break

        has_get_text = bool(re.search(r"invoke-virtual .+getText\(", smali_text))
        if not has_get_text:
            continue

        confidence = 0.90 if row["ui_sens"] == "HIGH" else 0.75
        session.run("""
            MATCH (m:Method {sig:$sig})
            SET m.taint_role='source', m.confidence=$conf,
                m.inference_source='UI_Inferred'
        """, sig=sig, conf=confidence)
        boosted.append(sig)

    return boosted


def _query_ui_context(driver) -> str:
    """Build a UI sensitivity context string for the LLM first message."""
    with driver.session() as s:
        rows = s.run("""
            MATCH (uv:UIView)
            WHERE uv.sensitivity_label IN ['HIGH', 'MEDIUM']
            OPTIONAL MATCH (m:Method)-[:READS_UI]->(uv)
            RETURN uv.view_id AS vid, uv.sensitivity_label AS label,
                   uv.hint_text AS hint, uv.input_type AS itype,
                   m.sig AS reader
        """).data()

    if not rows:
        return ""

    lines = ["## UI 敏感度上下文",
             "以下 UI 控件被标记为高/中敏感度，读取这些控件数据的方法很可能是 source："]
    for r in rows:
        reader = r["reader"] or "未关联"
        lines.append(f"- {r['vid']} ({r['label']}): hint={r['hint']!r}, "
                     f"inputType={r['itype']!r}, reader={reader}")
    return "\n".join(lines)


def _write_susi_xml(sources: list[str], sinks: list[str], path: str):
    lines = ["%SOURCES"]
    for src in sources:
        lines.append(f"{src} -> _SOURCE_")
    lines.append("")
    lines.append("%SINKS")
    for snk in sinks:
        lines.append(f"{snk} -> _SINK_ | 1")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[taint_agent] SuSi XML written to {path}")


# ── System prompt ─────────────────────────────────────────────────────────────

TAINT_SYSTEM = """你是一名 Android 污点分析专家。任务是找出 APK 中额外的污点 Source 和 Sink。

规则引擎已自动标注了高置信度的框架 API，你只需补充 app 自身代码中的额外 source/sink。

可用工具（每轮只能调用一个）：

1. search_smali — 用正则搜索所有 Smali 文件
   {"tool": "search_smali", "args": {"pattern": "getDeviceId", "context_lines": 2}}

2. get_method_body — 获取指定方法的完整 Smali 代码
   {"tool": "get_method_body", "args": {"class_path": "de/ecspride/MainActivity", "method_name": "onCreate"}}

3. query_neo4j — 查询图数据库
   {"tool": "query_neo4j", "args": {"cypher": "MATCH (m:Method {taint_role:'source'}) RETURN m.sig"}}

4. mark_source — 标记为污点源，写入 Neo4j
   {"tool": "mark_source", "args": {"sig": "<de.example.Foo: void bar()>", "reason": "读取设备ID"}}

5. mark_sink — 标记为污点汇，写入 Neo4j
   {"tool": "mark_sink", "args": {"sig": "<de.example.Foo: void bar()>", "reason": "发送短信"}}

6. query_ui_views — 查询高/中敏感度 UI 控件及其关联方法
   {"tool": "query_ui_views", "args": {}}

7. finish — 完成分析，输出汇总
   {"tool": "finish", "args": {
     "sources": ["<de.example.Foo: ...>"],
     "sinks": ["<de.example.Bar: ...>"],
     "susi_confidence": 0.85,
     "reasoning": "简要说明"
   }}

注意：finish 的 sources/sinks 只包含你新发现的，不要重复规则已标注的条目。
如果存在 UI 敏感度上下文，优先检查读取高敏感度 UI 控件的方法。
每轮严格输出一个 JSON 对象，不要输出其他文字。"""


# ── Main node function ────────────────────────────────────────────────────────

def run_taint_agent(state: AnalysisState) -> dict:
    print("[taint_agent] Starting taint analysis (Budget-Aware, max_loops=5) ...")

    smali_map = state["app_smali"]
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    # Step 1：读已知暴露 provider
    with driver.session() as s:
        providers = s.run(
            "MATCH (c:Component {type:'provider', exported:true}) "
            "RETURN c.name AS name, c.authority AS auth, "
            "c.root_path_protected AS rpp, c.vuln_description AS vuln"
        ).data()
    print(f"[taint_agent] Exported providers: {providers}")

    # Step 2：规则预分类
    framework_calls = extract_framework_api_calls(smali_map)
    auto_sources    = sorted(framework_calls & _FRAMEWORK_SOURCES)
    auto_sinks      = sorted(framework_calls & _FRAMEWORK_SINKS)
    print(f"[taint_agent] Rule_Based: {len(auto_sources)} sources, {len(auto_sinks)} sinks")

    with driver.session() as s:
        for sig in auto_sources:
            cls  = sig.lstrip("<").split(":")[0]
            name = sig.split(": ")[1].split("(")[0].split(" ")[-1]
            s.run("""
                MERGE (m:Method {sig:$sig})
                SET m.taint_role='source', m.confidence=0.95,
                    m.inference_source='Rule_Based',
                    m.name=$name, m.class=$cls
            """, sig=sig, name=name, cls=cls)
        for sig in auto_sinks:
            cls  = sig.lstrip("<").split(":")[0]
            name = sig.split(": ")[1].split("(")[0].split(" ")[-1]
            s.run("""
                MERGE (m:Method {sig:$sig})
                SET m.taint_role='sink', m.confidence=0.95,
                    m.inference_source='Rule_Based',
                    m.name=$name, m.class=$cls
            """, sig=sig, name=name, cls=cls)

        # Step 2b: UI-Inferred source boost
        ui_sources = _boost_from_ui_sensitivity(s, smali_map)
        if ui_sources:
            auto_sources = auto_sources + ui_sources
            print(f"[taint_agent] UI_Inferred: {len(ui_sources)} additional sources")

    # Step 3：工具闭包
    llm_added_sources: list[str] = []
    llm_added_sinks:   list[str] = []

    def search_smali(pattern: str, context_lines: int = 2) -> str:
        results = []
        try:
            regex = re.compile(pattern)
        except re.error as e:
            return f"[正则错误] {e}"
        for cls_path, text in smali_map.items():
            lines = text.splitlines()
            for i, line in enumerate(lines):
                if regex.search(line):
                    start   = max(0, i - context_lines)
                    end     = min(len(lines), i + context_lines + 1)
                    snippet = "\n".join(f"  {lines[j]}" for j in range(start, end))
                    results.append(f"[{cls_path}:{i+1}]\n{snippet}")
                    if len(results) >= 20:
                        results.append("... (已截断，最多 20 处匹配)")
                        return "\n\n".join(results)
        return "\n\n".join(results) if results else "（无匹配）"

    def get_method_body(class_path: str, method_name: str) -> str:
        normalized = class_path.replace(".", "/")
        text = smali_map.get(normalized, "")
        if not text:
            for k in smali_map:
                if k.endswith(normalized) or k.split("/")[-1] == normalized.split("/")[-1]:
                    text = smali_map[k]
                    break
        if not text:
            return f"（未找到类 {class_path!r}）"
        blocks = re.split(r"(?=\.method )", text)
        for block in blocks:
            if not block.startswith(".method "):
                continue
            if f" {method_name}(" in block or f" {method_name}\n" in block:
                end = block.find(".end method")
                return block[:end + len(".end method")] if end != -1 else block[:2000]
        return f"（未找到方法 {method_name!r} 在类 {class_path!r} 中）"

    def query_neo4j(cypher: str) -> str:
        try:
            with driver.session() as s:
                rows = s.run(cypher).data()
            return str(rows) if rows else "（无结果）"
        except Exception as e:
            return f"[Cypher 错误] {e}"

    def mark_source(sig: str, reason: str) -> str:
        try:
            with driver.session() as s:
                s.run("""
                    MATCH (m:Method {sig:$sig})
                    SET m.taint_role='source', m.confidence=0.8,
                        m.inference_source='LLM_Inferred'
                """, sig=sig)
            if sig not in llm_added_sources:
                llm_added_sources.append(sig)
            return f"已标记 source: {sig}"
        except Exception as e:
            return f"[写入错误] {e}"

    def mark_sink(sig: str, reason: str) -> str:
        try:
            with driver.session() as s:
                s.run("""
                    MATCH (m:Method {sig:$sig})
                    SET m.taint_role='sink', m.confidence=0.8,
                        m.inference_source='LLM_Inferred'
                """, sig=sig)
            if sig not in llm_added_sinks:
                llm_added_sinks.append(sig)
            return f"已标记 sink: {sig}"
        except Exception as e:
            return f"[写入错误] {e}"

    def query_ui_views() -> str:
        """查询所有 HIGH/MEDIUM 敏感度的 UI 控件及其关联方法。"""
        try:
            with driver.session() as s:
                rows = s.run("""
                    MATCH (uv:UIView)
                    WHERE uv.sensitivity_label IN ['HIGH', 'MEDIUM']
                    OPTIONAL MATCH (m:Method)-[:READS_UI]->(uv)
                    RETURN uv.view_id AS vid, uv.sensitivity_label AS label,
                           uv.hint_text AS hint, uv.input_type AS itype,
                           m.sig AS reader
                """).data()
            return str(rows) if rows else "（无高/中敏感度 UI 控件）"
        except Exception as e:
            return f"[错误] {e}"

    tool_executors = {
        "search_smali":    search_smali,
        "get_method_body": get_method_body,
        "query_neo4j":     query_neo4j,
        "mark_source":     mark_source,
        "mark_sink":       mark_sink,
        "query_ui_views":  query_ui_views,
    }

    # Step 4：LLM ReAct 循环
    auto_set = set(auto_sources) | set(auto_sinks)

    # Inject UI sensitivity context if available
    ui_context = _query_ui_context(driver)

    first_user_msg = (
        f"分析目标：{state['apk_name']}\n"
        f"已知暴露的 ContentProvider：{providers}\n\n"
        f"【规则已自动标注为 Source（无需重复选）】：\n"
        + ("\n".join(auto_sources) or "（无）")
        + "\n\n【规则已自动标注为 Sink（无需重复选）】：\n"
        + ("\n".join(auto_sinks) or "（无）")
        + (f"\n\n{ui_context}" if ui_context else "")
        + "\n\n请使用工具自主探索 app 代码，补充额外的 source 和 sink。"
          "如果存在 UI 敏感度上下文，可使用 query_ui_views 工具获取更多信息。"
    )

    result = run_agent_loop(
        agent_name    = "taint_agent",
        system_prompt = TAINT_SYSTEM,
        first_user_msg= first_user_msg,
        tool_executors= tool_executors,
        max_loops     = 5,
    )

    driver.close()

    # Step 5：合并两层结果，写 SuSi XML
    llm_sources = [s for s in result.get("sources", []) if s not in auto_set]
    llm_sinks   = [s for s in result.get("sinks",   []) if s not in auto_set]
    for s in llm_added_sources:
        if s not in auto_set and s not in llm_sources:
            llm_sources.append(s)
    for s in llm_added_sinks:
        if s not in auto_set and s not in llm_sinks:
            llm_sinks.append(s)

    all_sources = auto_sources + llm_sources
    all_sinks   = auto_sinks   + llm_sinks
    result["sources"] = all_sources
    result["sinks"]   = all_sinks

    susi_path = os.path.join(OUTPUT_DIR, "SourcesAndSinks.txt")
    _write_susi_xml(all_sources, all_sinks, susi_path)
    result["susi_path"] = susi_path

    print(f"[taint_agent] Done. sources={len(all_sources)}, sinks={len(all_sinks)}, "
          f"conclude_reason={result.get('conclude_reason')}, loops={result.get('loops_used')}")
    return {"taint_result": result}
