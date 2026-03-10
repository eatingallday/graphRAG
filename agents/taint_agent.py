"""
Node 2: Taint Agent
- Reads Manifest Agent result from Neo4j (exported providers)
- Extracts candidate method signatures from Smali (multiple-choice approach)
- Rule-based pre-classification of framework API sources/sinks (P0 fix)
- Calls Qwen to select additional sources/sinks from the candidate list
- Writes SuSi XML to output/SourcesAndSinks.txt
- Updates Method.taint_role in Neo4j
"""
import os
import re
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, PROMPTS_DIR, OUTPUT_DIR
from utils.llm_client import llm_call
from neo4j import GraphDatabase
from state import AnalysisState

os.makedirs(OUTPUT_DIR, exist_ok=True)

_CLASS_RE  = re.compile(r"\.class .+? ([\w/$]+);")
_METHOD_RE = re.compile(r"\.method (?:public |private |protected |static |final |abstract |bridge |synthetic )*(\w+)\(([^)]*)\)([\w/[\];$]+)")
_CALL_RE   = re.compile(
    r"invoke-\w+ \{[^}]*\}, ([\w/$]+);->(\w+)\(([^)]*)\)([\w/\[\];]+)"
)

_SMALI_TO_JAVA = {
    "V": "void", "Z": "boolean", "B": "byte", "C": "char",
    "S": "short", "I": "int", "J": "long", "F": "float", "D": "double",
}

# 高置信度框架 Source（DroidBench 实测覆盖）
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

# 高置信度框架 Sink（DroidBench 实测覆盖）
_FRAMEWORK_SINKS = {
    "<android.util.Log: int d(java.lang.String,java.lang.String)>",
    "<android.util.Log: int e(java.lang.String,java.lang.String)>",
    "<android.util.Log: int i(java.lang.String,java.lang.String)>",
    "<android.util.Log: int v(java.lang.String,java.lang.String)>",
    "<android.util.Log: int w(java.lang.String,java.lang.String)>",
    "<android.telephony.SmsManager: void sendTextMessage(java.lang.String,java.lang.String,java.lang.String,android.app.PendingIntent,android.app.PendingIntent)>",
    # IntentSink1: getDeviceId → putExtra → setResult
    "<android.app.Activity: void setResult(int,android.content.Intent)>",
    "<android.content.Intent: android.content.Intent putExtra(java.lang.String,java.lang.String)>",
    "<java.io.FileOutputStream: void write(byte[])>",
    "<java.io.FileOutputStream: void write(byte[],int,int)>",
    "<java.io.PrintWriter: void println(java.lang.String)>",
    "<java.net.HttpURLConnection: java.io.OutputStream getOutputStream()>",
    "<android.content.Context: void sendBroadcast(android.content.Intent)>",
    "<android.content.ClipboardManager: void setPrimaryClip(android.content.ClipData)>",
}

# 通用噪声类，过滤掉（调用太普遍，无分析价值）
_SKIP_FRAMEWORK_CLASSES = {
    "java.lang.Object", "java.lang.String", "java.lang.StringBuilder",
    "java.lang.Integer", "java.lang.Boolean", "java.lang.Long",
    "java.lang.Float", "java.lang.Double", "java.lang.Math", "java.lang.System",
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


def extract_method_sigs_from_smali(smali_map: dict) -> list[str]:
    """Extract Soot-format method signatures from app Smali files."""
    sigs = []
    for smali_key, smali_text in smali_map.items():
        cls_match = _CLASS_RE.search(smali_text)
        if not cls_match:
            continue
        cls_name = cls_match.group(1)
        # Strip leading 'L' from Smali class descriptor (e.g. Ledu/ksu → edu/ksu)
        if cls_name.startswith("L"):
            cls_name = cls_name[1:]
        java_cls = cls_name.replace("/", ".")
        for m in _METHOD_RE.finditer(smali_text):
            name, params, ret = m.groups()
            java_ret    = _smali_type(ret.strip())
            java_params = _smali_params(params)
            sig = f"<{java_cls}: {java_ret} {name}({java_params})>"
            sigs.append(sig)
    return sigs


def extract_framework_api_calls(smali_map: dict) -> set[str]:
    """
    扫描全部 Smali 的 invoke-* 指令，提取 app 实际调用的框架/库 API 签名。
    排除 app 自身类（依据 smali_map key 前缀）和通用噪声类。
    """
    # 收集 app 自身包前缀（取前两段，如 de.ecspride、edu.ksu）
    app_prefixes = set()
    for key in smali_map:
        parts = key.replace("/", ".").split(".")
        if len(parts) >= 2:
            app_prefixes.add(".".join(parts[:2]))

    framework_calls: set[str] = set()
    for smali_text in smali_map.values():
        for m in _CALL_RE.finditer(smali_text):
            callee_cls    = m.group(1).replace("/", ".")
            callee_name   = m.group(2)
            callee_params = m.group(3)
            callee_ret    = m.group(4)
            if any(callee_cls.startswith(p) for p in app_prefixes):
                continue
            if callee_cls in _SKIP_FRAMEWORK_CLASSES:
                continue
            sig = (f"<{callee_cls}: {_smali_type(callee_ret)} "
                   f"{callee_name}({_smali_params(callee_params)})>")
            framework_calls.add(sig)
    return framework_calls


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


def _load_prompt(name: str) -> str:
    path = os.path.join(PROMPTS_DIR, name)
    with open(path, encoding="utf-8") as f:
        return f.read()


def run_taint_agent(state: AnalysisState) -> dict:
    print("[taint_agent] Starting taint source/sink inference ...")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as s:
            providers = s.run(
                "MATCH (c:Component {type:'provider', exported:true}) "
                "RETURN c.name AS name, c.authority AS auth, "
                "c.root_path_protected AS rpp, c.vuln_description AS vuln"
            ).data()
    finally:
        driver.close()

    print(f"[taint_agent] Exported providers from Neo4j: {providers}")

    app_sigs        = extract_method_sigs_from_smali(state["app_smali"])
    framework_calls = extract_framework_api_calls(state["app_smali"])

    # 规则预分类（取交集）
    auto_sources = sorted(framework_calls & _FRAMEWORK_SOURCES)
    auto_sinks   = sorted(framework_calls & _FRAMEWORK_SINKS)
    # LLM 候选集 = app 方法 + 黑名单未覆盖的框架调用
    llm_candidates = app_sigs + sorted(framework_calls - _FRAMEWORK_SOURCES - _FRAMEWORK_SINKS)

    print(f"[taint_agent] Rule_Based: {len(auto_sources)} sources, {len(auto_sinks)} sinks")
    print(f"[taint_agent] LLM candidates: {len(llm_candidates)}")

    # 规则预分类结果写 Neo4j（MERGE 保证框架 API 即使不在 HPG 里也能建节点）
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
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
    finally:
        driver.close()

    # 构造区分两类候选集的 LLM prompt
    provider_key = next(
        (k for k in state["app_smali"] if "provider" in k.lower() or "Provider" in k), ""
    )
    provider_smali = state["app_smali"].get(provider_key, "")

    system = _load_prompt("taint_system.md")
    user = (
        f"已知暴露的 ContentProvider（来自 Neo4j）：{providers}\n\n"
        f"【规则已自动标注为 Source】（无需重复选）：\n"
        + ("\n".join(auto_sources) or "（无）")
        + f"\n\n【规则已自动标注为 Sink】（无需重复选）：\n"
        + ("\n".join(auto_sinks) or "（无）")
        + f"\n\n【待分类的候选签名】（请从此列表中选额外的 source 和 sink）：\n"
        + "\n".join(llm_candidates)
        + f"\n\n当前分析目标的 Smali 代码：\n{provider_smali}"
    )

    result = llm_call(system, user, json_mode=True)
    print(f"[taint_agent] LLM result: sources={result.get('sources')}, sinks={result.get('sinks')}")

    # 合并：去重后写 SuSi XML
    auto_set    = set(auto_sources) | set(auto_sinks)
    all_sources = auto_sources + [s for s in result.get("sources", []) if s not in auto_set]
    all_sinks   = auto_sinks   + [s for s in result.get("sinks",   []) if s not in auto_set]
    result["sources"] = all_sources
    result["sinks"]   = all_sinks

    susi_path = os.path.join(OUTPUT_DIR, "SourcesAndSinks.txt")
    _write_susi_xml(all_sources, all_sinks, susi_path)
    result["susi_path"] = susi_path

    # LLM 新增部分写 Neo4j（inference_source='LLM_Inferred'）
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as s:
            for sig in all_sources:
                if sig not in auto_set:
                    s.run("MATCH (m:Method {sig:$sig}) "
                          "SET m.taint_role='source', m.confidence=0.8,"
                          "    m.inference_source='LLM_Inferred'", sig=sig)
            for sig in all_sinks:
                if sig not in auto_set:
                    s.run("MATCH (m:Method {sig:$sig}) "
                          "SET m.taint_role='sink', m.confidence=0.8,"
                          "    m.inference_source='LLM_Inferred'", sig=sig)
    finally:
        driver.close()

    return {"taint_result": result}
