"""
Node 2: Taint Agent
- Reads Manifest Agent result from Neo4j (exported providers)
- Extracts candidate method signatures from Smali (multiple-choice approach)
- Calls Qwen to select sources/sinks from the candidate list
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

_SMALI_TO_JAVA = {
    "V": "void", "Z": "boolean", "B": "byte", "C": "char",
    "S": "short", "I": "int", "J": "long", "F": "float", "D": "double",
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

    # Extract candidate signatures from app Smali (multiple-choice approach)
    candidate_sigs = extract_method_sigs_from_smali(state["app_smali"])
    print(f"[taint_agent] Candidate signatures: {len(candidate_sigs)}")

    # Get provider Smali content
    provider_key = "edu/ksu/cs/benign/provider/UserDetailsContentProvider"
    provider_smali = state["app_smali"].get(provider_key, "")

    system = _load_prompt("taint_system.md")
    user = (
        f"已知暴露的 ContentProvider（来自 Neo4j）：{providers}\n\n"
        f"候选方法签名列表（从中选择 source 和 sink，不要发明新签名）：\n"
        + "\n".join(candidate_sigs)
        + f"\n\n当前分析目标的 Smali 代码：\n{provider_smali}"
    )

    result = llm_call(system, user, json_mode=True)
    print(f"[taint_agent] LLM result: sources={result.get('sources')}, sinks={result.get('sinks')}")

    # Write SuSi XML
    susi_path = os.path.join(OUTPUT_DIR, "SourcesAndSinks.txt")
    _write_susi_xml(result.get("sources", []), result.get("sinks", []), susi_path)
    result["susi_path"] = susi_path

    # Update Method.taint_role in Neo4j
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as s:
            for sig in result.get("sources", []):
                s.run(
                    "MATCH (m:Method {sig:$sig}) "
                    "SET m.taint_role='source', m.confidence=0.8, m.inference_source='LLM_Inferred'",
                    sig=sig
                )
            for sig in result.get("sinks", []):
                s.run(
                    "MATCH (m:Method {sig:$sig}) "
                    "SET m.taint_role='sink', m.confidence=0.8, m.inference_source='LLM_Inferred'",
                    sig=sig
                )
    finally:
        driver.close()

    return {"taint_result": result}
