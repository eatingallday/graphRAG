"""
UI Semantic Agent — parses Android layout XML files and classifies
each view's data sensitivity using LLM (primary) or rule fallback.

Writes UIView nodes to Neo4j with inference_source annotation:
  - LLM_Inferred: successful LLM classification
  - Rule_Based:   fallback using autofillHints / inputType system signals
"""
import os
import sys
import json
import re
import xml.etree.ElementTree as ET
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, ANALYSIS_DIR, PROMPTS_DIR
from utils.llm_client import llm_call
from neo4j import GraphDatabase
from state import AnalysisState

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Support-library layout prefixes to skip (not app-authored)
_SKIP_PREFIXES = ("abc_", "notification_", "select_dialog_", "support_")

# Fallback rule signals: Android API-level system semantics (not keyword heuristics)
_AUTOFILL_HIGH = {
    "password", "creditCardNumber", "creditCardSecurityCode",
    "creditCardExpirationDate", "postalAddress", "smsOtpCode",
}
_INPUTTYPE_HIGH = {"textPassword", "numberPassword", "textVisiblePassword"}
_AUTOFILL_MED = {
    "emailAddress", "phoneNumber", "personName", "username",
    "birthDateDay", "birthDateMonth", "birthDateYear", "postalCode",
}


# ── Layout discovery ───────────────────────────────────────────────────────────

def _find_layout_files() -> list[str]:
    """Search apktool and jadx output dirs for layout XML files."""
    candidates = [
        os.path.join(ANALYSIS_DIR, "smali", "res", "layout"),
        os.path.join(ANALYSIS_DIR, "java", "resources", "res", "layout"),
        os.path.join(ANALYSIS_DIR, "res", "layout"),
    ]
    found = []
    for layout_dir in candidates:
        if not os.path.isdir(layout_dir):
            continue
        for fname in os.listdir(layout_dir):
            if not fname.endswith(".xml"):
                continue
            if any(fname.startswith(p) for p in _SKIP_PREFIXES):
                continue
            found.append(os.path.join(layout_dir, fname))
    return found


# ── XML parser ────────────────────────────────────────────────────────────────

def _strip_id(raw: str) -> str:
    """Remove @id/ or @+id/ prefix from android:id value."""
    return re.sub(r"^@\+?id/", "", raw)


def _parse_layout_xml(xml_path: str) -> list[dict]:
    """Extract view metadata from a single layout XML file."""
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        print(f"[ui_semantic] XML parse error in {xml_path}: {e}")
        return []

    layout_name = os.path.basename(xml_path)
    views = []

    for elem in tree.iter():
        raw_id       = elem.get(f"{{{ANDROID_NS}}}id", "")
        raw_text     = elem.get(f"{{{ANDROID_NS}}}text", "")
        raw_hint     = elem.get(f"{{{ANDROID_NS}}}hint", "")
        raw_content  = elem.get(f"{{{ANDROID_NS}}}contentDescription", "")
        raw_label    = elem.get(f"{{{ANDROID_NS}}}labelFor", "")
        raw_itype    = elem.get(f"{{{ANDROID_NS}}}inputType", "")
        raw_autofill = elem.get(f"{{{ANDROID_NS}}}autofillHints", "")

        # Only include elements with at least one of: id, text, hint
        if not raw_id and not raw_text and not raw_hint:
            continue

        view_id = _strip_id(raw_id) if raw_id else ""
        # Strip @string/ resource refs to get the key name (not resolved value)
        def _strip_res(v: str) -> str:
            m = re.match(r"@(?:string|dimen|color)/(.+)", v)
            return m.group(1) if m else v

        views.append({
            "view_id":       view_id,
            "view_type":     elem.tag.split(".")[-1] if "." in elem.tag else elem.tag,
            "layout_file":   layout_name,
            "display_text":  _strip_res(raw_text),
            "hint_text":     _strip_res(raw_hint),
            "input_type":    raw_itype,
            "content_desc":  _strip_res(raw_content),
            "autofill_hints": raw_autofill,
            "label_for":     _strip_id(raw_label) if raw_label else "",
        })

    return views


# ── Fallback classifier (system signals only) ─────────────────────────────────

def _classify_view_fallback(view: dict) -> tuple[str, float]:
    """Use only Android system-level signals (autofillHints, inputType)."""
    af = view.get("autofill_hints", "")
    it = view.get("input_type", "")
    for hint in af.split("|"):
        if hint.strip() in _AUTOFILL_HIGH:
            return "HIGH", 0.90
    for t in it.split("|"):
        if t.strip() in _INPUTTYPE_HIGH:
            return "HIGH", 0.85
    for hint in af.split("|"):
        if hint.strip() in _AUTOFILL_MED:
            return "MEDIUM", 0.60
    return "LOW", 0.20


# ── System prompt loader ──────────────────────────────────────────────────────

def _load_prompt(name: str) -> str:
    path = os.path.join(PROMPTS_DIR, name)
    with open(path, encoding="utf-8") as f:
        return f.read()


# ── Main node function ────────────────────────────────────────────────────────

def run_ui_semantic_agent(state: AnalysisState) -> dict:
    print("[ui_semantic] Starting UI semantic analysis ...")

    layout_files = _find_layout_files()
    print(f"[ui_semantic] Found {len(layout_files)} layout file(s): "
          + ", ".join(os.path.basename(f) for f in layout_files))

    if not layout_files:
        return {"ui_semantic_result": {
            "total_views": 0, "sensitive_views": [], "status": "no_layouts_found",
        }}

    system_prompt = _load_prompt("ui_semantic_system.md")
    all_views = []

    for lf in layout_files:
        raw_views = _parse_layout_xml(lf)
        if not raw_views:
            continue
        layout_name = os.path.basename(lf)
        print(f"[ui_semantic] Processing {layout_name}: {len(raw_views)} views")

        try:
            user_prompt = (
                f"布局文件名：{layout_name}\n\n"
                f"视图列表（JSON）：\n"
                + json.dumps(raw_views, ensure_ascii=False, indent=2)
            )
            result = llm_call(system_prompt, user_prompt, json_mode=True)
            llm_views = {v["view_id"]: v for v in result.get("views", [])}
            for v in raw_views:
                llm_info = llm_views.get(v["view_id"], {})
                v["sensitivity_label"] = llm_info.get("sensitivity_label", "LOW")
                v["sensitivity_score"] = float(llm_info.get("sensitivity_score", 0.2))
                v["reason"]            = llm_info.get("reason", "")
                v["key_signals"]       = llm_info.get("key_signals", [])
                v["inference_source"]  = "LLM_Inferred"
            print(f"[ui_semantic] LLM classified {len(llm_views)} views in {layout_name}")
        except Exception as e:
            print(f"[ui_semantic] LLM call failed for {layout_name}, using rule fallback: {e}")
            for v in raw_views:
                label, score = _classify_view_fallback(v)
                v["sensitivity_label"] = label
                v["sensitivity_score"] = score
                v["reason"]            = "规则后备（autofillHints/inputType）"
                v["key_signals"]       = []
                v["inference_source"]  = "Rule_Based"

        all_views.extend(raw_views)

    # Write UIView nodes to Neo4j
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        with driver.session() as s:
            for v in all_views:
                s.run("""
                    MERGE (uv:UIView {view_id:$vid, layout_file:$lf})
                    SET uv.view_type=$vtype, uv.display_text=$text,
                        uv.hint_text=$hint, uv.input_type=$itype,
                        uv.sensitivity_label=$label, uv.sensitivity_score=$score,
                        uv.inference_source=$isrc, uv.reason=$reason,
                        uv.key_signals=$signals
                """, vid=v["view_id"], lf=v["layout_file"],
                     vtype=v["view_type"], text=v["display_text"],
                     hint=v["hint_text"], itype=v["input_type"],
                     label=v["sensitivity_label"], score=v["sensitivity_score"],
                     isrc=v["inference_source"], reason=v["reason"],
                     signals=v["key_signals"])
        print(f"[ui_semantic] Wrote {len(all_views)} UIView nodes to Neo4j.")
    finally:
        driver.close()

    sensitive = [v for v in all_views if v["sensitivity_label"] != "LOW"]
    print(f"[ui_semantic] 共 {len(all_views)} 个视图，{len(sensitive)} 个高/中敏感度")

    return {"ui_semantic_result": {
        "total_views":    len(all_views),
        "sensitive_views": sensitive,
        "status":         "success",
    }}
