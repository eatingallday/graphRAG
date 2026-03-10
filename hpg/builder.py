"""
HPG (Hybrid Program Graph) builder.

Parses AndroidManifest.xml + app Smali files and creates the minimal
Neo4j graph that subsequent agents will augment.
"""
import re
import sys
import os
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, ANALYSIS_DIR
from neo4j import GraphDatabase

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# ── Smali helpers ─────────────────────────────────────────────────────────────

_CLASS_RE  = re.compile(r"\.class .+? ([\w/$]+);")
_METHOD_RE = re.compile(r"\.method (.+?) (\w+)\(([^)]*)\)([\w/[\];]+)")
_CONST_STR_RE = re.compile(r'const-string [vp]\d+, "([^"]+)"')
_CALL_RE   = re.compile(r"invoke-\w+ \{[^}]*\}, ([\w/$]+);->(\w+)\(([^)]*)\)([\w/[\];]+)")

_SMALI_TO_JAVA = {
    "V": "void", "Z": "boolean", "B": "byte", "C": "char",
    "S": "short", "I": "int", "J": "long", "F": "float", "D": "double",
}


def _smali_type_to_java(t: str) -> str:
    if t in _SMALI_TO_JAVA:
        return _SMALI_TO_JAVA[t]
    if t.startswith("["):
        return _smali_type_to_java(t[1:]) + "[]"
    if t.startswith("L") and t.endswith(";"):
        return t[1:-1].replace("/", ".")
    return t


def _smali_params_to_java(params: str) -> str:
    """Convert Smali param string to comma-separated Java types."""
    if not params:
        return ""
    parts, i = [], 0
    while i < len(params):
        if params[i] == "[":
            j = i + 1
            while j < len(params) and params[j] == "[":
                j += 1
            if params[j] == "L":
                end = params.index(";", j) + 1
                parts.append(_smali_type_to_java(params[i:end]))
                i = end
            else:
                parts.append(_smali_type_to_java(params[i:j+1]))
                i = j + 1
        elif params[i] == "L":
            end = params.index(";", i) + 1
            parts.append(_smali_type_to_java(params[i:end]))
            i = end
        else:
            parts.append(_smali_type_to_java(params[i]))
            i += 1
    return ",".join(parts)


def _build_soot_sig(cls: str, ret: str, name: str, params: str) -> str:
    java_cls    = cls.replace("/", ".")
    java_ret    = _smali_type_to_java(ret)
    java_params = _smali_params_to_java(params)
    return f"<{java_cls}: {java_ret} {name}({java_params})>"


def _parse_smali_methods(smali_text: str, cls_name: str) -> list[dict]:
    """Extract method metadata from a single Smali file."""
    methods = []
    for m in _METHOD_RE.finditer(smali_text):
        modifiers, name, params, ret = m.groups()
        sig = _build_soot_sig(cls_name, ret, name, params)
        java_cls = cls_name.replace("/", ".")
        is_entry = (
            "provider/UserDetailsContentProvider" in cls_name
            and name in ("query", "insert", "update", "delete", "getType", "onCreate")
        ) or (
            name in ("onCreate", "onStart", "onResume", "onReceive")
        )
        methods.append({
            "sig":      sig,
            "name":     name,
            "class":    java_cls,
            "is_entry": is_entry,
        })
    return methods


def _extract_string_consts(smali_text: str) -> list[str]:
    return _CONST_STR_RE.findall(smali_text)


# ── R.id mapping ─────────────────────────────────────────────────────────────

_RID_FIELD_RE = re.compile(
    r"\.field public static final (\w+):I = (0x[0-9a-fA-F]+)"
)


def build_rid_mapping(smali_map: dict) -> dict[int, str]:
    """Parse R$id.smali to build {hex_resource_id: view_id_name} mapping.

    This allows us to resolve `const vX, 0x7f...` → human-readable view ID
    when tracing findViewById calls in method bodies.
    """
    rid_map: dict[int, str] = {}
    for key, text in smali_map.items():
        if not key.endswith("R$id"):
            continue
        for m in _RID_FIELD_RE.finditer(text):
            field_name = m.group(1)
            hex_val = int(m.group(2), 16)
            rid_map[hex_val] = field_name
    return rid_map


def _extract_calls(smali_text: str) -> list[tuple[str, str, str, str]]:
    """Return list of (callee_class, callee_method, params, ret) tuples."""
    return [
        (m.group(1), m.group(2), m.group(3), m.group(4))
        for m in _CALL_RE.finditer(smali_text)
    ]


def _iter_method_bodies(smali_text: str, cls_name: str):
    """Split by .method / .end method blocks, yield (soot_sig, body_text)."""
    blocks = re.split(r"(?=\.method )", smali_text)
    for block in blocks:
        if not block.startswith(".method "):
            continue
        end = block.find(".end method")
        if end == -1:
            continue
        nl = block.find("\n")
        first_line = block[:nl] if nl != -1 else block
        body = block[nl:end] if nl != -1 else ""
        m = _METHOD_RE.search(first_line)
        if m:
            modifiers, name, params, ret = m.groups()
            sig = _build_soot_sig(cls_name, ret, name, params)
            yield sig, body


def _build_call_graph_edges(s, smali_map: dict, app_sigs: set):
    """Second pass: create DIRECT_CALL edges between intra-app methods."""
    count = 0
    for smali_key, smali_text in smali_map.items():
        for caller_sig, body in _iter_method_bodies(smali_text, smali_key):
            if caller_sig not in app_sigs:
                continue
            for callee_cls, callee_name, callee_params, callee_ret in _extract_calls(body):
                java_cls = callee_cls.replace("/", ".")
                callee_sig = (f"<{java_cls}: {_smali_type_to_java(callee_ret)} "
                              f"{callee_name}({_smali_params_to_java(callee_params)})>")
                if callee_sig in app_sigs:
                    s.run(
                        "MATCH (c:Method {sig:$caller}), (e:Method {sig:$callee}) "
                        "MERGE (c)-[:DIRECT_CALL]->(e)",
                        caller=caller_sig, callee=callee_sig
                    )
                    count += 1
    print(f"[hpg.builder] 建立了 {count} 条 DIRECT_CALL 边。")


# ── Manifest parser ───────────────────────────────────────────────────────────

def _parse_manifest(manifest_path: str) -> dict:
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    app  = root.find("application")

    components = []
    permissions = []
    path_permissions = []

    # Declared permissions
    for p in root.findall("permission"):
        pname  = p.get(f"{{{ANDROID_NS}}}name", "")
        plevel = p.get(f"{{{ANDROID_NS}}}protectionLevel", "normal")
        permissions.append({"name": pname, "protectionLevel": plevel})

    def _bool(v: str | None) -> bool:
        return str(v).lower() == "true"

    def _parse_component(elem, comp_type: str):
        name     = elem.get(f"{{{ANDROID_NS}}}name", "")
        exported = _bool(elem.get(f"{{{ANDROID_NS}}}exported"))
        auth     = elem.get(f"{{{ANDROID_NS}}}authorities", "")
        comp     = {
            "name":     name.split(".")[-1],   # short name
            "fullname": name,
            "type":     comp_type,
            "exported": exported,
            "authority": auth,
            "path_permissions": [],
        }
        for pp in elem.findall("path-permission"):
            pp_data = {
                "pathPrefix":       pp.get(f"{{{ANDROID_NS}}}pathPrefix", ""),
                "readPermission":   pp.get(f"{{{ANDROID_NS}}}readPermission", ""),
                "writePermission":  pp.get(f"{{{ANDROID_NS}}}writePermission", ""),
            }
            comp["path_permissions"].append(pp_data)
            path_permissions.append(pp_data)

        intent_filter_actions    = []
        intent_filter_categories = []
        for intent_filter in elem.findall("intent-filter"):
            for action_elem in intent_filter.findall("action"):
                action_name = action_elem.get(f"{{{ANDROID_NS}}}name", "")
                if action_name:
                    intent_filter_actions.append(action_name)
            for cat_elem in intent_filter.findall("category"):
                cat_name = cat_elem.get(f"{{{ANDROID_NS}}}name", "")
                if cat_name:
                    intent_filter_categories.append(cat_name)

        comp["intent_filter_actions"]    = intent_filter_actions
        comp["intent_filter_categories"] = intent_filter_categories
        components.append(comp)

    if app is not None:
        for tag, ctype in [
            ("activity", "activity"),
            ("service",  "service"),
            ("provider", "provider"),
            ("receiver", "receiver"),
        ]:
            for elem in app.findall(tag):
                _parse_component(elem, ctype)

    return {
        "components":        components,
        "permissions":       permissions,
        "path_permissions":  path_permissions,
    }


# ── Sensitivity classifier ────────────────────────────────────────────────────

_HIGH   = {"ssn", "password", "passwd", "secret", "credit", "cvv", "pin", "private_key"}
_MEDIUM = {"address", "email", "phone", "birthday", "dob"}


def _classify_sensitivity(val: str) -> str:
    low = val.lower()
    for kw in _HIGH:
        if kw in low:
            return "HIGH"
    for kw in _MEDIUM:
        if kw in low:
            return "MEDIUM"
    return "LOW"


# ── Neo4j write helpers ───────────────────────────────────────────────────────

def _write_hpg(driver, manifest_data: dict, smali_map: dict):
    with driver.session() as s:
        # Clear existing data for idempotency
        s.run("MATCH (n) DETACH DELETE n")

        # ── Permission nodes ──────────────────────────────────────────────
        for p in manifest_data["permissions"]:
            s.run(
                "MERGE (p:Permission {name:$name}) SET p.protectionLevel=$pl",
                name=p["name"], pl=p["protectionLevel"]
            )

        # ── Component nodes + path permissions ───────────────────────────
        for comp in manifest_data["components"]:
            # Check if root path has a readPermission (i.e., is protected)
            root_protected = False
            if comp["path_permissions"]:
                for pp in comp["path_permissions"]:
                    # "/" or "" pathPrefix would protect root
                    if pp["pathPrefix"] in ("/", ""):
                        root_protected = True
            # For this APK: pathPrefix="/user" → root "/" is unprotected
            short = comp["name"]
            s.run("""
                MERGE (c:Component {name:$name})
                SET c.fullname=$full, c.type=$type,
                    c.exported=$exp, c.authority=$auth,
                    c.root_path_protected=$rpp,
                    c.intent_filter_actions=$actions,
                    c.intent_filter_categories=$categories,
                    c.analysis_confidence=0.0, c.vuln_description=""
            """, name=short, full=comp["fullname"], type=comp["type"],
                 exp=comp["exported"], auth=comp["authority"],
                 rpp=root_protected,
                 actions=comp["intent_filter_actions"],
                 categories=comp["intent_filter_categories"])

            # PathPermission nodes + edges
            for pp in comp["path_permissions"]:
                s.run("""
                    MERGE (pp:PathPermission {pathPrefix:$pfx})
                    SET pp.readPermission=$rp, pp.writePermission=$wp
                    WITH pp
                    MATCH (c:Component {name:$comp})
                    MERGE (c)-[:HAS_PATH_PERMISSION]->(pp)
                """, pfx=pp["pathPrefix"], rp=pp["readPermission"],
                     wp=pp["writePermission"], comp=short)

                # Link to permission node if exists
                if pp["readPermission"]:
                    s.run("""
                        MATCH (c:Component {name:$comp}), (p:Permission {name:$pname})
                        MERGE (c)-[:REQUIRES_PERM {scope:"read"}]->(p)
                    """, comp=short, pname=pp["readPermission"])

        # ── Method nodes + edges from Smali ──────────────────────────────
        app_sigs = set()
        for smali_key, smali_text in smali_map.items():
            cls_name = smali_key  # slash-separated, e.g. edu/ksu/cs/benign/provider/UserDetailsContentProvider
            methods  = _parse_smali_methods(smali_text, cls_name)
            consts   = _extract_string_consts(smali_text)

            for m in methods:
                s.run("""
                    MERGE (m:Method {sig:$sig})
                    SET m.name=$name, m.class=$cls,
                        m.is_entry=$entry, m.taint_role="unknown",
                        m.confidence=0.0
                """, sig=m["sig"], name=m["name"], cls=m["class"],
                     entry=m["is_entry"])
                app_sigs.add(m["sig"])  # collect for call-graph pass

                # Link method to component (match by class suffix)
                comp_short = cls_name.split("/")[-1]
                s.run("""
                    MATCH (c:Component {name:$comp}), (m:Method {sig:$sig})
                    MERGE (c)-[:CONTAINS]->(m)
                """, comp=comp_short, sig=m["sig"])

            # StringConst nodes (URI paths, interesting strings only)
            # Also create ACCESSES edges from entry methods in this class
            entry_method_sigs = [m["sig"] for m in methods if m["is_entry"]]
            for val in consts:
                if "/" in val or len(val) < 3:
                    sens = _classify_sensitivity(val)
                    stype = "uri_path" if val.startswith("/") else "string_literal"
                    s.run("""
                        MERGE (sc:StringConst {value:$val})
                        SET sc.sensitivity=$sens, sc.type=$stype
                    """, val=val, sens=sens, stype=stype)

                    # Link entry methods (query, onCreate, etc.) to their string consts
                    for esig in entry_method_sigs:
                        s.run("""
                            MATCH (m:Method {sig:$sig}), (sc:StringConst {value:$val})
                            MERGE (m)-[:ACCESSES]->(sc)
                        """, sig=esig, val=val)

        # Build DIRECT_CALL edges between intra-app methods
        _build_call_graph_edges(s, smali_map, app_sigs)
        print("[hpg.builder] HPG written to Neo4j successfully.")


# ── Public entry point ────────────────────────────────────────────────────────

def build_hpg(analysis_dir: str | None = None,
              manifest_path: str | None = None,
              smali_map: dict | None = None):
    """
    Build the initial HPG from manifest + smali.
    If smali_map is None, loads from analysis_dir automatically.
    """
    from utils.file_loader import load_apk_artifacts

    if analysis_dir is None:
        analysis_dir = ANALYSIS_DIR

    if manifest_path is None:
        manifest_path = os.path.join(analysis_dir, "apktool", "AndroidManifest.xml")

    manifest_data = _parse_manifest(manifest_path)

    if smali_map is None:
        _, smali_map, _ = load_apk_artifacts(analysis_dir)

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        _write_hpg(driver, manifest_data, smali_map)
    finally:
        driver.close()

    return manifest_data
