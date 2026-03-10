"""
ICC Bridge Node — Layer B: intra-to-cross-component path escalation.

Handles four ICC channel types:
  1. ContentProvider (exported=true + IntraPath) → CrossPath
  2. STATIC_FIELD: cross-component via shared static fields
  3. DYNAMIC_BROADCAST: sendBroadcast / registerReceiver
  4. SET_RESULT: setResult() returning data to caller Activity
  5. EXPLICIT_INTENT: startActivity with const-class target
"""
import os
import re
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from neo4j import GraphDatabase
from state import AnalysisState

# ── Regex constants ────────────────────────────────────────────────────────────

_CONST_STR_RE  = re.compile(r'const-string [vp]\d+, "([^"]+)"')
_SPUT_RE       = re.compile(r"sput-\w+ [vp]\d+, (L[^;]+);->([^:]+):")
_SGET_RE       = re.compile(r"sget-\w+ [vp]\d+, (L[^;]+);->([^:]+):")
_SEND_BC_RE    = re.compile(r"invoke-\w+ \{[^}]+\},\s*[^;]+;->sendBroadcast\(")
_REG_RCV_RE    = re.compile(r"invoke-\w+ \{[^}]+\},\s*[^;]+;->registerReceiver\(")
_SET_RESULT_RE = re.compile(r"invoke-\w+ \{[^}]+\},\s*[^;]+;->setResult\(")
_START_ACT_RE  = re.compile(r"invoke-\w+ \{[^}]+\},\s*[^;]+;->startActivity\(")
_METHOD_RE_ICC = re.compile(r"\.method .+? ([\w<>$]+)\(([^)]*)\)([\w/\[\];$]+)")

_SMALI_TO_JAVA_ICC = {
    "V": "void", "Z": "boolean", "B": "byte", "C": "char",
    "S": "short", "I": "int", "J": "long", "F": "float", "D": "double",
}

# ── Smali type helpers ─────────────────────────────────────────────────────────

def _sjtype(t: str) -> str:
    """Smali type → Java type (icc_bridge internal use)."""
    if t in _SMALI_TO_JAVA_ICC:
        return _SMALI_TO_JAVA_ICC[t]
    if t.startswith("["):
        return _sjtype(t[1:]) + "[]"
    if t.startswith("L") and t.endswith(";"):
        return t[1:-1].replace("/", ".")
    return t


def _sjparams(params: str) -> str:
    """Smali param list → Java comma-separated types."""
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
                    parts.append(_sjtype(params[i:end]))
                    i = end
                except ValueError:
                    i = j + 1
            else:
                parts.append(_sjtype(params[i:j+1]))
                i = j + 1
        elif params[i] == "L":
            try:
                end = params.index(";", i) + 1
                parts.append(_sjtype(params[i:end]))
                i = end
            except ValueError:
                i += 1
        else:
            parts.append(_sjtype(params[i]))
            i += 1
    return ",".join(parts)


def _iter_method_bodies_icc(smali_text: str, cls_slash: str):
    """Split by .method / .end method blocks, yield (sig, body)."""
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
        m = _METHOD_RE_ICC.search(first_line)
        if m:
            name, params, ret = m.groups()
            java_cls = cls_slash.replace("/", ".")
            sig = f"<{java_cls}: {_sjtype(ret)} {name}({_sjparams(params)})>"
            yield sig, body


# ── Smali ICC pattern scanner ─────────────────────────────────────────────────

def _analyze_smali_for_icc(smali_map: dict) -> dict:
    """
    Scan all Smali files once, return 4 ICC pattern lists:
    - static_writes:  [(field_owner_slash, field_name, writer_sig)]
    - static_reads:   [(field_owner_slash, field_name, reader_sig)]
    - send_bcs:       [(sender_sig, sender_cls_slash, file_level_strings)]
    - reg_rcvs:       [(reg_sig, reg_cls_slash, [rcv_class_candidates], file_strings)]
    - set_results:    [(cls_slash, method_sig)]
    - start_acts:     [(caller_sig, caller_cls_slash, target_cls_slash, extra_keys)]
    """
    # First pass: collect per-file const-strings (for ACTION matching)
    file_strings: dict[str, list[str]] = {}
    for key, text in smali_map.items():
        cm = re.search(r"\.class .+? (L[^;]+);", text)
        if cm:
            file_strings[cm.group(1).lstrip("L")] = _CONST_STR_RE.findall(text)

    static_writes, static_reads = [], []
    send_bcs, reg_rcvs, set_results, start_acts = [], [], [], []

    # Second pass: per-method pattern extraction
    for key, smali_text in smali_map.items():
        cm = re.search(r"\.class .+? (L[^;]+);", smali_text)
        if not cm:
            continue
        cls_slash = cm.group(1).lstrip("L")
        f_strs = file_strings.get(cls_slash, [])

        for sig, body in _iter_method_bodies_icc(smali_text, cls_slash):
            for m in _SPUT_RE.finditer(body):
                static_writes.append((m.group(1).lstrip("L"), m.group(2), sig))
            for m in _SGET_RE.finditer(body):
                static_reads.append((m.group(1).lstrip("L"), m.group(2), sig))
            if _SEND_BC_RE.search(body):
                send_bcs.append((sig, cls_slash, f_strs))
            if _REG_RCV_RE.search(body):
                rcv_candidates = [
                    r.lstrip("L") for r in
                    re.findall(r"new-instance [vp]\d+, (L[^;]+);", body)
                    if "android/" not in r
                ]
                reg_rcvs.append((sig, cls_slash, rcv_candidates, f_strs))
            if _SET_RESULT_RE.search(body):
                set_results.append((cls_slash, sig))
            if _START_ACT_RE.search(body):
                tm = re.search(r"const-class [vp]\d+, (L[^;]+);", body)
                target = tm.group(1).lstrip("L") if tm else ""
                start_acts.append((sig, cls_slash, target, _CONST_STR_RE.findall(body)))

    return dict(
        static_writes=static_writes, static_reads=static_reads,
        send_bcs=send_bcs, reg_rcvs=reg_rcvs,
        set_results=set_results, start_acts=start_acts,
    )


# ── CrossPath handlers ────────────────────────────────────────────────────────

def _handle_static_field_icc(s, static_writes, static_reads, cross_paths):
    """Pattern A: cross-component via shared static field (ActivityCommunication1)."""
    for (owner, fname, writer_sig) in static_writes:
        writer_comp = writer_sig.split(":")[0].lstrip("<").rsplit(".", 1)[-1]
        for (owner2, fname2, reader_sig) in static_reads:
            if owner != owner2 or fname != fname2:
                continue
            reader_comp = reader_sig.split(":")[0].lstrip("<").rsplit(".", 1)[-1]
            if writer_comp == reader_comp:
                continue  # same component, not cross-component
            cp_id = f"static_field_{owner.replace('/','_')}_{fname}"
            s.run("""
                MERGE (cp:CrossPath {id:$cpid})
                SET cp.channel_type='STATIC_FIELD', cp.field=$field,
                    cp.layer='B', cp.confidence=0.80, cp.attack_vector=$av
                WITH cp
                MATCH (wm:Method {sig:$wsig}) MERGE (wm)-[:STATIC_WRITE_TO]->(cp)
                WITH cp
                MATCH (rm:Method {sig:$rsig}) MERGE (cp)-[:STATIC_READ_BY]->(rm)
            """, cpid=cp_id,
                 field=f"{owner.replace('/','.')}.{fname}",
                 av=f"{writer_comp} 通过静态字段 {fname} 将数据传递给 {reader_comp}",
                 wsig=writer_sig, rsig=reader_sig)
            cross_paths.append({
                "id": cp_id, "channel_type": "STATIC_FIELD",
                "field": f"{owner}.{fname}", "confidence": 0.80,
            })
            print(f"[icc_bridge] STATIC_FIELD CrossPath: {cp_id}")


def _handle_broadcast_icc(s, send_bcs, reg_rcvs, action_to_components, cross_paths):
    """Pattern B: dynamic broadcast channel — two-phase matching."""
    for (sender_sig, sender_cls, sender_strs) in send_bcs:
        manifest_matched = False

        # 阶段 1：Manifest intent-filter 精确匹配（置信度 0.85）
        for action_str in sender_strs:
            if action_str not in action_to_components:
                continue
            manifest_matched = True
            for comp in action_to_components[action_str]:
                onreceive_sig = (f"<{comp['fullname']}: void onReceive"
                                 f"(android.content.Context,android.content.Intent)>")
                cp_id = f"broadcast_mf_{abs(hash(sender_sig + action_str)) % 0xFFFFFF:x}"
                s.run("""
                    MERGE (cp:CrossPath {id:$cpid})
                    SET cp.channel_type='DYNAMIC_BROADCAST',
                        cp.broadcast_action=$action,
                        cp.match_method='manifest_intent_filter',
                        cp.layer='B', cp.confidence=0.85,
                        cp.attack_vector=$av
                    WITH cp
                    MATCH (sm:Method {sig:$ssig}) MERGE (sm)-[:BROADCAST_SENDS]->(cp)
                    WITH cp
                    MATCH (rm:Method {sig:$rsig}) MERGE (cp)-[:BROADCAST_RECEIVED_BY]->(rm)
                """, cpid=cp_id, action=action_str,
                     av=f"sendBroadcast '{action_str}' → {comp['name']}.onReceive()",
                     ssig=sender_sig, rsig=onreceive_sig)
                cross_paths.append({
                    "id": cp_id, "channel_type": "DYNAMIC_BROADCAST",
                    "action": action_str, "confidence": 0.85,
                    "match_method": "manifest_intent_filter",
                })
                print(f"[icc_bridge] DYNAMIC_BROADCAST (manifest) CrossPath: {cp_id} action={action_str}")

        # 阶段 2：Smali const-string 交集后备（置信度 0.65）——仅在 manifest 无匹配时触发
        if not manifest_matched:
            sender_set = {x for x in sender_strs if len(x) > 5}
            for (reg_sig, reg_cls, rcv_classes, reg_strs) in reg_rcvs:
                overlap = sender_set & {x for x in reg_strs if len(x) > 5}
                if not overlap:
                    continue
                action = max(overlap, key=len)
                for rcv_cls in rcv_classes:
                    java_rcv = rcv_cls.replace("/", ".")
                    onreceive_sig = (f"<{java_rcv}: void onReceive"
                                     f"(android.content.Context,android.content.Intent)>")
                    cp_id = f"broadcast_{abs(hash(sender_sig + action)) % 0xFFFFFF:x}"
                    s.run("""
                        MERGE (cp:CrossPath {id:$cpid})
                        SET cp.channel_type='DYNAMIC_BROADCAST',
                            cp.broadcast_action=$action,
                            cp.match_method='smali_string_overlap',
                            cp.layer='B', cp.confidence=0.65,
                            cp.attack_vector=$av
                        WITH cp
                        MATCH (sm:Method {sig:$ssig}) MERGE (sm)-[:BROADCAST_SENDS]->(cp)
                        WITH cp
                        MATCH (rm:Method {sig:$rsig}) MERGE (cp)-[:BROADCAST_RECEIVED_BY]->(rm)
                    """, cpid=cp_id, action=action,
                         av=f"sendBroadcast '{action}' → {rcv_cls.split('/')[-1]}.onReceive()",
                         ssig=sender_sig, rsig=onreceive_sig)
                    cross_paths.append({
                        "id": cp_id, "channel_type": "DYNAMIC_BROADCAST",
                        "action": action, "confidence": 0.65,
                        "match_method": "smali_string_overlap",
                    })
                    print(f"[icc_bridge] DYNAMIC_BROADCAST (smali) CrossPath: {cp_id} action={action}")


def _handle_set_result_icc(s, set_results, cross_paths):
    """Pattern C: setResult() data return (IntentSink1)."""
    for (cls_slash, method_sig) in set_results:
        result = s.run("""
            MATCH (m:Method {sig:$sig})-[:HAS_INTRA_PATH]->(ip:IntraPath)
            RETURN ip.id LIMIT 1
        """, sig=method_sig).single()
        conf = 0.70 if result else 0.40
        cp_id = f"set_result_{cls_slash.replace('/','_')}"
        s.run("""
            MERGE (cp:CrossPath {id:$cpid})
            SET cp.channel_type='SET_RESULT', cp.result_activity=$cls,
                cp.layer='B', cp.confidence=$conf, cp.attack_vector=$av
            WITH cp
            MATCH (m:Method {sig:$sig}) MERGE (m)-[:RESULT_SENT_VIA]->(cp)
        """, cpid=cp_id, cls=cls_slash.split("/")[-1], conf=conf,
             av=f"Activity {cls_slash.split('/')[-1]} 通过 setResult() 将敏感数据返回调用方",
             sig=method_sig)
        cross_paths.append({
            "id": cp_id, "channel_type": "SET_RESULT", "confidence": conf,
        })
        print(f"[icc_bridge] SET_RESULT CrossPath: {cp_id} (conf={conf:.2f})")


def _handle_implicit_intent_icc(s, start_acts, action_to_components, cross_paths):
    """处理 target_cls 为空的隐式 Intent（const-string action 匹配 manifest）。"""
    for (caller_sig, caller_cls, target_cls, extra_keys) in start_acts:
        if target_cls:
            continue  # 显式 Intent 由 _handle_start_activity_icc 处理
        for key_str in extra_keys:
            if key_str not in action_to_components:
                continue
            for comp in action_to_components[key_str]:
                cp_id = f"implicit_intent_{abs(hash(caller_sig + key_str)) % 0xFFFFFF:x}"
                s.run("""
                    MERGE (cp:CrossPath {id:$cpid})
                    SET cp.channel_type='IMPLICIT_INTENT',
                        cp.action=$action, cp.target_component=$target,
                        cp.layer='B', cp.confidence=0.75, cp.attack_vector=$av
                    WITH cp
                    MATCH (m:Method {sig:$sig}) MERGE (m)-[:INTENT_SENDS_TO]->(cp)
                """, cpid=cp_id, action=key_str,
                     target=comp["fullname"],
                     av=f"隐式 Intent action='{key_str}' → {comp['name']}",
                     sig=caller_sig)
                cross_paths.append({
                    "id": cp_id, "channel_type": "IMPLICIT_INTENT",
                    "action": key_str, "confidence": 0.75,
                })
                print(f"[icc_bridge] IMPLICIT_INTENT: {cp_id} action={key_str}")


def _handle_start_activity_icc(s, start_acts, cross_paths):
    """Pattern D: explicit startActivity with const-class target."""
    for (caller_sig, caller_cls, target_cls, extra_keys) in start_acts:
        if not target_cls:
            continue
        cp_id = f"start_act_{caller_cls.replace('/','_')}_{target_cls.split('/')[-1]}"
        s.run("""
            MERGE (cp:CrossPath {id:$cpid})
            SET cp.channel_type='EXPLICIT_INTENT', cp.target_component=$target,
                cp.extra_keys=$keys, cp.layer='B', cp.confidence=0.65,
                cp.attack_vector=$av
            WITH cp
            MATCH (m:Method {sig:$sig}) MERGE (m)-[:INTENT_SENDS_TO]->(cp)
        """, cpid=cp_id,
             target=target_cls.replace("/", "."),
             keys=extra_keys[:10],
             av=f"{caller_cls.split('/')[-1]} 通过 startActivity 向 {target_cls.split('/')[-1]} 传递 Intent",
             sig=caller_sig)
        cross_paths.append({
            "id": cp_id, "channel_type": "EXPLICIT_INTENT",
            "target": target_cls, "confidence": 0.65,
        })
        print(f"[icc_bridge] EXPLICIT_INTENT CrossPath: {cp_id}")


# ── Main node function ────────────────────────────────────────────────────────

def run_icc_bridge(state: AnalysisState) -> dict:
    print("[icc_bridge] Building ICC bridge (Layer B) ...")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    cross_paths = []

    # 从 Neo4j 读 manifest 声明的 intent-filter，构建 action→组件 索引
    with driver.session() as s:
        comp_rows = s.run("""
            MATCH (c:Component)
            WHERE c.intent_filter_actions IS NOT NULL AND size(c.intent_filter_actions) > 0
            RETURN c.name AS name, c.fullname AS fullname,
                   c.type AS type, c.intent_filter_actions AS actions
        """).data()

    action_to_components: dict[str, list] = {}
    for row in comp_rows:
        for action in (row["actions"] or []):
            action_to_components.setdefault(action, []).append(row)

    print(f"[icc_bridge] intent-filter 索引: {len(action_to_components)} 个 action")

    try:
        with driver.session() as s:
            # ── Pattern 0: exported ContentProvider + IntraPath ──────────
            rows = s.run("""
                MATCH (c:Component {type:'provider', exported:true})-[:CONTAINS]->(m:Method)
                      -[:HAS_INTRA_PATH]->(ip:IntraPath)
                RETURN c.name AS comp, c.root_path_protected AS rpp,
                       m.name AS method, ip.id AS ipid,
                       ip.source AS src, ip.sink AS sink,
                       ip.confidence AS conf
            """).data()

            print(f"[icc_bridge] Found {len(rows)} IntraPath rows for exported providers.")

            for row in rows:
                rpp = row.get("rpp", True)
                if not rpp:
                    attack_vector = (
                        f"ContentProvider '{row['comp']}' is exported with no root "
                        "path permission. Any app can query root URI without any permission, "
                        "bypassing the /user path-permission restriction."
                    )
                    confidence = 0.95
                else:
                    attack_vector = (
                        f"ContentProvider '{row['comp']}' is exported but root path "
                        "appears protected. Attack requires further investigation."
                    )
                    confidence = 0.5

                cp_id = f"cross_{row['ipid']}"
                s.run("""
                    MERGE (cp:CrossPath {id:$cpid})
                    SET cp.entry_component = $comp,
                        cp.attack_vector   = $av,
                        cp.intra_path_id   = $ipid,
                        cp.layer           = "B",
                        cp.confidence      = $conf
                    WITH cp
                    MATCH (ip:IntraPath {id:$ipid})
                    MERGE (ip)-[:ESCALATED_TO]->(cp)
                """, cpid=cp_id, comp=row["comp"], av=attack_vector,
                     ipid=row["ipid"], conf=confidence)

                cross_paths.append({
                    "id":              cp_id,
                    "entry_component": row["comp"],
                    "attack_vector":   attack_vector,
                    "intra_path_id":   row["ipid"],
                    "confidence":      confidence,
                })
                print(f"[icc_bridge] Created CrossPath: {cp_id} (conf={confidence:.2f})")

        # ── Patterns 1-4: Smali-based ICC analysis ────────────────────────
        icc_data = _analyze_smali_for_icc(state.get("app_smali", {}))
        print(f"[icc_bridge] Smali ICC scan — static_writes={len(icc_data['static_writes'])}, "
              f"static_reads={len(icc_data['static_reads'])}, "
              f"send_bcs={len(icc_data['send_bcs'])}, reg_rcvs={len(icc_data['reg_rcvs'])}, "
              f"set_results={len(icc_data['set_results'])}, start_acts={len(icc_data['start_acts'])}")

        with driver.session() as s:
            _handle_static_field_icc(s, icc_data["static_writes"], icc_data["static_reads"], cross_paths)
            _handle_broadcast_icc(s, icc_data["send_bcs"], icc_data["reg_rcvs"], action_to_components, cross_paths)
            _handle_set_result_icc(s, icc_data["set_results"], cross_paths)
            _handle_start_activity_icc(s, icc_data["start_acts"], cross_paths)
            _handle_implicit_intent_icc(s, icc_data["start_acts"], action_to_components, cross_paths)

    finally:
        driver.close()

    return {"icc_bridge_result": {"cross_paths": cross_paths, "status": "success"}}
