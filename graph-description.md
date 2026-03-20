# Graph Description (Code-Accurate, v1)

This document describes what each node/edge/property in Neo4j means, where it is written, and what to watch out for.
It reflects the current code under `analysis-pipeline/`.

## 1. Graph Lifecycle

- Graph reset behavior:
  - `hpg.builder._write_hpg()` starts with `MATCH (n) DETACH DELETE n`.
  - This means each pipeline run rebuilds the graph from scratch.
- Build/enrichment order:
  - Base graph from manifest + smali (`hpg.builder`)
  - UI enrichment (`ui_semantic_agent`)
  - SAST enrichment (`sast_prior_node`, if `--sast-reports` is provided)
  - Taint updates (`taint_agent`)
  - Optional semantic confidence adjustment (`semantic_agent`)
  - IntraPath (`flowdroid_node`)
  - CrossPath (`icc_bridge`)

## 2. Edge Catalog (Complete)

| Edge | Direction | Writer | Creation logic | Notes |
|---|---|---|---|---|
| `CONTAINS` | `Component -> Method` | `hpg.builder` | For each smali class, `comp_short = cls_name.split('/')[-1]`; `MATCH (c:Component {name:$comp}), (m:Method {sig:$sig})` | Relies on short class name matching, not full package |
| `DIRECT_CALL` | `Method -> Method` | `hpg.builder` | Smali `invoke-*` parsed; edge only if callee signature is in app method set | Structural call edge |
| `HAS_PATH_PERMISSION` | `Component -> PathPermission` | `hpg.builder` | From manifest `<path-permission>` entries | Structural config edge |
| `REQUIRES_PERM` | `Component -> Permission` | `hpg.builder` | Created only for `readPermission` (with `scope='read'`) | No write-scope edge in current code |
| `ACCESSES` | `Method -> StringConst` | `hpg.builder` | Entry methods in class linked to selected string constants | Heuristic enrichment edge |
| `READS_UI` | `Method -> UIView` | `ui_semantic_agent` | `findViewById` tracing + `R$id` mapping | Matching uses `UIView {view_id}` only |
| `HAS_UI` | `Component -> UIView` | `ui_semantic_agent` | Derived via `Component-[:CONTAINS]->Method-[:READS_UI]->UIView` | Derived edge |
| `HAS_INTRA_PATH` | `Method -> IntraPath` | `flowdroid_node` | `MATCH (m:Method {name:'query'})` then link to each IntraPath | Attached by method name, not exact source signature |
| `ESCALATED_TO` | `IntraPath -> CrossPath` | `icc_bridge` | Exported provider path escalation pattern | ICC layer-B escalation |
| `STATIC_WRITE_TO` | `Method -> CrossPath` | `icc_bridge` | Static field write pattern (`sput`) | ICC heuristic |
| `STATIC_READ_BY` | `CrossPath -> Method` | `icc_bridge` | Static field read pattern (`sget`) | ICC heuristic |
| `BROADCAST_SENDS` | `Method -> CrossPath` | `icc_bridge` | Dynamic broadcast sender match | ICC heuristic |
| `BROADCAST_RECEIVED_BY` | `CrossPath -> Method` | `icc_bridge` | Dynamic broadcast receiver match | ICC heuristic |
| `RESULT_SENT_VIA` | `Method -> CrossPath` | `icc_bridge` | `setResult()` pattern | ICC heuristic |
| `INTENT_SENDS_TO` | `Method -> CrossPath` | `icc_bridge` | Explicit intent and implicit intent patterns | Covers `EXPLICIT_INTENT` and `IMPLICIT_INTENT` channel types |
| `IMPLICATES` | `SASTFinding -> (Component or Method)` | `sast_prior_node` | Created when finding `alignment_status` is `aligned` or `candidate` | Provenance edge, not code structure |
| `EVIDENCED_BY` | `(Component or Method) -> SASTFinding` | `sast_prior_node` | Created only for `aligned` findings during node enrichment | Provenance edge, not code structure |

## 3. Node Catalog and Property Provenance (Complete)

### 3.1 `Component`

- Key:
  - `name` (short class/component name, not fully-qualified)
- Base properties from `hpg.builder`:
  - `fullname`, `type`, `exported`, `authority`
  - `root_path_protected`
  - `intent_filter_actions`, `intent_filter_categories`
  - `analysis_confidence` (initialized `0.0`)
  - `vuln_description` (initialized `""`)
- Updated by `manifest_agent`:
  - `vuln_description`, `analysis_confidence`
  - `root_path_protected` may be overwritten by `finish` result
- Updated by `sast_prior_node`:
  - Aligned finding aggregation:
    - `sast_fused_score`
    - `sast_cwes`
    - `sast_tools_flagged`
    - `sast_finding_count`
  - Hint fields:
    - `sast_search_priority`
    - `sast_hint_text`

### 3.2 `Method`

- Key:
  - `sig` (Soot-style signature built by `_build_soot_sig`)
- Base properties from `hpg.builder`:
  - `name`, `class`, `is_entry`
  - `taint_role` (initialized `"unknown"`)
  - `confidence` (initialized `0.0`)
- Updated by `taint_agent`:
  - Rule-based framework classification:
    - `taint_role` (`source`/`sink`)
    - `confidence` (`0.95`)
    - `inference_source='Rule_Based'`
    - also sets `name`, `class` for merged methods
  - UI-derived boost:
    - `taint_role='source'`
    - `confidence` (`0.90` for HIGH UI, `0.75` for MEDIUM UI)
    - `inference_source='UI_Inferred'`
  - LLM tool calls (`mark_source` / `mark_sink`):
    - `taint_role`
    - `confidence=0.8`
    - `inference_source='LLM_Inferred'`
- Updated by `semantic_agent`:
  - `confidence` only (does not set `inference_source`)
- Updated by `sast_prior_node`:
  - Aligned finding aggregation:
    - `sast_fused_score`
    - `sast_cwes`
    - `sast_tools_flagged`
    - `sast_finding_count`
  - Taint hint fields:
    - `sast_taint_hint` (`potential_source` / `potential_sink` / `potential_taint_relevant`)
    - `sast_hint_score`
    - `sast_hint_tool`
    - update guard: only if `existing_score` is null or lower
  - Search hint fields:
    - `sast_search_priority`
    - `sast_hint_text`
    - update guard: do not downgrade existing `high` to `medium`

### 3.3 `Permission`

- Key:
  - `name`
- Properties from `hpg.builder`:
  - `protectionLevel`

### 3.4 `PathPermission`

- Key:
  - `pathPrefix`
- Properties from `hpg.builder`:
  - `readPermission`
  - `writePermission`

### 3.5 `StringConst`

- Key:
  - `value`
- Properties from `hpg.builder`:
  - `sensitivity` (`HIGH`/`MEDIUM`/`LOW` by keyword heuristic)
  - `type` (`uri_path` or `string_literal`)

### 3.6 `UIView`

- Key:
  - Composite key: `(view_id, layout_file)`
- Properties from `ui_semantic_agent`:
  - `view_type`, `display_text`, `hint_text`, `input_type`
  - `sensitivity_label`, `sensitivity_score`
  - `inference_source` (`LLM_Inferred` or `Rule_Based`)
  - `reason`, `key_signals`

### 3.7 `IntraPath`

- Key:
  - `id`
- Properties from `flowdroid_node`:
  - `source`, `sink`
  - `path` (list of path element statements)
  - `layer` (always `"A"`)
  - `confidence`
  - `synthetic` (boolean)
  - `inference_source`
    - `"Synthetic"` when fallback synthetic paths are used
    - `"FlowDroid"` otherwise (including parsed FlowDroid XML results)

### 3.8 `CrossPath`

- Key:
  - `id`
- Common properties (pattern-dependent population):
  - `layer` (always `"B"` where set)
  - `confidence`
  - `attack_vector`
- Channel-specific properties:
  - Static field pattern:
    - `channel_type='STATIC_FIELD'`
    - `field`
  - Dynamic broadcast pattern:
    - `channel_type='DYNAMIC_BROADCAST'`
    - `broadcast_action`
    - `match_method` (`manifest_intent_filter` or `smali_string_overlap`)
  - Set result pattern:
    - `channel_type='SET_RESULT'`
    - `result_activity`
  - Implicit intent pattern:
    - `channel_type='IMPLICIT_INTENT'`
    - `action`
    - `target_component`
  - Explicit intent pattern:
    - `channel_type='EXPLICIT_INTENT'`
    - `target_component`
    - `extra_keys`
  - Exported provider escalation pattern:
    - `channel_type='CONTENT_PROVIDER_EXPORT'`
    - `entry_component`
    - `intra_path_id`

### 3.9 `SASTFinding`

- Key:
  - `id` (deterministic from tool/rule/title in fusion stage)
- Properties from `sast_prior_node`:
  - Identity/severity:
    - `tool_name`, `rule_id`, `title`, `severity`, `description`
  - Fusion outputs:
    - `fused_score`
    - `signal_polarity`
    - `cwe_ids`
    - `capability_id`
    - `capability_taint_relevance`
    - `capability_analysis_depth`
    - `corroboration_count`
  - Alignment outputs:
    - `alignment_status` (`aligned`/`candidate`/`unmatched`)
    - `alignment_method`
    - `matched_node_type`
    - `matched_node_id`
  - Location/evidence fields:
    - `method_signature`, `class_name`, `component_name`

## 4. Source Mapping Summary

- Deterministic structural build:
  - `hpg.builder` (manifest + smali parsing)
- LLM-assisted updates:
  - `manifest_agent` (component risk fields)
  - `ui_semantic_agent` (UIView sensitivity labels when LLM succeeds)
  - `taint_agent` (LLM `mark_source/mark_sink`)
  - `semantic_agent` (confidence adjustment)
- Tool/heuristic analysis:
  - `flowdroid_node` (`IntraPath`)
  - `icc_bridge` (`CrossPath` and ICC edges)
  - `sast_prior_node` (`SASTFinding`, provenance edges, sast_* enrichments)

## 5. Important Caveats for Agents

1. `Component.name` is a short name key. Same short names across packages can collide.
2. `PathPermission` is keyed only by `pathPrefix`; different components can merge onto one node.
3. `READS_UI` links by `UIView {view_id}` (without `layout_file`) and may attach to multiple layouts sharing the same ID.
4. `HAS_INTRA_PATH` links all IntraPath nodes to methods named `query`, not to exact parsed source signatures.
5. `taint_agent` can create framework `Method` nodes via `MERGE` even if they are not app-owned methods in `CONTAINS`.
6. `IMPLICATES` includes both `aligned` and `candidate` SAST alignments; for strong evidence, filter `alignment_status='aligned'`.
7. `IMPLICATES` and `EVIDENCED_BY` are provenance edges only; they are not program-structure or data-flow edges.
8. In `_write_hints`, update guards prevent score/priority downgrade, but current in-memory counters (`hints_written`, returned hint lists) count attempted hints, not guaranteed successful writes after `WHERE` filtering.
9. **CONTAINS edge direction is Component→Method, never the reverse.** To look up the component that owns a given method, always write: `MATCH (c:Component)-[:CONTAINS]->(m:Method {sig:$sig}) RETURN c.name, c.exported` — writing `(m:Method)-[:CONTAINS]->(c:Component)` will always return zero rows.
10. **IntraPath query**: `IntraPath` nodes are NOT attached to Method nodes via `HAS_INTRA_PATH` for all paths. The most reliable query is `MATCH (ip:IntraPath) RETURN ip.source, ip.sink, ip.confidence, ip.synthetic` directly, rather than traversing from Method.
11. **CrossPath channel types** in use: `EXPLICIT_INTENT`, `IMPLICIT_INTENT`, `STATIC_FIELD`, `DYNAMIC_BROADCAST`, `SET_RESULT`, `CONTENT_PROVIDER_EXPORT`. When searching for service/activity exposure, use `EXPLICIT_INTENT` or `IMPLICIT_INTENT`, not `CONTENT_PROVIDER_EXPORT` (which is only for ContentProvider escalation paths).
12. **SAST+Method→Component**: To confirm whether a SAST-flagged method is in an exported component, use the three-hop query: `MATCH (c:Component)-[:CONTAINS]->(m:Method)-[:EVIDENCED_BY]->(sf:SASTFinding) WHERE sf.fused_score > 0.5 RETURN c.name, c.exported, m.sig, sf.title, sf.fused_score`.
