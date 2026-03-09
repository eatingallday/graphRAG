"""
HPG schema description for Text2CypherRetriever.
Keep this in sync with the node labels/properties written by builder.py.
"""

HPG_SCHEMA = """
Node labels and properties:

Component {
  name: str,               -- e.g., "UserDetailsContentProvider"
  type: str,               -- 'activity' | 'service' | 'provider' | 'receiver'
  exported: bool,          -- true = reachable by external apps (attack entry)
  authority: str,          -- provider only: content URI authority
  root_path_protected: bool, -- false = root path has NO readPermission (vulnerability flag)
  vuln_description: str,   -- written by Manifest Agent
  analysis_confidence: float
}

Method {
  sig: str,        -- Soot-format signature, e.g. "<edu.ksu.cs.benign.provider.UserDetailsContentProvider: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[],java.lang.String)>"
  name: str,       -- short method name, e.g. "query"
  class: str,      -- owner class name
  is_entry: bool,  -- true = can be called externally (ContentProvider query/insert/delete/update)
  taint_role: str, -- 'source'|'sink'|'propagate'|'sanitizer'|'unknown'  (written by Taint Agent)
  confidence: float
}

Permission {
  name: str,              -- e.g., "edu.ksu.cs.benign.permission.internalRead"
  protectionLevel: str    -- 'normal'|'dangerous'|'signature'
}

PathPermission {
  pathPrefix: str,      -- e.g., "/user"
  readPermission: str   -- required permission name
}

StringConst {
  value: str,        -- e.g., "/user/ssn"
  sensitivity: str,  -- 'HIGH'|'MEDIUM'|'LOW'
  type: str          -- 'uri_path'|'string_literal'
}

IntraPath {
  id: str,
  source: str,      -- FlowDroid source method sig (Soot format)
  sink: str,        -- FlowDroid sink method sig
  layer: str,       -- "A" (always)
  confidence: float
}

CrossPath {
  id: str,
  entry_component: str,  -- attack entry component name
  attack_vector: str,    -- human-readable attack description
  intra_path_id: str,    -- linked IntraPath id
  layer: str,            -- "B" (always)
  confidence: float
}

Relationship types:
- CONTAINS:             (Component)-[:CONTAINS]->(Method)
- REQUIRES_PERM:        (Component)-[:REQUIRES_PERM]->(Permission)
- HAS_PATH_PERMISSION:  (Component)-[:HAS_PATH_PERMISSION]->(PathPermission)
- ACCESSES:             (Method)-[:ACCESSES]->(StringConst)
- DIRECT_CALL:          (Method)-[:DIRECT_CALL]->(Method)
- HAS_INTRA_PATH:       (Method)-[:HAS_INTRA_PATH]->(IntraPath)
- ESCALATED_TO:         (IntraPath)-[:ESCALATED_TO]->(CrossPath)
"""
