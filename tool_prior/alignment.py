"""
Three-layer deterministic alignment of fused findings to HPG nodes.
"""

from __future__ import annotations

from .fusion import FusedFinding


def _empty_alignment() -> dict:
    return {
        "status": "unmatched",
        "matched_node_type": None,
        "matched_node_id": None,
        "alignment_method": None,
        "candidates": [],
    }


def _fetch_components(session) -> list[dict]:
    return session.run(
        "MATCH (c:Component) "
        "RETURN c.name AS name, c.fullname AS fullname, c.type AS type, c.exported AS exported"
    ).data()


def _fetch_methods(session) -> list[dict]:
    return session.run(
        "MATCH (m:Method) RETURN m.sig AS sig, m.name AS name, m.class AS cls"
    ).data()


def _normalize_class_name(raw: str) -> str:
    return (raw or "").strip().lstrip("L").replace("/", ".").rstrip(";")


def _try_method(finding: FusedFinding, methods: list[dict]) -> dict | None:
    sig = (finding.method_signature or "").strip()
    if not sig:
        return None
    method_sigs = {m["sig"] for m in methods if m.get("sig")}
    if sig in method_sigs:
        return {"node_type": "Method", "node_id": sig, "method": "exact_method"}
    if not sig.startswith("<"):
        bracketed = f"<{sig}>"
        if bracketed in method_sigs:
            return {
                "node_type": "Method",
                "node_id": bracketed,
                "method": "exact_method_bracket",
            }
    return None


def _try_class(finding: FusedFinding, methods: list[dict]) -> dict | None:
    cls = _normalize_class_name(finding.class_name)
    if not cls:
        return None
    matched = [m for m in methods if (m.get("cls") or "") == cls]
    if not matched:
        return None
    return {
        "node_type": "Method",
        "node_id": matched[0]["sig"],
        "method": "class_match",
        "class_name": cls,
    }


def _try_component(finding: FusedFinding, components: list[dict]) -> dict | None:
    targets = []
    if (finding.component_name or "").strip():
        targets.append(finding.component_name.strip())
    targets.extend(c.strip() for c in finding.affected_components if c.strip())
    if not targets:
        return None

    name_map = {c["name"]: c for c in components if c.get("name")}
    fullname_map = {c.get("fullname"): c for c in components if c.get("fullname")}

    for target in targets:
        if target in name_map:
            return {
                "node_type": "Component",
                "node_id": target,
                "method": "exact_component",
            }
        if target in fullname_map:
            return {
                "node_type": "Component",
                "node_id": fullname_map[target]["name"],
                "method": "exact_component_full",
            }
        for component in components:
            fullname = component.get("fullname") or ""
            if fullname.endswith(f".{target}") or fullname.endswith(f"/{target}"):
                return {
                    "node_type": "Component",
                    "node_id": component["name"],
                    "method": "component_suffix",
                }
    return None


def _heur_package(finding: FusedFinding, components: list[dict]) -> dict | None:
    cls = _normalize_class_name(finding.class_name)
    if "." not in cls:
        return None
    pkg = ".".join(cls.split(".")[:-1])
    for component in components:
        component_fullname = component.get("fullname") or ""
        component_pkg = ".".join(component_fullname.split(".")[:-1])
        if component_pkg and (pkg.startswith(component_pkg) or component_pkg.startswith(pkg)):
            return {
                "node_type": "Component",
                "node_id": component["name"],
                "method": "package_prefix",
            }
    return None


def _heur_filepath(finding: FusedFinding, methods: list[dict]) -> dict | None:
    file_path = (finding.file_path or "").strip()
    if not file_path:
        return None

    cls = (
        file_path.replace(".java", "")
        .replace(".smali", "")
        .replace("/", ".")
        .replace("\\", ".")
    )
    for prefix in ("src.main.java.", "smali.", "smali_classes2.", "smali_classes3."):
        if cls.startswith(prefix):
            cls = cls[len(prefix) :]

    matched = [m for m in methods if (m.get("cls") or "") == cls]
    if not matched:
        return None
    return {
        "node_type": "Method",
        "node_id": matched[0]["sig"],
        "method": "filepath_to_class",
    }


def align_findings(fused: list[FusedFinding], driver) -> list[FusedFinding]:
    with driver.session() as session:
        components = _fetch_components(session)
        methods = _fetch_methods(session)

    for finding in fused:
        alignment = _empty_alignment()

        match = (
            _try_method(finding, methods)
            or _try_class(finding, methods)
            or _try_component(finding, components)
        )
        if match:
            alignment["status"] = "aligned"
            alignment["matched_node_type"] = match["node_type"]
            alignment["matched_node_id"] = match["node_id"]
            alignment["alignment_method"] = match["method"]
            finding.alignment = alignment
            continue

        candidates = []
        for fn, data in [(_heur_package, components), (_heur_filepath, methods)]:
            candidate = fn(finding, data)
            if candidate:
                candidates.append(candidate)

        if candidates:
            alignment["status"] = "candidate"
            alignment["candidates"] = candidates
            alignment["matched_node_type"] = candidates[0]["node_type"]
            alignment["matched_node_id"] = candidates[0]["node_id"]
            alignment["alignment_method"] = candidates[0]["method"]

        finding.alignment = alignment

    return fused
