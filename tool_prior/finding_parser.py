"""
Parse heterogeneous SAST reports into NormalizedFinding records.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .finding_schema import NormalizedFinding

_URL_RE = re.compile(r"https?://[^\s)>\]\"']+")
_CWE_RE = re.compile(r"CWE-\d+")
_SMALI_SIG_RE = re.compile(r"(L[\w/$]+;)->([\w$<>]+)\(([^)]*)\)([\w/$\[\];]+)")
_AUSERA_SECTION_RE = re.compile(r"=+\[(.+?)\]:\[(.+?)\]=+")
_ANDROBUGS_HEADER_RE = re.compile(
    r"^\[(Critical|Warning|Notice|Info)\]\s*(?:<([^>]+)>\s*)?(.+?):\s*$",
    re.MULTILINE,
)
_SPECK_RULE_RE = re.compile(r"^\[§\]\s*RULE:\s*(\d+)\s*$", re.MULTILINE)

_SMALI_TO_JAVA = {
    "V": "void",
    "Z": "boolean",
    "B": "byte",
    "C": "char",
    "S": "short",
    "I": "int",
    "J": "long",
    "F": "float",
    "D": "double",
}


def _slugify(text: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return value or "unknown_rule"


def _safe_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _extract_urls(text: str) -> list[str]:
    if not text:
        return []
    return sorted(set(_URL_RE.findall(text)))


def _extract_cwe_ids(text: str) -> list[str]:
    if not text:
        return []
    return sorted(set(_CWE_RE.findall(text)))


def _smali_type_to_java(t: str) -> str:
    if t in _SMALI_TO_JAVA:
        return _SMALI_TO_JAVA[t]
    if t.startswith("["):
        return _smali_type_to_java(t[1:]) + "[]"
    if t.startswith("L") and t.endswith(";"):
        return t[1:-1].replace("/", ".")
    return t


def _smali_params_to_java(params: str) -> str:
    if not params:
        return ""
    parts: list[str] = []
    i = 0
    while i < len(params):
        if params[i] == "[":
            j = i + 1
            while j < len(params) and params[j] == "[":
                j += 1
            if j < len(params) and params[j] == "L":
                end = params.find(";", j)
                if end == -1:
                    break
                end += 1
                parts.append(_smali_type_to_java(params[i:end]))
                i = end
            else:
                parts.append(_smali_type_to_java(params[i : j + 1]))
                i = j + 1
        elif params[i] == "L":
            end = params.find(";", i)
            if end == -1:
                break
            end += 1
            parts.append(_smali_type_to_java(params[i:end]))
            i = end
        else:
            parts.append(_smali_type_to_java(params[i]))
            i += 1
    return ",".join(parts)


def _build_soot_sig(cls: str, ret: str, name: str, params: str) -> str:
    java_cls = cls.replace("/", ".")
    java_ret = _smali_type_to_java(ret)
    java_params = _smali_params_to_java(params)
    return f"<{java_cls}: {java_ret} {name}({java_params})>"


def _normalize_method_signature(raw: str) -> str:
    if not raw:
        return ""
    text = raw.strip()
    if text.startswith("<") and text.endswith(">") and ": " in text:
        return text
    m = _SMALI_SIG_RE.search(text)
    if not m:
        return ""
    cls, name, params, ret = m.groups()
    return _build_soot_sig(cls[1:-1], ret, name, params)


def _extract_class_from_sig(method_signature: str) -> str:
    if not method_signature.startswith("<") or ": " not in method_signature:
        return ""
    return method_signature[1:].split(": ", 1)[0]


def _normalize_severity(tool: str, value: Any) -> tuple[str, str]:
    raw = str(value or "").strip()
    low = raw.lower()

    if tool == "androbugs":
        mapping = {
            "critical": "critical",
            "warning": "medium",
            "notice": "low",
            "info": "info",
        }
        return mapping.get(low, "info"), raw

    if tool == "apkhunt":
        return "info", raw or "Advisory"

    if tool == "ausera":
        mapping = {"high": "high", "medium": "medium", "low": "low"}
        return mapping.get(low, "info"), raw

    if tool == "droidstatx":
        return ("high" if low in {"true", "1", "yes"} else "info"), raw

    if tool == "jaadas":
        mapping = {"0": "info", "1": "low", "2": "medium", "3": "high"}
        return mapping.get(low, "info"), raw

    if tool == "marvin":
        mapping = {"0": "info", "1": "low", "2": "medium", "3": "high"}
        return mapping.get(low, "info"), raw

    if tool == "mobsf":
        mapping = {
            "critical": "critical",
            "high": "high",
            "warning": "medium",
            "medium": "medium",
            "low": "low",
            "info": "info",
            "good": "info",
            "secure": "info",
        }
        return mapping.get(low, "info"), raw

    if tool == "qark":
        mapping = {"critical": "critical", "warning": "medium", "info": "info"}
        return mapping.get(low, "info"), raw

    if tool == "speck":
        mapping = {
            "critical": "critical",
            "warning": "medium",
            "ok": "info",
            "none": "info",
            "na": "info",
        }
        return mapping.get(low, "info"), raw

    if tool == "super":
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "warning": "low",
        }
        return mapping.get(low, "info"), raw

    if tool == "trueseeing":
        mapping = {"high": "high", "medium": "medium", "low": "low", "info": "info"}
        return mapping.get(low, "info"), raw

    return "info", raw


def _signal_from_tool_severity(tool: str, original: str) -> str:
    low = (original or "").strip().lower()
    if tool in {"mobsf", "speck"} and low in {"good", "ok", "secure"}:
        return "hardening_present"
    return "vulnerability"


def _load_json_from_text(text: str) -> dict | list | None:
    stripped = text.strip()
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(stripped[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None


def _extract_first_python_dict_blob(text: str) -> str:
    start = text.find("{")
    if start < 0:
        return ""
    depth = 0
    in_str = False
    quote = ""
    escaped = False
    for idx, ch in enumerate(text[start:], start=start):
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                in_str = False
            continue
        if ch in {"'", '"'}:
            in_str = True
            quote = ch
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : idx + 1]
    return ""


def detect_tool(file_path: str) -> str:
    """Infer tool name from filename and content sniffing."""
    path = Path(file_path)
    name = path.name.lower()

    filename_patterns = [
        ("_androbugs.txt", "androbugs"),
        ("_apkhunt.txt", "apkhunt"),
        ("_ausera.txt", "ausera"),
        ("_droidstatx.txt", "droidstatx"),
        ("_jaadas.txt", "jaadas"),
        ("_marvin.txt", "marvin"),
        ("_mobsf.txt", "mobsf"),
        ("_qark.xml", "qark"),
        ("_speck.txt", "speck"),
        ("_super.json", "super"),
        ("_trueseeing.json", "trueseeing"),
        ("trueseeing_report.json", "trueseeing"),
    ]
    for suffix, tool in filename_patterns:
        if name.endswith(suffix):
            return tool

    text = path.read_text(encoding="utf-8", errors="ignore")
    data = _load_json_from_text(text)
    if isinstance(data, dict):
        if "super_version" in data:
            return "super"
        if "issues" in data and "app" in data:
            return "trueseeing"
        if "results" in data and "md5hash" in data:
            return "jaadas"
        if "manifest_analysis" in data or "certificate_analysis" in data:
            return "mobsf"

    low = text.lower()
    if "<issue" in low and "</issue>" in low:
        return "qark"
    if "androbugs framework" in low:
        return "androbugs"
    if "ausera (apk engine)" in low:
        return "ausera"
    if "[§] rule:" in low:
        return "speck"
    if "owasp masvs static analyzer" in low or "apkhunt report" in low:
        return "apkhunt"
    if "activitieswithoutflagsecure:" in low and "allowbackup:" in low:
        return "droidstatx"
    if "saaf-module" in low and "reference_method" in low:
        return "marvin"

    raise ValueError(f"Unable to detect tool from: {file_path}")


def _parse_trueseeing(data: dict) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for issue in data.get("issues", []):
        detector = issue.get("detector") or issue.get("sig") or ""
        severity, original = _normalize_severity("trueseeing", issue.get("severity"))
        description = " ".join(
            p.strip()
            for p in [issue.get("synopsis", ""), issue.get("description", "")]
            if p and str(p).strip()
        ).strip()
        refs: list[str] = []
        seealso = issue.get("seealso")
        if isinstance(seealso, str):
            refs.extend(_extract_urls(seealso))
        elif isinstance(seealso, list):
            for item in seealso:
                refs.extend(_extract_urls(str(item)))
        refs = sorted(set(refs))

        instances = issue.get("instances") or [{}]
        for inst in instances:
            source = str(inst.get("source") or "")
            method_sig = _normalize_method_signature(source)
            file_path = source if source.endswith(".xml") or source.endswith(".java") else ""
            if source and not file_path and "/" in source and not method_sig:
                file_path = source

            finding = NormalizedFinding(
                tool_name="trueseeing",
                rule_id=detector or _slugify(issue.get("summary", "trueseeing_issue")),
                title=issue.get("summary") or detector or "trueseeing finding",
                description=description,
                severity=severity,
                original_severity=original,
                cvss_score=_safe_float(issue.get("cvss3_score")),
                cvss_vector=str(issue.get("cvss3_vector") or ""),
                file_path=file_path,
                line_number=_safe_int(inst.get("row")),
                column_number=_safe_int(inst.get("col")),
                method_signature=method_sig,
                class_name=_extract_class_from_sig(method_sig),
                code_snippet="",
                matched_string=str(inst.get("info") or ""),
                category=(detector.split("-", 1)[0] if detector else ""),
                cwe_ids=_extract_cwe_ids(description),
                reference_urls=refs,
                recommendation=str(issue.get("solution") or ""),
                signal_polarity="observation"
                if any(k in detector for k in ("detect-", "fingerprint", "observe"))
                else "vulnerability",
            )
            findings.append(finding)
    return findings


def _parse_super(data: dict) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for bucket in ("criticals", "highs", "mediums", "lows", "warnings"):
        for item in data.get(bucket, []):
            criticality = str(item.get("criticality") or bucket.rstrip("s"))
            severity, original = _normalize_severity("super", criticality)
            name = str(item.get("name") or "super finding")
            findings.append(
                NormalizedFinding(
                    tool_name="super",
                    rule_id=_slugify(name),
                    title=name,
                    description=str(item.get("description") or ""),
                    severity=severity,
                    original_severity=original,
                    file_path=str(item.get("file") or ""),
                    line_number=_safe_int(item.get("line")),
                    code_snippet=str(item.get("code") or ""),
                    category="super_builtin",
                )
            )
    return findings


def _parse_jaadas(data: dict) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for result in data.get("results", []):
        desc = str(result.get("desc") or "jaadas finding")
        severity, original = _normalize_severity("jaadas", result.get("vulnKind"))
        method_sig = _normalize_method_signature(str(result.get("sourceMethod") or ""))
        call_path = []
        for path in result.get("paths", []) or []:
            if isinstance(path, list):
                call_path.extend(str(p) for p in path)
            else:
                call_path.append(str(path))
        findings.append(
            NormalizedFinding(
                tool_name="jaadas",
                rule_id=desc,
                title=desc,
                description=str(result.get("custom") or ""),
                severity=severity,
                original_severity=original,
                method_signature=method_sig,
                class_name=_extract_class_from_sig(method_sig),
                matched_string=str(result.get("sourceStmt") or ""),
                call_path=call_path,
                category="jaadas_result",
            )
        )
    return findings


def _parse_mobsf(data: dict) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []

    manifest_findings = (
        data.get("manifest_analysis", {}) or {}
    ).get("manifest_findings", []) or []
    for item in manifest_findings:
        severity, original = _normalize_severity("mobsf", item.get("severity"))
        findings.append(
            NormalizedFinding(
                tool_name="mobsf",
                rule_id=str(item.get("rule") or _slugify(item.get("title", "manifest_finding"))),
                title=str(item.get("title") or item.get("name") or "manifest finding"),
                description=str(item.get("description") or ""),
                severity=severity,
                original_severity=original,
                file_path="AndroidManifest.xml",
                affected_components=[str(c) for c in (item.get("component") or [])],
                component_name=str((item.get("component") or [""])[0] if item.get("component") else ""),
                category="manifest",
                signal_polarity=_signal_from_tool_severity("mobsf", original),
            )
        )

    code_findings = (data.get("code_analysis", {}) or {}).get("findings", {}) or {}
    for rule_id, payload in code_findings.items():
        metadata = payload.get("metadata", {}) if isinstance(payload, dict) else {}
        files = payload.get("files", {}) if isinstance(payload, dict) else {}
        severity, original = _normalize_severity("mobsf", metadata.get("severity"))
        cwe_ids = _extract_cwe_ids(str(metadata.get("cwe") or ""))
        refs = _extract_urls(str(metadata.get("ref") or ""))
        title = str(metadata.get("description") or rule_id)
        if not files:
            findings.append(
                NormalizedFinding(
                    tool_name="mobsf",
                    rule_id=str(rule_id),
                    title=title,
                    description=str(metadata.get("message") or metadata.get("description") or ""),
                    severity=severity,
                    original_severity=original,
                    category="code",
                    cwe_ids=cwe_ids,
                    reference_urls=refs,
                    signal_polarity=_signal_from_tool_severity("mobsf", original),
                )
            )
            continue
        for file_path, line_blob in files.items():
            first_line = None
            if isinstance(line_blob, str):
                for token in line_blob.split(","):
                    token = token.strip()
                    if token.isdigit():
                        first_line = int(token)
                        break
            findings.append(
                NormalizedFinding(
                    tool_name="mobsf",
                    rule_id=str(rule_id),
                    title=title,
                    description=str(metadata.get("message") or metadata.get("description") or ""),
                    severity=severity,
                    original_severity=original,
                    file_path=str(file_path),
                    line_number=first_line,
                    category="code",
                    cwe_ids=cwe_ids,
                    reference_urls=refs,
                    signal_polarity=_signal_from_tool_severity("mobsf", original),
                )
            )

    cert_findings = (data.get("certificate_analysis", {}) or {}).get("certificate_findings", []) or []
    for entry in cert_findings:
        if not isinstance(entry, list) or len(entry) < 3:
            continue
        sev, desc, title = entry[0], entry[1], entry[2]
        severity, original = _normalize_severity("mobsf", sev)
        findings.append(
            NormalizedFinding(
                tool_name="mobsf",
                rule_id=_slugify(title),
                title=str(title),
                description=str(desc),
                severity=severity,
                original_severity=original,
                category="certificate",
                signal_polarity=_signal_from_tool_severity("mobsf", original),
            )
        )

    network_findings = (data.get("network_security", {}) or {}).get("network_findings", []) or []
    for item in network_findings:
        severity, original = _normalize_severity("mobsf", item.get("severity"))
        findings.append(
            NormalizedFinding(
                tool_name="mobsf",
                rule_id=_slugify(str(item.get("scope") or "network_security")),
                title=str(item.get("scope") or "Network Security Finding"),
                description=str(item.get("description") or ""),
                severity=severity,
                original_severity=original,
                category="network_security",
                signal_polarity=_signal_from_tool_severity("mobsf", original),
            )
        )

    binary_findings = data.get("binary_analysis", []) or []
    for lib in binary_findings:
        if not isinstance(lib, dict):
            continue
        lib_name = str(lib.get("name") or "")
        for key, value in lib.items():
            if not isinstance(value, dict):
                continue
            if "severity" not in value:
                continue
            severity, original = _normalize_severity("mobsf", value.get("severity"))
            findings.append(
                NormalizedFinding(
                    tool_name="mobsf",
                    rule_id=f"binary_{_slugify(key)}",
                    title=f"Binary {key}",
                    description=str(value.get("description") or ""),
                    severity=severity,
                    original_severity=original,
                    file_path=lib_name,
                    category="binary",
                    signal_polarity=_signal_from_tool_severity("mobsf", original),
                )
            )

    return findings


def _parse_qark(xml_text: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    text = xml_text.strip()
    if not text:
        return findings
    # QARK report can contain an XML declaration followed by multiple rootless <issue> entries.
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text, flags=re.IGNORECASE).strip()
    wrapped = f"<root>{text}</root>"
    root = ET.fromstring(wrapped)
    for issue in root.findall("issue"):
        severity, original = _normalize_severity("qark", issue.findtext("severity"))
        title = (issue.findtext("name") or "qark finding").strip()
        rule_id = (issue.get("issueid") or "").strip() or _slugify(title)
        findings.append(
            NormalizedFinding(
                tool_name="qark",
                rule_id=rule_id,
                title=title,
                severity=severity,
                original_severity=original,
                category="qark_issue",
            )
        )
    return findings


def _parse_ausera(text: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    matches = list(_AUSERA_SECTION_RE.finditer(text))
    for idx, match in enumerate(matches):
        title = match.group(1).strip()
        original_sev = match.group(2).strip()
        severity, original = _normalize_severity("ausera", original_sev)
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        body = text[start:end].strip()

        class_method_pairs = re.findall(
            r"ClassName:\s*([^;]+);\s*MethodName:\s*([^\n\r]+)",
            body,
        )
        description = "\n".join(
            line.strip()
            for line in body.splitlines()
            if line.strip() and not line.strip().startswith("ClassName:")
        ).strip()

        if class_method_pairs:
            for class_name, method_name in class_method_pairs:
                findings.append(
                    NormalizedFinding(
                        tool_name="ausera",
                        rule_id=_slugify(title),
                        title=title,
                        description=description,
                        severity=severity,
                        original_severity=original,
                        method_signature=f"{class_name.strip()}.{method_name.strip()}",
                        class_name=class_name.strip(),
                        category="ausera_section",
                    )
                )
        else:
            findings.append(
                NormalizedFinding(
                    tool_name="ausera",
                    rule_id=_slugify(title),
                    title=title,
                    description=description,
                    severity=severity,
                    original_severity=original,
                    category="ausera_section",
                )
            )
    return findings


def _parse_androbugs(text: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    matches = list(_ANDROBUGS_HEADER_RE.finditer(text))

    rule_map: list[tuple[str, str]] = [
        ("ssl connection checking", "SSL_URLS_NOT_IN_HTTPS"),
        ("androidmanifest adb backup checking", "ALLOW_BACKUP"),
        ("runtime command checking", "COMMAND"),
        ("executing \"root\" or system privilege checking", "COMMAND_SU"),
        ("sqlitedatabase transaction deprecated checking", "DB_DEPRECATED_USE1"),
        ("sqlite encryption extension (see)", "DB_SEE"),
        ("sqlcipher", "DB_SQLCIPHER"),
        ("sqlite databases vulnerability checking", "DB_SQLITE_JOURNAL"),
        ("android debug mode checking", "DEBUGGABLE"),
        ("dynamic code loading", "DYNAMIC_CODE_LOADING"),
        ("external storage accessing", "EXTERNAL_STORAGE"),
        ("file unsafe delete checking", "FILE_DELETE"),
        ("fragment vulnerability checking", "FRAGMENT_INJECTION"),
        ("base64 string encryption", "HACKER_BASE64_STRING_DECODE"),
        ("key for android sqlite databases encryption", "HACKER_DB_KEY"),
        ("keystore protection checking", "HACKER_KEYSTORE_NO_PWD"),
        ("httpurlconnection android bug checking", "HTTPURLCONNECTION_BUG"),
        ("keystore type checking", "KEYSTORE_TYPE_CHECK"),
        ("master key type i vulnerability", "MASTER_KEY"),
        ("app sandbox permission checking", "MODE_WORLD_READABLE_OR_MODE_WORLD_WRITEABLE"),
        ("dangerous protectionlevel of permission checking", "PERMISSION_DANGEROUS"),
        ("exported components checking", "PERMISSION_EXPORTED"),
        ("permissiongroup checking", "PERMISSION_GROUP_EMPTY_VALUE"),
        ("implicit service checking", "PERMISSION_IMPLICIT_SERVICE"),
        ("\"intent-filter\" settings checking", "PERMISSION_INTENT_FILTER_MISCONFIG"),
        ("normal protectionlevel of permission checking", "PERMISSION_NORMAL"),
        ("exported lost prefix checking", "PERMISSION_NO_PREFIX_EXPORTED"),
        ("contentprovider exported checking", "PERMISSION_PROVIDER_EXPLICIT_EXPORTED"),
        ("getting imei and device id", "SENSITIVE_DEVICE_ID"),
        ("getting android_id", "SENSITIVE_SECURE_ANDROID_ID"),
        ("codes for sending sms", "SENSITIVE_SMS"),
        ("shareduserid checking", "SHARED_USER_ID"),
        ("verifying host name in custom classes", "SSL_CN1"),
        ("verifying host name in fields", "SSL_CN2"),
        ("insecure component", "SSL_CN3"),
        ("httphost", "SSL_DEFAULT_SCHEME_NAME"),
        ("webviewclient for webview", "SSL_WEBVIEW"),
        ("ssl certificate verification checking", "SSL_X509"),
        ("unnecessary permission checking", "USE_PERMISSION_ACCESS_MOCK_LOCATION"),
        ("accessing the internet checking", "USE_PERMISSION_INTERNET"),
        ("system use permission checking", "USE_PERMISSION_SYSTEM_APP"),
        ("webview local file access attacks checking", "WEBVIEW_ALLOW_FILE_ACCESS"),
        ("webview potential xss attacks checking", "WEBVIEW_JS_ENABLED"),
        ("webview rce vulnerability checking", "WEBVIEW_RCE"),
    ]

    def mapped_rule_id(tag: str, title: str) -> str:
        low = title.lower().strip()
        for needle, rule in rule_map:
            if needle in low:
                return rule
        if tag:
            return tag
        return _slugify(title)

    for idx, match in enumerate(matches):
        original_sev = match.group(1)
        tag = (match.group(2) or "").strip()
        title = match.group(3).strip()
        severity, original = _normalize_severity("androbugs", original_sev)

        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        urls = _extract_urls(body)
        cwe_ids = _extract_cwe_ids(body)

        method_refs = set(re.findall(r"=>\s*(L[\w/$]+;->[\w$<>]+\([^)]*\)[\w/$\[\];]+)", body))
        method_refs.update(re.findall(r"(L[\w/$]+;->[\w$<>]+\([^)]*\)[\w/$\[\];]+)", body))

        if method_refs:
            for ref in sorted(method_refs):
                soot = _normalize_method_signature(ref)
                findings.append(
                    NormalizedFinding(
                        tool_name="androbugs",
                        rule_id=mapped_rule_id(tag, title),
                        title=title,
                        description=body,
                        severity=severity,
                        original_severity=original,
                        method_signature=soot,
                        class_name=_extract_class_from_sig(soot),
                        matched_string=ref,
                        category=tag or "androbugs",
                        cwe_ids=cwe_ids,
                        reference_urls=urls,
                    )
                )
        else:
            findings.append(
                NormalizedFinding(
                    tool_name="androbugs",
                    rule_id=mapped_rule_id(tag, title),
                    title=title,
                    description=body,
                    severity=severity,
                    original_severity=original,
                    category=tag or "androbugs",
                    cwe_ids=cwe_ids,
                    reference_urls=urls,
                )
            )
    return findings


def _parse_speck(text: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    rule_matches = list(_SPECK_RULE_RE.finditer(text))
    for idx, match in enumerate(rule_matches):
        rule_no = match.group(1)
        start = match.end()
        end = rule_matches[idx + 1].start() if idx + 1 < len(rule_matches) else len(text)
        block = text[start:end]
        lines = [line.rstrip() for line in block.splitlines()]
        title = ""
        for line in lines:
            if line.strip():
                title = line.strip()
                break
        if not title:
            title = f"Rule {rule_no}"

        if "No violation has been found" in block:
            continue

        cur_file = ""
        cur_msg = ""
        cur_sev = "info"
        produced = 0
        for line in lines:
            if "CRITICAL issue" in line:
                cur_sev = "critical"
            elif "WARNING" in line:
                cur_sev = "medium"

            m_file = re.match(r"^\[(?:EXTERNAL|INTERNAL)\]\s*>>>\s*(.+)$", line.strip())
            if m_file:
                cur_file = m_file.group(1).strip()
                continue

            if line.strip().startswith("* "):
                cur_msg = line.strip()[2:].strip()
                continue

            m_loc = re.match(r"^- at line (\d+):\s*'?(.*?)'?\s*$", line.strip())
            if not m_loc:
                continue

            findings.append(
                NormalizedFinding(
                    tool_name="speck",
                    rule_id=f"rule_{rule_no}",
                    title=title,
                    description=cur_msg,
                    severity=cur_sev,
                    original_severity=cur_sev,
                    file_path=cur_file,
                    line_number=_safe_int(m_loc.group(1)),
                    code_snippet=m_loc.group(2),
                    category=f"Rule {rule_no}",
                )
            )
            produced += 1

        if produced == 0 and ("CRITICAL issue" in block or "WARNING" in block):
            findings.append(
                NormalizedFinding(
                    tool_name="speck",
                    rule_id=f"rule_{rule_no}",
                    title=title,
                    description=cur_msg,
                    severity=cur_sev,
                    original_severity=cur_sev,
                    file_path=cur_file,
                    category=f"Rule {rule_no}",
                )
            )
    return findings


def _parse_marvin(text: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    blob = _extract_first_python_dict_blob(text)
    if not blob:
        return findings
    try:
        data = ast.literal_eval(blob)
    except (SyntaxError, ValueError):
        return findings
    if not isinstance(data, dict):
        return findings

    for category, items in data.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            severity, original = _normalize_severity("marvin", item.get("severity"))
            class_path = str(item.get("reference_class") or "")
            class_name = class_path.replace("/", ".").replace(".java", "")
            method_name = str(item.get("reference_method") or "")
            method_signature = f"{class_name}.{method_name}" if class_name and method_name else ""
            desc = str(item.get("description") or "")
            findings.append(
                NormalizedFinding(
                    tool_name="marvin",
                    rule_id=str(category),
                    title=str(category).replace("_", " ").title(),
                    description=desc,
                    severity=severity,
                    original_severity=original,
                    file_path=class_path,
                    method_signature=method_signature,
                    class_name=class_name,
                    category=str(category),
                    confidence=_safe_float(item.get("confidence")),
                )
            )
    return findings


def _parse_list_value(raw: str) -> list[str]:
    text = raw.strip()
    if not text.startswith("[") or not text.endswith("]"):
        return []
    try:
        parsed = ast.literal_eval(text)
        if isinstance(parsed, list):
            return [str(x) for x in parsed]
    except (SyntaxError, ValueError):
        pass
    inner = text[1:-1].strip()
    if not inner:
        return []
    return [part.strip().strip("'").strip('"') for part in inner.split(",") if part.strip()]


def _parse_bool_value(raw: str) -> bool | None:
    low = raw.strip().lower()
    if low in {"true", "yes", "1"}:
        return True
    if low in {"false", "no", "0"}:
        return False
    return None


def _parse_droidstatx(text: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    kv: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        kv[key.strip()] = value.strip()

    bool_findings = [
        ("debuggable", "App debuggable enabled", "high"),
        ("allowBackup", "ADB backup enabled", "medium"),
    ]
    for key, title, sev in bool_findings:
        flag = _parse_bool_value(kv.get(key, ""))
        if flag:
            findings.append(
                NormalizedFinding(
                    tool_name="droidstatx",
                    rule_id=_slugify(key),
                    title=title,
                    severity=sev,
                    original_severity="True",
                    category=key,
                )
            )

    list_fields = [
        ("exportedActivities", "Exported activity", "high", "component"),
        ("exportedProviders", "Exported content provider", "high", "component"),
        ("exportedReceivers", "Exported receiver", "high", "component"),
        ("exportedServices", "Exported service", "high", "component"),
        ("activitiesWithoutFlagSecure", "Activity missing FLAG_SECURE", "high", "component"),
        ("vulnerableContentProvidersSQLiLocations", "Potential provider SQLi location", "high", "code"),
        ("vulnerableContentProvidersPathTraversalLocations", "Potential provider path traversal location", "high", "code"),
        ("vulnerableHostnameVerifiers", "Vulnerable hostname verifier", "high", "code"),
        ("vulnerableSetHostnameVerifiers", "Vulnerable setHostnameVerifier usage", "high", "code"),
        ("vulnerableTrustManagers", "Vulnerable trust manager", "high", "code"),
        ("vulnerableWebViewSSLErrorBypass", "WebView SSL error bypass", "high", "code"),
        ("webViewAddJavascriptInterfaceUsageLocation", "WebView addJavascriptInterface usage", "medium", "code"),
        ("webViewLoadUrlUsageLocation", "WebView loadUrl usage", "low", "code"),
    ]
    for key, title, sev, kind in list_fields:
        values = _parse_list_value(kv.get(key, "[]"))
        for val in values:
            findings.append(
                NormalizedFinding(
                    tool_name="droidstatx",
                    rule_id=_slugify(key),
                    title=title,
                    severity=sev,
                    original_severity=sev,
                    matched_string=val,
                    component_name=val if kind == "component" else "",
                    file_path=val if "/" in val or val.endswith(".smali") else "",
                    category=key,
                )
            )

    # Keep multidex as an informational observation.
    is_multidex = kv.get("isMultiDex", "").strip().lower()
    if is_multidex in {"yes", "true"}:
        findings.append(
            NormalizedFinding(
                tool_name="droidstatx",
                rule_id="is_multi_dex",
                title="App uses multidex",
                severity="info",
                original_severity=kv.get("isMultiDex", ""),
                category="isMultiDex",
                signal_polarity="observation",
            )
        )

    return findings


def _strip_html_tags(text: str) -> str:
    no_script = re.sub(r"<script[\s\S]*?</script>", "", text, flags=re.IGNORECASE)
    return re.sub(r"<[^>]+>", "", no_script)


def _extract_apkhunt_quicknote(section: str) -> str:
    m = re.search(r"\[\!\]\s*QuickNote:\s*(.*?)(?:\n\s*\[\*]|\Z)", section, re.DOTALL)
    if not m:
        return ""
    return " ".join(line.strip() for line in m.group(1).splitlines() if line.strip())


def _parse_apkhunt(text: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    clean = _strip_html_tags(text)

    if "Only Alphanumeric string with/without underscore/dash is accepted as APK file-name" in clean:
        findings.append(
            NormalizedFinding(
                tool_name="apkhunt",
                rule_id="invalid_apk_filename",
                title="APKHunt scan aborted due to filename constraint",
                description="APKHunt requires an alphanumeric APK filename with underscore/dash only.",
                severity="info",
                original_severity="Advisory",
                category="runtime_error",
                signal_polarity="observation",
            )
        )

    section_matches = list(re.finditer(r"^==>>\s+(.+?)\s*$", clean, re.MULTILINE))
    for idx, match in enumerate(section_matches):
        section_title = match.group(1).strip()
        start = match.end()
        end = section_matches[idx + 1].start() if idx + 1 < len(section_matches) else len(clean)
        body = clean[start:end]
        rule_id = _slugify(section_title)

        current_file = ""
        produced = 0
        for line in body.splitlines():
            candidate = line.strip()
            if not candidate:
                continue
            if candidate.startswith("/"):
                current_file = candidate
                continue
            m_line = re.match(r"^(\d+):\s*(.+)$", candidate)
            if m_line and current_file:
                findings.append(
                    NormalizedFinding(
                        tool_name="apkhunt",
                        rule_id=rule_id,
                        title=section_title,
                        description=_extract_apkhunt_quicknote(body),
                        severity="info",
                        original_severity="Advisory",
                        file_path=current_file,
                        line_number=_safe_int(m_line.group(1)),
                        code_snippet=m_line.group(2).strip(),
                        category="apkhunt_section",
                    )
                )
                produced += 1

        if produced == 0:
            note = _extract_apkhunt_quicknote(body)
            if note:
                findings.append(
                    NormalizedFinding(
                        tool_name="apkhunt",
                        rule_id=rule_id,
                        title=section_title,
                        description=note,
                        severity="info",
                        original_severity="Advisory",
                        category="apkhunt_section",
                        signal_polarity="observation",
                    )
                )
    return findings


def parse_report(file_path: str, tool_name: str | None = None) -> list[NormalizedFinding]:
    """Parse one report into normalized findings."""
    path = Path(file_path)
    text = path.read_text(encoding="utf-8", errors="ignore")
    tool = (tool_name or detect_tool(file_path)).strip().lower()

    if tool == "trueseeing":
        data = _load_json_from_text(text)
        return _parse_trueseeing(data if isinstance(data, dict) else {})
    if tool == "super":
        data = _load_json_from_text(text)
        return _parse_super(data if isinstance(data, dict) else {})
    if tool == "jaadas":
        data = _load_json_from_text(text)
        return _parse_jaadas(data if isinstance(data, dict) else {})
    if tool == "mobsf":
        data = _load_json_from_text(text)
        return _parse_mobsf(data if isinstance(data, dict) else {})
    if tool == "qark":
        return _parse_qark(text)
    if tool == "ausera":
        return _parse_ausera(text)
    if tool == "androbugs":
        return _parse_androbugs(text)
    if tool == "speck":
        return _parse_speck(text)
    if tool == "marvin":
        return _parse_marvin(text)
    if tool == "droidstatx":
        return _parse_droidstatx(text)
    if tool == "apkhunt":
        return _parse_apkhunt(text)

    raise ValueError(f"Unsupported tool: {tool}")


def _discover_report_files(base_dir: Path, recursive: bool) -> list[Path]:
    if recursive:
        files = [p for p in base_dir.rglob("*") if p.is_file()]
    else:
        files = [p for p in base_dir.iterdir() if p.is_file()]
    return [p for p in files if p.name != ".DS_Store"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normalize SAST reports to unified findings.")
    parser.add_argument("--dir", required=True, help="Directory containing reports")
    parser.add_argument("--recursive", action="store_true", help="Traverse subdirectories")
    args = parser.parse_args()

    base = Path(args.dir).resolve()
    files = _discover_report_files(base, recursive=args.recursive)

    tool_report_counts: Counter[str] = Counter()
    tool_finding_counts: Counter[str] = Counter()
    severity_counts: defaultdict[str, Counter[str]] = defaultdict(Counter)
    failed: list[tuple[str, str]] = []

    for file in files:
        try:
            tool = detect_tool(str(file))
            parsed = parse_report(str(file), tool_name=tool)
            tool_report_counts[tool] += 1
            tool_finding_counts[tool] += len(parsed)
            for finding in parsed:
                severity_counts[tool][finding.severity] += 1
        except Exception as exc:  # pragma: no cover - CLI diagnostics
            failed.append((str(file), str(exc)))

    print(f"Scanned files: {len(files)}")
    print(f"Parsed reports: {sum(tool_report_counts.values())}")
    print(f"Failed reports: {len(failed)}")
    for tool in sorted(tool_report_counts):
        sev = ", ".join(
            f"{k}={v}" for k, v in sorted(severity_counts[tool].items())
        )
        print(
            f"{tool:10s} reports={tool_report_counts[tool]:4d} "
            f"findings={tool_finding_counts[tool]:6d}  [{sev}]"
        )

    if failed:
        print("\nFailures:")
        for path, err in failed[:30]:
            print(f"- {path}: {err}")
