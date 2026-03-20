"""
Structured trace logging utilities for pipeline debugging.

All events are written as JSON lines so execution can be replayed step-by-step.
"""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime
from typing import Any

_TRACE_LOCK = threading.Lock()
_TRACE_PATH: str | None = None


def _safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "")
    return cleaned.strip("_") or "run"


def _default_trace_path() -> str:
    try:
        from config import OUTPUT_DIR

        return os.path.join(OUTPUT_DIR, "pipeline_trace.jsonl")
    except Exception:
        return os.path.join(os.getcwd(), "pipeline_trace.jsonl")


def set_trace_file(path: str, reset: bool = False) -> str:
    """Set active trace output file path."""
    global _TRACE_PATH
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if reset and os.path.exists(path):
        os.remove(path)
    _TRACE_PATH = path
    return _TRACE_PATH


def init_trace_for_run(output_dir: str, apk_name: str = "") -> str:
    """Initialize per-run trace file under output_dir."""
    safe_name = _safe_filename(apk_name) if apk_name else "run"
    path = os.path.join(output_dir, f"pipeline_trace_{safe_name}.jsonl")
    set_trace_file(path, reset=True)
    trace_event(
        "trace_init",
        {
            "apk_name": apk_name,
            "trace_path": path,
            "cwd": os.getcwd(),
        },
    )
    return path


def _json_default(value: Any):
    if isinstance(value, set):
        return sorted(value)
    return str(value)


def _active_trace_path() -> str:
    return _TRACE_PATH or os.environ.get("PIPELINE_TRACE_FILE", _default_trace_path())


def trace_event(event: str, data: Any | None = None, agent: str | None = None):
    """Append one structured event record."""
    if os.environ.get("PIPELINE_TRACE_DISABLED", "0") == "1":
        return
    record: dict[str, Any] = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "event": event,
    }
    if agent:
        record["agent"] = agent
    if data is not None:
        record["data"] = data

    line = json.dumps(record, ensure_ascii=False, default=_json_default)
    path = _active_trace_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with _TRACE_LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def summarize_value(value: Any, preview_chars: int = 300) -> Any:
    """Compact representation for verbose values in state snapshots."""
    if isinstance(value, str):
        if len(value) <= preview_chars:
            return value
        return {
            "type": "str",
            "len": len(value),
            "preview": value[:preview_chars] + "...",
        }
    if isinstance(value, dict):
        return {
            "type": "dict",
            "size": len(value),
            "sample_keys": list(value.keys())[:10],
        }
    if isinstance(value, list):
        return {
            "type": "list",
            "size": len(value),
            "sample": value[:5],
        }
    return value


def summarize_state(state: dict[str, Any] | None) -> dict[str, Any]:
    """Produce a compact, stable state summary for tracing."""
    if not isinstance(state, dict):
        return {"type": type(state).__name__}

    summary: dict[str, Any] = {}
    for key, value in state.items():
        if key in {"app_smali", "app_java"} and isinstance(value, dict):
            summary[key] = {
                "type": "dict",
                "size": len(value),
                "sample_keys": list(value.keys())[:10],
            }
            continue
        summary[key] = summarize_value(value)
    return summary


def log_file_output(path: str, label: str = "", agent: str | None = None):
    """Trace metadata of generated files."""
    info = {
        "label": label,
        "path": path,
        "exists": os.path.exists(path),
    }
    if os.path.exists(path):
        stat = os.stat(path)
        info.update(
            {
                "size_bytes": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            }
        )
    trace_event("file_output", info, agent=agent)
