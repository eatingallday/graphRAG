"""
JSON persistence helpers for ToolPrior instances.
"""

from __future__ import annotations

import json
import types
from dataclasses import fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Union, get_args, get_origin, get_type_hints

from .schema import ToolPrior

_UNION_ORIGINS = [Union]
if hasattr(types, "UnionType"):
    _UNION_ORIGINS.append(types.UnionType)


def _serialize(value: Any) -> Any:
    """Convert dataclasses/enums to JSON-safe primitives."""
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {
            field.name: _serialize(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _serialize(item) for key, item in value.items()}
    return value


def _deserialize_value(value: Any, annotation: Any) -> Any:
    if value is None or annotation is Any:
        return value

    origin = get_origin(annotation)
    args = get_args(annotation)

    if origin in (list, list[str].__origin__):
        item_type = args[0] if args else Any
        return [_deserialize_value(item, item_type) for item in value]

    if origin in (dict, dict[str, Any].__origin__):
        key_type = args[0] if len(args) > 0 else Any
        value_type = args[1] if len(args) > 1 else Any
        return {
            _deserialize_value(key, key_type): _deserialize_value(item, value_type)
            for key, item in value.items()
        }

    if origin in tuple(_UNION_ORIGINS):
        non_none_args = [arg for arg in args if arg is not type(None)]
        if len(non_none_args) == 1:
            return _deserialize_value(value, non_none_args[0])

    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return annotation(value)

    if isinstance(annotation, type) and is_dataclass(annotation):
        return _deserialize_dataclass(value, annotation)

    return value


def _deserialize_dataclass(data: dict[str, Any], cls: type[Any]) -> Any:
    type_hints = get_type_hints(cls)
    kwargs = {}
    for field in fields(cls):
        if field.name not in data:
            continue
        annotation = type_hints.get(field.name, field.type)
        kwargs[field.name] = _deserialize_value(data[field.name], annotation)
    return cls(**kwargs)


def save_prior(prior: ToolPrior, output_dir: str) -> str:
    """Save one ToolPrior as <tool_name>.json in output_dir."""
    if not prior.extracted_at:
        prior.extracted_at = datetime.now(timezone.utc).isoformat()

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"{prior.tool_name.strip().lower()}.json"
    path = Path(output_dir) / filename
    with path.open("w", encoding="utf-8") as fh:
        json.dump(_serialize(prior), fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return str(path)


def load_prior(json_path: str) -> ToolPrior:
    """Load a ToolPrior from a JSON file."""
    with open(json_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return _deserialize_dataclass(data, ToolPrior)


def save_all(priors: list[ToolPrior], output_dir: str) -> list[str]:
    """Save all priors. Returns list of written file paths."""
    return [save_prior(prior, output_dir) for prior in priors]


def load_all(json_dir: str) -> list[ToolPrior]:
    """Load all *.json files in a directory as ToolPrior instances."""
    base = Path(json_dir)
    if not base.exists():
        return []
    return [load_prior(str(path)) for path in sorted(base.glob("*.json"))]


def save_to_neo4j(prior: ToolPrior, driver) -> None:
    """Stub — Neo4j persistence is deferred to the online module."""
    raise NotImplementedError("Neo4j storage deferred to online module phase")
