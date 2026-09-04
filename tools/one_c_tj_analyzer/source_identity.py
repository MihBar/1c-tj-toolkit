"""Stable logical source identities; physical locations are separate evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

SOURCE_IDENTITY_VERSION = "1.0"
EVENT_IDENTITY_VERSION = "1.0"


def canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def identity(*parts) -> str:
    return hashlib.sha256(canonical(list(parts)).encode("utf-8")).hexdigest()


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def locator(source, root: Path) -> dict:
    return {"path": source.path.relative_to(root).as_posix(), "kind": source.kind,
            "member": source.member, "member_ordinal": source.member_ordinal}


def assign_sources(health: list, root: Path, map_path: Path | None, capture_id: str | None) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key in source map: " + key)
            result[key] = value
        return result

    supplied = json.loads(map_path.read_text(encoding="utf-8-sig"), object_pairs_hook=pairs) if map_path else {}
    if map_path and (not isinstance(supplied, dict) or supplied.get("source_identity_version") != SOURCE_IDENTITY_VERSION or
                     not isinstance(supplied.get("sources"), list) or not isinstance(supplied.get("capture_id"), str) or not supplied["capture_id"]):
        raise ValueError("Unsupported source map")
    if capture_id and supplied.get("capture_id", capture_id) != capture_id:
        raise ValueError("--capture-id conflicts with source map")
    capture = capture_id or supplied.get("capture_id") or "inferred:" + identity("capture-root/v1", str(root))
    if not isinstance(capture, str) or not capture:
        raise ValueError("capture_id must be a nonempty string")
    entries = {}
    for entry in supplied.get("sources", []):
        key = canonical(entry["locator"])
        if key in entries:
            raise ValueError("Duplicate locator in source map")
        entries[key] = entry
    result, versions = [], {}
    for item in health:
        source = item.source
        physical = locator(source, root)
        entry = entries.get(canonical(physical))
        source.capture_id = capture
        source.origin_id = entry["origin_id"] if entry else "(unknown-origin)"
        source.process_scope = entry["process_scope"] if entry else source.process or "(unknown-process)"
        source.logical_log_key = entry["logical_log_key"] if entry else canonical(physical)
        source.identity_status = "explicit_map" if entry else "inferred_relative_path"
        if not all(isinstance(v, str) and v for v in (source.origin_id, source.process_scope, source.logical_log_key)):
            raise ValueError("Source map identity fields must be nonempty strings")
        source.stable_id = identity("source/v1", capture, source.origin_id, source.process_scope, source.logical_log_key)
        source.version_id = identity("source-version/v1", source.stable_id, item.sha256 or "unreadable")
        result.append({"locator": physical, "origin_id": source.origin_id, "process_scope": source.process_scope,
                       "logical_log_key": source.logical_log_key, "source_id": source.stable_id})
        if item.status not in {"valid", "valid_no_timestamp", "partial_nul_salvaged"}:
            continue
        previous = versions.get(source.stable_id)
        if previous is None:
            versions[source.stable_id] = item
        elif previous.sha256 != item.sha256 or not item.sha256:
            raise ValueError("Conflicting versions of one logical source; select one explicitly")
        else:
            item.status = "skipped_duplicate"
            item.analyzed_bytes = 0
            item.reason = "byte-identical logical source to " + previous.source.display_path
    return {"source_identity_version": SOURCE_IDENTITY_VERSION, "capture_id": capture,
            "capture_identity_status": "inferred_root" if not capture_id and not supplied.get("capture_id") else "supplied",
            "sources": result}
