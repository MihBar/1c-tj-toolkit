#!/usr/bin/env python3
"""Verify slice outputs and reproduce them from saved CSV/JSON, never TJ."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from derive_slices import CALCULATOR_NAME, MANIFEST_NAME, SLICE_METHOD, csv_bytes
from slice_config import CALCULATOR_VERSION, SLICE_SCHEMA_VERSION, SliceError, canonical_json, digest_bytes, normalize_config, strict_json
from slice_input import load_bundle, require
from slice_metrics import SLICE_BUILDERS


def verify(analysis_dir: Path, slices_dir: Path) -> dict:
    bundle = load_bundle(analysis_dir)
    root = slices_dir.resolve(strict=True)
    manifest_path = root / MANIFEST_NAME
    require(manifest_path.resolve(strict=True).parent == root, "Slice manifest escapes result directory")
    manifest = strict_json(manifest_path.read_text(encoding="utf-8-sig"), "slice manifest")
    require(isinstance(manifest, dict), "Invalid slice manifest")
    require(manifest.get("calculator") == CALCULATOR_NAME, "Unknown calculator")
    require(manifest.get("calculator_version") == CALCULATOR_VERSION, "Calculator version mismatch")
    require(manifest.get("slice_schema_version") == SLICE_SCHEMA_VERSION, "Slice schema mismatch")
    require(manifest.get("input_schema_version") == bundle.manifest["schema_version"], "Input schema mismatch")
    require(manifest.get("input_analyzer_version") == bundle.manifest["analyzer_version"], "Input analyzer version mismatch")
    require(manifest.get("input_sql_normalization_version") == bundle.sql_normalization_version, "Input SQL normalization version mismatch")
    require(manifest.get("input_error_rules") == {key: bundle.manifest.get(key) for key in ("error_signature_version", "error_linkage_rules_version", "incident_rules_version")}, "Input error rules mismatch")
    require(manifest.get("input_linkage_rules_version") == bundle.manifest.get("linkage_rules_version", "legacy_end_longest/v1"), "Input linkage rules version mismatch")
    require(manifest.get("bundle_id") == bundle.bundle_id and manifest.get("input_files") == bundle.input_files, "Input hashes/bundle identity mismatch")
    config = normalize_config(manifest.get("configuration"))
    require(manifest.get("configuration") == config, "Noncanonical saved configuration")
    require(manifest.get("config_version") == config["config_version"], "Configuration version mismatch")
    require(manifest.get("configuration_effective_sha256") == digest_bytes(canonical_json(config).encode()), "Effective configuration hash mismatch")
    raw_hash = manifest.get("configuration_file_sha256")
    require(isinstance(raw_hash, str) and len(raw_hash) == 64 and all(c in "0123456789abcdef" for c in raw_hash), "Invalid recorded configuration file hash")
    require(config["expected_bundle_id"] in (None, bundle.bundle_id), "Configured bundle identity mismatch")
    require(manifest.get("source_analysis_complete") == bundle.manifest["analysis_complete"], "Source completeness mismatch")
    require(manifest.get("recorded_source_set_hash_sha256") == bundle.manifest["source_set_hash_sha256"], "Recorded source manifest mismatch")
    require(manifest.get("selected_slices") == config["slices"], "Slice selection mismatch")
    population = {"primary": "call_observations.csv", "key": ["bundle_id", "call_id"], "count": len(bundle.calls), "json_and_top_calls_are_not_additional_observations": True}
    require(manifest.get("population") == population, "Population contract mismatch")
    require(manifest.get("input_files_unchanged") is True and manifest.get("validation_checks") == bundle.checks, "Validation metadata mismatch")
    require(manifest.get("method") == SLICE_METHOD, "Calculation method metadata mismatch")
    expected_outputs = {}
    for name in config["slices"]:
        fields, builder = SLICE_BUILDERS[name]
        rows = builder(bundle, config)
        expected = csv_bytes(fields, rows)
        filename = name + ".csv"
        path = root / filename
        require(path.resolve(strict=True).parent == root, "Slice file escapes result directory")
        actual = path.read_bytes()
        require(actual == expected, f"{filename}: output differs from deterministic recalculation")
        expected_outputs[filename] = {"sha256": digest_bytes(expected), "size_bytes": len(expected), "row_count": len(rows), "columns": fields}
    require(manifest.get("outputs") == expected_outputs, "Output hash/schema/row-count mismatch")
    bundle.assert_unchanged()
    return {"status": "PASS", "bundle_id": bundle.bundle_id, "verified_slices": config["slices"], "input_files_unchanged": True, "original_config_file_not_reopened": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis-dir", type=Path, required=True)
    parser.add_argument("--slices-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    try:
        print(canonical_json(verify(args.analysis_dir, args.slices_dir)))
        return 0
    except (SliceError, OSError, UnicodeError) as exc:
        print(canonical_json({"status": "ERROR", "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
