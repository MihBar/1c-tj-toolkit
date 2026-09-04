#!/usr/bin/env python3
"""Independent deterministic QA for a 1C TJ analyzer output directory.

The verifier reads the explicitly selected analysis directory. The legacy 1.2
branch also checks existence of source paths recorded in ``files.csv``.
It does not import the analyzer or the PDF generator, does not scan raw journals,
and uses only the Python standard library. A compact JSON document is written
to stdout; exit code 0 means all integrity checks passed. Nonzero codes mean
validation failed: legacy checks may return 1, while strict bundle rejection
and input errors return 2. PASS alone does not establish collection completeness.
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import math
import statistics
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


MIN_SCHEMA_VERSION = (1, 2)
VERIFIER_VERSION = "1.2.0"
REQUIRED_FILES = (
    "analysis_metrics.json",
    "files.csv",
    "datasets.csv",
    "operations.csv",
    "identical_operations.csv",
    "heavy_sql.csv",
    "errors.csv",
    "locks.csv",
    "linkage.csv",
    "top_calls.csv",
    "call_observations.csv",
)

CSV_COUNT_KEYS = {
    "files.csv": "sources_discovered",
    "datasets.csv": "datasets",
    "operations.csv": "operations",
    "identical_operations.csv": "identical_operation_rows",
    "heavy_sql.csv": "sql_patterns",
    "errors.csv": "error_signatures",
    "locks.csv": "lock_signatures",
    "linkage.csv": "linkage_rows",
    "call_observations.csv": "call_observations",
}

JSON_ARRAY_KEYS = {
    "files.csv": "files",
    "datasets.csv": "datasets",
    "operations.csv": "operations",
    "identical_operations.csv": "identical_operations",
    "heavy_sql.csv": "heavy_sql",
    "errors.csv": "errors",
    "locks.csv": "locks",
    "linkage.csv": "linkage",
}

INTEGER_SUM_FIELDS = (
    "duration_us",
    "cpu_us",
    "memory",
    "db_count",
    "db_duration_us",
    "rows_affected",
    "in_bytes",
    "out_bytes",
    "lock_count",
    "lock_duration_us",
    "error_count",
)

class ValidationInputError(RuntimeError):
    """The selected bundle cannot be read as an analyzer result."""


class Checks:
    """Collect compact named check results without stopping at the first error."""

    def __init__(self) -> None:
        self.items: dict[str, dict[str, Any]] = {}

    def add(self, name: str, ok: bool, **details: Any) -> None:
        item: dict[str, Any] = {"ok": bool(ok)}
        for key, value in details.items():
            if value not in (None, [], {}, ""):
                item[key] = value
        self.items[name] = item

    @property
    def passed(self) -> bool:
        return bool(self.items) and all(item["ok"] for item in self.items.values())


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify a deterministic 1C TJ analysis bundle and print compact JSON.",
    )
    parser.add_argument(
        "--analysis-dir",
        type=Path,
        required=True,
        help="Directory produced by analyze_1c_tj.py (schemas 1.2 through 1.6)",
    )
    return parser.parse_args(argv)


def parse_schema_version(value: Any) -> tuple[int, ...]:
    text = str(value or "").strip()
    parts = text.split(".")
    if len(parts) < 2 or any(not part.isdigit() for part in parts):
        raise ValueError(f"invalid schema_version {text!r}")
    return tuple(int(part) for part in parts)


def read_csv(path: Path) -> list[dict[str, str]]:
    previous_limit = csv.field_size_limit()
    try:
        csv.field_size_limit(16 * 1024 * 1024)
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle, strict=True)
            if reader.fieldnames is None:
                raise ValidationInputError(f"CSV has no header: {path.name}")
            if len(set(reader.fieldnames)) != len(reader.fieldnames):
                raise ValidationInputError(f"CSV has duplicate columns: {path.name}")
            rows = []
            for index, row in enumerate(reader, 2):
                if None in row or None in row.values():
                    raise ValidationInputError(f"malformed CSV row {index}: {path.name}")
                rows.append(row)
            return rows
    except (OSError, UnicodeError, csv.Error) as exc:
        raise ValidationInputError(f"cannot read {path.name}: {exc}") from exc
    finally:
        csv.field_size_limit(previous_limit)


def as_int(value: Any, label: str) -> int:
    text = str(value if value is not None else "").strip()
    try:
        return int(text)
    except ValueError as exc:
        raise ValidationInputError(f"{label} is not an integer: {text!r}") from exc


def as_float(value: Any, label: str) -> float:
    text = str(value if value is not None else "").strip()
    try:
        number = float(text)
    except ValueError as exc:
        raise ValidationInputError(f"{label} is not numeric: {text!r}") from exc
    if not math.isfinite(number):
        raise ValidationInputError(f"{label} is not finite: {text!r}")
    return number


def optional_float(value: Any, label: str) -> float | None:
    if value is None or str(value).strip() == "":
        return None
    return as_float(value, label)


def as_bool(value: Any, label: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ValidationInputError(f"{label} is not a JSON boolean")


def nearest_rank(values: Sequence[int], percentile: float) -> int:
    ordered = sorted(values)
    if not ordered:
        return 0
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return ordered[index]


def close_enough(actual: float, expected: float, tolerance: float = 1e-6) -> bool:
    return math.isclose(actual, expected, rel_tol=tolerance, abs_tol=tolerance)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def expected_percentage(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator * 100, 6) if denominator else None


def percentile_check_rows(
    rows: Iterable[Mapping[str, Any]],
    *,
    include_minimum: bool,
    threshold_counts: bool,
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    for index, row in enumerate(rows, start=2):
        try:
            count = as_int(row.get("count"), f"row {index} count")
            median = as_float(row.get("median_us"), f"row {index} median_us")
            p95 = as_float(row.get("p95_us"), f"row {index} p95_us")
            p99 = as_float(row.get("p99_us"), f"row {index} p99_us")
            maximum = as_float(row.get("max_us"), f"row {index} max_us")
            average = as_float(row.get("avg_us"), f"row {index} avg_us")
            minimum = as_float(row.get("min_us"), f"row {index} min_us") if include_minimum else 0.0
            if count < 0 or minimum < 0 or not (minimum <= median <= p95 <= p99 <= maximum):
                errors.append(f"row {index}: invalid percentile order")
            if count and not (minimum <= average <= maximum):
                errors.append(f"row {index}: average outside min/max")
            if threshold_counts:
                over = [as_int(row.get(name), f"row {index} {name}") for name in (
                    "over_1s", "over_5s", "over_10s", "over_30s"
                )]
                if not (count >= over[0] >= over[1] >= over[2] >= over[3] >= 0):
                    errors.append(f"row {index}: invalid duration threshold counts")
        except ValidationInputError as exc:
            errors.append(str(exc))
        if len(errors) >= 20:
            break
    return not errors, errors


def check_dataset_event_stats(rows: Sequence[Mapping[str, str]]) -> tuple[bool, int, int, list[str]]:
    call_count = 0
    call_duration = 0
    errors: list[str] = []
    for index, row in enumerate(rows, start=2):
        try:
            raw = json.loads(row.get("event_stats", ""))
            if not isinstance(raw, dict):
                raise ValueError("event_stats is not an object")
            for event, metrics in raw.items():
                if not isinstance(metrics, dict):
                    errors.append(f"row {index} event {event}: metrics are not an object")
                    continue
                count = as_int(metrics.get("count"), f"row {index} {event}.count")
                median = as_float(metrics.get("median_us"), f"row {index} {event}.median_us")
                p95 = as_float(metrics.get("p95_us"), f"row {index} {event}.p95_us")
                p99 = as_float(metrics.get("p99_us"), f"row {index} {event}.p99_us")
                maximum = as_float(metrics.get("max_us"), f"row {index} {event}.max_us")
                average = as_float(metrics.get("avg_us"), f"row {index} {event}.avg_us")
                over = [as_int(metrics.get(name), f"row {index} {event}.{name}") for name in (
                    "over_1s", "over_5s", "over_10s", "over_30s"
                )]
                if not (0 <= median <= p95 <= p99 <= maximum):
                    errors.append(f"row {index} event {event}: invalid percentile order")
                if count and not (0 <= average <= maximum):
                    errors.append(f"row {index} event {event}: average outside range")
                if not (count >= over[0] >= over[1] >= over[2] >= over[3] >= 0):
                    errors.append(f"row {index} event {event}: invalid threshold counts")
                if event == "CALL":
                    call_count += count
                    call_duration += as_int(metrics.get("duration_us"), f"row {index} CALL.duration_us")
        except (json.JSONDecodeError, TypeError, ValueError, ValidationInputError) as exc:
            errors.append(f"row {index}: invalid event_stats: {exc}")
        if len(errors) >= 20:
            break
    return not errors, call_count, call_duration, errors


def operation_key(row: Mapping[str, str]) -> tuple[str, str, str, str]:
    return (
        row.get("measurement_id", ""),
        row.get("dataset_id", ""),
        row.get("user", ""),
        row.get("signature", ""),
    )


def reconcile_operations(
    calls: Sequence[Mapping[str, str]],
    operations: Sequence[Mapping[str, str]],
) -> tuple[bool, dict[str, int], list[str]]:
    grouped: dict[tuple[str, str, str, str], list[Mapping[str, str]]] = collections.defaultdict(list)
    for row in calls:
        grouped[operation_key(row)].append(row)
    operation_by_key: dict[tuple[str, str, str, str], Mapping[str, str]] = {}
    errors: list[str] = []
    for row in operations:
        key = operation_key(row)
        if key in operation_by_key:
            errors.append(f"duplicate operation key: {key!r}")
        operation_by_key[key] = row
    missing = sorted(set(grouped) - set(operation_by_key))
    extra = sorted(set(operation_by_key) - set(grouped))
    if missing:
        errors.append(f"{len(missing)} CALL group(s) missing from operations.csv")
    if extra:
        errors.append(f"{len(extra)} operation group(s) have no CALL observations")

    totals_calls: collections.Counter[str] = collections.Counter()
    totals_ops: collections.Counter[str] = collections.Counter()
    totals_calls["count"] = len(calls)
    for row in calls:
        source_names = {
            "rows_affected": "db_rows",
        }
        for field in INTEGER_SUM_FIELDS:
            source_field = source_names.get(field, field)
            totals_calls[field] += as_int(row.get(source_field), f"call {row.get('call_id')} {source_field}")
    for row in operations:
        totals_ops["count"] += as_int(row.get("count"), "operation count")
        for field in INTEGER_SUM_FIELDS:
            totals_ops[field] += as_int(row.get(field), f"operation {field}")

    for key in sorted(set(grouped) & set(operation_by_key)):
        members = grouped[key]
        operation = operation_by_key[key]
        durations = [as_int(row.get("duration_us"), f"CALL {row.get('call_id')} duration_us") for row in members]
        expected_values: dict[str, float | int] = {
            "count": len(members),
            "duration_us": sum(durations),
            "avg_us": round(sum(durations) / len(durations), 3),
            "median_us": statistics.median(durations),
            "p95_us": nearest_rank(durations, 0.95),
            "p99_us": nearest_rank(durations, 0.99),
            "min_us": min(durations),
            "max_us": max(durations),
            "over_1s": sum(value >= 1_000_000 for value in durations),
            "over_5s": sum(value >= 5_000_000 for value in durations),
            "over_10s": sum(value >= 10_000_000 for value in durations),
            "over_30s": sum(value >= 30_000_000 for value in durations),
        }
        for field in INTEGER_SUM_FIELDS:
            source_field = "db_rows" if field == "rows_affected" else field
            expected_values[field] = sum(
                as_int(row.get(source_field), f"CALL {row.get('call_id')} {source_field}")
                for row in members
            )
        for field, expected in expected_values.items():
            actual = as_float(operation.get(field), f"operation {key!r} {field}")
            if not close_enough(actual, float(expected)):
                errors.append(f"operation {key!r}: {field}={actual:g}, expected {expected}")
                if len(errors) >= 20:
                    break
        if len(errors) >= 20:
            break

    for field in ("count",) + INTEGER_SUM_FIELDS:
        if totals_calls[field] != totals_ops[field]:
            errors.append(
                f"CALL/operation total mismatch for {field}: "
                f"{totals_calls[field]} != {totals_ops[field]}"
            )
    totals = {f"call_{key}": value for key, value in sorted(totals_calls.items())}
    totals.update({f"operation_{key}": value for key, value in sorted(totals_ops.items())})
    return not errors, totals, errors[:20]


def verify_linkage(
    calls: Sequence[Mapping[str, str]],
    linkage: Sequence[Mapping[str, str]],
) -> tuple[bool, dict[str, int], list[str]]:
    grouped: dict[tuple[str, str], collections.Counter[str]] = collections.defaultdict(collections.Counter)
    for row in calls:
        key = (row.get("measurement_id", ""), row.get("dataset_id", ""))
        grouped[key]["call_count"] += 1
        grouped[key]["db_count"] += as_int(row.get("db_count"), f"CALL {row.get('call_id')} db_count")
        grouped[key]["db_duration_us"] += as_int(
            row.get("db_duration_us"), f"CALL {row.get('call_id')} db_duration_us"
        )

    seen: set[tuple[str, str]] = set()
    errors: list[str] = []
    totals: collections.Counter[str] = collections.Counter()
    percent_specs = (
        ("dbpostgrs_linked_count", "dbpostgrs_total_count", "dbpostgrs_linked_count_percent"),
        ("dbpostgrs_linked_duration_us", "dbpostgrs_total_duration_us", "dbpostgrs_linked_duration_percent"),
        ("sdbl_linked_count", "sdbl_total_count", "sdbl_linked_count_percent"),
        ("lock_linked_count", "lock_total_count", "lock_linked_count_percent"),
        ("error_linked_count", "error_total_count", "error_linked_count_percent"),
    )
    for index, row in enumerate(linkage, start=2):
        key = (row.get("measurement_id", ""), row.get("dataset_id", ""))
        if key in seen:
            errors.append(f"duplicate linkage key: {key!r}")
        seen.add(key)
        call_count = as_int(row.get("call_count"), f"linkage row {index} call_count")
        linked_db = as_int(row.get("dbpostgrs_linked_count"), f"linkage row {index} linked DB")
        linked_db_duration = as_int(
            row.get("dbpostgrs_linked_duration_us"), f"linkage row {index} linked DB duration"
        )
        expected = grouped.get(key, collections.Counter())
        if call_count != expected["call_count"]:
            errors.append(f"linkage {key!r}: call_count {call_count} != {expected['call_count']}")
        if linked_db != expected["db_count"]:
            errors.append(f"linkage {key!r}: linked DB {linked_db} != {expected['db_count']}")
        if linked_db_duration != expected["db_duration_us"]:
            errors.append(
                f"linkage {key!r}: linked DB duration {linked_db_duration} "
                f"!= {expected['db_duration_us']}"
            )

        all_total = 0
        all_linked = 0
        for numerator_name, denominator_name, percent_name in percent_specs:
            numerator = as_int(row.get(numerator_name), f"linkage row {index} {numerator_name}")
            denominator = as_int(row.get(denominator_name), f"linkage row {index} {denominator_name}")
            if not (0 <= numerator <= denominator):
                errors.append(f"linkage {key!r}: {numerator_name} outside 0..{denominator_name}")
            actual_percent = optional_float(row.get(percent_name), f"linkage row {index} {percent_name}")
            expected_percent = expected_percentage(numerator, denominator)
            if expected_percent is None:
                if actual_percent is not None:
                    errors.append(f"linkage {key!r}: {percent_name} must be blank for zero denominator")
            elif actual_percent is None or not close_enough(actual_percent, expected_percent):
                errors.append(
                    f"linkage {key!r}: {percent_name}={actual_percent!r}, expected {expected_percent}"
                )
            if numerator_name.endswith("_count"):
                all_linked += numerator
                all_total += denominator

        unexplained = sum(
            as_int(row.get(name), f"linkage row {index} {name}")
            for name in (
                "unlinked_missing_timestamp",
                "unlinked_missing_thread",
                "unlinked_no_containing_call",
            )
        )
        if all_total - all_linked != unexplained:
            errors.append(
                f"linkage {key!r}: unlinked reason sum {unexplained} != {all_total - all_linked}"
            )
        totals["call_count"] += call_count
        totals["dbpostgrs_total_count"] += as_int(
            row.get("dbpostgrs_total_count"), f"linkage row {index} dbpostgrs_total_count"
        )
        totals["dbpostgrs_linked_count"] += linked_db
        totals["dbpostgrs_total_duration_us"] += as_int(
            row.get("dbpostgrs_total_duration_us"), f"linkage row {index} DB total duration"
        )
        totals["dbpostgrs_linked_duration_us"] += linked_db_duration

    if set(grouped) - seen:
        errors.append(f"{len(set(grouped) - seen)} CALL measurement/dataset group(s) lack linkage rows")
    return not errors, dict(sorted(totals.items())), errors[:20]


def verify(analysis_dir: Path) -> tuple[dict[str, Any], int]:
    checks = Checks()
    try:
        root = analysis_dir.resolve(strict=True)
        if not root.is_dir():
            raise ValidationInputError(f"not a directory: {root}")
    except (OSError, ValidationInputError) as exc:
        raise ValidationInputError(f"invalid --analysis-dir: {exc}") from exc

    missing = [name for name in REQUIRED_FILES if not (root / name).is_file()]
    checks.add("required_output_files", not missing, required=len(REQUIRED_FILES), missing=missing)
    if missing:
        return {
            "status": "FAIL",
            "analysis_dir": str(root),
            "schema_version": None,
            "checks": checks.items,
        }, 2

    try:
        with (root / "analysis_metrics.json").open("r", encoding="utf-8-sig") as handle:
            manifest = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationInputError(f"cannot read analysis_metrics.json: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ValidationInputError("analysis_metrics.json root is not an object")

    schema_text = str(manifest.get("schema_version", ""))
    if schema_text in {"1.3", "1.4", "1.5", "1.6"}:
        from slice_input import load_bundle
        from slice_config import SliceError
        try:
            bundle = load_bundle(root)
        except SliceError as exc:
            return {"status": "FAIL", "schema_version": schema_text, "error": str(exc)}, 2
        for name in bundle.checks:
            checks.add(name, True)
        for name in ("operations", "heavy_sql", "locks"):
            ok, errors = percentile_check_rows(bundle.tables[name], include_minimum=name == "operations", threshold_counts=True)
            checks.add(name + "_percentiles_and_thresholds", ok, errors=errors)
        ok, _, _, errors = check_dataset_event_stats(bundle.tables["datasets"])
        checks.add("dataset_event_distributions", ok, errors=errors)
        completeness = {
            "source_processing_complete": manifest.get("source_processing_complete", manifest["analysis_complete"]),
            "absolute_timestamps_complete": manifest["absolute_timestamps_complete"],
            "collection_completeness": manifest.get("collection_completeness", "unknown"),
            "source_status_counts": dict(collections.Counter(r["status"] for r in manifest["files"])),
            "warning_counts": dict(collections.Counter(r["type"] for r in manifest["warnings"])),
            "events_without_absolute_timestamp": sum(r["events_without_absolute_timestamp"] for r in manifest["datasets"]),
        }
        if schema_text in {"1.5", "1.6"}:
            from contextlib import closing
            with closing(sqlite3.connect((root/"analysis.sqlite").as_uri()+"?mode=ro&immutable=1", uri=True)) as db:
                completeness["parse_issue_counts"] = dict(db.execute("SELECT code,count(*) FROM parse_issues GROUP BY code ORDER BY code"))
                completeness["stored_event_count"] = db.execute("SELECT count(*) FROM events").fetchone()[0]
            bundle.assert_unchanged()
        observation_state = "complete" if completeness["source_processing_complete"] and completeness["absolute_timestamps_complete"] else "partial"
        if not sum(r["records"] for r in manifest["datasets"]):
            observation_state = "empty"
        return {
            "status": "PASS" if checks.passed else "FAIL", "analysis_dir": str(root), "schema_version": schema_text,
            "analyzer_version": manifest.get("analyzer_version"),
            "analysis_complete": manifest.get("analysis_complete"),
            "verifier_version": VERIFIER_VERSION,
            "observation_state": observation_state,
            "completeness": completeness,
            "percentile_validation": {"CALL": "individual_observations", "SQL_locks_dataset_events": "individual_observations" if schema_text in {"1.5", "1.6"} else "aggregate_constraints_only"},
            "checks": checks.items, "output_sha256": bundle.input_files,
            "verification_scope": "consistency of saved evidence, not proof of complete log collection; 1.5+ verifies exact event distributions, counter populations, references and single-owner accounting; 1.6 also verifies error events and incident hypotheses",
        }, 0 if checks.passed else 2
    try:
        schema_tuple = parse_schema_version(schema_text)
        schema_ok = schema_tuple == MIN_SCHEMA_VERSION
        schema_error = "" if schema_ok else f"unsupported schema {schema_text}; supported: 1.2, 1.3, 1.4, 1.5, 1.6"
    except ValueError as exc:
        schema_ok = False
        schema_error = str(exc)
    checks.add("schema_version", schema_ok, actual=schema_text, minimum="1.2", error=schema_error)
    if not schema_ok:
        return {"status": "FAIL", "schema_version": schema_text, "checks": checks.items}, 2

    tables = {name: read_csv(root / name) for name in REQUIRED_FILES if name.endswith(".csv")}
    counts = manifest.get("counts")
    if not isinstance(counts, dict):
        raise ValidationInputError("analysis_metrics.json counts is not an object")

    count_errors: list[str] = []
    for filename, count_key in CSV_COUNT_KEYS.items():
        expected = counts.get(count_key)
        if not isinstance(expected, int) or isinstance(expected, bool):
            count_errors.append(f"counts.{count_key} is not an integer")
            continue
        actual = len(tables[filename])
        if actual != expected:
            count_errors.append(f"{filename}: {actual} rows != counts.{count_key} {expected}")
        json_key = JSON_ARRAY_KEYS.get(filename)
        if json_key is not None:
            json_rows = manifest.get(json_key)
            if not isinstance(json_rows, list):
                count_errors.append(f"JSON {json_key} is not an array")
            elif len(json_rows) != actual:
                count_errors.append(f"JSON {json_key}: {len(json_rows)} rows != {actual} CSV rows")
    files = tables["files.csv"]
    analyzed_count = sum(
        row.get("status") in {"valid", "valid_no_timestamp", "partial_read_error", "partial_nul_salvaged"}
        for row in files
    )
    skipped_count = sum(row.get("status", "").startswith("skipped") for row in files)
    duplicate_count = sum(row.get("status") == "skipped_duplicate" for row in files)
    for name, actual in (
        ("sources_analyzed", analyzed_count),
        ("sources_skipped", skipped_count),
        ("sources_skipped_as_duplicates", duplicate_count),
    ):
        if counts.get(name) != actual:
            count_errors.append(f"counts.{name}={counts.get(name)!r}, expected {actual}")
    checks.add("manifest_and_csv_counts", not count_errors, errors=count_errors[:20])

    output_hashes = {name: sha256_file(root / name) for name in REQUIRED_FILES}
    checks.add("output_file_hashes", all(len(value) == 64 for value in output_hashes.values()), files=len(output_hashes))

    source_hash_errors: list[str] = []
    valid_hashes = 0
    for index, row in enumerate(files, start=2):
        digest = row.get("sha256", "")
        if digest:
            valid_hashes += 1
            if len(digest) != 64 or any(character not in "0123456789abcdefABCDEF" for character in digest):
                source_hash_errors.append(f"files.csv row {index}: invalid SHA-256")
    complete_hashes = bool(files) and valid_hashes == len(files)
    try:
        manifest_hash_flag = as_bool(manifest.get("source_content_hashes_complete"), "source_content_hashes_complete")
        if manifest_hash_flag != complete_hashes:
            source_hash_errors.append(
                f"source_content_hashes_complete={manifest_hash_flag}, expected {complete_hashes}"
            )
    except ValidationInputError as exc:
        source_hash_errors.append(str(exc))
    manifest_lines = [
        "\t".join((
            row.get("source", ""),
            row.get("size_bytes", ""),
            row.get("sha256", "") or "UNHASHED",
            row.get("status", ""),
        ))
        for row in sorted(files, key=lambda item: item.get("source", "").lower())
    ]
    expected_source_set_hash = hashlib.sha256("\n".join(manifest_lines).encode("utf-8")).hexdigest()
    if manifest.get("source_set_hash_sha256") != expected_source_set_hash:
        source_hash_errors.append("source_set_hash_sha256 does not match files.csv manifest")
    checks.add(
        "source_hash_manifest",
        not source_hash_errors,
        hashed=valid_hashes,
        total=len(files),
        source_set_hash_sha256=expected_source_set_hash,
        errors=source_hash_errors[:20],
    )

    unique_sources = sorted({row.get("resolved_source", "") for row in files if row.get("resolved_source")})
    missing_sources = [source for source in unique_sources if not Path(source).is_file()]
    checks.add(
        "recorded_source_files_present",
        not missing_sources,
        unique_sources=len(unique_sources),
        missing_count=len(missing_sources),
        missing=missing_sources[:10],
    )

    salvage_errors: list[str] = []
    salvaged = [row for row in files if row.get("status") == "partial_nul_salvaged"]
    salvage_enabled = manifest.get("salvage_nul_prefix")
    if not isinstance(salvage_enabled, bool):
        salvage_errors.append("salvage_nul_prefix is not a JSON boolean")
    if salvaged and salvage_enabled is not True:
        salvage_errors.append("partial_nul_salvaged rows exist while salvage_nul_prefix is false")
    for row in salvaged:
        try:
            size = as_int(row.get("size_bytes"), "partial size_bytes")
            analyzed = as_int(row.get("analyzed_bytes"), "partial analyzed_bytes")
            nul_offset = as_int(row.get("nul_offset"), "partial nul_offset")
            if not (0 < analyzed <= nul_offset < size):
                salvage_errors.append(
                    f"{row.get('source')}: expected 0 < analyzed_bytes <= nul_offset < size_bytes"
                )
            if "damaged after byte" not in row.get("reason", ""):
                salvage_errors.append(f"{row.get('source')}: salvage reason is not explicit")
        except ValidationInputError as exc:
            salvage_errors.append(str(exc))
    warnings = manifest.get("warnings", [])
    if not isinstance(warnings, list):
        salvage_errors.append("warnings is not an array")
        warnings = []
    warning_types = {item.get("type") for item in warnings if isinstance(item, dict)}
    if salvaged and "partial_nul_prefix_salvage" not in warning_types:
        salvage_errors.append("partial_nul_prefix_salvage warning is missing")
    archive_error = "archive_error" in warning_types
    material_problem = any(
        row.get("status") in {"partial_read_error", "partial_nul_salvaged"}
        or (
            row.get("status") == "skipped"
            and not row.get("reason", "").startswith(("empty file", "empty/BOM marker"))
        )
        for row in files
    ) or archive_error
    try:
        analysis_complete = as_bool(manifest.get("analysis_complete"), "analysis_complete")
        if analysis_complete != (not material_problem):
            salvage_errors.append(
                f"analysis_complete={analysis_complete}, expected {not material_problem} from files/warnings"
            )
    except ValidationInputError as exc:
        salvage_errors.append(str(exc))
    checks.add(
        "partial_nul_salvage_consistency",
        not salvage_errors,
        salvaged_sources=len(salvaged),
        salvaged_bytes=sum(as_int(row.get("analyzed_bytes"), "analyzed_bytes") for row in salvaged),
        material_source_problem=material_problem,
        errors=salvage_errors[:20],
    )

    calls = tables["call_observations.csv"]
    call_id_errors: list[str] = []
    call_ids: list[int] = []
    for row in calls:
        try:
            call_id = as_int(row.get("call_id"), "call_id")
            if call_id <= 0:
                call_id_errors.append(f"non-positive call_id {call_id}")
            call_ids.append(call_id)
        except ValidationInputError as exc:
            call_id_errors.append(str(exc))
    duplicate_ids = len(call_ids) - len(set(call_ids))
    if duplicate_ids:
        call_id_errors.append(f"{duplicate_ids} duplicate call_id value(s)")
    if call_ids and set(call_ids) != set(range(1, len(call_ids) + 1)):
        call_id_errors.append("call_id values are not contiguous 1..N")
    top_call_ids: list[int] = []
    for row in tables["top_calls.csv"]:
        try:
            top_call_ids.append(as_int(row.get("call_id"), "top_calls.call_id"))
        except ValidationInputError as exc:
            call_id_errors.append(str(exc))
    if len(top_call_ids) != len(set(top_call_ids)):
        call_id_errors.append("top_calls.csv contains duplicate call_id values")
    unknown_top = sorted(set(top_call_ids) - set(call_ids))
    if unknown_top:
        call_id_errors.append(f"top_calls.csv references {len(unknown_top)} unknown call_id value(s)")
    checks.add(
        "call_id_uniqueness",
        not call_id_errors,
        call_count=len(call_ids),
        unique_call_ids=len(set(call_ids)),
        top_call_count=len(top_call_ids),
        errors=call_id_errors[:20],
    )

    operation_ok, call_totals, operation_errors = reconcile_operations(calls, tables["operations.csv"])
    checks.add("call_operation_reconciliation", operation_ok, totals=call_totals, errors=operation_errors)

    dataset_ok, dataset_call_count, dataset_call_duration, dataset_errors = check_dataset_event_stats(
        tables["datasets.csv"]
    )
    expected_call_duration = sum(as_int(row.get("duration_us"), "CALL duration_us") for row in calls)
    if dataset_call_count != len(calls):
        dataset_errors.append(f"dataset CALL count {dataset_call_count} != observations {len(calls)}")
    if dataset_call_duration != expected_call_duration:
        dataset_errors.append(
            f"dataset CALL duration {dataset_call_duration} != observations {expected_call_duration}"
        )
    checks.add(
        "dataset_call_totals",
        dataset_ok and not dataset_errors,
        call_count=dataset_call_count,
        call_duration_us=dataset_call_duration,
        errors=dataset_errors[:20],
    )

    linkage_ok, linkage_totals, linkage_errors = verify_linkage(calls, tables["linkage.csv"])
    dataset_db_count = 0
    for row in tables["datasets.csv"]:
        event_stats = json.loads(row.get("event_stats", "{}"))
        if isinstance(event_stats, dict) and isinstance(event_stats.get("DBPOSTGRS"), dict):
            dataset_db_count += as_int(event_stats["DBPOSTGRS"].get("count"), "dataset DBPOSTGRS count")
    if linkage_totals.get("dbpostgrs_total_count", 0) != dataset_db_count:
        linkage_errors.append(
            f"linkage DBPOSTGRS total {linkage_totals.get('dbpostgrs_total_count', 0)} "
            f"!= dataset event total {dataset_db_count}"
        )
    checks.add(
        "db_linkage_reconciliation",
        linkage_ok and not linkage_errors,
        totals=linkage_totals,
        dataset_dbpostgrs_count=dataset_db_count,
        errors=linkage_errors[:20],
    )

    percentile_results: dict[str, list[str]] = {}
    for filename, include_minimum in (
        ("operations.csv", True),
        ("heavy_sql.csv", False),
        ("locks.csv", False),
    ):
        ok, errors = percentile_check_rows(
            tables[filename], include_minimum=include_minimum, threshold_counts=True
        )
        if not ok:
            percentile_results[filename] = errors
    checks.add("percentile_and_threshold_monotonicity", not percentile_results, errors=percentile_results)

    manifest_operations = manifest.get("operations", [])
    manifest_call_ids: list[int] = []
    manifest_id_errors: list[str] = []
    if isinstance(manifest_operations, list):
        for index, row in enumerate(manifest_operations):
            ids = row.get("call_ids") if isinstance(row, dict) else None
            if not isinstance(ids, list):
                manifest_id_errors.append(f"JSON operation {index} has no call_ids array")
                continue
            for value in ids:
                if not isinstance(value, int) or isinstance(value, bool):
                    manifest_id_errors.append(f"JSON operation {index} has non-integer call_id")
                else:
                    manifest_call_ids.append(value)
    else:
        manifest_id_errors.append("JSON operations is not an array")
    if len(manifest_call_ids) != len(set(manifest_call_ids)):
        manifest_id_errors.append("JSON operation call_ids are not unique")
    if set(manifest_call_ids) != set(call_ids):
        manifest_id_errors.append("JSON operation call_ids do not cover call_observations.csv exactly")
    checks.add(
        "json_operation_call_membership",
        not manifest_id_errors,
        referenced_call_ids=len(manifest_call_ids),
        errors=manifest_id_errors[:20],
    )

    result = {
        "status": "PASS" if checks.passed else "FAIL",
        "analysis_dir": str(root),
        "schema_version": schema_text,
        "analyzer_version": manifest.get("analyzer_version"),
        "analysis_complete": manifest.get("analysis_complete"),
        "checks": checks.items,
        "output_sha256": output_hashes,
    }
    return result, 0 if checks.passed else 1


def main(argv: Sequence[str] | None = None) -> int:
    # Windows may inherit a legacy console encoding (for example cp1252) even
    # when paths and JSON contain Cyrillic.  Keep the CLI machine-readable.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass
    args = parse_args(argv)
    try:
        result, exit_code = verify(args.analysis_dir)
    except (ValidationInputError, ValueError, OSError, sqlite3.Error) as exc:
        result = {
            "status": "ERROR",
            "analysis_dir": str(args.analysis_dir),
            "error": str(exc),
        }
        exit_code = 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
