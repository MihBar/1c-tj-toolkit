"""Read/validate exactly one schema-1.2 through 1.6 bundle, never recorded TJ paths.

Only the allowlisted bundle files are opened (16 in 1.5, 21 in 1.6). ``source``, ``member``,
``resolved_source`` and ``input_root`` are opaque provenance strings.
CSV CALL observations are the sole population; JSON and top_calls are checks.
"""
from __future__ import annotations

import collections
import csv
import datetime as dt
import io
import math
import re
import statistics
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from slice_config import SliceError, SUPPORTED_INPUT_SCHEMAS, canonical_json, digest_bytes, strict_json
from numeric_quality import (FIELDS, STATES, NUMERIC_RULES_VERSION, QUALITY_CSV_FIELDS,
                             CounterStats, operation_counters, parse_counter)
from sql_normalization import (SQL_NORMALIZATION_VERSION, LEGACY_SQL_NORMALIZATION_VERSION,
                               SQL_FINGERPRINT_ALGORITHM, SQL_CSV_FIELDS,
                               sql_fingerprint, normalization_status)
from event_store import DETAIL_FILES, CALL_DETAIL_FIELDS
from error_rules import ERROR_GROUP_FIELDS, ERROR_METADATA
from source_identity import file_hash
from verify_event_store import verify_detail, descriptors, safe_path
from verification_policy import MODES, BASIC_CHECKS, validate_metadata
from verify_populations import CHECKS as POPULATION_CHECKS

CALL_FIELDS = "call_id measurement_id dataset_id user signature start_timestamp end_timestamp duration_us cpu_us db_count db_duration_us db_rows sdbl_count in_bytes out_bytes memory memory_peak lock_count lock_duration_us error_count process source context_sample".split()
CALL_INTS = "duration_us cpu_us db_count db_duration_us db_rows sdbl_count in_bytes out_bytes memory memory_peak lock_count lock_duration_us error_count".split()
HEADERS = {
    "call_observations": CALL_FIELDS,
    "top_calls": CALL_FIELDS,
    "files": "source resolved_source kind member size_bytes analyzed_bytes dataset_id measurement_id process status reason nul_offset sha256 records parse_errors".split(),
    "datasets": "dataset_id measurement_id actual_measurement_ids files_analyzed bytes_analyzed records parse_errors first_timestamp last_timestamp calendar_span_seconds users sessions connect_ids processes day_events night_events background_events events_without_absolute_timestamp active_minutes_with_events dbpostgrs_per_active_minute busiest_db_minute busiest_db_minute_count event_stats top_call_signatures".split(),
    "operations": "measurement_id dataset_id user priority priority_rule priority_basis signature count first_timestamp last_timestamp duration_us avg_us median_us p95_us p99_us max_us min_us over_1s over_5s over_10s over_30s cpu_us cpu_percent_of_wall memory memory_per_call memory_max memory_peak_avg memory_peak_median memory_peak_p95 db_count db_per_call db_duration_us db_seconds_per_call max_db_per_call rows_affected in_bytes in_bytes_per_call out_bytes out_bytes_per_call max_out_bytes memory_peak_max lock_count lock_duration_us error_count coefficient_of_variation unattributed_us_floor unattributed_percent_floor attribution_overflow_us context_sample".split(),
    "identical_operations": "signature comparison_scope comparability_level comparability_reasons comparison_order measurement_id dataset_id dataset_ids user first_timestamp last_timestamp count avg_us median_us p95_us max_us db_per_call db_seconds_per_call cpu_percent_of_wall out_bytes_per_call previous_measurement_id previous_first_timestamp".split(),
    "heavy_sql": "measurement_id measurements_all measurement_count sql_fingerprint_sha256 count duration_us avg_us median_us p95_us p99_us max_us over_1s over_5s over_10s over_30s rows_affected max_rows_affected count_0_5_to_2s has_join has_case has_distinct has_order_by has_group_by has_union has_temp_table has_limit_or_top users contexts tables first_timestamp last_timestamp normalized_sql sample_sql".split(),
    "errors": "measurement_id event category signature sample event_count incident_count users contexts first_timestamp last_timestamp linked_call_count".split(),
    "locks": "measurement_id event context count duration_us avg_us median_us p95_us p99_us max_us over_1s over_5s over_10s over_30s users linked_call_count".split(),
    "linkage": "measurement_id dataset_id call_count calls_without_absolute_time dbpostgrs_total_count dbpostgrs_linked_count dbpostgrs_linked_count_percent dbpostgrs_total_duration_us dbpostgrs_linked_duration_us dbpostgrs_linked_duration_percent sdbl_total_count sdbl_linked_count sdbl_linked_count_percent lock_total_count lock_linked_count lock_linked_count_percent error_total_count error_linked_count error_linked_count_percent unlinked_missing_timestamp unlinked_missing_thread unlinked_no_containing_call".split(),
}
REQUIRED_FILES = tuple(sorted(["analysis_metrics.json"] + [f"{name}.csv" for name in HEADERS]))
COUNT_KEYS = dict(zip(
    "call_observations files datasets operations identical_operations heavy_sql errors locks linkage".split(),
    "call_observations sources_discovered datasets operations identical_operation_rows sql_patterns error_signatures lock_signatures linkage_rows".split(),
))
VALID_SOURCE_STATUSES = {"valid", "valid_no_timestamp", "partial_read_error", "partial_nul_salvaged"}
SOURCE_STATUSES = VALID_SOURCE_STATUSES | {"skipped", "skipped_duplicate"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SliceError(message)


def integer(value: Any, label: str, minimum: int | None = 0) -> int:
    require(not isinstance(value, bool), f"{label}: boolean is not an integer")
    text = str(value)
    require(re.fullmatch(r"-?[0-9]+", text) is not None, f"{label}: invalid integer {value!r}")
    result = int(text)
    require(minimum is None or result >= minimum, f"{label}: must be >= {minimum}")
    return result


def number(value: Any, label: str) -> float:
    require(not isinstance(value, bool), f"{label}: boolean is not numeric")
    try:
        result = float(value)
    except (ValueError, TypeError) as exc:
        raise SliceError(f"{label}: invalid number {value!r}") from exc
    require(math.isfinite(result), f"{label}: non-finite number")
    return result


def timestamp(value: str, label: str) -> dt.datetime | None:
    if value == "":
        return None
    try:
        result = dt.datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise SliceError(f"{label}: invalid timestamp {value!r}") from exc
    require(result.tzinfo is None, f"{label}: unexpected timezone in schema 1.2")
    return result


def scalar(value: Any) -> str:
    """Schema-1.2 CSV representation, used solely for mirror validation."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        if any(isinstance(item, (dict, list, tuple)) for item in value):
            return canonical_json(value)
        return " | ".join(str(item) for item in sorted(value))
    if isinstance(value, dict):
        return canonical_json(value)
    return str(value)


def safe_bundle_file(root: Path, name: str) -> Path:
    require(name in REQUIRED_FILES or name in DETAIL_FILES, f"Not an allowlisted bundle file: {name}")
    path = root / name
    # Resolving checks the supplied result file, never any provenance path.
    resolved = path.resolve(strict=True)
    require(resolved.parent == root and path.is_file(), f"Bundle file escapes input directory or is not regular: {name}")
    return path


def hash_input_files(root: Path, names=REQUIRED_FILES) -> dict[str, dict]:
    result = {}
    for name in names:
        path = safe_bundle_file(root, name)
        result[name] = {"sha256": file_hash(path), "size_bytes": path.stat().st_size}
    return result


def read_table(raw: bytes, name: str, schema="1.2") -> list[dict[str, str]]:
    old_limit = csv.field_size_limit()
    try:
        csv.field_size_limit(16 * 1024 * 1024)
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline=""), strict=True)
        header = reader.fieldnames
        require(header is not None, f"{name}.csv: missing header")
        require(len(set(header)) == len(header), f"{name}.csv: duplicate column names")
        required = ERROR_GROUP_FIELDS if schema == "1.6" and name == "errors" else HEADERS[name]
        require(set(required) <= set(header), f"{name}.csv: missing columns {sorted(set(required) - set(header))}")
        if schema == "1.6" and name == "errors":
            require(not {"linked_call_count", "incident_count"} & set(header), "Legacy error counters in schema 1.6")
        result = []
        for index, row in enumerate(reader, 2):
            require(None not in row and None not in row.values(), f"{name}.csv row {index}: malformed column count")
            result.append(row)
        return result
    finally:
        csv.field_size_limit(old_limit)


def unique(rows: list[dict], fields: tuple[str, ...], label: str) -> dict[tuple, dict]:
    result = {}
    for row in rows:
        key = tuple(row[field] for field in fields)
        require(key not in result, f"{label}: duplicate key {key!r}")
        result[key] = row
    return result


def source_problem(row: dict) -> bool:
    return row["status"] in {"partial_read_error", "partial_nul_salvaged"} or (
        row["status"] == "skipped" and not row["reason"].startswith(("empty file", "empty/BOM marker"))
    )


def percentage(numerator: int, denominator: int) -> float | None:
    return round(100 * numerator / denominator, 6) if denominator else None


def check_value(actual: Any, expected: Any, label: str) -> None:
    if expected is None:
        require(actual in (None, ""), f"{label}: expected unavailable value")
    elif isinstance(expected, dict):
        require(actual == expected, f"{label}: numeric quality mismatch")
    elif isinstance(expected, int):
        parsed = actual if type(actual) is float and math.isfinite(actual) and actual.is_integer() else integer(actual, label, None)
        require(parsed == expected, f"{label}: does not reconcile ({actual} != {expected})")
    else:
        require(math.isclose(number(actual, label), expected, rel_tol=1e-9, abs_tol=1e-6), f"{label}: does not reconcile ({actual} != {expected})")


def nearest_rank(values: list[int], p: float) -> int:
    return sorted(values)[math.ceil(p * len(values)) - 1]


def validate_counter_summary(summary: dict, eligible: int, label: str) -> None:
    require(isinstance(summary, dict) and set(summary) == set(CounterStats().as_dict()), label + ": invalid summary fields")
    counts = [summary["available_count"]] + [summary[s + "_count"] for s in STATES[1:]]
    require(all(type(v) is int and v >= 0 for v in counts), label + ": invalid state counts")
    require(type(summary["eligible_count"]) is int and summary["eligible_count"] == eligible == sum(counts), label + ": population mismatch")
    available = counts[0]
    require(type(summary["zero_count"]) is int and 0 <= summary["zero_count"] <= available, label + ": invalid zero count")
    require(type(summary["mean_denominator"]) is int and summary["mean_denominator"] == available, label + ": wrong mean denominator")
    total, maximum = summary["sum_known"], summary["max_known"]
    if available:
        require(type(total) is int and type(maximum) is int, label + ": missing available sum/max")
    else:
        require(total is None and maximum is None, label + ": unknown sum/max represented as zero")
    check_value(summary["sum_complete"], total if eligible and available == eligible else None, label + ".sum_complete")
    check_value(summary["mean"], total / available if available else None, label + ".mean")
    check_value(summary["coverage_percent"], 100 * available / eligible if eligible else None, label + ".coverage")


@dataclass
class Bundle:
    root: Path
    manifest: dict
    tables: dict[str, list[dict]]
    calls: list[dict]
    input_files: dict[str, dict]
    bundle_id: str
    checks: list[str]

    @property
    def sql_normalization_version(self) -> str:
        return self.manifest.get("sql_normalization_version", LEGACY_SQL_NORMALIZATION_VERSION)

    def assert_unchanged(self) -> None:
        require(hash_input_files(self.root, self.input_files) == self.input_files, "Input bundle changed during calculation")


def validate(manifest: dict, tables: dict[str, list[dict]], verification: str = "full") -> tuple[list[dict], list[str]]:
    require(isinstance(manifest, dict), "analysis_metrics.json: expected an object")
    require(manifest.get("schema_version") in SUPPORTED_INPUT_SCHEMAS, "Unsupported input schema; supported: 1.2, 1.3, 1.4, 1.5, 1.6")
    numeric_schema = manifest["schema_version"] in {"1.3", "1.4", "1.5", "1.6"}
    versioned_sql = manifest["schema_version"] in {"1.4", "1.5", "1.6"}
    event_detail = manifest["schema_version"] in {"1.5", "1.6"}
    if manifest["schema_version"] != "1.6":
        require(not set(ERROR_METADATA) & set(manifest), "Legacy schema cannot declare versioned error hypotheses")
    sql_version = SQL_NORMALIZATION_VERSION if versioned_sql else LEGACY_SQL_NORMALIZATION_VERSION
    if versioned_sql:
        require(manifest.get("sql_normalization_version") == sql_version, "Unsupported SQL normalization version")
        require(manifest.get("sql_fingerprint_algorithm") == SQL_FINGERPRINT_ALGORITHM, "Unsupported SQL fingerprint algorithm")
    else:
        require("sql_normalization_version" not in manifest and "sql_fingerprint_algorithm" not in manifest,
                "Legacy schema cannot declare a versioned SQL normalization contract")
    if numeric_schema:
        require(manifest.get("numeric_rules_version") == NUMERIC_RULES_VERSION, "Unsupported numeric rules")
        for filename, fields in QUALITY_CSV_FIELDS.items():
            for row in tables[filename[:-4]]:
                require(set(fields) <= set(row), f"{filename}: missing numeric-quality columns")
    require(isinstance(manifest.get("analyzer_version"), str) and bool(manifest["analyzer_version"]), "Missing analyzer_version")
    for field in ("analysis_complete", "absolute_timestamps_complete", "source_content_hashes_complete", "salvage_nul_prefix"):
        require(type(manifest.get(field)) is bool, f"Manifest {field}: expected boolean")
    for field in ("counts", "method", "units"):
        require(isinstance(manifest.get(field), dict), f"Manifest {field}: expected object")
    require(manifest["units"].get("duration_fields") == "microseconds unless field name explicitly contains seconds", "Unsupported duration units")
    require(manifest["units"].get("io_fields") == "bytes", "Unsupported I/O units")
    require(manifest["units"].get("memory_fields") == "bytes as recorded by the technological journal", "Unsupported memory units")
    require(isinstance(manifest["method"].get("db_to_call_link"), str) and bool(manifest["method"]["db_to_call_link"]), "Missing DB linkage method")
    warnings = manifest.get("warnings")
    require(isinstance(warnings, list) and all(isinstance(x, dict) and isinstance(x.get("type"), str) for x in warnings), "Invalid warnings")
    require(isinstance(manifest.get("archive_inventory"), list), "Missing archive_inventory")
    for table, key in COUNT_KEYS.items():
        check_value(manifest["counts"].get(key), len(tables[table]), f"counts.{key}")
    for name, csv_rows in tables.items():
        if name == "call_observations":
            continue
        json_rows = manifest.get(name)
        if verification == "basic":
            require(isinstance(json_rows, list) and all(isinstance(row, dict) for row in json_rows), f"Invalid {name} rows")
            continue
        require(isinstance(json_rows, list) and len(json_rows) == len(csv_rows), f"{name}: CSV/JSON row count mismatch")
        for index, (csv_row, json_row) in enumerate(zip(csv_rows, json_rows), 2):
            require(isinstance(json_row, dict), f"JSON {name} row {index}: expected object")
            for field, value in csv_row.items():
                require(field in json_row and value == scalar(json_row[field]), f"{name} row {index} {field}: CSV/JSON mismatch")
    checks = ["schema_and_required_fields", "csv_json_mirrors_and_counts"]

    files = tables["files"]
    source_index = unique(files, ("source",), "files")
    datasets = unique(tables["datasets"], ("dataset_id",), "datasets")
    for row in files:
        require(bool(row["source"]), "Empty source identifier")
        require(bool(row["dataset_id"]) and bool(row["measurement_id"]), "Empty file dataset/capture identifier")
        require(row["status"] in SOURCE_STATUSES, f"Unknown source status {row['status']!r}")
        for field in ("size_bytes", "analyzed_bytes", "records", "parse_errors"):
            integer(row[field], f"files.{field}")
        require(int(row["analyzed_bytes"]) <= int(row["size_bytes"]), "analyzed_bytes exceeds source size")
        sha = row["sha256"]
        require(not sha or (len(sha) == 64 and all(c in "0123456789abcdef" for c in sha)), "Invalid recorded source SHA-256")
        if row["status"] in VALID_SOURCE_STATUSES:
            require((row["dataset_id"],) in datasets, "Accepted file references an unknown dataset")
        if row["status"] == "partial_nul_salvaged":
            require(manifest["salvage_nul_prefix"], "Salvaged file but salvage flag is false")
            nul = integer(row["nul_offset"], "nul_offset")
            require(0 < int(row["analyzed_bytes"]) <= nul < int(row["size_bytes"]), "Invalid salvaged prefix bounds")
    for key, count in {
        "sources_analyzed": sum(r["status"] in VALID_SOURCE_STATUSES for r in files),
        "sources_skipped": sum(r["status"].startswith("skipped") for r in files),
        "sources_skipped_as_duplicates": sum(r["status"] == "skipped_duplicate" for r in files),
    }.items():
        check_value(manifest["counts"].get(key), count, key)
    recorded_hash_lines = ["\t".join((r["source"], r["size_bytes"], r["sha256"] or "UNHASHED", r["status"])) for r in sorted(files, key=lambda r: r["source"].lower())]
    require(manifest.get("source_set_hash_sha256") == digest_bytes("\n".join(recorded_hash_lines).encode()), "Recorded source-set hash mismatch")
    require(manifest["source_content_hashes_complete"] == (bool(files) and all(r["sha256"] for r in files)), "Recorded source-hash completeness mismatch")
    material_problem = any(source_problem(r) for r in files) or any(r["type"] in {"archive_error", "discovery_error"} for r in warnings)
    require(manifest["analysis_complete"] == (not material_problem), "analysis_complete contradicts source metadata")
    timestamps_complete = all(r["status"] != "valid_no_timestamp" for r in files)
    if event_detail:
        timestamps_complete = timestamps_complete and not any(r["events_without_absolute_timestamp"] for r in manifest["datasets"])
    require(manifest["absolute_timestamps_complete"] == timestamps_complete, "absolute_timestamps_complete contradicts source/event metadata")
    checks.append("source_metadata_without_source_access")

    calls = []
    for raw in tables["call_observations"]:
        call = dict(raw)
        call["call_id"] = integer(raw["call_id"], "call_id", 1)
        for field in CALL_INTS:
            call[field] = None if numeric_schema and field in {*FIELDS, "db_rows"} and raw[field] == "" else integer(raw[field], f"CALL {call['call_id']} {field}", None if field in {"memory", "memory_peak"} else 0)
        if numeric_schema:
            call["rows_affected"] = None if raw["rows_affected"] == "" else integer(raw["rows_affected"], "CALL.rows_affected")
            call["numeric_quality"] = strict_json(raw["numeric_quality"], "CALL.numeric_quality")
            require(isinstance(call["numeric_quality"], dict) and set(call["numeric_quality"]) == set(FIELDS), "CALL numeric fields mismatch")
            for name, quality in call["numeric_quality"].items():
                require(isinstance(quality, dict), "Invalid numeric observation")
                require(quality.get("value") is None or type(quality["value"]) is int, "Counter value must be integer or null")
                original = quality.get("raw_value")
                require(original is None or isinstance(original, str), "Counter raw value must be string or null")
                require(quality == parse_counter(name, original), f"CALL.{name}: invalid numeric state/value")
                check_value(call[name], quality["value"], f"CALL.{name}")
            call["db_rows_quality"] = strict_json(raw["db_rows_quality"], "CALL.db_rows_quality")
            validate_counter_summary(call["db_rows_quality"], call["db_count"], "CALL.db_rows")
            check_value(call["db_rows"], call["db_rows_quality"]["sum_known"], "CALL.db_rows")
        for field in ("measurement_id", "dataset_id", "user", "signature", "source"):
            require(bool(raw[field]), f"CALL {call['call_id']}: empty {field}")
        require((raw["dataset_id"],) in datasets, "CALL references unknown dataset")
        source = source_index.get((raw["source"],))
        require(source is not None and source["status"] in VALID_SOURCE_STATUSES, "CALL references unknown/skipped source")
        require(source["dataset_id"] == raw["dataset_id"] and source["process"] == raw["process"], "CALL source identity mismatch")
        start = timestamp(raw["start_timestamp"], "CALL.start_timestamp")
        end = timestamp(raw["end_timestamp"], "CALL.end_timestamp")
        require((start is None) == (end is None), "CALL has only one timestamp")
        if start is not None:
            delta = end - start
            elapsed = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
            require(elapsed == call["duration_us"], "CALL interval does not match duration_us")
        calls.append(call)
    call_index = unique(calls, ("call_id",), "CALL")
    top_ids = set()
    raw_calls = {int(row["call_id"]): row for row in tables["call_observations"]}
    for row in tables["top_calls"]:
        cid = integer(row["call_id"], "top_calls.call_id", 1)
        require(cid not in top_ids and cid in raw_calls and row == raw_calls[cid], "top_calls is not a unique exact subset of CALL")
        top_ids.add(cid)
    checks.append("unique_calls_and_exact_top_subset")

    if verification == "basic":
        # CALL conversion, null semantics and input references above are needed
        # by the calculators. The following full branch only reconciles results.
        for name, keys in (
            ("operations", ("measurement_id", "dataset_id", "user", "signature")),
            ("linkage", ("measurement_id", "dataset_id")),
            ("heavy_sql", ("measurement_id", "sql_fingerprint_sha256")),
            ("errors", ("measurement_id", "event", "signature_id" if event_detail and manifest["schema_version"] == "1.6" else "signature")),
            ("locks", ("measurement_id", "event", "context")),
            ("identical_operations", ("signature", "user", "measurement_id")),
        ):
            unique(tables[name], keys, name)
        return sorted(calls, key=lambda c: c["call_id"]), BASIC_CHECKS[:3]

    op_fields = ("measurement_id", "dataset_id", "user", "signature")
    op_index = unique(tables["operations"], op_fields, "operations")
    grouped = collections.defaultdict(list)
    for call in calls:
        grouped[tuple(call[k] for k in op_fields)].append(call)
    require(set(grouped) == set(op_index), "CALL/operation grouping mismatch")
    used_ids = []
    for op in manifest["operations"]:
        key = tuple(op[k] for k in op_fields)
        members = grouped[key]
        ids = op.get("call_ids")
        require(isinstance(ids, list) and all(type(i) is int for i in ids), "Invalid operation call_ids")
        require(sorted(ids) == sorted(c["call_id"] for c in members), "Operation CALL membership mismatch")
        used_ids.extend(ids)
        durations = [c["duration_us"] for c in members]
        expected = {
            "count": len(members), "duration_us": sum(durations),
            "avg_us": round(sum(durations) / len(members), 3),
            "median_us": statistics.median(durations), "p95_us": nearest_rank(durations, .95),
            "p99_us": nearest_rank(durations, .99), "min_us": min(durations), "max_us": max(durations),
        }
        for field in CALL_INTS:
            if field not in {"duration_us", "memory_peak", "db_rows", "sdbl_count"}:
                if not numeric_schema or field not in FIELDS:
                    expected[field] = sum(c[field] for c in members)
        if numeric_schema:
            expected.update(operation_counters(members))
        else:
            expected["rows_affected"] = sum(c["db_rows"] for c in members)
        for sec in (1, 5, 10, 30):
            expected[f"over_{sec}s"] = sum(d >= sec * 1_000_000 for d in durations)
        for field, value in expected.items():
            check_value(op.get(field), value, f"operation.{field}")
    require(len(used_ids) == len(call_index), "Operation membership duplicates observations")
    checks.append("operation_membership_sums_and_percentiles")

    link_index = unique(tables["linkage"], ("measurement_id", "dataset_id"), "linkage")
    linked_calls = collections.defaultdict(list)
    for call in calls:
        linked_calls[(call["measurement_id"], call["dataset_id"])].append(call)
    require(set(linked_calls) <= set(link_index), "CALL has no linkage row")
    for key, link in link_index.items():
        require((link["dataset_id"],) in datasets, "Linkage references an unknown dataset")
        for field, value in link.items():
            if field not in {"measurement_id", "dataset_id"} and not field.endswith("percent"):
                integer(value, f"linkage.{field}")
        members = linked_calls[key]
        check_value(link["call_count"], len(members), "linkage.call_count")
        check_value(link["calls_without_absolute_time"], sum(not c["end_timestamp"] for c in members), "linkage.calls_without_absolute_time")
        for category, field in (("dbpostgrs", "db_count"), ("sdbl", "sdbl_count"), ("lock", "lock_count"), ("error", "error_count")):
            total = int(link[f"{category}_total_count"])
            linked = int(link[f"{category}_linked_count"])
            require(linked <= total, "Linked count exceeds total")
            if not event_detail:
                check_value(linked, sum(c[field] for c in members), f"linkage.{category}_linked_count")
            check_value(link[f"{category}_linked_count_percent"], percentage(linked, total), f"linkage.{category}_linked_count_percent")
        total_time = int(link["dbpostgrs_total_duration_us"])
        linked_time = int(link["dbpostgrs_linked_duration_us"])
        require(linked_time <= total_time, "Linked DB time exceeds total")
        if not event_detail:
            check_value(linked_time, sum(c["db_duration_us"] for c in members), "linkage.db_time")
        check_value(link["dbpostgrs_linked_duration_percent"], percentage(linked_time, total_time), "linkage.dbpostgrs_linked_duration_percent")
        unmatched = sum(int(link[f"{c}_total_count"]) - int(link[f"{c}_linked_count"]) for c in ("dbpostgrs", "sdbl", "lock", "error"))
        check_value(sum(int(link[k]) for k in ("unlinked_missing_timestamp", "unlinked_missing_thread", "unlinked_no_containing_call")), unmatched, "linkage.unlinked_reasons")
    checks.append("linkage_counts_times_and_percentages")

    for dataset in manifest["datasets"]:
        did = dataset["dataset_id"]
        require(isinstance(did, str) and bool(did) and isinstance(dataset["measurement_id"], str) and bool(dataset["measurement_id"]), "Invalid dataset/capture identifier")
        for field in ("files_analyzed", "bytes_analyzed", "records", "parse_errors", "day_events", "night_events", "background_events", "events_without_absolute_timestamp", "active_minutes_with_events", "busiest_db_minute_count"):
            integer(dataset.get(field), f"dataset.{field}")
        for field in ("users", "sessions", "connect_ids", "processes"):
            require(isinstance(dataset.get(field), list) and all(isinstance(x, str) for x in dataset[field]), f"dataset.{field}: expected string array")
        timestamp(dataset["first_timestamp"], "dataset.first_timestamp")
        timestamp(dataset["last_timestamp"], "dataset.last_timestamp")
        actual = dataset.get("actual_measurement_ids")
        require(isinstance(actual, list) and all(isinstance(x, str) and x for x in actual) and len(set(actual)) == len(actual), "Invalid dataset actual_measurement_ids")
        ds_calls = [c for c in calls if c["dataset_id"] == did]
        for call in ds_calls:
            require(call["measurement_id"] in actual or (not call["end_timestamp"] and call["measurement_id"] == dataset["measurement_id"] + "@unknown-date"), "CALL measurement inconsistent with dataset")
        events = dataset.get("event_stats")
        require(isinstance(events, dict), "Invalid dataset event_stats")
        for event, stats in events.items():
            require(isinstance(stats, dict), f"dataset.{event}: expected event statistics")
            integer(stats.get("count"), f"dataset.{event}.count")
            integer(stats.get("duration_us"), f"dataset.{event}.duration_us")
        call_stats = events.get("CALL", {})
        check_value(call_stats.get("count", 0), len(ds_calls), "dataset.CALL.count")
        check_value(call_stats.get("duration_us", 0), sum(c["duration_us"] for c in ds_calls), "dataset.CALL.duration_us")
        ds_links = [v for k, v in link_index.items() if k[1] == did]
        for link in ds_links:
            require(link["measurement_id"] in actual or (dataset["events_without_absolute_timestamp"] and link["measurement_id"] == dataset["measurement_id"] + "@unknown-date"), "Linkage measurement inconsistent with dataset")
        for event_names, category in ((("DBPOSTGRS",), "dbpostgrs"), (("SDBL",), "sdbl"), (("TLOCK", "TTIMEOUT", "TDEADLOCK"), "lock"), (("EXCP", "QERR"), "error")):
            expected_count = sum(integer(events.get(e, {}).get("count", 0), f"dataset.{e}.count") for e in event_names)
            check_value(sum(int(r[f"{category}_total_count"]) for r in ds_links), expected_count, f"dataset.{category}.count")
        check_value(sum(int(r["dbpostgrs_total_duration_us"]) for r in ds_links), events.get("DBPOSTGRS", {}).get("duration_us", 0), "dataset.DBPOSTGRS.duration_us")
    checks.append("dataset_event_totals")
    unique(tables["heavy_sql"], ("measurement_id", "sql_fingerprint_sha256"), "heavy_sql")
    unique(tables["errors"], ("measurement_id", "event", "signature_id" if manifest["schema_version"] == "1.6" else "signature"), "errors")
    unique(tables["locks"], ("measurement_id", "event", "context"), "locks")
    unique(tables["identical_operations"], ("signature", "user", "measurement_id"), "identical_operations")

    def validate_sql(row: dict) -> None:
        require(isinstance(row, dict) and isinstance(row.get("normalized_sql"), str) and
                isinstance(row.get("sql_fingerprint_sha256"), str), "Invalid SQL row text/fingerprint")
        if versioned_sql:
            require(row.get("sql_normalization_version") == sql_version, "SQL row normalization version mismatch")
            require(row.get("sql_normalization_status") == normalization_status(row["normalized_sql"]), "SQL normalization status mismatch")
        else:
            require(not any(key in row for key in SQL_CSV_FIELDS), "Versioned SQL row in legacy schema")
        require(row["sql_fingerprint_sha256"] == sql_fingerprint(row["normalized_sql"], sql_version), "SQL fingerprint does not match saved normalized SQL/version")

    for row in tables["heavy_sql"]:
        validate_sql(row)
    for row in manifest["heavy_sql"]:
        validate_sql(row)
    for operation in manifest["operations"]:
        nested = operation.get("top_nested_sql", [])
        require(isinstance(nested, list) and all(isinstance(row, dict) for row in nested), "Invalid nested SQL rows")
        for row in nested:
            if versioned_sql:
                validate_sql(row)
            else:
                require(not any(key in row for key in SQL_CSV_FIELDS), "Versioned nested SQL in legacy schema")
                if "sql_fingerprint_sha256" in row:
                    validate_sql(row)
    if numeric_schema:
        for row in manifest["heavy_sql"]:
            quality = row.get("numeric_quality")
            require(isinstance(quality, dict) and set(quality) == set(FIELDS), "SQL numeric fields mismatch")
            for name, summary in quality.items():
                validate_counter_summary(summary, row["count"], "SQL." + name)
            for name, key in (("rows_affected", "sum_known"), ("max_rows_affected", "max_known"), ("rows_affected_per_event", "mean")):
                check_value(row.get(name), quality["rows_affected"][key], "SQL." + name)
        for dataset in manifest["datasets"]:
            for event, stats in dataset["event_stats"].items():
                quality = stats.get("numeric_quality")
                require(isinstance(quality, dict) and set(quality) == set(FIELDS), "Dataset numeric fields mismatch")
                for name, summary in quality.items():
                    validate_counter_summary(summary, stats["count"], event + "." + name)
        checks.append("numeric_states_coverage_available_denominators_and_paired_cpu")
    checks.append("auxiliary_table_keys_and_sql_fingerprints")
    return sorted(calls, key=lambda c: c["call_id"]), checks


def load_bundle(path: Path, verification: str = "full") -> Bundle:
    try:
        require(verification in MODES, "verification must be full or basic")
        root = path.resolve(strict=True)
        require(root.is_dir(), "Input must be a saved-result directory")
        manifest_raw = safe_bundle_file(root, "analysis_metrics.json").read_bytes()
        manifest = strict_json(manifest_raw.decode("utf-8-sig"), "analysis_metrics.json")
        require(isinstance(manifest, dict), "analysis_metrics.json: expected an object")
        require(manifest.get("schema_version") in SUPPORTED_INPUT_SCHEMAS, "Unsupported input schema; supported: 1.2, 1.3, 1.4, 1.5, 1.6")
        if "verification" in manifest:
            validate_metadata(manifest["verification"])
            require(manifest["verification"]["input_schema_version"] == manifest.get("schema_version"), "Verification schema mismatch")
        hashes = {"analysis_metrics.json": {"sha256": digest_bytes(manifest_raw), "size_bytes": len(manifest_raw)}}
        tables = {}
        for name in sorted(HEADERS):
            raw = safe_bundle_file(root, name + ".csv").read_bytes()
            hashes[name + ".csv"] = {"sha256": digest_bytes(raw), "size_bytes": len(raw)}
            tables[name] = read_table(raw, name, manifest["schema_version"])
            header = next(csv.reader(io.StringIO(raw.decode("utf-8-sig"))))
            if manifest["schema_version"] in {"1.3", "1.4", "1.5", "1.6"}:
                require(set(QUALITY_CSV_FIELDS.get(name + ".csv", [])) <= set(header), f"{name}: missing numeric-quality header")
            if manifest["schema_version"] in {"1.5", "1.6"} and name in {"call_observations", "top_calls"}:
                require(set(CALL_DETAIL_FIELDS) <= set(header), f"{name}: missing event identity header")
            if name == "heavy_sql":
                if manifest["schema_version"] in {"1.4", "1.5", "1.6"}:
                    require(set(SQL_CSV_FIELDS) <= set(header), "heavy_sql: missing SQL normalization header")
                else:
                    require(not set(SQL_CSV_FIELDS) & set(header), "Versioned SQL header in legacy schema")
        calls, checks = validate(manifest, tables, verification)
        if manifest["schema_version"] in {"1.5", "1.6"}:
            if verification == "full":
                hashes.update(verify_detail(root, manifest, calls))
                checks.extend(POPULATION_CHECKS)
                checks.append("full_db_events_dictionary_link_decisions_candidates_and_accounting")
                if manifest["schema_version"] == "1.6":
                    checks.append("error_events_distinct_calls_and_versioned_incident_hypotheses")
            else:
                hashes.update(load_detail_structure(root, manifest))
        if verification == "basic":
            checks.append(BASIC_CHECKS[3])
        bundle_id = digest_bytes(canonical_json(hashes).encode())
        bundle = Bundle(root, manifest, tables, calls, hashes, bundle_id, checks)
        bundle.assert_unchanged()
        return bundle
    except SliceError:
        raise
    except (OSError, UnicodeError, csv.Error, sqlite3.Error, KeyError, TypeError, ValueError, OverflowError) as exc:
        raise SliceError(f"Invalid saved-result bundle: {exc}") from exc


def load_detail_structure(root, manifest):
    """Read identity and storage metadata without scanning event populations."""
    from contextlib import closing
    from event_store import VERSIONS, LEGACY_VERSIONS
    require(manifest.get("publication_state") == "complete", "incomplete publication")
    require(manifest.get("source_processing_complete") == manifest["analysis_complete"], "source completeness mismatch")
    versions = VERSIONS if manifest["schema_version"] == "1.6" else LEGACY_VERSIONS
    require(all(manifest.get(k) == v for k, v in versions.items()), "Unsupported detail versions")
    hashes = descriptors(root, manifest)
    source_map = strict_json(safe_path(root, "source_map.json").read_text(encoding="utf-8"), "source map")
    require(isinstance(source_map, dict) and source_map.get("capture_id") == manifest.get("capture_id")
            and isinstance(source_map.get("sources"), list), "Invalid source map")
    with closing(sqlite3.connect(safe_path(root, "analysis.sqlite").as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        require(db.execute("PRAGMA user_version").fetchone()[0] == (2 if manifest["schema_version"] == "1.6" else 1), "Unsupported storage schema")
        saved = {k: strict_json(v, "SQLite metadata") for k, v in db.execute("SELECT key,value FROM metadata")}
        require(saved.get("publication_state") == "complete" and all(saved.get(k) == v for k, v in versions.items()), "Invalid storage metadata")
        schema_names = ["event_schema.sql"] + (["error_schema.sql"] if manifest["schema_version"] == "1.6" else [])
        expected_tables = set()
        for name in schema_names:
            expected_tables.update(re.findall(r"CREATE TABLE (\w+)", Path(__file__).with_name(name).read_text(encoding="utf-8")))
        actual_tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        require(expected_tables <= actual_tables, "Missing storage tables")
    return hashes
