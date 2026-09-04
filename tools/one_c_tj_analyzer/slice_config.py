"""Versioned, strict configuration for saved-result slices (stdlib only)."""
from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal
from pathlib import Path
from typing import Any

CALCULATOR_VERSION = "1.8.0"
SLICE_SCHEMA_VERSION = "1.8"
CONFIG_VERSION = "1.0"
SUPPORTED_INPUT_SCHEMAS = {"1.2", "1.3", "1.4", "1.5", "1.6"}
REGISTERED_SLICES = ("data_quality", "operation_history", "operation_history_all_users", "measurement_comparisons", "comparability",
                     "db_chatty", "db_chatty_calls", "db_chatty_fast_calls", "db_chatty_duration", "db_chatty_coverage", "db_chatty_changes",
                     "apdex", "apdex_calls", "apdex_uncovered", "apdex_coverage", "apdex_overall", "apdex_composition", "apdex_changes",
                     "problem_registry", "problem_history", "problem_improved", "problem_persisting", "problem_worsened",
                     "problem_new", "problem_unchecked", "problem_rule_coverage")


class SliceError(ValueError):
    """Actionable input/configuration/consistency error."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def seconds_to_us(value: Any, label: str) -> int:
    """Reject sub-microsecond/invalid settings instead of silently rounding."""
    if type(value) not in (int, float) or value < 0 or value > 9_007_199_254 or not math.isfinite(value):
        raise SliceError(f"{label}: expected finite nonnegative seconds")
    microseconds = Decimal(str(value)) * 1_000_000
    if microseconds != microseconds.to_integral_value():
        raise SliceError(f"{label}: must be representable in whole microseconds")
    if Decimal(str(int(microseconds) / 1_000_000)) * 1_000_000 != microseconds:
        raise SliceError(f"{label}: cannot normalize seconds without losing microsecond precision")
    return int(microseconds)


def strict_json(text: str, label: str) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SliceError(f"{label}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise SliceError(f"{label}: non-finite JSON value {value}")

    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            invalid_constant(value)
        return result

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant, parse_float=finite_float)
    except (ValueError, TypeError) as exc:
        raise SliceError(f"{label}: {exc}") from exc


def names(value: Any, label: str, *, empty: bool = False) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
        raise SliceError(f"{label}: expected a list of non-empty strings")
    if not empty and not value:
        raise SliceError(f"{label}: must not be empty")
    if len(set(value)) != len(value):
        raise SliceError(f"{label}: duplicate names")
    return sorted(value)


def load_config(path: Path, selected: list[str] | None = None) -> tuple[dict, str]:
    try:
        raw = path.read_bytes()
        config = strict_json(raw.decode("utf-8-sig"), "configuration")
    except (OSError, UnicodeError) as exc:
        raise SliceError(f"Cannot read configuration: {exc}") from exc
    return normalize_config(config, selected), digest_bytes(raw)


def normalize_config(config: Any, selected: list[str] | None = None) -> dict:
    """Validate an object, also usable for the saved effective configuration."""
    if not isinstance(config, dict):
        raise SliceError("configuration: expected an object")
    allowed = {"config_version", "slices", "measurement_ids", "expected_bundle_id", "data_quality", "operations", "db_chatty", "apdex", "problems"}
    unknown = set(config) - allowed
    if unknown:
        raise SliceError(f"configuration: unknown keys {sorted(unknown)}")
    if config.get("config_version") != CONFIG_VERSION:
        raise SliceError(f"configuration: config_version must be {CONFIG_VERSION}")
    configured = names(config.get("slices", ["data_quality"]), "slices")
    chosen = names(selected, "--slices") if selected is not None else configured
    for value in configured + chosen:
        if value not in REGISTERED_SLICES:
            raise SliceError(f"Unknown/unimplemented slice {value!r}; available: {REGISTERED_SLICES}")
    if "apdex_overall" in chosen:
        chosen = sorted(set(chosen) | {"apdex_composition"})
    measurements = config.get("measurement_ids")
    if measurements is not None:
        measurements = names(measurements, "measurement_ids")
    expected = config.get("expected_bundle_id")
    if expected is not None and (not isinstance(expected, str) or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected)):
        raise SliceError("expected_bundle_id must be a lowercase SHA-256 or null")
    quality = config.get("data_quality", {})
    if not isinstance(quality, dict) or set(quality) - {"min_call_count", "db_linkage_warning_percent"}:
        raise SliceError("data_quality: expected only min_call_count and db_linkage_warning_percent")
    minimum = quality.get("min_call_count", 10)
    threshold = quality.get("db_linkage_warning_percent", 99)
    if type(minimum) is not int or minimum < 1:
        raise SliceError("data_quality.min_call_count must be a positive integer")
    if type(threshold) not in (int, float) or not 0 <= threshold <= 100:
        raise SliceError("data_quality.db_linkage_warning_percent must be in [0, 100]")
    operations = config.get("operations", {})
    if not isinstance(operations, dict) or set(operations) - {"series_baseline_measurement_id", "measurement_order", "min_comparison_count"}:
        raise SliceError("operations: unknown keys or invalid object")
    baseline = operations.get("series_baseline_measurement_id")
    if baseline is not None and (not isinstance(baseline, str) or not baseline):
        raise SliceError("operations.series_baseline_measurement_id must be a non-empty identifier or null")
    order = operations.get("measurement_order")
    if order is not None:
        names(order, "operations.measurement_order")
        order = list(order)  # Validation must not sort an explicitly declared order.
    comparison_minimum = operations.get("min_comparison_count", 10)
    if type(comparison_minimum) is not int or comparison_minimum < 1:
        raise SliceError("operations.min_comparison_count must be a positive integer")
    chatty = config.get("db_chatty", {})
    if not isinstance(chatty, dict) or set(chatty) - {"thresholds", "duration_bounds_seconds", "fast_call_max_seconds"}:
        raise SliceError("db_chatty: unknown keys or invalid object")
    thresholds = chatty.get("thresholds", [100, 500, 1000, 5000])
    if (not isinstance(thresholds, list) or not thresholds or
            any(type(t) is not int or t <= 0 for t in thresholds) or len(set(thresholds)) != len(thresholds)):
        raise SliceError("db_chatty.thresholds: expected distinct positive integers")
    bounds = chatty.get("duration_bounds_seconds", [1, 5, 10, 30])
    if not isinstance(bounds, list) or not bounds:
        raise SliceError("db_chatty.duration_bounds_seconds: expected a nonempty list")
    bound_us = [seconds_to_us(v, "db_chatty.duration_bounds_seconds") for v in bounds]
    if any(v <= 0 for v in bound_us) or len(set(bound_us)) != len(bound_us):
        raise SliceError("db_chatty.duration_bounds_seconds: expected distinct positive bounds")
    fast_us = seconds_to_us(chatty.get("fast_call_max_seconds", 1), "db_chatty.fast_call_max_seconds")
    from slice_apdex_config import normalize_apdex
    from slice_problem_config import normalize_problems
    return {
        "config_version": CONFIG_VERSION,
        "slices": chosen,
        "measurement_ids": measurements,
        "expected_bundle_id": expected,
        "data_quality": {"min_call_count": minimum, "db_linkage_warning_percent": float(threshold)},
        "operations": {"series_baseline_measurement_id": baseline, "measurement_order": order, "min_comparison_count": comparison_minimum},
        "db_chatty": {"thresholds": sorted(thresholds), "duration_bounds_seconds": [v / 1_000_000 for v in sorted(bound_us)], "fast_call_max_seconds": fast_us / 1_000_000},
        "apdex": normalize_apdex(config.get("apdex", {})),
        "problems": normalize_problems(config.get("problems", {})),
    }
