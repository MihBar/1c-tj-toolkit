"""Allowlisted numerical problem rules. No text matching, eval or causal labels."""
from __future__ import annotations

import math

from slice_config import SliceError, names
from slice_operations import METRIC_FIELDS
from slice_db_chatty import PROFILE_FIELDS


def unit(field):
    if "percent" in field:
        return "percent"
    if "bytes" in field or field.startswith("memory_peak"):
        return "bytes"
    if "seconds" in field:
        return "seconds_per_CALL"
    if "_us" in field:
        return "microseconds"
    if "per_call" in field:
        return "DB_events_per_CALL"
    return "count"


METRICS = {"operation." + f: {"source": "operation_history", "field": f, "unit": unit(f)} for f in ["count", *METRIC_FIELDS]}
METRICS.update({"db_chatty." + f: {"source": "db_chatty", "field": f, "unit": unit(f)} for f in PROFILE_FIELDS})
METRICS.update({
    "apdex.deficit": {"source": "apdex", "field": "apdex", "unit": "1_minus_APDEX"},
    "apdex.frustrated_count": {"source": "apdex", "field": "frustrated_count", "unit": "CALL_count"},
    "apdex.forced_frustrated_count": {"source": "apdex", "field": "forced_frustrated_count", "unit": "CALL_count"},
})


def nonempty(value, label):
    if not isinstance(value, str) or not value.strip():
        raise SliceError(f"{label}: expected a nonempty string")
    return value


def normalize_problems(raw):
    if not isinstance(raw, dict) or set(raw) - {"series_id", "rules"}:
        raise SliceError("problems: expected only series_id and rules")
    series_id = raw.get("series_id")
    if series_id is not None:
        nonempty(series_id, "problems.series_id")
    rules = raw.get("rules", [])
    if not isinstance(rules, list):
        raise SliceError("problems.rules must be a list")
    if rules and series_id is None:
        raise SliceError("problems.series_id is required for stable problem identities")
    result, seen = [], set()
    required = {"rule_id", "metric", "operator", "threshold", "min_call_count", "source"}
    optional = {"scope", "signatures", "users", "db_events_threshold", "min_db_linked_count_percent",
                "min_db_linked_duration_percent", "require_clean_sources"}
    for rule in rules:
        if not isinstance(rule, dict) or not required <= set(rule) or set(rule) - required - optional:
            raise SliceError(f"Problem rule: required {sorted(required)}; optional {sorted(optional)}")
        rid = nonempty(rule["rule_id"], "problem rule_id")
        if rid in seen:
            raise SliceError(f"Duplicate problem rule_id {rid!r}")
        seen.add(rid)
        metric = rule["metric"]
        if not isinstance(metric, str) or metric not in METRICS:
            raise SliceError("Unknown problem metric; use allowlisted operation.*, db_chatty.* or apdex.deficit/frustrated_count/forced_frustrated_count")
        if rule["operator"] not in (">", ">="):
            raise SliceError("Problem rules support > or >= adverse-magnitude bounds; use apdex.deficit for low APDEX")
        threshold = rule["threshold"]
        if type(threshold) not in (int, float) or threshold < 0 or threshold > 10**30 or not math.isfinite(threshold):
            raise SliceError("Problem threshold must be a finite nonnegative number <= 1e30")
        if metric == "apdex.deficit" and threshold > 1:
            raise SliceError("APDEX deficit threshold must be in [0,1]")
        if type(threshold) is float and threshold.is_integer():
            threshold = int(threshold)
        minimum = rule["min_call_count"]
        if type(minimum) is not int or minimum < 1:
            raise SliceError("Problem min_call_count must be a positive integer")
        if rule.get("scope", "same_user") != "same_user":
            raise SliceError("Problem comparison scope must be same_user; no pooled-user comparisons")
        row = {"rule_id": rid, "metric": metric, "operator": rule["operator"], "threshold": threshold,
               "min_call_count": minimum, "source": nonempty(rule["source"], "problem rule source"), "scope": "same_user"}
        for name in ("signatures", "users"):
            selected = rule.get(name)
            row[name] = names(selected, "problem " + name) if selected is not None else None
        db_k = rule.get("db_events_threshold")
        if metric.startswith("db_chatty."):
            if type(db_k) is not int or db_k < 1:
                raise SliceError("db_chatty problem rules require a positive db_events_threshold (CALL.db_count > K)")
        elif db_k is not None:
            raise SliceError("db_events_threshold is only valid for db_chatty metrics")
        row["db_events_threshold"] = db_k
        for name in ("min_db_linked_count_percent", "min_db_linked_duration_percent"):
            value = rule.get(name)
            if value is not None and (type(value) not in (int, float) or not 0 <= value <= 100):
                raise SliceError(f"{name} must be null or in [0,100]")
            if value is not None and not (metric.startswith("db_chatty.") or metric.startswith("operation.db_")):
                raise SliceError("DB coverage gates are only applicable to DB metrics")
            row[name] = float(value) if value is not None else None
        clean = rule.get("require_clean_sources", False)
        if type(clean) is not bool:
            raise SliceError("require_clean_sources must be a boolean")
        row["require_clean_sources"] = clean
        result.append(row)
    return {"series_id": series_id, "rules": sorted(result, key=lambda r: r["rule_id"])}
