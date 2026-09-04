"""Schema 1.3 numeric rules. Unknown counters are never measured zeroes.

Sums are sums of available observations (None if none); means divide by
available_count. sum_complete is only populated for a nonempty, complete
population. Signed memory counters retain the schema-1.2 sign convention.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
import statistics

NUMERIC_RULES_VERSION = "1.0"
FIELDS = {
    "cpu_us": ("CpuTime", "us", 0),
    "memory": ("Memory", "bytes", -(2**63)),
    "memory_peak": ("MemoryPeak", "bytes", -(2**63)),
    "in_bytes": ("InBytes", "bytes", 0),
    "out_bytes": ("OutBytes", "bytes", 0),
    "rows_affected": ("RowsAffected", "rows", 0),
}
STATES = ("valid", "missing", "empty", "invalid", "out_of_range")
QUALITY_CSV_FIELDS = {
    "call_observations.csv": ["rows_affected", "numeric_quality", "db_rows_quality"],
    "top_calls.csv": ["rows_affected", "numeric_quality", "db_rows_quality"],
    "operations.csv": ["numeric_quality", "call_rows_affected", "cpu_available_count", "cpu_wall_us", "cpu_coverage_percent", "cpu_wall_coverage_percent"],
    "identical_operations.csv": ["numeric_quality", "cpu_available_count", "cpu_wall_us", "cpu_coverage_percent", "cpu_wall_coverage_percent"],
    "heavy_sql.csv": ["numeric_quality", "rows_affected_per_event"],
}


def parse_counter(name: str, raw: str | None) -> dict:
    _, unit, minimum = FIELDS[name]
    value, reason = None, None
    if raw is None:
        state = "missing"
    elif not raw.strip():
        state = "empty"
    elif re.fullmatch(r"[+-]?[0-9]+", raw.strip()) is None:
        state, reason = "invalid", "not_an_integer"
    else:
        # Avoid Python's decimal conversion limit on malformed huge counters.
        digits = raw.strip().lstrip("+-").lstrip("0") or "0"
        if len(digits) > 19:
            state, reason = "out_of_range", "outside_supported_range"
        else:
            value = int(("-" if raw.strip().startswith("-") else "") + digits)
            state = "valid" if minimum <= value <= 2**63-1 else "out_of_range"
            if state != "valid":
                value, reason = None, "outside_supported_range"
    return {"state": state, "raw_value": raw, "value": value, "unit": unit, "reason": reason}


def parse_counters(attrs: dict[str, str]) -> dict:
    return {name: parse_counter(name, attrs.get(spec[0])) for name, spec in FIELDS.items()}


@dataclass
class CounterStats:
    counts: dict = field(default_factory=lambda: dict.fromkeys(STATES, 0))
    total: int = 0
    maximum: int | None = None
    zero_count: int = 0

    def add(self, observation: dict) -> None:
        self.counts[observation["state"]] += 1
        if observation["state"] == "valid":
            value = observation["value"]
            self.total += value
            self.maximum = value if self.maximum is None else max(self.maximum, value)
            self.zero_count += value == 0

    def merge(self, summary: dict) -> None:
        self.counts["valid"] += summary["available_count"]
        for state in STATES[1:]:
            self.counts[state] += summary[state + "_count"]
        if summary["available_count"]:
            self.total += summary["sum_known"]
            other = summary["max_known"]
            self.maximum = other if self.maximum is None else max(self.maximum, other)
        self.zero_count += summary["zero_count"]

    def as_dict(self) -> dict:
        n, available = sum(self.counts.values()), self.counts["valid"]
        return {
            "eligible_count": n, "available_count": available,
            **{state + "_count": self.counts[state] for state in STATES[1:]},
            "zero_count": self.zero_count,
            "sum_known": self.total if available else None,
            "sum_complete": self.total if n and available == n else None,
            "mean": self.total / available if available else None,
            "mean_denominator": available,
            "max_known": self.maximum,
            "coverage_percent": 100 * available / n if n else None,
        }


def get(row, name):
    return row.get(name) if isinstance(row, dict) else getattr(row, name)


def counter_summaries(calls) -> dict:
    result = {}
    for name in FIELDS:
        stats = CounterStats()
        for call in calls:
            stats.add(get(call, "numeric_quality")[name])
        result[name] = stats.as_dict()
    db = CounterStats()
    for call in calls:
        db.merge(get(call, "db_rows_quality"))
    result["db_rows"] = db.as_dict()
    return result


def available_stats(values) -> dict:
    values = sorted(v for v in values if v is not None)
    n = len(values)
    return {"count": n, "sum": sum(values) if n else None,
            "avg": sum(values)/n if n else None, "max": max(values) if n else None,
            "median": statistics.median(values) if n else None,
            "p95": values[(95*n+99)//100-1] if n else None,
            "p99": values[(99*n+99)//100-1] if n else None}


def cpu_population(calls) -> dict:
    covered = [c for c in calls if get(c, "cpu_us") is not None]
    wall = sum(get(c, "duration_us") for c in covered)
    total_wall = sum(get(c, "duration_us") for c in calls)
    cpu = sum(get(c, "cpu_us") for c in covered) if covered else None
    db = sum(get(c, "db_duration_us") for c in covered)
    residual = max(0, wall-cpu-db) if covered else None
    return {
        "cpu_available_count": len(covered), "cpu_wall_us": wall,
        "cpu_coverage_percent": 100*len(covered)/len(calls) if calls else None,
        "cpu_wall_coverage_percent": 100*wall/total_wall if total_wall else None,
        "cpu_percent_of_wall": 100*cpu/wall if wall and cpu is not None else None,
        "unattributed_us_floor": residual,
        "unattributed_percent_floor": 100*residual/wall if wall and residual is not None else None,
        "attribution_overflow_us": max(0, cpu+db-wall) if covered else None,
    }


def operation_counters(calls) -> dict:
    """Counters for parser operation rows, from CALL and linked DB populations."""
    quality = counter_summaries(calls)
    result = {"numeric_quality": quality, **cpu_population(calls)}
    for name in ("cpu_us", "memory", "in_bytes", "out_bytes"):
        result[name] = quality[name]["sum_known"]
    for name in ("memory", "in_bytes", "out_bytes"):
        mean = quality[name]["mean"]
        result[name + "_per_call"] = round(mean, 3) if mean is not None else None
    result.update(memory_max=quality["memory"]["max_known"],
                  max_out_bytes=quality["out_bytes"]["max_known"],
                  call_rows_affected=quality["rows_affected"]["sum_known"],
                  rows_affected=quality["db_rows"]["sum_known"])
    peaks = available_stats(get(c, "memory_peak") for c in calls)
    for name in ("avg", "median", "p95", "max"):
        value = peaks[name]
        result["memory_peak_" + name] = round(value, 3) if name == "avg" and value is not None else value
    for name, digits in (("cpu_percent_of_wall", 4), ("unattributed_percent_floor", 6)):
        if result[name] is not None:
            result[name] = round(result[name], digits)
    return result
