"""Strict explicit APDEX targets and externally confirmed failure policy."""
from __future__ import annotations

from slice_config import SliceError, names, seconds_to_us

TARGET_STATUSES = ("business_approved", "engineering_proposal")
FAILURE_POLICIES = ("latency_only", "confirmed_failures_frustrated")


def nonempty(value, label):
    if not isinstance(value, str) or not value.strip():
        raise SliceError(f"{label}: expected a nonempty string")
    return value


def sha256_or_none(value, label):
    if value is not None and (not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value)):
        raise SliceError(f"{label}: expected lowercase SHA-256 or null")
    return value


def normalize_apdex(raw):
    if not isinstance(raw, dict) or set(raw) - {"targets", "classes", "min_call_count", "failure_policy", "confirmed_failures"}:
        raise SliceError("apdex: unknown keys or invalid object")
    minimum = raw.get("min_call_count", 10)
    if type(minimum) is not int or minimum < 1:
        raise SliceError("apdex.min_call_count: expected positive integer")
    policy = raw.get("failure_policy", "latency_only")
    if policy not in FAILURE_POLICIES:
        raise SliceError(f"apdex.failure_policy: expected one of {FAILURE_POLICIES}")
    result = {"min_call_count": minimum, "failure_policy": policy}
    for category, identity in (("targets", "signature"), ("classes", "class_id")):
        entries = raw.get(category, [])
        if not isinstance(entries, list):
            raise SliceError(f"apdex.{category}: expected a list")
        normalized = []
        seen = set()
        for entry in entries:
            required = {identity, "t_seconds", "status", "source"} | ({"signatures"} if category == "classes" else set())
            if not isinstance(entry, dict) or set(entry) != required:
                raise SliceError(f"apdex.{category}: required exactly {sorted(required)}")
            key = nonempty(entry[identity], f"apdex.{category}.{identity}")
            if key in seen:
                raise SliceError(f"apdex.{category}: duplicate {identity} {key!r}")
            seen.add(key)
            t_us = seconds_to_us(entry["t_seconds"], "apdex.t_seconds")
            if not t_us:
                raise SliceError("apdex.t_seconds must be positive; omit a target rather than assigning zero")
            if entry["status"] not in TARGET_STATUSES:
                raise SliceError(f"apdex target status must be one of {TARGET_STATUSES}")
            row = {identity: key, "t_seconds": t_us / 1_000_000, "status": entry["status"],
                   "source": nonempty(entry["source"], "apdex target source")}
            if category == "classes":
                row["signatures"] = names(entry["signatures"], "apdex class signatures")
                for sig in row["signatures"]:
                    nonempty(sig, "apdex class signature")
            normalized.append(row)
        result[category] = sorted(normalized, key=lambda r: r[identity])
    members = {}
    for cls in result["classes"]:
        for sig in cls["signatures"]:
            if sig in members:
                raise SliceError(f"apdex: signature {sig!r} belongs to multiple classes; ambiguous target")
            members[sig] = cls["class_id"]
    failures = raw.get("confirmed_failures", {})
    if not isinstance(failures, dict) or set(failures) - {"bundle_id", "calls"}:
        raise SliceError("apdex.confirmed_failures: expected bundle_id and calls only")
    bundle_id = sha256_or_none(failures.get("bundle_id"), "apdex.confirmed_failures.bundle_id")
    calls = failures.get("calls", [])
    if not isinstance(calls, list):
        raise SliceError("apdex.confirmed_failures.calls: expected a list")
    seen = set()
    confirmed = []
    for entry in calls:
        if not isinstance(entry, dict) or set(entry) != {"call_id", "evidence"}:
            raise SliceError("apdex confirmed failure requires exactly call_id and evidence")
        call_id = entry["call_id"]
        if type(call_id) is not int or call_id < 1 or call_id in seen:
            raise SliceError("apdex confirmed failure call_id must be positive and unique")
        seen.add(call_id)
        confirmed.append({"call_id": call_id, "evidence": nonempty(entry["evidence"], "confirmed failure evidence")})
    if confirmed and (bundle_id is None or policy != "confirmed_failures_frustrated"):
        raise SliceError("Confirmed failures require bundle_id and failure_policy=confirmed_failures_frustrated")
    result["confirmed_failures"] = {"bundle_id": bundle_id, "calls": sorted(confirmed, key=lambda c: c["call_id"])}
    return result
