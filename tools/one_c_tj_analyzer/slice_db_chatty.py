"""Diagnostic DB-event density from retained individual CALLs; never SQL/N+1 inference."""
from __future__ import annotations

import collections
import statistics

from slice_config import seconds_to_us
from slice_input import nearest_rank
from slice_operations import (COMPARISON_COMMON, OperationSeries, UNKNOWN_PARAMETERS,
                              UNKNOWN_USER_VALUES, stable_id)

LIMITATIONS = [
    "diagnostic_thresholds_not_official_norms_or_proof_of_excess",
    "zero_linked_db_does_not_prove_no_database_access",
    "per_call_db_linkage_confidence_unavailable",
    "no_N_plus_1_diagnosis_or_complete_CALL_SQL_reconstruction",
    "nested_threshold_populations_overlap_do_not_sum_thresholds",
]
PROFILE_FIELDS = (
    "db_count_sum db_per_call_avg db_per_call_median db_per_call_p95 db_per_call_max "
    "call_duration_us_sum call_duration_us_avg call_duration_us_median call_duration_us_p95 call_duration_us_max "
    "linked_db_duration_us_sum linked_db_seconds_per_call calls_with_zero_linked_db "
    "calls_above_threshold_count call_share_denominator calls_above_threshold_percent "
    "fast_call_count fast_calls_above_threshold_count fast_call_share_denominator fast_calls_above_threshold_percent "
    "chatty_db_count_sum chatty_call_duration_us_sum chatty_call_duration_us_avg "
    "chatty_call_duration_us_median chatty_call_duration_us_p95 chatty_call_duration_us_max "
    "chatty_linked_db_duration_us_sum chatty_linked_db_seconds_per_call"
).split()
GROUP_METADATA = (
    "group_id history_id operation_id cohort_id signature user population_scope measurement_id measurement_order "
    "series_order_reliable order_basis observation_status observation_label count "
    "threshold_db_events threshold_operator fast_call_max_us fast_operator "
    "group_mean_above_threshold calls_in_mean_flagged_group_count sample_size_status "
    "measurement_db_linked_count_percent measurement_db_linked_duration_percent measurement_source_health "
    "calls_from_partial_sources known_limitations"
).split()
GROUP_FIELDS = GROUP_METADATA + PROFILE_FIELDS
CALL_FIELDS = (
    "observation_id call_id history_id operation_id cohort_id signature user measurement_id measurement_order "
    "dataset_id source process start_timestamp end_timestamp duration_us linked_db_count linked_db_duration_us "
    "thresholds_exceeded threshold_operator group_mean_thresholds_exceeded is_fast_call fast_call_max_us fast_operator "
    "duration_band_index duration_lower_us_exclusive duration_upper_us_inclusive "
    "measurement_db_linked_count_percent measurement_db_linked_duration_percent source_status known_limitations"
).split()
DURATION_FIELDS = (
    "distribution_id group_id history_id operation_id cohort_id signature user measurement_id threshold_db_events "
    "threshold_operator duration_band_index duration_lower_us_exclusive duration_upper_us_inclusive "
    "group_call_count band_call_count band_calls_above_threshold_count within_band_call_denominator "
    "within_band_above_threshold_percent group_chatty_call_denominator share_of_group_chatty_calls_percent "
    "band_call_duration_us_sum band_linked_db_duration_us_sum chatty_call_duration_us_sum "
    "chatty_linked_db_duration_us_sum known_limitations"
).split()
COVERAGE_FIELDS = (
    "coverage_id population_scope measurement_id measurement_ids threshold_db_events threshold_operator "
    "total_call_count chatty_call_count call_share_denominator chatty_call_percent "
    "observed_operation_count affected_operation_count operation_share_denominator affected_operation_percent "
    "observed_known_user_count affected_known_user_count known_user_share_denominator affected_known_user_percent "
    "calls_with_unknown_user_count chatty_calls_with_unknown_user_count "
    "observed_operation_user_measurement_group_count mean_flagged_group_count "
    "mean_flagged_operation_count mean_flagged_known_user_count calls_in_mean_flagged_groups_count "
    "mean_flagged_group_call_denominator calls_in_mean_flagged_groups_percent "
    "fast_call_count fast_chatty_call_count fast_call_share_denominator fast_chatty_call_percent "
    "fast_call_max_us fast_operator calls_with_zero_linked_db "
    "call_duration_us_sum linked_db_duration_us_sum chatty_call_duration_us_sum chatty_linked_db_duration_us_sum "
    "measurement_db_coverage known_limitations"
).split()
CHANGE_FIELDS = COMPARISON_COMMON + (
    "operation_comparison_id threshold_db_events threshold_operator "
    "reference_group_mean_above_threshold current_group_mean_above_threshold "
    "reference_call_share_denominator current_call_share_denominator "
    "reference_measurement_db_linked_count_percent current_measurement_db_linked_count_percent "
    "reference_measurement_db_linked_duration_percent current_measurement_db_linked_duration_percent "
    "signature_match user_match known_differences unknown_parameters known_limitations "
    "percent_undefined_zero_reference_metrics unavailable_metrics"
).split() + [m + s for m in PROFILE_FIELDS for s in ("_reference", "_current", "_delta_absolute", "_delta_percent")]


def percentage(numerator: int, denominator: int) -> float | None:
    # Keep the full computed ratio, not a rounded percentage used as a new base.
    return 100 * numerator / denominator if denominator else None


def distribution(values: list[int]) -> dict:
    return {"sum": sum(values), "avg": sum(values) / len(values) if values else None,
            "median": statistics.median(values) if values else None,
            "p95": nearest_rank(values, .95) if values else None, "max": max(values) if values else None}


def profile(calls: list[dict], threshold: int, fast_us: int) -> dict:
    """The group mean flag and actual CALL hits are separate predicates."""
    n = len(calls)
    hit = [c for c in calls if c["db_count"] > threshold]
    fast = [c for c in calls if c["duration_us"] <= fast_us]
    fast_hit = [c for c in fast if c["db_count"] > threshold]
    counts = [c["db_count"] for c in calls]
    db_sum = sum(counts)
    # Integer comparison avoids a floating-point boundary error in the mean.
    mean_flag = db_sum > threshold * n if n else None
    row = {
        "count": n, "group_mean_above_threshold": mean_flag,
        "calls_in_mean_flagged_group_count": n if mean_flag else 0,
        "db_count_sum": db_sum if n else None, "db_per_call_avg": db_sum / n if n else None,
        "db_per_call_median": statistics.median(counts) if n else None,
        "db_per_call_p95": nearest_rank(counts, .95) if n else None, "db_per_call_max": max(counts) if n else None,
        "linked_db_duration_us_sum": sum(c["db_duration_us"] for c in calls) if n else None,
        "linked_db_seconds_per_call": sum(c["db_duration_us"] for c in calls) / n / 1_000_000 if n else None,
        "calls_with_zero_linked_db": sum(c["db_count"] == 0 for c in calls),
        "calls_above_threshold_count": len(hit), "call_share_denominator": n,
        "calls_above_threshold_percent": percentage(len(hit), n),
        "fast_call_count": len(fast), "fast_calls_above_threshold_count": len(fast_hit),
        "fast_call_share_denominator": len(fast), "fast_calls_above_threshold_percent": percentage(len(fast_hit), len(fast)),
        "chatty_db_count_sum": sum(c["db_count"] for c in hit) if n else None,
        "chatty_linked_db_duration_us_sum": sum(c["db_duration_us"] for c in hit) if n else None,
        "chatty_linked_db_seconds_per_call": sum(c["db_duration_us"] for c in hit) / len(hit) / 1_000_000 if hit else None,
    }
    for prefix, population in (("call_duration_us_", calls), ("chatty_call_duration_us_", hit)):
        row.update({prefix + k: (v if n else None) for k, v in distribution([c["duration_us"] for c in population]).items()})
    assert set(row) == {"count", "group_mean_above_threshold", "calls_in_mean_flagged_group_count", *PROFILE_FIELDS}
    return row


class ChattySeries:
    def __init__(self, bundle, config):
        self.series = OperationSeries(bundle, config)
        self.bundle = bundle
        self.config = config
        cfg = config["db_chatty"]
        self.thresholds = cfg["thresholds"]
        self.fast_us = seconds_to_us(cfg["fast_call_max_seconds"], "fast_call_max_seconds")
        bounds = [seconds_to_us(v, "duration_bounds_seconds") for v in cfg["duration_bounds_seconds"]]
        self.bands = list(zip([None] + bounds, bounds + [None]))
        self.cache = {}

    def group(self, sig, user, mid, threshold):
        key = (sig, user, mid, threshold)
        if key in self.cache:
            return self.cache[key]
        h = self.series.history(sig, user, mid)
        values = profile(self.series.groups.get((sig, user, mid), []), threshold, self.fast_us)
        row = {k: h[k] for k in (
            "history_id", "operation_id", "cohort_id", "signature", "user", "population_scope", "measurement_id",
            "measurement_order", "series_order_reliable", "order_basis", "observation_status", "observation_label",
            "measurement_db_linked_count_percent", "measurement_db_linked_duration_percent", "measurement_source_health",
            "calls_from_partial_sources")}
        row.update(group_id=stable_id(h["history_id"], "db_chatty", threshold), threshold_db_events=threshold,
                   threshold_operator=">", fast_call_max_us=self.fast_us, fast_operator="<=",
                   sample_size_status="no_calls" if not h["count"] else (
                       "below_configured_minimum" if h["count"] < self.config["operations"]["min_comparison_count"] else "meets_count_threshold_only"),
                   known_limitations=sorted(set(h["known_limitations"]) | set(LIMITATIONS)), **values)
        assert set(row) == set(GROUP_FIELDS)
        self.cache[key] = row
        return row

    def groups(self):
        for sig, user in self.series.pairs:
            for mid in self.series.selected:
                for threshold in self.thresholds:
                    yield self.group(sig, user, mid, threshold)

    def band(self, duration):
        return next((i, lo, hi) for i, (lo, hi) in enumerate(self.bands) if hi is None or duration <= hi)

    def coverage_metadata(self, mids):
        return [{"measurement_id": mid,
                 "db_linked_count_percent": self.series.quality[mid]["db_linked_count_percent"],
                 "db_linked_duration_percent": self.series.quality[mid]["db_linked_duration_percent"],
                 "source_health": self.series.quality[mid]["recorded_source_health"]} for mid in mids]


def db_chatty(bundle, config):
    return list(ChattySeries(bundle, config).groups())


def db_chatty_calls(bundle, config):
    data = ChattySeries(bundle, config)
    rows = []
    for sig, user in data.series.pairs:
        for mid in data.series.selected:
            groups = [data.group(sig, user, mid, t) for t in data.thresholds]
            for call in sorted(data.series.groups.get((sig, user, mid), []), key=lambda c: c["call_id"]):
                exceeded = [t for t in data.thresholds if call["db_count"] > t]
                if not exceeded:
                    continue
                h = data.series.history(sig, user, mid)
                band, lower, upper = data.band(call["duration_us"])
                row = {k: call[k] for k in ("call_id", "signature", "user", "measurement_id", "dataset_id", "source", "process",
                                             "start_timestamp", "end_timestamp", "duration_us")}
                row.update({k: h[k] for k in ("history_id", "operation_id", "cohort_id", "measurement_order",
                                             "measurement_db_linked_count_percent", "measurement_db_linked_duration_percent")})
                row.update(observation_id=stable_id(bundle.bundle_id, call["call_id"]), linked_db_count=call["db_count"],
                    linked_db_duration_us=call["db_duration_us"], thresholds_exceeded=exceeded, threshold_operator=">",
                    group_mean_thresholds_exceeded=[g["threshold_db_events"] for g in groups if g["group_mean_above_threshold"]],
                    is_fast_call=call["duration_us"] <= data.fast_us, fast_call_max_us=data.fast_us, fast_operator="<=",
                    duration_band_index=band, duration_lower_us_exclusive=lower, duration_upper_us_inclusive=upper,
                    source_status=data.series.source_status[call["source"]], known_limitations=groups[0]["known_limitations"])
                assert set(row) == set(CALL_FIELDS)
                rows.append(row)
    return rows


def db_chatty_fast_calls(bundle, config):
    """An explicit overlapping view of the actual fast CALL exceedances."""
    return [row for row in db_chatty_calls(bundle, config) if row["is_fast_call"]]


def db_chatty_duration(bundle, config):
    data = ChattySeries(bundle, config)
    rows = []
    for group in data.groups():
        if not group["count"]:
            continue  # Absence stays in db_chatty.csv, not invented duration observations.
        sig, user, mid = (group[k] for k in ("signature", "user", "measurement_id"))
        threshold = group["threshold_db_events"]
        for i, (lo, hi) in enumerate(data.bands):
            calls = [c for c in data.series.groups[(sig, user, mid)] if
                     (lo is None or c["duration_us"] > lo) and (hi is None or c["duration_us"] <= hi)]
            hit = [c for c in calls if c["db_count"] > threshold]
            row = {k: group[k] for k in ("group_id", "history_id", "operation_id", "cohort_id", "signature", "user", "measurement_id",
                                         "threshold_db_events", "threshold_operator", "known_limitations")}
            row.update(distribution_id=stable_id(group["group_id"], "duration", lo, hi), duration_band_index=i,
                duration_lower_us_exclusive=lo, duration_upper_us_inclusive=hi, group_call_count=group["count"],
                band_call_count=len(calls), band_calls_above_threshold_count=len(hit), within_band_call_denominator=len(calls),
                within_band_above_threshold_percent=percentage(len(hit), len(calls)),
                group_chatty_call_denominator=group["calls_above_threshold_count"],
                share_of_group_chatty_calls_percent=percentage(len(hit), group["calls_above_threshold_count"]),
                band_call_duration_us_sum=sum(c["duration_us"] for c in calls), band_linked_db_duration_us_sum=sum(c["db_duration_us"] for c in calls),
                chatty_call_duration_us_sum=sum(c["duration_us"] for c in hit), chatty_linked_db_duration_us_sum=sum(c["db_duration_us"] for c in hit))
            assert set(row) == set(DURATION_FIELDS)
            rows.append(row)
    return rows


def db_chatty_coverage(bundle, config):
    data = ChattySeries(bundle, config)
    by_measurement = collections.defaultdict(list)
    for call in bundle.calls:
        by_measurement[call["measurement_id"]].append(call)
    scopes = [("measurement_all_users", [m]) for m in data.series.selected]
    scopes.append(("selected_measurements_all_users", data.series.selected))
    rows = []
    for scope, mids in scopes:
        calls = [c for mid in mids for c in by_measurement[mid]]
        operations = {c["signature"] for c in calls}
        users = {c["user"] for c in calls if c["user"] not in UNKNOWN_USER_VALUES}
        keys = sorted({(c["signature"], c["user"], c["measurement_id"]) for c in calls})
        for threshold in data.thresholds:
            hit = [c for c in calls if c["db_count"] > threshold]
            fast = [c for c in calls if c["duration_us"] <= data.fast_us]
            fast_hit = [c for c in hit if c["duration_us"] <= data.fast_us]
            affected_ops = {c["signature"] for c in hit}
            affected_users = {c["user"] for c in hit if c["user"] not in UNKNOWN_USER_VALUES}
            flagged = [data.group(*key, threshold) for key in keys if data.group(*key, threshold)["group_mean_above_threshold"]]
            flagged_calls = sum(g["count"] for g in flagged)
            limitations = set(LIMITATIONS) | {
                "coverage_units_CALLs_exact_signatures_known_user_identifiers_are_separate",
                "one_user_identifier_is_not_proof_of_one_physical_person",
                "series_unique_counts_recomputed_not_summed_across_measurements",
                "mean_flags_computed_per_signature_user_measurement_not_pooled_across_series",
                "coverage_scopes_overlap_do_not_sum_measurement_and_series_rows",
                "linked_db_and_CALL_duration_sums_not_exclusive_wall_time",
                "coverage_fields_are_whole_measurement_not_this_operation_or_user",
                "source_completeness_not_established",
            }
            if not bundle.manifest["analysis_complete"]:
                limitations.add("source_analysis_incomplete")
            row = {
                "coverage_id": stable_id(bundle.bundle_id, "db_chatty_coverage", scope, mids, threshold),
                "population_scope": scope, "measurement_id": mids[0] if scope == "measurement_all_users" else None,
                "measurement_ids": mids, "threshold_db_events": threshold, "threshold_operator": ">",
                "total_call_count": len(calls), "chatty_call_count": len(hit), "call_share_denominator": len(calls),
                "chatty_call_percent": percentage(len(hit), len(calls)),
                "observed_operation_count": len(operations), "affected_operation_count": len(affected_ops),
                "operation_share_denominator": len(operations), "affected_operation_percent": percentage(len(affected_ops), len(operations)),
                "observed_known_user_count": len(users), "affected_known_user_count": len(affected_users),
                "known_user_share_denominator": len(users), "affected_known_user_percent": percentage(len(affected_users), len(users)),
                "calls_with_unknown_user_count": sum(c["user"] in UNKNOWN_USER_VALUES for c in calls),
                "chatty_calls_with_unknown_user_count": sum(c["user"] in UNKNOWN_USER_VALUES for c in hit),
                "observed_operation_user_measurement_group_count": len(keys), "mean_flagged_group_count": len(flagged),
                "mean_flagged_operation_count": len({g["signature"] for g in flagged}),
                "mean_flagged_known_user_count": len({g["user"] for g in flagged if g["user"] not in UNKNOWN_USER_VALUES}),
                "calls_in_mean_flagged_groups_count": flagged_calls, "mean_flagged_group_call_denominator": len(calls),
                "calls_in_mean_flagged_groups_percent": percentage(flagged_calls, len(calls)),
                "fast_call_count": len(fast), "fast_chatty_call_count": len(fast_hit), "fast_call_share_denominator": len(fast),
                "fast_chatty_call_percent": percentage(len(fast_hit), len(fast)), "fast_call_max_us": data.fast_us, "fast_operator": "<=",
                "calls_with_zero_linked_db": sum(c["db_count"] == 0 for c in calls),
                "call_duration_us_sum": sum(c["duration_us"] for c in calls), "linked_db_duration_us_sum": sum(c["db_duration_us"] for c in calls),
                "chatty_call_duration_us_sum": sum(c["duration_us"] for c in hit), "chatty_linked_db_duration_us_sum": sum(c["db_duration_us"] for c in hit),
                "measurement_db_coverage": data.coverage_metadata(mids), "known_limitations": sorted(limitations),
            }
            assert set(row) == set(COVERAGE_FIELDS)
            rows.append(row)
    return rows


def db_chatty_changes(bundle, config):
    data = ChattySeries(bundle, config)
    rows = []
    for common, before, after in data.series.comparisons():
        if common["comparison_basis"] not in {"first_observation", "previous_observation"}:
            continue
        for threshold in data.thresholds:
            current = data.group(common["signature"], common["user"], common["current_measurement_id"], threshold)
            reference = data.group(common["signature"], common["user"], common["reference_measurement_id"], threshold) if before else None
            both = bool(before and before["count"] and after["count"])
            unknown = list(UNKNOWN_PARAMETERS)
            if common["user"] in UNKNOWN_USER_VALUES:
                unknown.append("user_identity")
            if not data.series.reliable:
                unknown.append("measurement_order")
            row = {**common, "operation_comparison_id": common["comparison_id"],
                "comparison_id": stable_id(common["comparison_id"], "db_chatty", threshold),
                "threshold_db_events": threshold, "threshold_operator": ">",
                "reference_group_mean_above_threshold": reference["group_mean_above_threshold"] if reference else None,
                "current_group_mean_above_threshold": current["group_mean_above_threshold"],
                "reference_call_share_denominator": reference["count"] if reference else None,
                "current_call_share_denominator": current["count"],
                "signature_match": True if both else None,
                "user_match": True if both and common["user"] not in UNKNOWN_USER_VALUES else None,
                "unknown_parameters": unknown,
                "known_limitations": sorted(set(current["known_limitations"]) | (set(reference["known_limitations"]) if reference else set())),
                "known_differences": [f + "_changed" for f in ("count", "dataset_ids", "processes", "measurement_db_linked_count_percent",
                    "measurement_db_linked_duration_percent", "measurement_source_health", "calls_from_partial_sources") if before and before[f] != after[f]],
                "percent_undefined_zero_reference_metrics": [], "unavailable_metrics": [],
            }
            for coverage_field in ("measurement_db_linked_count_percent", "measurement_db_linked_duration_percent"):
                row["reference_" + coverage_field] = before[coverage_field] if before else None
                row["current_" + coverage_field] = after[coverage_field]
            for metric in PROFILE_FIELDS:
                ref = reference[metric] if reference else None
                cur = current[metric]
                comparable = common["comparison_state"] == "numerical_comparison" and ref is not None and cur is not None
                delta = cur - ref if comparable else None
                pct = 100 * delta / ref if comparable and ref != 0 else None
                if comparable and ref == 0:
                    row["percent_undefined_zero_reference_metrics"].append(metric)
                if ref is None or cur is None:
                    row["unavailable_metrics"].append(metric)
                row.update({metric + "_reference": ref, metric + "_current": cur,
                            metric + "_delta_absolute": delta, metric + "_delta_percent": pct})
            assert set(row) == set(CHANGE_FIELDS)
            rows.append(row)
    return rows
