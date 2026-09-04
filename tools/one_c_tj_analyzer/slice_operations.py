"""Exact-signature CALL histories and four separate same-user comparisons.

No parser, report, SQL normalization, fuzzy operation matching or causal
classification. Every numeric distribution is rebuilt from retained CALLs.
"""
from __future__ import annotations

import collections
import statistics

from slice_config import SliceError, canonical_json, digest_bytes
from slice_input import Bundle, nearest_rank, timestamp
from numeric_quality import available_stats, counter_summaries, cpu_population

TIME_THRESHOLDS_SECONDS = (1, 5, 10, 30)
METRIC_FIELDS = (
    "duration_us_sum avg_us median_us p95_us p99_us max_us "
    "duration_gt_1s_count duration_gt_5s_count duration_gt_10s_count duration_gt_30s_count "
    "db_count_sum db_per_call db_duration_us_sum db_seconds_per_call "
    "cpu_us_sum cpu_us_per_call cpu_us_max cpu_percent_of_wall "
    "in_bytes_sum in_bytes_per_call in_bytes_max out_bytes_sum out_bytes_per_call out_bytes_max "
    "memory_peak_avg memory_peak_median memory_peak_p95 memory_peak_p99 memory_peak_max"
).split()
CPU_COVERAGE_FIELDS = "cpu_available_count cpu_wall_us cpu_coverage_percent cpu_wall_coverage_percent".split()
METRIC_FIELDS += CPU_COVERAGE_FIELDS
HISTORY_FIELDS = (
    "history_id operation_id cohort_id signature population_scope user users measurement_id measurement_order "
    "order_basis series_order_reliable series_baseline_measurement_id first_observation_measurement_id "
    "first_operation_observation_all_users_measurement_id observation_status observation_label count "
    "first_call_start last_call_end dataset_ids processes call_ids calls_without_time calls_from_partial_sources "
    "measurement_source_health measurement_db_linked_count_percent measurement_db_linked_duration_percent "
    "counter_zero_counts numeric_quality known_limitations"
).split() + METRIC_FIELDS
BASES = ("series_baseline", "first_observation", "previous_observation", "previous_measurement")
COMPARISON_COMMON = (
    "comparison_id comparison_basis operation_id cohort_id signature population_scope user "
    "reference_measurement_id current_measurement_id reference_count current_count "
    "reference_history_id current_history_id reference_observation_status current_observation_status "
    "comparison_state reference_relation series_order_reliable sample_size_status "
    "sample_count_delta_absolute sample_count_delta_percent sample_count_percent_status interpretation"
).split()
COMPARISON_FIELDS = COMPARISON_COMMON + ["percent_undefined_zero_reference_metrics", "unavailable_metrics"] + [
    metric + suffix for metric in METRIC_FIELDS
    for suffix in ("_reference", "_current", "_delta_absolute", "_delta_percent")
]
COMPARABILITY_FIELDS = COMPARISON_COMMON + (
    "signature_match user_match key_signature_match key_user_match "
    "reference_operation_users_all current_operation_users_all "
    "reference_dataset_ids current_dataset_ids reference_processes current_processes "
    "reference_measurement_db_linked_count_percent current_measurement_db_linked_count_percent "
    "reference_measurement_db_linked_duration_percent current_measurement_db_linked_duration_percent "
    "reference_calls_from_partial_sources current_calls_from_partial_sources "
    "comparability_status known_differences unknown_parameters known_limitations"
).split()
UNKNOWN_PARAMETERS = [
    "role", "document", "parameters", "data_volume", "cold_warm", "concurrent_load",
    "application_version", "platform_version", "logging_configuration", "business_outcome",
]
BASE_LIMITATIONS = [
    "exact_signature_only_no_fuzzy_merging",
    "retained_call_events_not_business_transactions",
    "duration_sums_not_exclusive_wall_time",
    "legacy_missing_invalid_counter_vs_zero_not_distinguishable",
    "db_metrics_depend_on_inherited_linkage",
    "coverage_fields_are_whole_measurement_not_this_operation_or_user",
    "numerical_change_does_not_prove_code_change_effect",
]
UNKNOWN_USER_VALUES = {"(not specified)", "(unknown)", ""}


def stable_id(*values) -> str:
    return digest_bytes(canonical_json(values).encode("utf-8"))


def operation_metrics(calls: list[dict]) -> dict:
    if not calls:
        return {"count": 0, **dict.fromkeys(METRIC_FIELDS)}
    n = len(calls)
    durations = [c["duration_us"] for c in calls]
    total = sum(durations)
    result = {
        "count": n, "duration_us_sum": total, "avg_us": total / n,
        "median_us": statistics.median(durations), "p95_us": nearest_rank(durations, .95),
        "p99_us": nearest_rank(durations, .99), "max_us": max(durations),
    }
    for seconds in TIME_THRESHOLDS_SECONDS:
        result[f"duration_gt_{seconds}s_count"] = sum(d > seconds * 1_000_000 for d in durations)
    db_count = sum(c["db_count"] for c in calls)
    db_time = sum(c["db_duration_us"] for c in calls)
    result.update(db_count_sum=db_count, db_per_call=db_count / n,
                  db_duration_us_sum=db_time, db_seconds_per_call=db_time / n / 1_000_000)
    for field in ("cpu_us", "in_bytes", "out_bytes"):
        stats = available_stats(c[field] for c in calls)
        result.update({field + "_sum": stats["sum"], field + "_per_call": stats["avg"], field + "_max": stats["max"]})
    cpu = cpu_population(calls)
    result.update({name: cpu[name] for name in ["cpu_percent_of_wall", *CPU_COVERAGE_FIELDS]})
    # Old bundles expose stored numbers, but cannot establish raw coverage.
    if not all("numeric_quality" in c for c in calls):
        for name in CPU_COVERAGE_FIELDS:
            result[name] = None
    peaks = available_stats(c["memory_peak"] for c in calls)
    result.update({"memory_peak_" + name: peaks[name] for name in ("avg", "median", "p95", "p99", "max")})
    assert set(result) == {"count", *METRIC_FIELDS}
    return result


class OperationSeries:
    """Full bundle chronology and populations; selection affects output only."""

    def __init__(self, bundle: Bundle, config: dict):
        # Import after registry initialization to keep the existing quality
        # builder independent from this optional slice.
        from slice_metrics import data_quality, measurement_datasets
        self.bundle = bundle
        self.config = config
        membership = measurement_datasets(bundle)
        mids = set(membership)
        selected = config["measurement_ids"]
        if selected is not None and set(selected) - mids:
            raise SliceError(f"Unknown measurement_ids: {sorted(set(selected) - mids)}")
        call_times = collections.defaultdict(list)
        fallback_times = collections.defaultdict(list)
        self.groups = collections.defaultdict(list)
        self.pooled = collections.defaultdict(list)
        for call in bundle.calls:
            mid = call["measurement_id"]
            self.groups[(call["signature"], call["user"], mid)].append(call)
            self.pooled[(call["signature"], mid)].append(call)
            if call["start_timestamp"]:
                call_times[mid].append(timestamp(call["start_timestamp"], "CALL chronology"))
        # These tables supply chronology only, never CALL measurements/counts.
        for table in ("heavy_sql", "errors"):
            for row in bundle.tables[table]:
                if row["measurement_id"] in mids and row["first_timestamp"]:
                    fallback_times[row["measurement_id"]].append(timestamp(row["first_timestamp"], f"{table} chronology"))
        for ds in bundle.manifest["datasets"]:
            if len(ds["actual_measurement_ids"]) == 1 and ds["first_timestamp"]:
                fallback_times[ds["actual_measurement_ids"][0]].append(timestamp(ds["first_timestamp"], "dataset chronology"))
        times = {}
        self.order_basis = {}
        for mid in mids:
            values = call_times[mid] or fallback_times[mid]
            times[mid] = min(values) if values else None
            self.order_basis[mid] = "saved_call_start_time" if call_times[mid] else (
                "saved_event_summary_time" if values else "identifier_tiebreak_no_saved_time")
        explicit = config["operations"]["measurement_order"]
        if explicit is not None:
            if set(explicit) != mids:
                raise SliceError("operations.measurement_order must list every bundle measurement exactly once")
            self.order = list(explicit)
            self.reliable = True
            self.order_basis = dict.fromkeys(mids, "explicit_configured_order")
        else:
            self.order = sorted(mids, key=lambda m: (times[m] is None, times[m].isoformat() if times[m] else "", m))
            self.reliable = len(mids) <= 1 or (all(times.values()) and len(set(times.values())) == len(mids))
            if not self.reliable:
                for mid in mids:
                    self.order_basis[mid] += ";series_order_not_fully_established"
        self.position = {mid: i for i, mid in enumerate(self.order)}
        self.selected = [mid for mid in self.order if selected is None or mid in selected]
        baseline = config["operations"]["series_baseline_measurement_id"]
        if baseline is not None and baseline not in mids:
            raise SliceError("operations.series_baseline_measurement_id is not in the bundle")
        self.baseline_explicit = baseline is not None
        self.baseline = baseline if baseline is not None else (self.order[0] if self.reliable and self.order else None)
        self.pairs = sorted({(c["signature"], c["user"]) for c in bundle.calls})
        self.signatures = sorted({c["signature"] for c in bundle.calls})
        self.observed = {(sig, user): [m for m in self.order if self.groups.get((sig, user, m))] for sig, user in self.pairs}
        self.first_pooled = {
            sig: next((m for m in self.order if self.pooled.get((sig, m))), None) if self.reliable else None
            for sig in self.signatures
        }
        self.quality = {r["measurement_id"]: r for r in data_quality(bundle, {**config, "measurement_ids": None})}
        self.source_status = {r["source"]: r["status"] for r in bundle.tables["files"]}
        self.cache = {}

    def history(self, sig: str, user: str | None, mid: str) -> dict:
        key = (sig, user, mid)
        if key in self.cache:
            return self.cache[key]
        scope = "all_users" if user is None else "same_user"
        calls = self.pooled.get((sig, mid), []) if user is None else self.groups.get((sig, user, mid), [])
        values = operation_metrics(calls)
        observed = self.first_pooled[sig] if user is None else (self.observed[(sig, user)][0] if self.reliable else None)
        quality = self.quality[mid]
        limitations = list(BASE_LIMITATIONS)
        if self.bundle.manifest["schema_version"] in {"1.3", "1.4", "1.5", "1.6"}:
            limitations.remove("legacy_missing_invalid_counter_vs_zero_not_distinguishable")
            limitations.append("counter_means_use_available_observations_cpu_uses_paired_wall")
            if calls and any(q["available_count"] < q["eligible_count"] for q in counter_summaries(calls).values()):
                limitations.append("incomplete_numeric_counter_coverage")
        if user is None:
            limitations.append("all_users_summary_overlaps_same_user_history_do_not_sum_views")
        if not self.reliable:
            limitations.append("series_chronology_unresolved")
        if not self.bundle.manifest["analysis_complete"]:
            limitations.append("source_analysis_incomplete")
        if quality["recorded_source_health"] != "no_recorded_related_capture_problem":
            limitations.append("related_capture_has_recorded_source_gaps_scope_not_operation")
        starts = [c["start_timestamp"] for c in calls if c["start_timestamp"]]
        ends = [c["end_timestamp"] for c in calls if c["end_timestamp"]]
        row = {
            "history_id": stable_id(self.bundle.bundle_id, scope, sig, user, mid),
            "operation_id": stable_id(sig), "cohort_id": stable_id(scope, sig, user),
            "signature": sig, "population_scope": scope, "user": user,
            "users": sorted({c["user"] for c in calls}), "measurement_id": mid,
            "measurement_order": self.position[mid] + 1, "order_basis": self.order_basis[mid],
            "series_order_reliable": self.reliable, "series_baseline_measurement_id": self.baseline,
            "first_observation_measurement_id": observed,
            "first_operation_observation_all_users_measurement_id": self.first_pooled[sig],
            "observation_status": "observed" if calls else "not_observed",
            "observation_label": "наблюдалась" if calls else "не наблюдалась",
            "first_call_start": min(starts) if starts else None, "last_call_end": max(ends) if ends else None,
            "dataset_ids": sorted({c["dataset_id"] for c in calls}), "processes": sorted({c["process"] for c in calls}),
            "call_ids": sorted(c["call_id"] for c in calls), "calls_without_time": sum(not c["end_timestamp"] for c in calls),
            "calls_from_partial_sources": sum(self.source_status[c["source"]] in {"partial_read_error", "partial_nul_salvaged"} for c in calls),
            "measurement_source_health": quality["recorded_source_health"],
            "measurement_db_linked_count_percent": quality["db_linked_count_percent"],
            "measurement_db_linked_duration_percent": quality["db_linked_duration_percent"],
            "counter_zero_counts": {f: sum(c[f] == 0 for c in calls) for f in ("cpu_us", "in_bytes", "out_bytes", "memory_peak")} if calls else None,
            "numeric_quality": counter_summaries(calls) if calls and self.bundle.manifest["schema_version"] in {"1.3", "1.4", "1.5", "1.6"} else None,
            "known_limitations": sorted(limitations), **values,
        }
        assert set(row) == set(HISTORY_FIELDS)
        self.cache[key] = row
        return row

    def reference(self, sig: str, user: str, current: str, basis: str) -> tuple[str | None, str | None]:
        if basis == "series_baseline":
            return self.baseline, None if self.baseline is not None else "series_chronology_unresolved"
        if not self.reliable:
            return None, "series_chronology_unresolved"
        if basis == "first_observation":
            return self.observed[(sig, user)][0], None
        if basis == "previous_observation":
            previous = [m for m in self.observed[(sig, user)] if self.position[m] < self.position[current]]
            return (previous[-1], None) if previous else (None, "no_previous_observation")
        index = self.position[current]
        return (self.order[index - 1], None) if index else (None, "no_previous_measurement")

    def comparisons(self):
        for sig, user in self.pairs:
            for current in self.selected:
                after = self.history(sig, user, current)
                for basis in BASES:
                    reference, reason = self.reference(sig, user, current, basis)
                    before = self.history(sig, user, reference) if reference is not None else None
                    if reason:
                        state = reason
                    elif basis == "first_observation" and self.position[reference] > self.position[current]:
                        state = "before_first_observation"
                    elif not before["count"] and not after["count"]:
                        state = "both_not_observed"
                    elif not before["count"]:
                        state = "reference_not_observed"
                    elif not after["count"]:
                        state = "current_not_observed"
                    else:
                        state = "numerical_comparison"
                    n_ref = before["count"] if before else None
                    relation = "no_reference" if reference is None else (
                        "same_measurement" if reference == current else (
                            "unknown_order" if not self.reliable else (
                                "earlier" if self.position[reference] < self.position[current] else "later")))
                    min_n = self.config["operations"]["min_comparison_count"]
                    sample = "missing_observations" if state != "numerical_comparison" else (
                        "below_configured_minimum" if min(n_ref, after["count"]) < min_n else "meets_count_threshold_only")
                    common = {
                        "comparison_id": stable_id(self.bundle.bundle_id, sig, user, basis, reference, current),
                        "comparison_basis": basis, "operation_id": after["operation_id"], "cohort_id": after["cohort_id"],
                        "signature": sig, "population_scope": "same_user", "user": user,
                        "reference_measurement_id": reference, "current_measurement_id": current,
                        "reference_count": n_ref, "current_count": after["count"],
                        "reference_history_id": before["history_id"] if before else None, "current_history_id": after["history_id"],
                        "reference_observation_status": before["observation_status"] if before else "no_reference",
                        "current_observation_status": after["observation_status"],
                        "comparison_state": state, "series_order_reliable": self.reliable,
                        "reference_relation": relation,
                        "sample_count_delta_absolute": after["count"] - n_ref if n_ref is not None else None,
                        "sample_count_delta_percent": 100 * (after["count"] - n_ref) / n_ref if n_ref else None,
                        "sample_count_percent_status": "no_reference" if n_ref is None else ("undefined_zero_reference" if n_ref == 0 else "defined"),
                        "sample_size_status": sample, "interpretation": "numerical_change_only_not_proven_code_effect",
                    }
                    yield common, before, after


def operation_history(bundle: Bundle, config: dict) -> list[dict]:
    series = OperationSeries(bundle, config)
    return [series.history(sig, user, mid) for sig, user in series.pairs for mid in series.selected]


def operation_history_all_users(bundle: Bundle, config: dict) -> list[dict]:
    series = OperationSeries(bundle, config)
    return [series.history(sig, None, mid) for sig in series.signatures for mid in series.selected]


def measurement_comparisons(bundle: Bundle, config: dict) -> list[dict]:
    series = OperationSeries(bundle, config)
    rows = []
    for common, before, after in series.comparisons():
        row = dict(common)
        undefined = []
        unavailable = []
        for metric in METRIC_FIELDS:
            reference_value = before[metric] if before else None
            current_value = after[metric]
            comparable = common["comparison_state"] == "numerical_comparison" and reference_value is not None and current_value is not None
            delta = current_value - reference_value if comparable else None
            percent = 100 * delta / reference_value if comparable and reference_value != 0 else None
            if comparable and reference_value == 0:
                undefined.append(metric)
            if reference_value is None or current_value is None:
                unavailable.append(metric)
            row.update({metric + "_reference": reference_value, metric + "_current": current_value,
                        metric + "_delta_absolute": delta, metric + "_delta_percent": percent})
        row["percent_undefined_zero_reference_metrics"] = undefined
        row["unavailable_metrics"] = unavailable
        assert set(row) == set(COMPARISON_FIELDS)
        rows.append(row)
    return rows


def comparability(bundle: Bundle, config: dict) -> list[dict]:
    series = OperationSeries(bundle, config)
    rows = []
    for common, before, after in series.comparisons():
        reference = common["reference_measurement_id"]
        sig, user = common["signature"], common["user"]
        both = bool(before and before["count"] and after["count"])
        known_user = user not in UNKNOWN_USER_VALUES
        ref_users = sorted({c["user"] for c in series.pooled.get((sig, reference), [])})
        cur_users = sorted({c["user"] for c in series.pooled.get((sig, common["current_measurement_id"]), [])})
        differences = []
        if before and before["count"] != after["count"]:
            differences.append("sample_size_changed")
        if reference is not None and before and not before["count"] and ref_users:
            differences.append("reference_operation_observed_only_for_other_users")
        if not after["count"] and cur_users:
            differences.append("current_operation_observed_only_for_other_users")
        if both:
            if before["numeric_quality"] is not None and after["numeric_quality"] is not None:
                for field, quality in before["numeric_quality"].items():
                    current_quality = after["numeric_quality"][field]
                    if any(quality[k] != current_quality[k] for k in ("eligible_count", "available_count", "coverage_percent")):
                        differences.append(field + "_numeric_coverage_changed")
            for field in ("dataset_ids", "processes", "measurement_source_health", "measurement_db_linked_count_percent", "measurement_db_linked_duration_percent", "calls_from_partial_sources"):
                if before[field] != after[field]:
                    differences.append(field + "_changed")
        limitations = sorted(set(after["known_limitations"]) | (set(before["known_limitations"]) if before else set()))
        unknown = list(UNKNOWN_PARAMETERS)
        if not known_user:
            unknown.append("user_identity")
        if not series.reliable:
            unknown.append("measurement_order")
        status = "same_signature_same_user_uncontrolled" if both and known_user else (
            "user_identity_unknown" if both else "insufficient_observations_for_comparison")
        row = {
            **common, "signature_match": True if both else None, "user_match": True if both and known_user else None,
            "key_signature_match": True if before else None, "key_user_match": True if before else None,
            "reference_operation_users_all": ref_users, "current_operation_users_all": cur_users,
            "reference_dataset_ids": before["dataset_ids"] if before else [], "current_dataset_ids": after["dataset_ids"],
            "reference_processes": before["processes"] if before else [], "current_processes": after["processes"],
            "reference_measurement_db_linked_count_percent": before["measurement_db_linked_count_percent"] if before else None,
            "current_measurement_db_linked_count_percent": after["measurement_db_linked_count_percent"],
            "reference_measurement_db_linked_duration_percent": before["measurement_db_linked_duration_percent"] if before else None,
            "current_measurement_db_linked_duration_percent": after["measurement_db_linked_duration_percent"],
            "reference_calls_from_partial_sources": before["calls_from_partial_sources"] if before else None,
            "current_calls_from_partial_sources": after["calls_from_partial_sources"],
            "comparability_status": status, "known_differences": sorted(differences),
            "unknown_parameters": unknown, "known_limitations": limitations,
        }
        assert set(row) == set(COMPARABILITY_FIELDS)
        rows.append(row)
    return rows
