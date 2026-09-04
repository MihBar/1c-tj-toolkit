"""Pure deterministic slices of a validated saved-result bundle."""
from __future__ import annotations

import collections

from slice_config import SliceError
from slice_input import Bundle, CALL_INTS, percentage, source_problem

QUALITY_FIELDS = "measurement_id measurement_order order_basis dataset_ids capture_ids call_count user_count users operation_signature_count operation_user_count observed_call_start observed_call_end calls_without_time calls_from_partial_sources calls_with_zero_linked_db calls_with_linked_errors sample_size_status configured_min_call_count bundle_analysis_complete bundle_recorded_source_hashes_complete source_completeness recorded_source_health related_file_scope related_capture_file_count related_capture_partial_files related_capture_nonempty_skipped_files related_capture_duplicate_files related_dataset_parse_errors db_total_count db_linked_count db_unlinked_count db_linked_count_percent db_total_duration_us db_linked_duration_us db_unlinked_duration_us db_linked_duration_percent db_linkage_status configured_db_linkage_warning_percent metric_availability unavailable_dimensions linkage_method known_limitations".split()
AMBIGUOUS_COUNTERS = {"cpu_us", "in_bytes", "out_bytes", "memory", "memory_peak", "db_rows"}
from numeric_quality import counter_summaries, FIELDS


def measurement_datasets(bundle: Bundle) -> dict[str, set[str]]:
    result: dict[str, set[str]] = collections.defaultdict(set)
    for ds in bundle.manifest["datasets"]:
        for mid in ds["actual_measurement_ids"]:
            result[mid].add(ds["dataset_id"])
        if ds["events_without_absolute_timestamp"]:
            result[ds["measurement_id"] + "@unknown-date"].add(ds["dataset_id"])
    for name in ("call_observations", "linkage"):
        for row in bundle.tables[name]:
            result[row["measurement_id"]].add(row["dataset_id"])
    return result


def data_quality(bundle: Bundle, config: dict) -> list[dict]:
    memberships = measurement_datasets(bundle)
    requested = config["measurement_ids"]
    if requested is not None and set(requested) - set(memberships):
        raise SliceError(f"Unknown measurement_ids: {sorted(set(requested) - set(memberships))}")
    selected = set(requested) if requested is not None else set(memberships)
    grouped = collections.defaultdict(list)
    for call in bundle.calls:
        grouped[call["measurement_id"]].append(call)
    datasets = {r["dataset_id"]: r for r in bundle.manifest["datasets"]}
    source_index = {r["source"]: r for r in bundle.tables["files"]}
    linkage = collections.defaultdict(list)
    for row in bundle.tables["linkage"]:
        linkage[row["measurement_id"]].append(row)

    def order_key(mid):
        times = [c["start_timestamp"] for c in grouped[mid] if c["start_timestamp"]]
        return (min(times) if times else "9999-12-31 23:59:59", mid)

    result = []
    for order, mid in enumerate(sorted(selected, key=order_key), 1):
        calls = grouped[mid]
        ds_ids = sorted(memberships[mid])
        captures = sorted({datasets[did]["measurement_id"] for did in ds_ids})
        # Skipped sources may have no accepted dataset/day. Keep their broader
        # capture scope; do not manufacture an operation/day attribution.
        files = [r for r in bundle.tables["files"] if r["measurement_id"] in captures]
        partial = [r for r in files if r["status"] in {"partial_read_error", "partial_nul_salvaged"}]
        skipped = [r for r in files if r["status"] == "skipped" and source_problem(r)]
        n = len(calls)
        minimum = config["data_quality"]["min_call_count"]
        threshold = config["data_quality"]["db_linkage_warning_percent"]
        total_count = sum(int(r["dbpostgrs_total_count"]) for r in linkage[mid])
        linked_count = sum(int(r["dbpostgrs_linked_count"]) for r in linkage[mid])
        total_time = sum(int(r["dbpostgrs_total_duration_us"]) for r in linkage[mid])
        linked_time = sum(int(r["dbpostgrs_linked_duration_us"]) for r in linkage[mid])
        count_pct = percentage(linked_count, total_count)
        time_pct = percentage(linked_time, total_time)
        missing_time = sum(not c["end_timestamp"] for c in calls)
        partial_calls = sum(source_index[c["source"]]["status"] in {"partial_read_error", "partial_nul_salvaged"} for c in calls)
        limitations = {
            "retained_call_events_not_business_transactions",
            "call_and_db_duration_sums_are_not_exclusive_wall_time",
            "source_completeness_not_proven_by_file_integrity_or_linkage",
            "related_file_health_is_capture_scoped_not_day_or_operation_scoped",
            "legacy_zero_does_not_identify_missing_or_invalid_raw_counter",
            "db_linkage_quality_available_only_at_dataset_measurement_level",
            "db_linkage_percent_does_not_prove_correct_attribution",
            "no_raw_sources_reopened_or_verified",
        }
        if not bundle.manifest["analysis_complete"]:
            limitations.add("input_bundle_reports_incomplete_source_analysis")
        if partial or skipped:
            limitations.add("related_capture_has_unread_or_partial_sources")
        if any(w["type"] == "archive_error" for w in bundle.manifest["warnings"]):
            limitations.add("bundle_archive_error_scope_not_attributed_to_measurement")
        if missing_time:
            limitations.add("some_call_times_unavailable")
        if n < minimum:
            limitations.add("sample_below_configured_minimum")
        if n == 0:
            limitations.add("no_retained_call_observations")
        if count_pct is None:
            link_status = "no_db_events_denominator"
        elif any(p is not None and p < threshold for p in (count_pct, time_pct)):
            link_status = "below_configured_coverage_threshold"
        elif linked_count < total_count or linked_time < total_time:
            link_status = "partial_coverage_above_configured_threshold"
        else:
            link_status = "all_recorded_db_events_linked_not_source_completeness"
        if linked_count < total_count:
            limitations.add("some_recorded_db_events_not_assigned_to_call")
        metrics = {}
        for field in CALL_INTS:
            metrics[field] = {
                "stored_numeric_count": sum(c[field] is not None for c in calls),
                "stored_zero_count": sum(c[field] == 0 for c in calls),
                "raw_missing_count": None,
                "raw_invalid_count": None,
                "raw_missing_vs_zero_distinguishable": False if field in AMBIGUOUS_COUNTERS else None,
                "origin": "event_header" if field == "duration_us" else (
                    "legacy_counter_missing_or_invalid_mapped_to_zero" if field in AMBIGUOUS_COUNTERS
                    else "events_assigned_by_legacy_linkage_method"
                ),
            }
        if bundle.manifest["schema_version"] in {"1.3", "1.4", "1.5", "1.6"}:
            limitations.discard("legacy_zero_does_not_identify_missing_or_invalid_raw_counter")
            for field, summary in counter_summaries(calls).items():
                metrics[field] = {
                    "stored_numeric_count": sum(c[field] is not None for c in calls),
                    "stored_zero_count": sum(c[field] == 0 for c in calls),
                    "raw_missing_count": summary["missing_count"],
                    "raw_empty_count": summary["empty_count"],
                    "raw_invalid_count": summary["invalid_count"],
                    "raw_out_of_range_count": summary["out_of_range_count"],
                    "raw_missing_vs_zero_distinguishable": True,
                    "origin": "linked_DBPOSTGRS_RowsAffected" if field == "db_rows" else FIELDS[field][0],
                    "numeric_quality": summary,
                }
                if summary["available_count"] < summary["eligible_count"]:
                    limitations.add("incomplete_numeric_counter_coverage")
        starts = [c["start_timestamp"] for c in calls if c["start_timestamp"]]
        ends = [c["end_timestamp"] for c in calls if c["end_timestamp"]]
        row = {
            "measurement_id": mid, "measurement_order": order,
            "order_basis": "saved_call_start_time" if starts else "identifier_tiebreak_no_call_time",
            "dataset_ids": ds_ids, "capture_ids": captures,
            "call_count": n, "user_count": len({c["user"] for c in calls}),
            "users": sorted({c["user"] for c in calls}),
            "operation_signature_count": len({c["signature"] for c in calls}),
            "operation_user_count": len({(c["signature"], c["user"]) for c in calls}),
            "observed_call_start": min(starts) if starts else None,
            "observed_call_end": max(ends) if ends else None,
            "calls_without_time": missing_time, "calls_from_partial_sources": partial_calls,
            "calls_with_zero_linked_db": sum(c["db_count"] == 0 for c in calls),
            "calls_with_linked_errors": sum(c["error_count"] > 0 for c in calls),
            "sample_size_status": "no_calls" if n == 0 else ("below_configured_minimum" if n < minimum else "meets_count_threshold_only"),
            "configured_min_call_count": minimum,
            "bundle_analysis_complete": bundle.manifest["analysis_complete"],
            "bundle_recorded_source_hashes_complete": bundle.manifest["source_content_hashes_complete"],
            "source_completeness": "not_established_from_saved_results",
            "recorded_source_health": "known_related_capture_gaps" if partial or skipped else "no_recorded_related_capture_problem",
            "related_file_scope": "capture_not_day_or_operation_nonadditive_between_measurements",
            "related_capture_file_count": len(files),
            "related_capture_partial_files": len(partial),
            "related_capture_nonempty_skipped_files": len(skipped),
            "related_capture_duplicate_files": sum(r["status"] == "skipped_duplicate" for r in files),
            "related_dataset_parse_errors": sum(int(datasets[did]["parse_errors"]) for did in ds_ids),
            "db_total_count": total_count, "db_linked_count": linked_count,
            "db_unlinked_count": total_count - linked_count, "db_linked_count_percent": count_pct,
            "db_total_duration_us": total_time, "db_linked_duration_us": linked_time,
            "db_unlinked_duration_us": total_time - linked_time, "db_linked_duration_percent": time_pct,
            "db_linkage_status": link_status, "configured_db_linkage_warning_percent": threshold,
            "metric_availability": metrics,
            "unavailable_dimensions": ["role", "document", "parameters", "cold_warm", "session_id", "os_thread", "complete_call_sql_links", "per_call_db_linkage_confidence", "business_outcome", "raw_numeric_presence"],
            "linkage_method": bundle.manifest["method"]["db_to_call_link"],
            "known_limitations": sorted(limitations),
        }
        if bundle.manifest["schema_version"] in {"1.3", "1.4", "1.5", "1.6"}:
            row["unavailable_dimensions"].remove("raw_numeric_presence")
        assert set(row) == set(QUALITY_FIELDS)
        result.append(row)
    return result


from slice_operations import (HISTORY_FIELDS, COMPARISON_FIELDS, COMPARABILITY_FIELDS,
                              operation_history, operation_history_all_users,
                              measurement_comparisons, comparability)
from slice_db_chatty import (GROUP_FIELDS, CALL_FIELDS, DURATION_FIELDS, COVERAGE_FIELDS, CHANGE_FIELDS,
                             db_chatty, db_chatty_calls, db_chatty_fast_calls, db_chatty_duration, db_chatty_coverage, db_chatty_changes)
import slice_apdex
import slice_problems

SLICE_BUILDERS = {
    "data_quality": (QUALITY_FIELDS, data_quality),
    "operation_history": (HISTORY_FIELDS, operation_history),
    "operation_history_all_users": (HISTORY_FIELDS, operation_history_all_users),
    "measurement_comparisons": (COMPARISON_FIELDS, measurement_comparisons),
    "comparability": (COMPARABILITY_FIELDS, comparability),
    "db_chatty": (GROUP_FIELDS, db_chatty),
    "db_chatty_calls": (CALL_FIELDS, db_chatty_calls),
    "db_chatty_fast_calls": (CALL_FIELDS, db_chatty_fast_calls),
    "db_chatty_duration": (DURATION_FIELDS, db_chatty_duration),
    "db_chatty_coverage": (COVERAGE_FIELDS, db_chatty_coverage),
    "db_chatty_changes": (CHANGE_FIELDS, db_chatty_changes),
    "apdex": (slice_apdex.GROUP_FIELDS, slice_apdex.apdex),
    "apdex_calls": (slice_apdex.CALL_FIELDS, slice_apdex.apdex_calls),
    "apdex_uncovered": (slice_apdex.GROUP_FIELDS, slice_apdex.apdex_uncovered),
    "apdex_coverage": (slice_apdex.COVERAGE_FIELDS, slice_apdex.apdex_coverage),
    "apdex_overall": (slice_apdex.OVERALL_FIELDS, slice_apdex.apdex_overall),
    "apdex_composition": (slice_apdex.COMPOSITION_FIELDS, slice_apdex.apdex_composition),
    "apdex_changes": (slice_apdex.CHANGE_FIELDS, slice_apdex.apdex_changes),
    "problem_registry": (slice_problems.REGISTRY_FIELDS, slice_problems.problem_registry),
    "problem_history": (slice_problems.HISTORY_FIELDS, slice_problems.problem_history),
    "problem_improved": (slice_problems.TRANSITION_FIELDS, slice_problems.problem_improved),
    "problem_persisting": (slice_problems.REGISTRY_FIELDS, slice_problems.problem_persisting),
    "problem_worsened": (slice_problems.TRANSITION_FIELDS, slice_problems.problem_worsened),
    "problem_new": (slice_problems.HISTORY_FIELDS, slice_problems.problem_new),
    "problem_unchecked": (slice_problems.REGISTRY_FIELDS, slice_problems.problem_unchecked),
    "problem_rule_coverage": (slice_problems.RULE_COVERAGE_FIELDS, slice_problems.problem_rule_coverage),
}
