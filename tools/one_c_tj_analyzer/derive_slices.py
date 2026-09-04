#!/usr/bin/env python3
"""Standalone CLI: saved analyzer CSV/JSON -> deterministic selected slices."""
from __future__ import annotations

import argparse
import csv
import io
import os
from pathlib import Path
import sys
import tempfile

from slice_config import CALCULATOR_VERSION, SLICE_SCHEMA_VERSION, REGISTERED_SLICES, SliceError, canonical_json, digest_bytes, load_config, strict_json
from slice_input import load_bundle, require
from slice_metrics import SLICE_BUILDERS

CALCULATOR_NAME = "1c_tj_saved_result_slices"
MANIFEST_NAME = "slice_manifest.json"
SLICE_METHOD = {
    "raw_sources_accessed": False,
    "input_validation_scope": "saved_bundle_consistency_not_raw_log_completeness",
    "order": "minimum_saved_call_start_then_measurement_id; unknown_call_time_last",
    "db_coverage": "ratio_of_summed_linked_and_total_counts_or_durations; zero_denominator_is_null",
    "source_health_scope": "related_capture_not_day_or_operation; counts_nonadditive_across_measurements",
    "missing_counters": "schema_1.3/1.4/1.5/1.6_retains_raw_states_and_nulls; schema_1.2_legacy_ambiguity_preserved; no_imputation",
    "counter_population": "means_divide_by_available_count; CPU_and_residual_use_same_CALL_subset_with_available_CpuTime; count_and_wall_coverage_separate",
    "operation_identity": "exact_signature; same_user_comparisons; all_users_summary_is_a_separate_overlapping_view",
    "operation_percentiles": "computed_from_individual_CALLs; median_even_N_averages_middle_values; p95_p99_nearest_rank",
    "operation_thresholds": "strictly_greater_than_1_5_10_30_seconds; not_legacy_greater_or_equal_counters",
    "operation_chronology": "full_bundle_saved_CALL_time_then_event_summary_fallback; explicit_order_optional; unresolved_order_blocks_relative_bases",
    "operation_comparison_bases": ["series_baseline", "first_observation", "previous_observation", "previous_measurement"],
    "operation_selection": "measurement_filter_affects_output_only_not_baseline_or_reference_search",
    "operation_changes": "current_minus_reference; percent=100*delta/reference; zero_reference_percent=null; missing_population_no_performance_delta",
    "operation_units": "*_us=microseconds; db_seconds_per_call=seconds; bytes_and_memory_peak=bytes; cpu_percent_of_wall_delta_absolute=percentage_points",
    "db_chatty_thresholds": "configurable_diagnostic_not_normative; DB_count>threshold; group_sum>threshold*N_is_distinct_from_individual_CALL_hits",
    "db_chatty_distributions": "individual_CALLs; median_and_nearest_rank_p95; duration_bands_lower_exclusive_upper_inclusive; fast_duration<=configured_limit",
    "db_chatty_shares": "explicit_denominators; per_threshold_populations_overlap; unique_operations_and_known_users_separate_from_CALL_counts",
    "db_chatty_changes": "same_exact_signature_and_user; first_and_previous_observed_in_full_bundle; numerical_not_causal; share_delta_absolute_in_percentage_points",
    "db_chatty_linkage": "retained_linked_DBPOSTGRS_only; zero_does_not_prove_no_DB; whole_measurement_coverage_not_per_CALL_confidence; no_N_plus_1_or_SQL_link_reconstruction",
    "apdex_scope": "registered_server_CALLs_not_end_to_end; unknown_business_outcomes_not_assumed_successful",
    "apdex_formula": "(2*satisfied+tolerating)/(2*N); satisfied:duration<=T; tolerating:T<duration<=4T; frustrated:duration>4T_or_explicit_confirmed_failure",
    "apdex_targets": "no_default_T; exact_operation_override_or_explicit_class_membership; proposed_and_business_approved_targets_separate; one_current_configuration_for_whole_series",
    "apdex_failures": "explicit_latency_only_or_confirmed_failures_frustrated; failures_pinned_to_bundle_and_CALL_with_evidence; EXCP_not_automatic_failure; missing_T_still_unscored",
    "apdex_overall": "pooled_class_counts_not_mean_of_group_scores; separate_target_status_populations; composition_output_mandatory; mix_change_can_change_overall_without_operation_speedup",
    "problem_detection": "explicit_allowlisted_numeric_rules_from_CALL_derived_slices; first_raw_breach_retained_even_when_quality_or_sample_insufficient; no_report_text_input",
    "problem_identity": "series_id_plus_rule_numeric_definition_metric_parameters_exact_signature_user; independent_of_bundle_hash_and_first_discovery_date",
    "problem_history": "requires_established_full_series_order; from_first_breach_through_latest_including_absence; output_filter_does_not_rebase_or_change_latest_snapshot",
    "problem_changes": "separate_metrics_and_first_problem_vs_previous_eligible_observation; current-reference; zero_reference_percent=null; equal_value_has_no_direction_status",
    "problem_status": "threshold_status_separate_from_change_status; below_threshold_label_means_rule_not_breached_with_explicit_relation_for_equality; no_fixed_regression_or_causal_claim",
    "problem_selections": "improved_worsened=all_selected_history_changes_per_reference_basis; new=first_breach_rows; persisting_unchecked=latest_full_series_snapshot; views_overlap",
    "csv": "UTF-8 BOM, comma separator, LF; objects/lists JSON; null empty cell",
}


def csv_bytes(fields: list[str], rows: list[dict]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n", extrasaction="raise")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: (canonical_json(v) if isinstance(v, (list, dict, bool)) else v) for k, v in row.items()})
    return stream.getvalue().encode("utf-8-sig")


def validate_output_path(output: Path, input_root: Path, config_path: Path, overwrite: bool, selected: list[str]) -> None:
    require(not (output == input_root or output in input_root.parents or input_root in output.parents), "Input and output directories must be disjoint (no parent/child overlap)")
    require(config_path != output and output not in config_path.parents, "Configuration must not be inside the output directory")
    if not output.exists():
        return
    require(output.is_dir(), "Output exists and is not a directory")
    entries = list(output.iterdir())
    if not entries:
        return
    require(overwrite, "Output directory is not empty; use a new directory or explicit --overwrite")
    # An explicit overwrite authorizes only a recognized calculator result,
    # never an arbitrary populated folder, parser bundle, or directory tree.
    manifest_path = output / MANIFEST_NAME
    require(manifest_path.is_file() and not manifest_path.is_symlink(), "--overwrite requires an existing slice manifest")
    old = strict_json(manifest_path.read_text(encoding="utf-8-sig"), "existing slice manifest")
    require(isinstance(old, dict) and old.get("calculator") == CALCULATOR_NAME and old.get("slice_schema_version") == SLICE_SCHEMA_VERSION, "Output is not a recognized slice result")
    require(old.get("selected_slices") == selected, "Slice selection differs from the existing result; use a new output directory")
    allowed = {MANIFEST_NAME} | {name + ".csv" for name in REGISTERED_SLICES}
    require(all(p.name in allowed and p.is_file() and not p.is_symlink() for p in entries), "Output contains unrelated files, directories or symlinks; refusing overwrite")


def run(argv: list[str] | None = None) -> dict:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis-dir", type=Path, help="Saved analyzer schema-1.2 through 1.6 bundle; never a TJ directory")
    parser.add_argument("--output-dir", type=Path, help="Separate result directory")
    parser.add_argument("--config", type=Path, help="Versioned JSON configuration")
    parser.add_argument("--slices", nargs="+", help="Override selection; apdex_overall also includes required apdex_composition")
    parser.add_argument("--list-slices", action="store_true")
    parser.add_argument("--list-problem-metrics", action="store_true", help="List allowlisted problem metrics without reading a bundle")
    parser.add_argument("--validate-only", action="store_true", help="Validate bundle/config; write nothing")
    parser.add_argument("--overwrite", action="store_true", help="Replace only a recognized existing slice result")
    parser.add_argument("--version", action="version", version=CALCULATOR_VERSION)
    args = parser.parse_args(argv)
    if args.list_slices:
        return {"available_slices": list(REGISTERED_SLICES), "calculator_version": CALCULATOR_VERSION}
    if args.list_problem_metrics:
        from slice_problem_config import METRICS
        return {"calculator_version": CALCULATOR_VERSION, "metrics": METRICS, "operators": [">", ">="], "scope": "same_user"}
    require(args.analysis_dir is not None and args.config is not None, "--analysis-dir and --config are required")
    require(args.validate_only or args.output_dir is not None, "--output-dir is required unless --validate-only")
    config_path = args.config.resolve(strict=True)
    config, config_file_hash = load_config(config_path, args.slices)
    bundle = load_bundle(args.analysis_dir)
    require(config["expected_bundle_id"] in (None, bundle.bundle_id), "Input bundle does not match expected_bundle_id")
    output = args.output_dir.resolve() if args.output_dir is not None else None
    if output is not None and not args.validate_only:
        validate_output_path(output, bundle.root, config_path, args.overwrite, config["slices"])
    outputs = {}
    descriptors = {}
    for name in config["slices"]:
        fields, builder = SLICE_BUILDERS[name]
        rows = builder(bundle, config)
        data = csv_bytes(fields, rows)
        outputs[name + ".csv"] = data
        descriptors[name + ".csv"] = {"sha256": digest_bytes(data), "size_bytes": len(data), "row_count": len(rows), "columns": fields}
    bundle.assert_unchanged()
    require(digest_bytes(config_path.read_bytes()) == config_file_hash, "Configuration changed during calculation")
    summary = {
        "status": "PASS", "calculator_version": CALCULATOR_VERSION,
        "bundle_id": bundle.bundle_id, "call_count": len(bundle.calls),
        "source_analysis_complete": bundle.manifest["analysis_complete"],
        "validation_checks": bundle.checks, "selected_slices": config["slices"],
        "row_counts": {name: value["row_count"] for name, value in descriptors.items()},
        "input_files_unchanged": True, "validation_only": args.validate_only,
    }
    if args.validate_only:
        return summary
    manifest = {
        "calculator": CALCULATOR_NAME, "calculator_version": CALCULATOR_VERSION,
        "slice_schema_version": SLICE_SCHEMA_VERSION,
        "input_schema_version": bundle.manifest["schema_version"],
        "input_analyzer_version": bundle.manifest["analyzer_version"],
        "input_sql_normalization_version": bundle.sql_normalization_version,
        "input_error_rules": {key: bundle.manifest.get(key) for key in ("error_signature_version", "error_linkage_rules_version", "incident_rules_version")},
        "input_linkage_rules_version": bundle.manifest.get("linkage_rules_version", "legacy_end_longest/v1"),
        "config_version": config["config_version"], "configuration": config,
        "configuration_file_sha256": config_file_hash,
        "configuration_effective_sha256": digest_bytes(canonical_json(config).encode()),
        "bundle_id": bundle.bundle_id, "input_files": bundle.input_files,
        "recorded_source_set_hash_sha256": bundle.manifest["source_set_hash_sha256"],
        "source_analysis_complete": bundle.manifest["analysis_complete"],
        "validation_checks": bundle.checks, "input_files_unchanged": True,
        "selected_slices": config["slices"], "outputs": descriptors,
        "population": {"primary": "call_observations.csv", "key": ["bundle_id", "call_id"], "count": len(bundle.calls), "json_and_top_calls_are_not_additional_observations": True},
        "method": SLICE_METHOD,
    }
    # Compute/validate everything before touching output. Publish the manifest
    # last; it contains hashes needed to detect interrupted replacement.
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".tj-slices-", dir=output.parent))
    try:
        for name, data in outputs.items():
            (stage / name).write_bytes(data)
        bundle.assert_unchanged()
        require(digest_bytes(config_path.read_bytes()) == config_file_hash, "Configuration changed before publication")
        (stage / MANIFEST_NAME).write_text(canonical_json(manifest) + "\n", encoding="utf-8", newline="\n")
        validate_output_path(output, bundle.root, config_path, args.overwrite, config["slices"])
        output.mkdir(exist_ok=True)
        for name in sorted(outputs):
            os.replace(stage / name, output / name)
        os.replace(stage / MANIFEST_NAME, output / MANIFEST_NAME)
    finally:
        # Only direct files created by this invocation; no recursive deletion.
        for name in list(outputs) + [MANIFEST_NAME]:
            item = stage / name
            if item.exists():
                item.unlink()
        stage.rmdir()
    summary["output_dir"] = str(output)
    return summary


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    try:
        print(canonical_json(run(argv)))
        return 0
    except (SliceError, OSError, UnicodeError) as exc:
        print(canonical_json({"status": "ERROR", "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
