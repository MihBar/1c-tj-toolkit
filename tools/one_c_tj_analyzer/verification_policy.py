"""Execution policy, independent of analytical rules and source completeness."""

MODES = ("full", "basic")
BASIC_CHECKS = ["schema_and_required_fields", "source_metadata_without_source_access",
                "unique_calls_and_exact_top_subset", "artifact_hashes_and_storage_schema"]
DEEP_GROUPS = ["csv_json_reconciliation", "analytical_recalculation",
               "sqlite_integrity_and_foreign_keys", "event_links_and_populations"]


def metadata(mode, schema="1.6"):
    if mode not in MODES:
        raise ValueError("verification must be full or basic")
    if schema not in {"1.2", "1.3", "1.4", "1.5", "1.6"}:
        raise ValueError("Invalid verification input schema")
    deep_groups = DEEP_GROUPS if schema in {"1.5", "1.6"} else DEEP_GROUPS[:2]
    return {"policy_version": "1", "mode": mode, "input_schema_version": schema,
            "scope": "saved_analysis_bundle",
            "full_verification": "passed" if mode == "full" else "skipped",
            "completed_groups": ["structure_and_identity"] + (deep_groups[:] if mode == "full" else []),
            "skipped_groups": deep_groups[:] if mode == "basic" else []}


def validate_metadata(value):
    if not isinstance(value, dict) or value != metadata(value.get("mode"), value.get("input_schema_version")):
        raise ValueError("Invalid verification metadata")


def add_argument(parser):
    parser.add_argument("--verification", choices=MODES, default="full",
                        help="full (default): deep verification; basic: structure and identity only")
