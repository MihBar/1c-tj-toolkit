"""APDEX of retained server CALLs with explicit targets, policy and composition."""
from __future__ import annotations

from slice_context import family_rows

from slice_config import SliceError, seconds_to_us
from slice_apdex_config import TARGET_STATUSES
from slice_operations import COMPARISON_COMMON, OperationSeries, UNKNOWN_PARAMETERS, UNKNOWN_USER_VALUES, stable_id

SCOPE = "APDEX по зарегистрированным серверным CALL, не end-to-end"
LIMITATIONS = [
    "server_CALLs_not_end_to_end_response_or_business_transactions",
    "no_target_imputation_or_SLA_inferred_from_previous_proposals",
    "target_status_and_source_are_configuration_declarations_not_independent_approval_verification",
    "linked_EXCP_or_error_event_not_proof_of_business_failure",
    "unconfirmed_business_outcomes_unknown_even_when_latency_satisfied",
    "numerical_change_not_proven_effect_of_code_fix",
    "one_current_target_configuration_applied_to_entire_series_not_historical_SLA",
    "source_completeness_not_established_by_saved_bundle",
]
TARGET_FIELDS = "target_id target_kind target_class_id overridden_class_id t_seconds t_us four_t_us target_status target_source".split()
SCORE_FIELDS = (
    "count covered_call_count apdex_denominator satisfied_count tolerating_count frustrated_count "
    "apdex_numerator_twice apdex latency_frustrated_count forced_frustrated_count "
    "confirmed_failure_count business_outcome_unknown_count calls_with_linked_error_events"
).split()
GROUP_FIELDS = (
    "apdex_row_id history_id operation_id cohort_id signature user measurement_id measurement_order "
    "series_order_reliable observation_status observation_label target_coverage_status assessment_scope "
    "failure_policy min_call_count small_sample_warning sample_size_status "
    "calls_from_partial_sources measurement_source_health known_limitations"
).split() + TARGET_FIELDS + SCORE_FIELDS
CALL_FIELDS = (
    "observation_id call_id apdex_row_id history_id operation_id signature user measurement_id "
    "duration_us latency_category category confirmed_failure failure_evidence business_outcome "
    "linked_error_count failure_policy assessment_scope known_limitations"
).split() + TARGET_FIELDS
COVERAGE_FIELDS = (
    "coverage_id population_scope measurement_id measurement_ids assessment_scope failure_policy "
    "total_call_count covered_call_count uncovered_call_count call_share_denominator covered_call_percent "
    "observed_operation_count covered_operation_count uncovered_operation_count operation_share_denominator covered_operation_percent "
    "business_approved_call_count engineering_proposal_call_count business_approved_operation_count engineering_proposal_operation_count "
    "confirmed_failure_count uncovered_confirmed_failure_count known_limitations"
).split()
OVERALL_FIELDS = (
    "overall_id population_scope measurement_id measurement_ids target_status assessment_scope failure_policy "
    "total_calls_in_scope calls_without_target calls_with_other_target_status call_share_denominator scored_call_percent "
    "operation_count user_identifier_count target_ids composition_file composition_row_count "
    "min_call_count small_sample_warning sample_size_status known_limitations"
).split() + SCORE_FIELDS
COMPOSITION_FIELDS = (
    "composition_id overall_id population_scope scope_measurement_ids apdex_row_id operation_id signature user measurement_id "
    "call_count overall_apdex_denominator call_weight_percent satisfied_count tolerating_count frustrated_count "
    "apdex_numerator_twice operation_user_measurement_apdex contribution_to_overall_apdex "
    "assessment_scope failure_policy"
).split() + TARGET_FIELDS
CHANGE_METRICS = "apdex satisfied_count tolerating_count frustrated_count confirmed_failure_count forced_frustrated_count".split()
CHANGE_FIELDS = COMPARISON_COMMON + (
    "operation_comparison_state reference_apdex_row_id current_apdex_row_id target_match signature_match user_match "
    "reference_target_id current_target_id reference_t_us current_t_us reference_target_status current_target_status "
    "reference_target_source current_target_source reference_apdex_denominator current_apdex_denominator "
    "failure_policy assessment_scope min_call_count small_sample_warning known_differences unknown_parameters known_limitations "
    "percent_undefined_zero_reference_metrics unavailable_metrics"
).split() + [m + suffix for m in CHANGE_METRICS for suffix in ("_reference", "_current", "_delta_absolute", "_delta_percent")]


def percentage(n, d):
    return 100 * n / d if d else None


def latency_category(duration_us, t_us):
    if duration_us <= t_us:
        return "satisfied"
    if duration_us <= 4 * t_us:
        return "tolerating"
    return "frustrated"


def score(calls, t_us, confirmed):
    """No target => no classification. Confirmed failures stay in denominator."""
    n = len(calls)
    failures = sum(c["call_id"] in confirmed for c in calls)
    row = {"count": n, "covered_call_count": n if t_us is not None else 0,
           "apdex_denominator": n if t_us is not None else 0,
           "confirmed_failure_count": failures, "business_outcome_unknown_count": n - failures,
           "calls_with_linked_error_events": sum(c["error_count"] > 0 for c in calls)}
    if t_us is None or not calls:
        row.update(dict.fromkeys(("satisfied_count", "tolerating_count", "frustrated_count", "apdex_numerator_twice", "apdex",
                                  "latency_frustrated_count", "forced_frustrated_count")))
        return row
    counts = dict.fromkeys(("satisfied", "tolerating", "frustrated"), 0)
    latency_bad = forced = 0
    for call in calls:
        latency = latency_category(call["duration_us"], t_us)
        latency_bad += latency == "frustrated"
        is_failure = call["call_id"] in confirmed
        forced += is_failure and latency != "frustrated"
        counts["frustrated" if is_failure else latency] += 1
    assert sum(counts.values()) == n
    numerator = 2 * counts["satisfied"] + counts["tolerating"]
    row.update({k + "_count": v for k, v in counts.items()})
    row.update(apdex_numerator_twice=numerator, apdex=numerator / (2 * n),
               latency_frustrated_count=latency_bad, forced_frustrated_count=forced)
    assert set(row) == set(SCORE_FIELDS)
    return row


class ApdexSeries:
    def __init__(self, bundle, config, *, series=None):
        self.bundle = bundle
        self.config = config
        self.series = OperationSeries(bundle, config) if series is None else series
        cfg = config["apdex"]
        self.minimum = cfg["min_call_count"]
        self.policy = cfg["failure_policy"]
        evidence = cfg["confirmed_failures"]
        if evidence["bundle_id"] not in (None, bundle.bundle_id):
            raise SliceError("apdex.confirmed_failures.bundle_id does not match the input bundle")
        self.confirmed = {c["call_id"]: c["evidence"] for c in evidence["calls"]}
        unknown_ids = set(self.confirmed) - {c["call_id"] for c in bundle.calls}
        if unknown_ids:
            raise SliceError(f"APDEX confirmed failures refer to unknown CALL IDs: {sorted(unknown_ids)}")
        classes = {sig: cls for cls in cfg["classes"] for sig in cls["signatures"]}
        direct = {r["signature"]: r for r in cfg["targets"]}
        unknown_signatures = (set(classes) | set(direct)) - set(self.series.signatures)
        if unknown_signatures:
            raise SliceError(f"APDEX targets refer to unobserved signatures in the full bundle: {sorted(unknown_signatures)}")
        self.targets = {}
        for sig in self.series.signatures:
            selected = direct.get(sig) or classes.get(sig)
            if selected is None:
                self.targets[sig] = dict.fromkeys(TARGET_FIELDS)
                continue
            kind = "operation" if sig in direct else "explicit_class"
            class_id = classes[sig]["class_id"] if sig in classes else None
            t_us = seconds_to_us(selected["t_seconds"], "apdex.t_seconds")
            row = {"target_kind": kind, "target_class_id": class_id if kind == "explicit_class" else None,
                   "overridden_class_id": class_id if kind == "operation" else None,
                   "t_seconds": selected["t_seconds"], "t_us": t_us, "four_t_us": 4 * t_us,
                   "target_status": selected["status"], "target_source": selected["source"]}
            self.targets[sig] = {"target_id": stable_id("apdex_target", sig if kind == "operation" else class_id, row), **row}
        self.cache = {}

    def limitations(self):
        result = list(LIMITATIONS)
        if not self.bundle.manifest["analysis_complete"]:
            result.append("source_analysis_incomplete")
        if not self.series.reliable:
            result.append("series_chronology_unresolved")
        if not self.confirmed:
            result.append("no_confirmed_failure_evidence_supplied_not_proof_of_success")
        return sorted(result)

    def group(self, sig, user, mid):
        key = (sig, user, mid)
        if key in self.cache:
            return self.cache[key]
        h = self.series.history(sig, user, mid)
        target = self.targets[sig]
        calls = self.series.groups.get(key, [])
        values = score(calls, target["t_us"], self.confirmed)
        row = {k: h[k] for k in ("history_id", "operation_id", "cohort_id", "signature", "user", "measurement_id", "measurement_order",
                                 "series_order_reliable", "observation_status", "observation_label", "calls_from_partial_sources", "measurement_source_health")}
        row.update(apdex_row_id=stable_id(h["history_id"], "apdex", target["target_id"], self.policy, self.config["apdex"]["confirmed_failures"]),
            target_coverage_status="target_defined" if target["t_us"] is not None else "uncovered_no_target",
            assessment_scope=SCOPE, failure_policy=self.policy, min_call_count=self.minimum,
            small_sample_warning=0 < len(calls) < self.minimum,
            sample_size_status="no_calls" if not calls else ("below_configured_minimum" if len(calls) < self.minimum else "meets_count_threshold_only"),
            known_limitations=self.limitations(), **target, **values)
        assert set(row) == set(GROUP_FIELDS)
        self.cache[key] = row
        return row

    def groups(self):
        return [self.group(sig, user, mid) for sig, user in self.series.pairs for mid in self.series.selected]

    def scopes(self):
        return [("measurement_all_users", [m]) for m in self.series.selected] + [("selected_measurements_all_users", self.series.selected)]

    def overall_tables(self):
        overall, composition = [], []
        groups = self.groups()
        for scope, mids in self.scopes():
            observed = [g for g in groups if g["measurement_id"] in mids and g["count"]]
            total = sum(g["count"] for g in observed)
            missing = sum(g["count"] for g in observed if g["t_us"] is None)
            for status in TARGET_STATUSES:
                members = [g for g in observed if g["target_status"] == status]
                n = sum(g["count"] for g in members)
                overall_id = stable_id(self.bundle.bundle_id, "apdex_overall", scope, mids, status, self.config["apdex"])
                sums = {k: sum(g[k] for g in members) for k in SCORE_FIELDS if k != "apdex"}
                # Count-weighted totals, never an unweighted mean of group APDEX.
                sums["apdex"] = sums["apdex_numerator_twice"] / (2 * n) if n else None
                if not n:
                    for k in ("satisfied_count", "tolerating_count", "frustrated_count", "apdex_numerator_twice", "latency_frustrated_count", "forced_frustrated_count"):
                        sums[k] = None
                row = {"overall_id": overall_id, "population_scope": scope,
                    "measurement_id": mids[0] if scope == "measurement_all_users" else None, "measurement_ids": mids,
                    "target_status": status, "assessment_scope": SCOPE, "failure_policy": self.policy,
                    "total_calls_in_scope": total, "calls_without_target": missing, "calls_with_other_target_status": total - missing - n,
                    "call_share_denominator": total, "scored_call_percent": percentage(n, total),
                    "operation_count": len({g["signature"] for g in members}), "user_identifier_count": len({g["user"] for g in members}),
                    "target_ids": sorted({g["target_id"] for g in members}), "composition_file": "apdex_composition.csv",
                    "composition_row_count": len(members), "min_call_count": self.minimum, "small_sample_warning": 0 < n < self.minimum,
                    "sample_size_status": "no_scored_calls" if not n else ("below_configured_minimum" if n < self.minimum else "meets_count_threshold_only"),
                    "known_limitations": sorted(self.limitations() + ["overall_can_change_due_to_operation_user_measurement_mix_without_any_operation_speedup",
                        "overall_status_populations_are_separate_business_and_proposal_targets_never_blended",
                        "scope_rows_overlap_do_not_sum_measurement_and_series_totals",
                        "user_identifiers_include_unknown_labels_not_verified_unique_people"]), **sums}
                assert set(row) == set(OVERALL_FIELDS)
                overall.append(row)
                for g in members:
                    comp = {k: g[k] for k in ("apdex_row_id", "operation_id", "signature", "user", "measurement_id", "satisfied_count", "tolerating_count",
                                              "frustrated_count", "apdex_numerator_twice", "assessment_scope", "failure_policy", *TARGET_FIELDS)}
                    comp.update(composition_id=stable_id(overall_id, g["apdex_row_id"]), overall_id=overall_id, population_scope=scope,
                        scope_measurement_ids=mids, call_count=g["count"], overall_apdex_denominator=n,
                        call_weight_percent=percentage(g["count"], n), operation_user_measurement_apdex=g["apdex"],
                        contribution_to_overall_apdex=g["apdex_numerator_twice"] / (2 * n))
                    assert set(comp) == set(COMPOSITION_FIELDS)
                    composition.append(comp)
        return overall, composition


def apdex(bundle, config, *, context=None):
    return family_rows(bundle, config, "apdex", context)


def _apdex(data):
    return data.groups()


def apdex_uncovered(bundle, config, *, context=None):
    return family_rows(bundle, config, "apdex_uncovered", context)


def apdex_calls(bundle, config, *, context=None):
    return family_rows(bundle, config, "apdex_calls", context)


def _apdex_calls(data):
    bundle = data.bundle
    rows = []
    for sig, user in data.series.pairs:
        target = data.targets[sig]
        if target["t_us"] is None:
            continue
        for mid in data.series.selected:
            group = data.group(sig, user, mid)
            for call in sorted(data.series.groups.get((sig, user, mid), []), key=lambda c: c["call_id"]):
                latency = latency_category(call["duration_us"], target["t_us"])
                confirmed = call["call_id"] in data.confirmed
                row = {k: call[k] for k in ("call_id", "signature", "user", "measurement_id", "duration_us")}
                row.update({k: group[k] for k in ("apdex_row_id", "history_id", "operation_id", "assessment_scope", "failure_policy", "known_limitations", *TARGET_FIELDS)})
                row.update(observation_id=stable_id(bundle.bundle_id, call["call_id"]), latency_category=latency,
                    category="frustrated" if confirmed else latency, confirmed_failure=confirmed,
                    failure_evidence=data.confirmed.get(call["call_id"]), business_outcome="confirmed_failure" if confirmed else "unknown",
                    linked_error_count=call["error_count"])
                assert set(row) == set(CALL_FIELDS)
                rows.append(row)
    return rows


def apdex_coverage(bundle, config, *, context=None):
    return family_rows(bundle, config, "apdex_coverage", context)


def _apdex_coverage(data):
    bundle, config = data.bundle, data.config
    groups = data.groups()
    rows = []
    for scope, mids in data.scopes():
        observed = [g for g in groups if g["measurement_id"] in mids and g["count"]]
        covered = [g for g in observed if g["t_us"] is not None]
        ops = {g["signature"] for g in observed}
        covered_ops = {g["signature"] for g in covered}
        n = sum(g["count"] for g in observed)
        covered_n = sum(g["count"] for g in covered)
        row = {"coverage_id": stable_id(bundle.bundle_id, "apdex_coverage", scope, mids, config["apdex"]), "population_scope": scope,
            "measurement_id": mids[0] if scope == "measurement_all_users" else None, "measurement_ids": mids,
            "assessment_scope": SCOPE, "failure_policy": data.policy, "total_call_count": n, "covered_call_count": covered_n,
            "uncovered_call_count": n - covered_n, "call_share_denominator": n, "covered_call_percent": percentage(covered_n, n),
            "observed_operation_count": len(ops), "covered_operation_count": len(covered_ops), "uncovered_operation_count": len(ops - covered_ops),
            "operation_share_denominator": len(ops), "covered_operation_percent": percentage(len(covered_ops), len(ops)),
            "confirmed_failure_count": sum(g["confirmed_failure_count"] for g in observed),
            "uncovered_confirmed_failure_count": sum(g["confirmed_failure_count"] for g in observed if g["t_us"] is None),
            "known_limitations": sorted(data.limitations() + ["coverage_counts_configured_T_not_source_log_completeness",
                "unique_operations_recomputed_not_summed_between_users_or_measurements", "scope_rows_overlap_do_not_sum_measurement_and_series_totals"])}
        for status in TARGET_STATUSES:
            row[status + "_call_count"] = sum(g["count"] for g in covered if g["target_status"] == status)
            row[status + "_operation_count"] = len({g["signature"] for g in covered if g["target_status"] == status})
        assert set(row) == set(COVERAGE_FIELDS)
        rows.append(row)
    return rows


def apdex_overall(bundle, config, *, context=None):
    return family_rows(bundle, config, "apdex_overall", context)


def apdex_composition(bundle, config, *, context=None):
    return family_rows(bundle, config, "apdex_composition", context)


def apdex_changes(bundle, config, *, context=None):
    return family_rows(bundle, config, "apdex_changes", context)


def _apdex_changes(data):
    config = data.config
    rows = []
    for common, before, after in data.series.comparisons():
        current = data.group(common["signature"], common["user"], common["current_measurement_id"])
        reference = data.group(common["signature"], common["user"], common["reference_measurement_id"]) if before else None
        both = bool(before and before["count"] and after["count"])
        known_user = common["user"] not in UNKNOWN_USER_VALUES
        target_match = bool(reference and reference["target_id"] and reference["target_id"] == current["target_id"])
        state = common["comparison_state"]
        if state == "numerical_comparison":
            state = "missing_target" if not target_match else ("user_identity_unknown" if not known_user else state)
        unknown = list(UNKNOWN_PARAMETERS)
        if not known_user:
            unknown.append("user_identity")
        if not data.series.reliable:
            unknown.append("measurement_order")
        row = {**common, "operation_comparison_state": common["comparison_state"], "comparison_state": state,
            "comparison_id": stable_id(common["comparison_id"], "apdex", config["apdex"]),
            "reference_apdex_row_id": reference["apdex_row_id"] if reference else None, "current_apdex_row_id": current["apdex_row_id"],
            "target_match": target_match if both else None, "signature_match": True if both else None,
            "user_match": True if both and known_user else None, "failure_policy": data.policy, "assessment_scope": SCOPE,
            "min_call_count": data.minimum, "small_sample_warning": bool((reference and reference["small_sample_warning"]) or current["small_sample_warning"]),
            "sample_size_status": "missing_observations" if not both else (
                "below_configured_minimum" if min(reference["count"], current["count"]) < data.minimum else "meets_count_threshold_only"),
            "known_differences": [f + "_changed" for f in ("count", "dataset_ids", "processes", "measurement_source_health", "calls_from_partial_sources") if before and before[f] != after[f]],
            "unknown_parameters": unknown, "known_limitations": data.limitations(),
            "percent_undefined_zero_reference_metrics": [], "unavailable_metrics": []}
        if reference and reference["confirmed_failure_count"] != current["confirmed_failure_count"]:
            row["known_differences"].append("confirmed_failure_evidence_count_changed")
        for field in ("target_id", "t_us", "target_status", "target_source", "apdex_denominator"):
            row["reference_" + field] = reference[field] if reference else None
            row["current_" + field] = current[field]
        for metric in CHANGE_METRICS:
            ref, cur = (reference[metric] if reference else None), current[metric]
            comparable = state == "numerical_comparison" and ref is not None and cur is not None
            delta = cur - ref if comparable else None
            pct = 100 * delta / ref if comparable and ref != 0 else None
            if comparable and ref == 0:
                row["percent_undefined_zero_reference_metrics"].append(metric)
            if ref is None or cur is None:
                row["unavailable_metrics"].append(metric)
            row.update({metric + "_reference": ref, metric + "_current": cur, metric + "_delta_absolute": delta, metric + "_delta_percent": pct})
        assert set(row) == set(CHANGE_FIELDS)
        rows.append(row)
    return rows
