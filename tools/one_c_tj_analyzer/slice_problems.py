"""Numerical problem lineage, not report interpretation, incident count or causality."""
from __future__ import annotations

import collections

from slice_config import SliceError, seconds_to_us
from slice_operations import OperationSeries, UNKNOWN_PARAMETERS, UNKNOWN_USER_VALUES, stable_id
from slice_db_chatty import ChattySeries
from slice_apdex import ApdexSeries
from slice_problem_config import METRICS

EXCEEDED = "порог превышен"
DECREASED = "показатель снизился"
INCREASED = "показатель вырос"
BELOW = "ниже порога в наблюдениях"
INSUFFICIENT = "недостаточно данных"
ABSENT = "не наблюдалось"
LIMITATIONS = [
    "numeric_rule_candidates_not_independent_incidents_or_proven_software_defects",
    "first_observed_threshold_breach_not_time_of_introduction_in_code",
    "no_automatic_fixed_code_regression_or_proven_cause_status",
    "different_metrics_and_reference_bases_must_not_be_collapsed",
    "previous_comparable_means_exact_known_user_and_signature_plus_configured_gates_not_controlled_experiment",
    "absence_or_below_threshold_observations_do_not_prove_remediation",
    "zero_DB_count_may_reflect_missing_recording_or_linkage",
    "source_completeness_and_per_CALL_linkage_confidence_not_established",
    "first_breach_is_retained_even_if_sample_or_quality_is_insufficient",
]
IDENTITY_FIELDS = (
    "problem_id series_id rule_id rule_definition_id rule_source metric metric_unit metric_source_slice metric_parameters "
    "operator threshold min_call_count scope operation_id signature user first_problem_measurement_id first_problem_measurement_order "
    "first_problem_value first_problem_count first_problem_evaluable first_problem_source_row_id discovery_phase "
    "series_first_measurement_id series_latest_measurement_id"
).split()
VALUE_FIELDS = (
    "measurement_id measurement_order history_id metric_source_row_id count value source_metric_value metric_available "
    "threshold_breached threshold_relation threshold_status eligible_for_comparison insufficient_reasons "
    "dataset_ids processes calls_from_partial_sources measurement_source_health "
    "measurement_db_linked_count_percent measurement_db_linked_duration_percent "
    "apdex_t_us apdex_target_status apdex_target_source apdex_failure_policy"
).split()
CHANGE_PARTS = (
    "reference_measurement_id reference_count reference_value reference_evaluable "
    "delta_absolute delta_percent percent_status change_direction change_status comparison_available known_differences"
).split()
HISTORY_FIELDS = IDENTITY_FIELDS + VALUE_FIELDS + (
    "history_row_id is_first_problem_observation is_latest_series_measurement previous_observation_measurement_id "
    "first_reference_comparability previous_reference_comparability unknown_parameters known_limitations"
).split() + [prefix + field for prefix in ("first_problem_", "previous_comparable_") for field in CHANGE_PARTS]
REGISTRY_FIELDS = HISTORY_FIELDS + (
    "last_observed_measurement_id last_value_measurement_id last_evaluable_measurement_id "
    "observed_in_latest_measurement checked_in_latest_measurement historical_without_latest_check "
    "latest_check_scope output_measurement_ids"
).split()
TRANSITION_FIELDS = HISTORY_FIELDS + (
    "transition_id comparison_basis reference_measurement_id reference_count reference_value "
    "delta_absolute delta_percent change_status selection_scope"
).split()
RULE_COVERAGE_FIELDS = (
    "rule_id series_id metric operator threshold min_call_count rule_source scope measurement_id measurement_order "
    "selected_operation_user_cohort_count observed_cohort_count metric_available_cohort_count evaluable_cohort_count "
    "raw_threshold_breach_cohort_count evaluable_threshold_breach_cohort_count insufficient_cohort_count absent_cohort_count "
    "observed_call_count insufficient_reasons known_limitations"
).split()


class ProblemSeries:
    def __init__(self, bundle, config):
        self.bundle = bundle
        self.config = config
        self.cfg = config["problems"]
        if not self.cfg["rules"]:
            raise SliceError("Problem slices require explicit nonempty problems.rules and series_id")
        self.series = OperationSeries(bundle, config)
        if not self.series.reliable:
            raise SliceError("Problem history requires reliable chronology; provide operations.measurement_order explicitly")
        self.db = ChattySeries(bundle, config) if any(r["metric"].startswith("db_chatty.") for r in self.cfg["rules"]) else None
        self.apdex = ApdexSeries(bundle, config) if any(r["metric"].startswith("apdex.") for r in self.cfg["rules"]) else None
        self.rule_pairs = {}
        known_users = {c["user"] for c in bundle.calls}
        for rule in self.cfg["rules"]:
            if rule["signatures"] is not None and set(rule["signatures"]) - set(self.series.signatures):
                raise SliceError(f"Rule {rule['rule_id']}: unknown signature filter in full bundle")
            if rule["users"] is not None and set(rule["users"]) - known_users:
                raise SliceError(f"Rule {rule['rule_id']}: unknown user filter in full bundle")
            self.rule_pairs[rule["rule_id"]] = [(s, u) for s, u in self.series.pairs if
                (rule["signatures"] is None or s in rule["signatures"]) and (rule["users"] is None or u in rule["users"])]
        self.evaluation_cache = {}

    def parameters(self, rule, signature):
        metric = rule["metric"]
        result = {"numeric_method_version": "1", "transformation": "one_minus_APDEX" if metric == "apdex.deficit" else "identity"}
        if metric.startswith("db_chatty."):
            result["db_events_threshold"] = rule["db_events_threshold"]
            if ".fast_" in metric:
                result["fast_call_max_us"] = seconds_to_us(self.config["db_chatty"]["fast_call_max_seconds"], "fast_call_max_seconds")
        if metric.startswith("apdex."):
            target = self.apdex.targets[signature]
            result.update(t_us=target["t_us"], target_status=target["target_status"], failure_policy=self.apdex.policy)
        return result

    def evaluate(self, rule, sig, user, mid):
        key = (rule["rule_id"], sig, user, mid)
        if key in self.evaluation_cache:
            return self.evaluation_cache[key]
        h = self.series.history(sig, user, mid)
        catalog = METRICS[rule["metric"]]
        source = h
        source_id = h["history_id"]
        if catalog["source"] == "db_chatty":
            source = self.db.group(sig, user, mid, rule["db_events_threshold"])
            source_id = source["group_id"]
        elif catalog["source"] == "apdex":
            source = self.apdex.group(sig, user, mid)
            source_id = source["apdex_row_id"]
        raw_value = source[catalog["field"]] if h["count"] else None
        value = raw_value
        if rule["metric"] == "apdex.deficit" and raw_value is not None:
            # Compute from integer category counts; 1 - float(APDEX) can put
            # an exact boundary (e.g. deficit 0.15) spuriously above the rule.
            denominator = 2 * source["apdex_denominator"]
            value = (denominator - source["apdex_numerator_twice"]) / denominator
        breach = None if value is None else (value > rule["threshold"] if rule["operator"] == ">" else value >= rule["threshold"])
        relation = None if value is None else (">" if value > rule["threshold"] else ("<" if value < rule["threshold"] else "="))
        reasons = []
        if not h["count"]:
            reasons.append("operation_not_observed")
        else:
            if value is None:
                reasons.append("metric_unavailable")
                if catalog["source"] == "apdex" and source["t_us"] is None:
                    reasons.append("APDEX_T_not_defined")
            if h["count"] < rule["min_call_count"]:
                reasons.append("sample_below_rule_minimum")
            if user in UNKNOWN_USER_VALUES:
                reasons.append("user_identity_unknown")
            if rule["require_clean_sources"] and (h["measurement_source_health"] != "no_recorded_related_capture_problem" or h["calls_from_partial_sources"]):
                reasons.append("related_capture_has_recorded_source_gaps")
            for kind in ("count", "duration"):
                gate = rule[f"min_db_linked_{kind}_percent"]
                actual = h[f"measurement_db_linked_{kind}_percent"]
                if gate is not None and (actual is None or actual < gate):
                    reasons.append(f"measurement_DB_{kind}_coverage_unknown_or_below_gate")
        ready = not reasons
        status = ABSENT if not h["count"] else (INSUFFICIENT if not ready else (EXCEEDED if breach else BELOW))
        row = {k: h[k] for k in ("measurement_id", "measurement_order", "history_id", "count", "dataset_ids", "processes", "calls_from_partial_sources",
                                 "measurement_source_health", "measurement_db_linked_count_percent", "measurement_db_linked_duration_percent")}
        row.update(metric_source_row_id=source_id, value=value, source_metric_value=raw_value, metric_available=value is not None,
                   threshold_breached=breach, threshold_relation=relation, threshold_status=status,
                   eligible_for_comparison=ready, insufficient_reasons=sorted(reasons),
                   apdex_t_us=source.get("t_us") if catalog["source"] == "apdex" else None,
                   apdex_target_status=source.get("target_status") if catalog["source"] == "apdex" else None,
                   apdex_target_source=source.get("target_source") if catalog["source"] == "apdex" else None,
                   apdex_failure_policy=self.apdex.policy if catalog["source"] == "apdex" else None)
        assert set(row) == set(VALUE_FIELDS)
        self.evaluation_cache[key] = row
        return row

    @staticmethod
    def change(current, reference):
        available = bool(reference and reference["eligible_for_comparison"] and current["eligible_for_comparison"])
        ref_value = reference["value"] if reference else None
        delta = current["value"] - ref_value if available else None
        percent = 100 * delta / ref_value if available and ref_value != 0 else None
        direction = None if not available else ("decreased" if delta < 0 else ("increased" if delta > 0 else "unchanged"))
        change_status = ABSENT if not current["count"] else (INSUFFICIENT if not available else (DECREASED if delta < 0 else (INCREASED if delta > 0 else None)))
        differences = [field + "_changed" for field in ("count", "dataset_ids", "processes", "measurement_source_health", "calls_from_partial_sources",
            "measurement_db_linked_count_percent", "measurement_db_linked_duration_percent") if reference and reference[field] != current[field]]
        result = {
            "reference_measurement_id": reference["measurement_id"] if reference else None,
            "reference_count": reference["count"] if reference else None, "reference_value": ref_value,
            "reference_evaluable": reference["eligible_for_comparison"] if reference else None,
            "delta_absolute": delta, "delta_percent": percent,
            "percent_status": "not_comparable" if not available else ("undefined_zero_reference" if ref_value == 0 else "defined"),
            "change_direction": direction, "change_status": change_status, "comparison_available": available,
            "known_differences": differences,
        }
        assert set(result) == set(CHANGE_PARTS)
        return result

    def build(self):
        registry, history, coverage = [], [], []
        if not self.series.order:
            return registry, history, coverage
        first_mid, latest_mid = self.series.order[0], self.series.order[-1]
        for rule in self.cfg["rules"]:
            pairs = self.rule_pairs[rule["rule_id"]]
            for mid in self.series.selected:
                evaluated = [self.evaluate(rule, s, u, mid) for s, u in pairs]
                reasons = collections.Counter(reason for e in evaluated for reason in e["insufficient_reasons"])
                row = {"rule_id": rule["rule_id"], "series_id": self.cfg["series_id"], "metric": rule["metric"],
                    "operator": rule["operator"], "threshold": rule["threshold"], "min_call_count": rule["min_call_count"],
                    "rule_source": rule["source"], "scope": rule["scope"], "measurement_id": mid, "measurement_order": self.series.position[mid] + 1,
                    "selected_operation_user_cohort_count": len(evaluated), "observed_cohort_count": sum(e["count"] > 0 for e in evaluated),
                    "metric_available_cohort_count": sum(e["metric_available"] for e in evaluated), "evaluable_cohort_count": sum(e["eligible_for_comparison"] for e in evaluated),
                    "raw_threshold_breach_cohort_count": sum(e["threshold_breached"] is True for e in evaluated),
                    "evaluable_threshold_breach_cohort_count": sum(e["eligible_for_comparison"] and e["threshold_breached"] is True for e in evaluated),
                    "insufficient_cohort_count": sum(e["threshold_status"] == INSUFFICIENT for e in evaluated),
                    "absent_cohort_count": sum(e["threshold_status"] == ABSENT for e in evaluated),
                    "observed_call_count": sum(e["count"] for e in evaluated), "insufficient_reasons": dict(sorted(reasons.items())),
                    "known_limitations": LIMITATIONS}
                assert set(row) == set(RULE_COVERAGE_FIELDS)
                coverage.append(row)
            for sig, user in pairs:
                all_values = [self.evaluate(rule, sig, user, mid) for mid in self.series.order]
                first_index = next((i for i, e in enumerate(all_values) if e["threshold_breached"] is True), None)
                if first_index is None:
                    continue
                first = all_values[first_index]
                params = self.parameters(rule, sig)
                semantic_rule = {k: rule[k] for k in ("rule_id", "metric", "operator", "threshold", "min_call_count", "scope",
                    "min_db_linked_count_percent", "min_db_linked_duration_percent", "require_clean_sources")}
                rule_definition_id = stable_id("problem_rule_v1", semantic_rule, params)
                problem_id = stable_id("problem_v1", self.cfg["series_id"], rule_definition_id, sig, user)
                catalog = METRICS[rule["metric"]]
                identity = {
                    "problem_id": problem_id, "series_id": self.cfg["series_id"], "rule_id": rule["rule_id"], "rule_definition_id": rule_definition_id,
                    "rule_source": rule["source"], "metric": rule["metric"], "metric_unit": catalog["unit"], "metric_source_slice": catalog["source"],
                    "metric_parameters": params, "operator": rule["operator"], "threshold": rule["threshold"], "min_call_count": rule["min_call_count"],
                    "scope": rule["scope"], "operation_id": stable_id(sig), "signature": sig, "user": user,
                    "first_problem_measurement_id": first["measurement_id"], "first_problem_measurement_order": first["measurement_order"],
                    "first_problem_value": first["value"], "first_problem_count": first["count"], "first_problem_evaluable": first["eligible_for_comparison"],
                    "first_problem_source_row_id": first["metric_source_row_id"], "discovery_phase": "first_measurement" if first_index == 0 else "later_measurement",
                    "series_first_measurement_id": first_mid, "series_latest_measurement_id": latest_mid,
                }
                unknown = list(UNKNOWN_PARAMETERS)
                if user in UNKNOWN_USER_VALUES:
                    unknown.append("user_identity")
                last_observed = next((e["measurement_id"] for e in reversed(all_values) if e["count"]), None)
                last_value = next((e["measurement_id"] for e in reversed(all_values) if e["metric_available"]), None)
                last_evaluable = next((e["measurement_id"] for e in reversed(all_values[first_index:]) if e["eligible_for_comparison"]), None)
                for i in range(first_index, len(all_values)):
                    current = all_values[i]
                    previous = next((e for e in reversed(all_values[:i]) if e["eligible_for_comparison"]), None)
                    previous_observed = next((e["measurement_id"] for e in reversed(all_values[:i]) if e["count"]), None)
                    changes = {"first_problem_": self.change(current, first), "previous_comparable_": self.change(current, previous)}
                    limitations = sorted(set(LIMITATIONS) | set(self.series.history(sig, user, current["measurement_id"])["known_limitations"]))
                    if catalog["source"] == "apdex":
                        limitations = sorted(set(limitations) | set(self.apdex.limitations()))
                    row = {**identity, **current,
                        "history_row_id": stable_id(problem_id, current["measurement_id"]),
                        "is_first_problem_observation": i == first_index, "is_latest_series_measurement": current["measurement_id"] == latest_mid,
                        "previous_observation_measurement_id": previous_observed,
                        "first_reference_comparability": "exact_keys_only_uncontrolled" if changes["first_problem_"]["comparison_available"] else "not_comparable",
                        "previous_reference_comparability": "exact_keys_only_uncontrolled" if changes["previous_comparable_"]["comparison_available"] else "not_comparable",
                        "unknown_parameters": unknown, "known_limitations": limitations,
                    }
                    for prefix, change in changes.items():
                        row.update({prefix + k: v for k, v in change.items()})
                    assert set(row) == set(HISTORY_FIELDS)
                    if current["measurement_id"] in self.series.selected:
                        history.append(row)
                    if i == len(all_values) - 1:
                        record = {**row, "last_observed_measurement_id": last_observed, "last_value_measurement_id": last_value,
                            "last_evaluable_measurement_id": last_evaluable, "observed_in_latest_measurement": bool(current["count"]),
                            "checked_in_latest_measurement": current["eligible_for_comparison"],
                            "historical_without_latest_check": first_index < i and not current["eligible_for_comparison"],
                            "latest_check_scope": "latest_measurement_of_full_bundle_not_output_filter", "output_measurement_ids": self.series.selected}
                        assert set(record) == set(REGISTRY_FIELDS)
                        registry.append(record)
        def identity_order(row):
            return (row["first_problem_measurement_order"], row["signature"], row["user"], row["rule_id"], row["problem_id"])
        registry.sort(key=identity_order)
        history.sort(key=lambda r: (*identity_order(r), r["measurement_order"]))
        coverage.sort(key=lambda r: (r["measurement_order"], r["rule_id"]))
        return registry, history, coverage


def problem_registry(bundle, config):
    return ProblemSeries(bundle, config).build()[0]


def problem_history(bundle, config):
    return ProblemSeries(bundle, config).build()[1]


def problem_rule_coverage(bundle, config):
    return ProblemSeries(bundle, config).build()[2]


def problem_persisting(bundle, config):
    return [r for r in problem_registry(bundle, config) if r["threshold_status"] == EXCEEDED]


def problem_unchecked(bundle, config):
    return [r for r in problem_registry(bundle, config) if r["historical_without_latest_check"]]


def problem_new(bundle, config):
    # Discovery chronology includes first-measurement baseline problems AND later additions.
    return [r for r in problem_history(bundle, config) if r["is_first_problem_observation"]]


def transitions(bundle, config, direction):
    result = []
    for row in problem_history(bundle, config):
        for basis, prefix in (("first_problem", "first_problem_"), ("previous_comparable", "previous_comparable_")):
            if row[prefix + "change_direction"] != direction:
                continue
            event = {**row, "transition_id": stable_id(row["history_row_id"], basis), "comparison_basis": basis,
                     "selection_scope": "selected_history_observations_not_only_latest"}
            for field in ("reference_measurement_id", "reference_count", "reference_value", "delta_absolute", "delta_percent", "change_status"):
                event[field] = row[prefix + field]
            assert set(event) == set(TRANSITION_FIELDS)
            result.append(event)
    return result


def problem_improved(bundle, config):
    return transitions(bundle, config, "decreased")


def problem_worsened(bundle, config):
    return transitions(bundle, config, "increased")
