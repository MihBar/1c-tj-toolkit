"""Numerical problem lineage, persistent identities and non-causal selections."""
from __future__ import annotations

import contextlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from derive_slices import run
from slice_config import SliceError, normalize_config
from slice_input import load_bundle
from slice_problems import (EXCEEDED, DECREASED, INCREASED, BELOW, INSUFFICIENT, ABSENT,
    problem_registry, problem_history, problem_improved, problem_persisting, problem_worsened,
    problem_new, problem_unchecked, problem_rule_coverage)
from verify_slices import verify
from test_derive_slices import hashes, fixture
from test_slice_operations import saved_series, spec, M1, M2, M3, M4

BUILDERS = (problem_registry, problem_history, problem_improved, problem_persisting,
            problem_worsened, problem_new, problem_unchecked, problem_rule_coverage)


def rule(rid="slow", metric="operation.avg_us", threshold=10_000_000, **extra):
    return {"rule_id": rid, "metric": metric, "operator": ">", "threshold": threshold,
            "min_call_count": 1, "source": "Synthetic diagnostic rule, not SLA", **extra}


def config(rules=None, **extra):
    return normalize_config({"config_version": "1.0", "slices": [b.__name__ for b in BUILDERS],
        "problems": {"series_id": "synthetic_series", "rules": [rule()] if rules is None else rules}, **extra})


class ProblemHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tj-problem-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "input"

    def test_first_measurement_problems_remain_and_later_discoveries_are_added(self):
        b = saved_series(self.input, [spec(M1, 20, signature="A"), spec(M2, 8, signature="A"),
            spec(M2, 2, signature="B"), spec(M3, 30, signature="B")])
        registry = problem_registry(b, config())
        self.assertEqual([r["signature"] for r in registry], ["A", "B"])
        self.assertEqual([r["first_problem_measurement_id"] for r in registry], [M1, M3])
        self.assertEqual([r["discovery_phase"] for r in registry], ["first_measurement", "later_measurement"])
        history = problem_history(b, config())
        a = [r for r in history if r["signature"] == "A"]
        self.assertEqual([r["measurement_id"] for r in a], [M1, M2, M3])
        self.assertEqual([r["threshold_status"] for r in a], [EXCEEDED, BELOW, ABSENT])
        new = problem_new(b, config())
        self.assertEqual([(r["signature"], r["measurement_id"]) for r in new], [("A", M1), ("B", M3)])
        self.assertEqual([r["signature"] for r in problem_persisting(b, config())], ["B"])
        self.assertEqual([r["signature"] for r in problem_unchecked(b, config())], ["A"])

    def test_gap_previous_comparable_reference_and_last_check(self):
        b = saved_series(self.input, [spec(M1, 20), spec(M2, 1, signature="Other"), spec(M3, 8)])
        h = [r for r in problem_history(b, config()) if r["signature"] == "Operation"]
        self.assertIsNone(h[1]["value"])
        self.assertEqual(h[1]["threshold_status"], ABSENT)
        self.assertIsNone(h[1]["first_problem_delta_absolute"])
        self.assertEqual(h[2]["previous_comparable_reference_measurement_id"], M1)
        self.assertEqual(h[2]["first_problem_delta_absolute"], -12_000_000)
        self.assertEqual(h[2]["first_problem_delta_percent"], -60)
        self.assertEqual(h[2]["previous_comparable_reference_count"], 1)
        r = problem_registry(b, config())[0]
        self.assertEqual(r["last_observed_measurement_id"], M3)
        self.assertTrue(r["checked_in_latest_measurement"])
        self.assertFalse(r["historical_without_latest_check"])

    def test_last_absence_not_treated_as_improvement_or_fixed(self):
        b = saved_series(self.input, [spec(M1, 20), spec(M2, 1, signature="Other")])
        r = problem_unchecked(b, config())[0]
        self.assertFalse(r["observed_in_latest_measurement"])
        self.assertFalse(r["checked_in_latest_measurement"])
        self.assertEqual(r["last_observed_measurement_id"], M1)
        self.assertEqual(r["threshold_status"], ABSENT)
        self.assertEqual(problem_improved(b, config()), [])
        self.assertEqual(problem_persisting(b, config()), [])

    def test_CALL_improves_while_DB_worsens_are_distinct_problems(self):
        b = saved_series(self.input, [spec(M1, 20, db_count=100), spec(M2, 8, db_count=200)])
        cfg = config([rule(), rule("db", "operation.db_per_call", 50)])
        r = {r["rule_id"]: r for r in problem_registry(b, cfg)}
        self.assertEqual(r["slow"]["first_problem_change_status"], DECREASED)
        self.assertEqual(r["db"]["first_problem_change_status"], INCREASED)
        self.assertNotEqual(r["slow"]["problem_id"], r["db"]["problem_id"])
        self.assertEqual({r["rule_id"] for r in problem_improved(b, cfg)}, {"slow"})
        self.assertEqual({r["rule_id"] for r in problem_worsened(b, cfg)}, {"db"})
        self.assertEqual({r["rule_id"] for r in problem_persisting(b, cfg)}, {"db"})

    def test_opposite_directions_against_two_bases_are_not_collapsed(self):
        b = saved_series(self.input, [spec(M1, 20), spec(M2, 15), spec(M3, 18)])
        r = problem_registry(b, config())[0]
        self.assertEqual(r["threshold_status"], EXCEEDED)
        self.assertEqual(r["first_problem_change_status"], DECREASED)
        self.assertEqual(r["previous_comparable_change_status"], INCREASED)
        improved = [r for r in problem_improved(b, config()) if r["measurement_id"] == M3]
        worsened = [r for r in problem_worsened(b, config()) if r["measurement_id"] == M3]
        self.assertEqual([r["comparison_basis"] for r in improved], ["first_problem"])
        self.assertEqual([r["comparison_basis"] for r in worsened], ["previous_comparable"])

    def test_first_breach_and_previous_comparable_can_follow_earlier_normal_value(self):
        b = saved_series(self.input, [spec(M1, 5), spec(M2, 20)])
        h = problem_history(b, config())
        self.assertEqual(len(h), 1)
        self.assertEqual(h[0]["first_problem_measurement_id"], M2)
        self.assertEqual(h[0]["previous_comparable_reference_measurement_id"], M1)
        self.assertEqual(h[0]["previous_comparable_delta_absolute"], 15_000_000)

    def test_small_sample_breach_retained_but_not_claimed_sufficient(self):
        b = saved_series(self.input, [spec(M1, 20), spec(M2, 8)])
        cfg = config([rule(min_call_count=2)])
        r = problem_registry(b, cfg)[0]
        self.assertEqual(r["first_problem_measurement_id"], M1)
        self.assertFalse(r["first_problem_evaluable"])
        self.assertEqual(r["threshold_status"], INSUFFICIENT)
        self.assertFalse(r["threshold_breached"])
        self.assertIn("sample_below_rule_minimum", r["insufficient_reasons"])
        self.assertIsNone(r["first_problem_delta_absolute"])
        self.assertTrue(r["historical_without_latest_check"])
        self.assertEqual(problem_improved(b, cfg), [])

    def test_low_DB_coverage_observation_is_skipped_for_previous_comparison(self):
        b = saved_series(self.input, [spec(M1, 1, db_count=100), spec(M2, 1, db_count=5), spec(M3, 1, db_count=80)])
        cfg = config([rule("db", "operation.db_per_call", 50, min_db_linked_count_percent=90)])
        h = problem_history(b, cfg)
        self.assertEqual(h[1]["threshold_status"], INSUFFICIENT)
        self.assertEqual(h[2]["previous_observation_measurement_id"], M2)
        self.assertEqual(h[2]["previous_comparable_reference_measurement_id"], M1)
        self.assertEqual(h[2]["previous_comparable_delta_absolute"], -20)

    def test_pre_discovery_normal_sample_is_not_a_recheck_of_later_problem(self):
        b = saved_series(self.input, [spec(M1, 5), spec(M1, 5), spec(M2, 20)])
        r = problem_registry(b, config([rule(min_call_count=2)]))[0]
        self.assertEqual(r["first_problem_measurement_id"], M2)
        self.assertEqual(r["previous_comparable_reference_measurement_id"], M1)
        self.assertIsNone(r["last_evaluable_measurement_id"])

    def test_individual_DB_CALL_rule_does_not_rely_on_group_mean(self):
        b = saved_series(self.input, [spec(M1, 1, db_count=0)] * 9 + [spec(M1, 1, db_count=600)])
        cfg = config([rule("db_mean", "operation.db_per_call", 100),
            rule("db_actual", "db_chatty.calls_above_threshold_count", 0, db_events_threshold=500)])
        r = problem_registry(b, cfg)
        self.assertEqual([r["rule_id"] for r in r], ["db_actual"])
        self.assertEqual(r[0]["value"], 1)
        self.assertEqual(r[0]["count"], 10)

    def test_stable_identity_survives_append_bundle_change_and_rule_label_edit(self):
        b = saved_series(self.input, [spec(M1, 20)])
        first = problem_registry(b, config())[0]
        old_bundle = b.bundle_id
        later = saved_series(self.input, [spec(M1, 20), spec(M2, 8)])
        self.assertNotEqual(later.bundle_id, old_bundle)
        extended = problem_registry(later, config([rule(source="Changed description")]))[0]
        self.assertEqual(first["problem_id"], extended["problem_id"])
        self.assertNotEqual(first["first_problem_source_row_id"], extended["first_problem_source_row_id"])
        changed = problem_registry(later, config([rule(threshold=11_000_000)]))[0]
        self.assertNotEqual(first["problem_id"], changed["problem_id"])
        decimal = problem_registry(later, config([rule(threshold=10_000_000.0)]))[0]
        self.assertEqual(first["problem_id"], decimal["problem_id"])

    def test_exact_users_and_similar_signatures_are_separate(self):
        b = saved_series(self.input, [spec(M1, 20), spec(M2, 8, "Bob"), spec(M2, 20, signature="Operation2")])
        r = problem_registry(b, config())
        original = next(r for r in r if r["signature"] == "Operation")
        self.assertEqual(original["user"], "Alice")
        self.assertFalse(original["observed_in_latest_measurement"])
        self.assertEqual(original["threshold_status"], ABSENT)
        self.assertEqual(len(r), 2)

    def test_unknown_user_is_insufficient_for_same_user_check(self):
        b = saved_series(self.input, [spec(M1, 20, "(not specified)"), spec(M2, 8, "(not specified)")])
        r = problem_registry(b, config())[0]
        self.assertEqual(r["threshold_status"], INSUFFICIENT)
        self.assertIn("user_identity_unknown", r["insufficient_reasons"])
        self.assertIsNone(r["first_problem_delta_absolute"])

    def test_filter_does_not_change_first_problem_or_full_series_latest(self):
        b = saved_series(self.input, [spec(M1, 20), spec(M2, 15), spec(M3, 8)])
        cfg = dict(config(), measurement_ids=[M2])
        self.assertEqual([r["measurement_id"] for r in problem_history(b, cfg)], [M2])
        r = problem_registry(b, cfg)[0]
        self.assertEqual(r["first_problem_measurement_id"], M1)
        self.assertEqual(r["measurement_id"], M3)
        self.assertTrue(r["checked_in_latest_measurement"])
        self.assertEqual(problem_new(b, cfg), [])

    def test_APDEX_without_T_is_unassessed_not_a_fabricated_problem(self):
        b = saved_series(self.input, [spec(M1, 20)])
        cfg = config([rule("apdex", "apdex.deficit", .15)])
        self.assertEqual(problem_registry(b, cfg), [])
        coverage = problem_rule_coverage(b, cfg)[0]
        self.assertEqual(coverage["observed_cohort_count"], 1)
        self.assertEqual(coverage["evaluable_cohort_count"], 0)
        self.assertEqual(coverage["insufficient_reasons"]["APDEX_T_not_defined"], 1)

    def test_APDEX_deficit_polarity_and_exact_point15_boundary(self):
        target = {"signature": "Operation", "t_seconds": 1, "status": "engineering_proposal", "source": "Synthetic test target"}
        b = saved_series(self.input, [spec(M1, 1)] * 17 + [spec(M1, 5)] * 3)
        cfg = config([rule("apdex", "apdex.deficit", .15)], apdex={"targets": [target]})
        self.assertEqual(problem_registry(b, cfg), [])
        cfg = config([rule("apdex", "apdex.deficit", .14)], apdex={"targets": [target]})
        r = problem_registry(b, cfg)[0]
        self.assertEqual(r["value"], .15)
        self.assertEqual(r["source_metric_value"], .85)
        b = saved_series(self.input, [spec(M1, 5), spec(M2, 1)])
        r = problem_registry(b, cfg)[0]
        self.assertEqual(r["first_problem_change_status"], DECREASED)
        self.assertEqual(r["first_problem_delta_absolute"], -1)

    def test_zero_base_percentage_and_equality_do_not_invent_a_trend(self):
        b = saved_series(self.input, [spec(M1, 0), spec(M2, 1)])
        cfg = config([rule(threshold=0, operator=">=")])
        h = problem_history(b, cfg)
        self.assertEqual(h[0]["threshold_relation"], "=")
        self.assertIsNone(h[0]["first_problem_change_status"])
        self.assertEqual(h[0]["first_problem_change_direction"], "unchanged")
        self.assertEqual(h[1]["first_problem_delta_absolute"], 1_000_000)
        self.assertIsNone(h[1]["first_problem_delta_percent"])
        self.assertEqual(h[1]["first_problem_percent_status"], "undefined_zero_reference")

    def test_strict_threshold_equality_retains_relation_and_non_breach(self):
        b = saved_series(self.input, [spec(M1, 20), spec(M2, 10)])
        r = problem_registry(b, config())[0]
        self.assertEqual(r["threshold_relation"], "=")
        self.assertFalse(r["threshold_breached"])
        self.assertEqual(r["threshold_status"], BELOW)

    def test_metric_discovery_does_not_require_inputs(self):
        result = run(["--list-problem-metrics"])
        self.assertIn("operation.avg_us", result["metrics"])
        self.assertIn("apdex.deficit", result["metrics"])
        self.assertNotIn("apdex.apdex", result["metrics"])

    def test_ambiguous_chronology_requires_explicit_order(self):
        b = saved_series(self.input, [spec(M1, 20), spec(M2, 20)])
        b.calls[1]["start_timestamp"] = b.calls[0]["start_timestamp"]
        b.calls[1]["end_timestamp"] = b.calls[0]["end_timestamp"]
        with self.assertRaisesRegex(SliceError, "reliable chronology"):
            problem_registry(b, config())
        cfg = config(operations={"measurement_order": [M1, M2]})
        self.assertEqual(problem_registry(b, cfg)[0]["first_problem_measurement_id"], M1)

    def test_partial_source_can_be_reported_or_gated_but_never_hidden(self):
        fixture(self.input, partial=True)
        b = load_bundle(self.input)
        r = problem_registry(b, config([rule(threshold=0)]))[0]
        self.assertIn("source_analysis_incomplete", r["known_limitations"])
        self.assertGreater(r["calls_from_partial_sources"], 0)
        r = problem_registry(b, config([rule(threshold=0, require_clean_sources=True)]))[0]
        self.assertEqual(r["threshold_status"], INSUFFICIENT)
        self.assertTrue(r["threshold_breached"])

    def test_invalid_rules_and_scope_rejected(self):
        for change in ({"metric": "arbitrary.expression"}, {"operator": "<"}, {"threshold": "10"}, {"threshold": float("nan")},
            {"min_call_count": 0}, {"min_call_count": True}, {"source": ""}, {"scope": "all_users"}, {"require_clean_sources": "yes"},
            {"db_events_threshold": 100}, {"min_db_linked_count_percent": 90}):
            with self.subTest(change=change), self.assertRaises(SliceError):
                config([rule(**change)])
        with self.assertRaises(SliceError):
            config([rule(), rule()])
        with self.assertRaises(SliceError):
            normalize_config({"config_version": "1.0", "problems": {"rules": [rule()]}})
        b = saved_series(self.input, [spec(M1, 20)])
        with self.assertRaisesRegex(SliceError, "explicit nonempty"):
            problem_registry(b, config([]))
        for filt in ({"users": ["Nobody"]}, {"signatures": ["Other"]}):
            with self.assertRaises(SliceError):
                problem_registry(b, config([rule(**filt)]))

    def test_empty_bundle_is_not_a_problem_and_numeric_filter_is_explicit(self):
        fixture(self.input, empty=True)
        b = load_bundle(self.input)
        self.assertTrue(all(builder(b, config()) == [] for builder in BUILDERS))
        b = saved_series(self.input, [spec(M1, 20), spec(M1, 30, "Bob")])
        cfg = config([rule(users=["Alice"])])
        self.assertEqual([r["user"] for r in problem_registry(b, cfg)], ["Alice"])
        self.assertEqual(normalize_config(cfg), cfg)

    def test_output_statuses_only_requested_vocabulary(self):
        b = saved_series(self.input, [spec(M1, 20), spec(M2, 8), spec(M3, 15), spec(M4, 1, signature="Other")])
        allowed = {EXCEEDED, DECREASED, INCREASED, BELOW, INSUFFICIENT, ABSENT, None}
        for r in problem_history(b, config()):
            for field in ("threshold_status", "first_problem_change_status", "previous_comparable_change_status"):
                self.assertIn(r[field], allowed)

    def test_reproduction_row_order_no_overwrite_and_input_integrity(self):
        b = saved_series(self.input, [spec(M1, 20), spec(M2, 8), spec(M3, 15)])
        cfg = config()
        before_rows = [builder(b, cfg) for builder in BUILDERS]
        b.calls.reverse()
        self.assertEqual(before_rows, [builder(b, cfg) for builder in BUILDERS])
        input_hashes = hashes(self.input)
        path = self.root / "config.json"
        path.write_text(json.dumps(cfg), encoding="utf-8")
        outputs = [self.root / "out1", self.root / "out2"]
        for out in outputs:
            run(["--analysis-dir", str(self.input), "--config", str(path), "--output-dir", str(out)])
            self.assertEqual(verify(self.input, out)["status"], "PASS")
        self.assertEqual(hashes(outputs[0]), hashes(outputs[1]))
        self.assertEqual(input_hashes, hashes(self.input))
        with self.assertRaises(SliceError):
            run(["--analysis-dir", str(self.input), "--config", str(path), "--output-dir", str(outputs[0])])

    def test_no_original_path_or_network_access(self):
        saved_series(self.input, [spec(M1, 20), spec(M2, 8)])
        originals = {name: getattr(Path, name) for name in ("open", "stat", "exists", "is_file", "resolve")}
        def guard(name):
            def wrapped(path, *args, **kwargs):
                self.assertNotIn("DO_NOT_OPEN", str(path))
                return originals[name](path, *args, **kwargs)
            return wrapped
        with contextlib.ExitStack() as stack:
            for name in originals:
                stack.enter_context(mock.patch.object(Path, name, guard(name)))
            stack.enter_context(mock.patch("socket.socket", side_effect=AssertionError("network forbidden")))
            b = load_bundle(self.input)
            for builder in BUILDERS:
                builder(b, config())


if __name__ == "__main__":
    unittest.main()
