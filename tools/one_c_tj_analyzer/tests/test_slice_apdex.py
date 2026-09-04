"""APDEX formula/boundaries, target provenance, failures and changing mixtures."""
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
from slice_apdex import (apdex, apdex_calls, apdex_uncovered, apdex_coverage, apdex_overall,
                         apdex_composition, apdex_changes, latency_category, score)
from verify_slices import verify
from test_slice_operations import saved_series, spec, M1, M2, M3, M4
from test_derive_slices import fixture, hashes

BUILDERS = (apdex, apdex_calls, apdex_uncovered, apdex_coverage, apdex_overall, apdex_composition, apdex_changes)


def target(sig="Operation", t=1, status="engineering_proposal", source="Synthetic test target, not a real SLA"):
    return {"signature": sig, "t_seconds": t, "status": status, "source": source}


def config(targets=None, **extra):
    return normalize_config({"config_version": "1.0", "slices": [b.__name__ for b in BUILDERS],
                            "apdex": {"targets": [target()] if targets is None else targets, **extra}})


class ApdexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tj-apdex-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "input"

    def test_formula_and_exact_T_4T_boundaries_in_integer_microseconds(self):
        times = [0, 999_999, 1_000_000, 1_000_001, 3_999_999, 4_000_000, 4_000_001]
        b = saved_series(self.input, [spec(M1, 0, duration_us=d) for d in times])
        r = apdex(b, config())[0]
        self.assertEqual((r["satisfied_count"], r["tolerating_count"], r["frustrated_count"]), (3, 3, 1))
        self.assertEqual(r["count"], r["apdex_denominator"])
        self.assertEqual(r["apdex_numerator_twice"], 9)
        self.assertEqual(r["apdex"], 4.5 / 7)
        self.assertEqual([r["category"] for r in apdex_calls(b, config())], ["satisfied"] * 3 + ["tolerating"] * 3 + ["frustrated"])
        self.assertEqual(latency_category(1, 1), "satisfied")
        self.assertEqual(latency_category(4, 1), "tolerating")
        self.assertEqual(latency_category(5, 1), "frustrated")

    def test_missing_T_is_uncovered_not_zero_or_guessed_score(self):
        b = saved_series(self.input, [spec(M1, 1), spec(M2, 10)])
        cfg = config([])
        for r in apdex(b, cfg):
            self.assertIsNone(r["apdex"])
            self.assertIsNone(r["t_seconds"])
            self.assertIsNone(r["satisfied_count"])
            self.assertEqual(r["apdex_denominator"], 0)
        self.assertEqual(len(apdex_uncovered(b, cfg)), 2)
        self.assertEqual(apdex_calls(b, cfg), [])
        self.assertEqual(apdex_composition(b, cfg), [])
        self.assertTrue(all(r["apdex"] is None for r in apdex_overall(b, cfg)))
        cov = apdex_coverage(b, cfg)[-1]
        self.assertEqual((cov["covered_call_count"], cov["uncovered_call_count"]), (0, 2))
        self.assertEqual(cov["covered_call_percent"], 0)
        self.assertEqual(cov["uncovered_operation_count"], 1)
        row = next(r for r in apdex_changes(b, cfg) if r["current_measurement_id"] == M2 and r["comparison_basis"] == "previous_observation")
        self.assertEqual(row["comparison_state"], "missing_target")
        self.assertIsNone(row["apdex_delta_absolute"])

    def test_class_is_explicit_and_operation_override_preserves_source_status(self):
        b = saved_series(self.input, [spec(M1, 2, signature="A"), spec(M1, 2, signature="B"), spec(M1, 2, signature="B2")])
        cls = {"class_id": "example_class", "signatures": ["A", "B"], "t_seconds": 3, "status": "engineering_proposal", "source": "Test class proposal"}
        cfg = config([target("A", 1, "business_approved", "Test approval reference")], classes=[cls])
        rows = {r["signature"]: r for r in apdex(b, cfg)}
        self.assertEqual(rows["A"]["apdex"], .5)
        self.assertEqual(rows["A"]["target_kind"], "operation")
        self.assertEqual(rows["A"]["overridden_class_id"], "example_class")
        self.assertEqual(rows["A"]["target_status"], "business_approved")
        self.assertEqual(rows["A"]["target_source"], "Test approval reference")
        self.assertEqual(rows["B"]["apdex"], 1)
        self.assertEqual(rows["B"]["target_kind"], "explicit_class")
        self.assertEqual(rows["B"]["target_class_id"], "example_class")
        self.assertIsNone(rows["B2"]["apdex"])

    def test_business_and_proposed_overall_scores_never_blended(self):
        b = saved_series(self.input, [spec(M1, 1, signature="A"), spec(M1, 5, signature="B"), spec(M1, 1, signature="C")])
        cfg = config([target("A", status="business_approved"), target("B")])
        rows = [r for r in apdex_overall(b, cfg) if r["measurement_id"] == M1]
        self.assertEqual({r["target_status"]: r["apdex"] for r in rows}, {"business_approved": 1, "engineering_proposal": 0})
        for row in rows:
            self.assertEqual(row["total_calls_in_scope"], 3)
            self.assertEqual(row["calls_without_target"], 1)
            self.assertEqual(row["calls_with_other_target_status"], 1)
            self.assertEqual(row["apdex_denominator"], 1)

    def test_group_mix_changes_overall_without_any_per_operation_improvement(self):
        b = saved_series(self.input, [spec(M1, 1, signature="A")] + [spec(M1, 5, signature="B")] * 9 +
            [spec(M2, 1, signature="A")] * 9 + [spec(M2, 5, signature="B")])
        cfg = config([target("A"), target("B")])
        overall = {r["measurement_id"]: r for r in apdex_overall(b, cfg) if r["target_status"] == "engineering_proposal"}
        self.assertEqual(overall[M1]["apdex"], .1)
        self.assertEqual(overall[M2]["apdex"], .9)
        self.assertEqual(overall[None]["apdex"], .5)
        for row in apdex_changes(b, cfg):
            if row["current_measurement_id"] == M2 and row["comparison_basis"] == "previous_observation":
                self.assertEqual(row["apdex_delta_absolute"], 0)
        composition = apdex_composition(b, cfg)
        for mid in (M1, M2, None):
            members = [r for r in composition if r["overall_id"] == overall[mid]["overall_id"]]
            self.assertEqual(sum(r["call_count"] for r in members), overall[mid]["count"])
            self.assertAlmostEqual(sum(r["call_weight_percent"] for r in members), 100)
            self.assertAlmostEqual(sum(r["contribution_to_overall_apdex"] for r in members), overall[mid]["apdex"])
        first_a = next(r for r in composition if r["overall_id"] == overall[M1]["overall_id"] and r["signature"] == "A")
        second_a = next(r for r in composition if r["overall_id"] == overall[M2]["overall_id"] and r["signature"] == "A")
        self.assertEqual((first_a["call_weight_percent"], second_a["call_weight_percent"]), (10, 90))

    def test_EXCP_error_counter_is_not_a_business_failure_or_success_flag(self):
        call = {"call_id": 1, "duration_us": 100, "error_count": 12}
        row = score([call], 1_000_000, {})
        self.assertEqual(row["apdex"], 1)
        self.assertEqual(row["calls_with_linked_error_events"], 1)
        self.assertEqual(row["confirmed_failure_count"], 0)
        self.assertEqual(row["business_outcome_unknown_count"], 1)

    def test_confirmed_failure_policy_forces_fast_failures_once_and_keeps_denominator(self):
        b = saved_series(self.input, [spec(M1, 1), spec(M1, 5), spec(M1, 2)])
        failed = {"bundle_id": b.bundle_id, "calls": [{"call_id": c["call_id"], "evidence": "Synthetic confirmed failure"} for c in b.calls[:2]]}
        cfg = config(failure_policy="confirmed_failures_frustrated", confirmed_failures=failed)
        row = apdex(b, cfg)[0]
        self.assertEqual((row["satisfied_count"], row["tolerating_count"], row["frustrated_count"]), (0, 1, 2))
        self.assertEqual(row["apdex_denominator"], 3)
        self.assertEqual(row["apdex"], .5 / 3)
        self.assertEqual(row["forced_frustrated_count"], 1)
        self.assertEqual(row["latency_frustrated_count"], 1)
        self.assertEqual(row["confirmed_failure_count"], 2)
        self.assertEqual(row["business_outcome_unknown_count"], 1)
        call = apdex_calls(b, cfg)[0]
        self.assertEqual(call["category"], "frustrated")
        self.assertEqual(call["latency_category"], "satisfied")
        self.assertEqual(call["business_outcome"], "confirmed_failure")
        self.assertEqual(call["failure_evidence"], "Synthetic confirmed failure")

    def test_confirmed_failure_without_T_is_still_unscored(self):
        b = saved_series(self.input, [spec(M1, 1)])
        cfg = config([], failure_policy="confirmed_failures_frustrated", confirmed_failures={"bundle_id": b.bundle_id, "calls": [{"call_id": 1, "evidence": "Test"}]})
        r = apdex(b, cfg)[0]
        self.assertIsNone(r["apdex"])
        self.assertIsNone(r["frustrated_count"])
        self.assertEqual(apdex_coverage(b, cfg)[-1]["uncovered_confirmed_failure_count"], 1)

    def test_invalid_T_status_source_class_membership_and_duplicates_rejected(self):
        invalid = [dict(target(), t_seconds=v) for v in (None, 0, -1, True, .0000001, float("inf"))]
        invalid += [dict(target(), source=""), dict(target(), status="SLA"), dict(target(), signature=" "), dict(target(), guessed=True)]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(SliceError):
                config([value])
        with self.assertRaises(SliceError):
            config([target(), target()])
        cls = {"class_id": "one", "signatures": ["Operation"], "t_seconds": 1, "status": "engineering_proposal", "source": "Test"}
        for classes in ([cls, dict(cls, class_id="two")], [dict(cls, signatures=[])], [dict(cls, signatures=["Operation", "Operation"])], [dict(cls, pattern="*")]):
            with self.subTest(classes=classes), self.assertRaises(SliceError):
                config([], classes=classes)

    def test_target_typo_is_rejected_not_silently_ignored(self):
        b = saved_series(self.input, [spec(M1, 1)])
        with self.assertRaisesRegex(SliceError, "unobserved signatures"):
            apdex(b, config([target("Operation2")]))

    def test_failure_evidence_is_pinned_to_bundle_and_valid_CALL(self):
        b = saved_series(self.input, [spec(M1, 1)])
        entry = {"call_id": 1, "evidence": "Test"}
        for evidence in ({"bundle_id": None, "calls": [entry]}, {"bundle_id": b.bundle_id, "calls": [entry, entry]},
                         {"bundle_id": b.bundle_id, "calls": [{"call_id": 1, "evidence": ""}]}):
            with self.subTest(evidence=evidence), self.assertRaises(SliceError):
                config(failure_policy="confirmed_failures_frustrated", confirmed_failures=evidence)
        with self.assertRaises(SliceError):
            config(failure_policy="latency_only", confirmed_failures={"bundle_id": b.bundle_id, "calls": [entry]})
        for pin, cid in (("0" * 64, 1), (b.bundle_id, 99)):
            cfg = config(failure_policy="confirmed_failures_frustrated", confirmed_failures={"bundle_id": pin, "calls": [{"call_id": cid, "evidence": "Test"}]})
            with self.assertRaises(SliceError):
                apdex(b, cfg)

    def test_small_sample_and_empty_population_not_apdex_zero(self):
        b = saved_series(self.input, [spec(M1, 1), spec(M2, 1, signature="Other")])
        rows = apdex(b, config())
        r = next(r for r in rows if r["signature"] == "Operation" and r["measurement_id"] == M1)
        self.assertTrue(r["small_sample_warning"])
        self.assertEqual(r["sample_size_status"], "below_configured_minimum")
        absent = next(r for r in rows if r["signature"] == "Operation" and r["measurement_id"] == M2)
        self.assertEqual(absent["observation_label"], "не наблюдалась")
        self.assertIsNone(absent["apdex"])
        self.assertFalse(absent["small_sample_warning"])
        fixture(self.input, empty=True)
        empty = load_bundle(self.input)
        self.assertEqual(apdex(empty, config([])), [])
        self.assertIsNone(apdex_coverage(empty, config([]))[0]["covered_call_percent"])

    def test_comparable_dynamics_gap_selection_and_zero_base(self):
        b = saved_series(self.input, [spec(M1, 5), spec(M2, 1, signature="Other"), spec(M3, 2), spec(M4, 1)])
        cfg = dict(config(), measurement_ids=[M4])
        rows = [r for r in apdex_changes(b, cfg) if r["signature"] == "Operation"]
        first = next(r for r in rows if r["comparison_basis"] == "first_observation")
        prev = next(r for r in rows if r["comparison_basis"] == "previous_observation")
        self.assertEqual(first["reference_measurement_id"], M1)
        self.assertEqual(first["apdex_delta_absolute"], 1)
        self.assertIsNone(first["apdex_delta_percent"])
        self.assertIn("apdex", first["percent_undefined_zero_reference_metrics"])
        self.assertEqual(prev["reference_measurement_id"], M3)
        self.assertEqual(prev["apdex_delta_absolute"], .5)
        self.assertEqual(prev["apdex_delta_percent"], 100)
        self.assertEqual((prev["reference_count"], prev["current_count"]), (1, 1))
        gap = next(r for r in apdex_changes(b, config()) if r["signature"] == "Operation" and r["current_measurement_id"] == M3 and r["comparison_basis"] == "previous_observation")
        self.assertEqual(gap["reference_measurement_id"], M1)

    def test_different_and_unknown_users_are_not_controlled_comparisons(self):
        b = saved_series(self.input, [spec(M1, 5), spec(M2, 1, "Bob"), spec(M1, 5, "(not specified)"), spec(M2, 1, "(not specified)")])
        rows = apdex_changes(b, config())
        bob = next(r for r in rows if r["user"] == "Bob" and r["current_measurement_id"] == M2 and r["comparison_basis"] == "previous_observation")
        self.assertIsNone(bob["reference_measurement_id"])
        unknown = next(r for r in rows if r["user"] == "(not specified)" and r["current_measurement_id"] == M2 and r["comparison_basis"] == "previous_observation")
        self.assertEqual(unknown["comparison_state"], "user_identity_unknown")
        self.assertIsNone(unknown["apdex_delta_absolute"])

    def test_coverage_deduplicates_operations_across_users_and_measurements(self):
        b = saved_series(self.input, [spec(M1, 1), spec(M1, 2, "Bob"), spec(M2, 1), spec(M2, 2, signature="Other")])
        r = apdex_coverage(b, config())[-1]
        self.assertEqual((r["covered_call_count"], r["call_share_denominator"]), (3, 4))
        self.assertEqual((r["covered_operation_count"], r["operation_share_denominator"]), (1, 2))
        self.assertEqual(r["covered_call_percent"], 75)
        self.assertEqual(r["covered_operation_percent"], 50)

    def test_ambiguous_chronology_and_partial_source_warning_survive(self):
        b = saved_series(self.input, [spec(M1, 1), spec(M2, 2)])
        b.calls[1]["start_timestamp"] = b.calls[0]["start_timestamp"]
        b.calls[1]["end_timestamp"] = b.calls[0]["end_timestamp"]
        r = next(r for r in apdex_changes(b, config()) if r["current_measurement_id"] == M2 and r["comparison_basis"] == "previous_observation")
        self.assertEqual(r["comparison_state"], "series_chronology_unresolved")
        self.assertIsNone(r["apdex_delta_absolute"])
        fixture(self.input, partial=True)
        partial = load_bundle(self.input)
        sig = partial.calls[0]["signature"]
        row = apdex(partial, config([target(sig)]))[0]
        self.assertIn("source_analysis_incomplete", row["known_limitations"])
        self.assertGreater(row["calls_from_partial_sources"], 0)

    def test_config_roundtrip_and_custom_sample_minimum(self):
        cfg = config(min_call_count=2)
        self.assertEqual(normalize_config(cfg), cfg)
        b = saved_series(self.input, [spec(M1, 1), spec(M1, 2)])
        self.assertFalse(apdex(b, cfg)[0]["small_sample_warning"])
        for bad in (0, True, "10"):
            with self.assertRaises(SliceError):
                config(min_call_count=bad)
        with self.assertRaises(SliceError):
            config(failure_policy="all_EXCP_are_failures")

    def test_overall_always_exports_composition_even_with_cli_selection_override(self):
        saved_series(self.input, [spec(M1, 1)])
        cfg = config()
        path = self.root / "config.json"
        path.write_text(json.dumps(cfg), encoding="utf-8")
        out = self.root / "out"
        result = run(["--analysis-dir", str(self.input), "--config", str(path), "--output-dir", str(out), "--slices", "apdex_overall"])
        self.assertEqual(result["selected_slices"], ["apdex_composition", "apdex_overall"])
        self.assertEqual(verify(self.input, out)["status"], "PASS")
        self.assertTrue((out / "apdex_composition.csv").is_file())

    def test_row_order_reproduction_and_input_preservation(self):
        b = saved_series(self.input, [spec(M1, 1), spec(M2, 2), spec(M2, 1, signature="Other")])
        cfg = config()
        expected = [builder(b, cfg) for builder in BUILDERS]
        b.calls.reverse()
        self.assertEqual(expected, [builder(b, cfg) for builder in BUILDERS])
        before = hashes(self.input)
        path = self.root / "config.json"
        path.write_text(json.dumps(cfg), encoding="utf-8")
        outputs = [self.root / "out1", self.root / "out2"]
        for out in outputs:
            run(["--analysis-dir", str(self.input), "--config", str(path), "--output-dir", str(out)])
            self.assertEqual(verify(self.input, out)["status"], "PASS")
        self.assertEqual(hashes(outputs[0]), hashes(outputs[1]))
        self.assertEqual(hashes(self.input), before)
        with self.assertRaises(SliceError):
            run(["--analysis-dir", str(self.input), "--config", str(path), "--output-dir", str(outputs[0])])

    def test_no_original_path_or_network_access(self):
        saved_series(self.input, [spec(M1, 1), spec(M2, 5, signature="Other")])
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
                self.assertTrue(builder(b, config()))


if __name__ == "__main__":
    unittest.main()
