"""Separate mean flags, actual CALL hits, denominators, duration and provenance."""
from __future__ import annotations

import csv
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
from slice_db_chatty import (db_chatty, db_chatty_calls, db_chatty_fast_calls, db_chatty_duration,
                            db_chatty_coverage, db_chatty_changes, profile)
from verify_slices import verify
from slice_input import load_bundle
from test_derive_slices import hashes, fixture
from test_slice_operations import saved_series, spec, M1, M2, M3, M4

BUILDERS = (db_chatty, db_chatty_calls, db_chatty_duration, db_chatty_coverage, db_chatty_changes, db_chatty_fast_calls)


class DbChattyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tj-chatty-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "input"
        self.config = normalize_config({"config_version": "1.0", "slices": [b.__name__ for b in BUILDERS]})

    def group(self, bundle, mid=M1, threshold=100, user="Alice", signature="Operation"):
        return next(r for r in db_chatty(bundle, self.config) if r["measurement_id"] == mid and
                    r["threshold_db_events"] == threshold and r["user"] == user and r["signature"] == signature)

    def test_group_mean_hides_one_extreme_call(self):
        b = saved_series(self.input, [spec(M1, .5, db_count=0)] * 50 + [spec(M1, .5, db_count=5000)])
        g = self.group(b)
        self.assertEqual(g["count"], 51)
        self.assertEqual(g["db_per_call_avg"], 5000 / 51)
        self.assertFalse(g["group_mean_above_threshold"])
        self.assertEqual(g["calls_above_threshold_count"], 1)
        self.assertEqual(g["call_share_denominator"], 51)
        self.assertEqual(g["calls_above_threshold_percent"], 100 / 51)
        self.assertEqual(g["db_per_call_median"], 0)
        self.assertEqual(g["db_per_call_p95"], 0)
        self.assertEqual(g["db_per_call_max"], 5000)
        self.assertEqual(g["fast_calls_above_threshold_count"], 1)
        self.assertEqual(len(db_chatty_calls(b, self.config)), 1)

    def test_high_group_mean_does_not_mark_every_call_as_chatty(self):
        b = saved_series(self.input, [spec(M1, .2, db_count=0)] * 9 + [spec(M1, 30, db_count=2000)])
        g = self.group(b)
        self.assertTrue(g["group_mean_above_threshold"])
        self.assertEqual(g["calls_in_mean_flagged_group_count"], 10)
        self.assertEqual(g["calls_above_threshold_count"], 1)
        self.assertEqual(g["calls_above_threshold_percent"], 10)
        self.assertEqual(g["db_per_call_median"], 0)
        c = next(r for r in db_chatty_coverage(b, self.config) if r["measurement_id"] == M1 and r["threshold_db_events"] == 100)
        self.assertEqual(c["calls_in_mean_flagged_groups_count"], 10)
        self.assertEqual(c["chatty_call_count"], 1)
        self.assertEqual(c["calls_in_mean_flagged_groups_percent"], 100)
        self.assertEqual(c["chatty_call_percent"], 10)

    def test_exact_threshold_is_not_an_exceedance_for_mean_or_call(self):
        b = saved_series(self.input, [spec(M1, 1, db_count=0), spec(M1, 1, db_count=100), spec(M1, 1, db_count=200)])
        g = self.group(b)
        self.assertEqual(g["db_per_call_avg"], 100)
        self.assertFalse(g["group_mean_above_threshold"])
        self.assertEqual(g["calls_above_threshold_count"], 1)
        self.assertEqual(len(db_chatty_calls(b, self.config)), 1)

    def test_one_call_one_row_even_when_multiple_thresholds_crossed(self):
        b = saved_series(self.input, [spec(M1, 1, db_count=5001)])
        rows = db_chatty_calls(b, self.config)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["thresholds_exceeded"], [100, 500, 1000, 5000])
        self.assertEqual(rows[0]["call_id"], b.calls[0]["call_id"])
        self.assertTrue(rows[0]["is_fast_call"])
        for field in ("db_per_call_avg", "db_per_call_median", "db_per_call_p95", "db_per_call_max"):
            self.assertEqual(self.group(b)[field], 5001)

    def test_duration_partition_and_fast_boundary_with_two_denominators(self):
        b = saved_series(self.input, [spec(M1, d, duration_us=round(d * 1_000_000), db_count=count, db_duration_us=20) for d, count in
            [(0, 101), (1, 100), (1.000001, 501), (5, 501), (10, 0), (30, 1001), (31, 5001)]])
        rows = [r for r in db_chatty_duration(b, self.config) if r["threshold_db_events"] == 100]
        self.assertEqual([r["band_call_count"] for r in rows], [2, 2, 1, 1, 1])
        self.assertEqual([r["band_calls_above_threshold_count"] for r in rows], [1, 2, 0, 1, 1])
        self.assertEqual(sum(r["band_call_count"] for r in rows), 7)
        self.assertEqual(sum(r["band_calls_above_threshold_count"] for r in rows), 5)
        self.assertEqual(rows[0]["within_band_above_threshold_percent"], 50)
        self.assertEqual(rows[0]["share_of_group_chatty_calls_percent"], 20)
        self.assertEqual(rows[0]["within_band_call_denominator"], 2)
        self.assertEqual(rows[0]["group_chatty_call_denominator"], 5)
        g = self.group(b)
        self.assertEqual(g["fast_call_count"], 2)
        self.assertEqual(g["fast_calls_above_threshold_count"], 1)
        self.assertEqual(g["fast_calls_above_threshold_percent"], 50)
        self.assertEqual(g["linked_db_duration_us_sum"], 140)
        self.assertEqual(g["chatty_linked_db_duration_us_sum"], 100)
        self.assertEqual(sum(r["chatty_linked_db_duration_us_sum"] for r in rows), 100)

    def test_empty_bins_and_absent_operations_are_not_zero_time_observations(self):
        b = saved_series(self.input, [spec(M1, 2, db_count=0), spec(M2, 3, signature="Other", db_count=101)])
        absent = self.group(b, mid=M2)
        self.assertEqual(absent["observation_label"], "не наблюдалась")
        for k in ("group_mean_above_threshold", "db_per_call_avg", "calls_above_threshold_percent", "call_duration_us_sum"):
            self.assertIsNone(absent[k])
        rows = [r for r in db_chatty_duration(b, self.config) if r["measurement_id"] == M1 and r["threshold_db_events"] == 100]
        self.assertIsNone(rows[0]["within_band_above_threshold_percent"])
        self.assertIsNone(rows[1]["share_of_group_chatty_calls_percent"])
        self.assertEqual(rows[1]["within_band_above_threshold_percent"], 0)
        self.assertTrue(all(r["signature"] != "Operation" for r in db_chatty_duration(b, self.config) if r["measurement_id"] == M2))

    def test_coverage_unique_units_not_summed_and_unknown_users_not_invented(self):
        b = saved_series(self.input, [spec(M1, 1, db_count=101), spec(M1, 1, "Bob", db_count=0),
            spec(M2, 1, db_count=201), spec(M2, 1, "Bob", "Other", db_count=101),
            spec(M2, 1, "(not specified)", "Other", db_count=101)])
        row = next(r for r in db_chatty_coverage(b, self.config) if r["population_scope"] == "selected_measurements_all_users" and r["threshold_db_events"] == 100)
        self.assertEqual((row["chatty_call_count"], row["call_share_denominator"]), (4, 5))
        self.assertEqual((row["affected_operation_count"], row["operation_share_denominator"]), (2, 2))
        self.assertEqual((row["affected_known_user_count"], row["known_user_share_denominator"]), (2, 2))
        self.assertEqual(row["chatty_calls_with_unknown_user_count"], 1)
        self.assertEqual(row["observed_operation_user_measurement_group_count"], 5)

    def test_first_previous_references_skip_gaps_and_do_not_change_under_filter(self):
        b = saved_series(self.input, [spec(M1, 1, db_count=1000), spec(M2, 1, signature="Other"),
                                      spec(M3, 1, db_count=500), spec(M4, 1, db_count=250)])
        cfg = dict(self.config, measurement_ids=[M4])
        rows = [r for r in db_chatty_changes(b, cfg) if r["signature"] == "Operation" and r["threshold_db_events"] == 100]
        self.assertEqual([r["reference_measurement_id"] for r in rows], [M1, M3])
        self.assertEqual([r["db_per_call_avg_delta_percent"] for r in rows], [-75, -50])
        gap = next(r for r in db_chatty_changes(b, self.config) if r["current_measurement_id"] == M3 and r["comparison_basis"] == "previous_observation" and r["signature"] == "Operation" and r["threshold_db_events"] == 100)
        self.assertEqual(gap["reference_measurement_id"], M1)
        self.assertEqual(gap["reference_count"], 1)
        self.assertEqual(gap["current_count"], 1)
        scope = next(r for r in db_chatty_coverage(b, cfg) if r["population_scope"] == "selected_measurements_all_users")
        self.assertEqual(scope["total_call_count"], 1)

    def test_different_user_is_not_a_previous_reference(self):
        b = saved_series(self.input, [spec(M1, 1, db_count=1000), spec(M2, 1, "Bob", db_count=200)])
        row = next(r for r in db_chatty_changes(b, self.config) if r["user"] == "Bob" and r["current_measurement_id"] == M2 and r["comparison_basis"] == "previous_observation")
        self.assertIsNone(row["reference_measurement_id"])
        self.assertIsNone(row["db_per_call_avg_delta_percent"])
        self.assertEqual(row["comparison_state"], "no_previous_observation")

    def test_zero_reference_and_no_fast_denominator_remain_undefined(self):
        b = saved_series(self.input, [spec(M1, 2, db_count=0, db_duration_us=0), spec(M2, 2, db_count=101)])
        row = next(r for r in db_chatty_changes(b, self.config) if r["current_measurement_id"] == M2 and r["comparison_basis"] == "previous_observation" and r["threshold_db_events"] == 100)
        self.assertEqual(row["db_per_call_avg_delta_absolute"], 101)
        self.assertIsNone(row["db_per_call_avg_delta_percent"])
        self.assertIn("db_per_call_avg", row["percent_undefined_zero_reference_metrics"])
        self.assertEqual(row["calls_above_threshold_percent_delta_absolute"], 100)
        self.assertIsNone(row["fast_calls_above_threshold_percent_current"])
        self.assertIn("zero_linked_db_does_not_prove_no_database_access", row["known_limitations"])

    def test_invalid_thresholds_bounds_unknown_keys_and_precision_rejected(self):
        for settings in ({"thresholds": []}, {"thresholds": [100, 100]}, {"thresholds": [True]}, {"thresholds": [-1]},
            {"thresholds": [1.5]}, {"duration_bounds_seconds": []}, {"duration_bounds_seconds": [0]},
            {"duration_bounds_seconds": [1, 1]}, {"duration_bounds_seconds": [0.0000001]},
            {"duration_bounds_seconds": [float("inf")]}, {"fast_call_max_seconds": -1},
            {"fast_call_max_seconds": True}, {"fast_call_max_seconds": 10**1000}, {"infer_n_plus_1": True}):
            with self.subTest(settings=settings), self.assertRaises(SliceError):
                normalize_config({"config_version": "1.0", "db_chatty": settings})
        cfg = normalize_config({"config_version": "1.0", "db_chatty": {"thresholds": [500, 100], "duration_bounds_seconds": [5, .5], "fast_call_max_seconds": .25}})
        self.assertEqual(cfg["db_chatty"]["thresholds"], [100, 500])
        self.assertEqual(cfg["db_chatty"]["duration_bounds_seconds"], [.5, 5])
        self.assertEqual(cfg, normalize_config(cfg))

    def test_custom_threshold_duration_and_fast_settings_are_used(self):
        b = saved_series(self.input, [spec(M1, .25, db_count=11), spec(M1, .5, db_count=20), spec(M1, 2, db_count=21)])
        cfg = normalize_config({"config_version": "1.0", "db_chatty": {"thresholds": [20, 10], "duration_bounds_seconds": [.5], "fast_call_max_seconds": .25}})
        rows = db_chatty(b, cfg)
        self.assertEqual([r["threshold_db_events"] for r in rows], [10, 20])
        self.assertEqual([r["calls_above_threshold_count"] for r in rows], [3, 1])
        self.assertEqual([r["fast_calls_above_threshold_count"] for r in rows], [1, 0])
        bins = [r for r in db_chatty_duration(b, cfg) if r["threshold_db_events"] == 10]
        self.assertEqual([r["band_call_count"] for r in bins], [2, 1])

    def test_p95_is_from_calls_not_group_averages(self):
        calls = [{"db_count": n, "duration_us": n, "db_duration_us": 1} for n in range(1, 101)]
        row = profile(calls, 90, 100)
        self.assertEqual(row["db_per_call_median"], 50.5)
        self.assertEqual(row["db_per_call_p95"], 95)
        self.assertEqual(row["db_per_call_max"], 100)
        self.assertEqual(row["calls_above_threshold_count"], 10)
        self.assertEqual(row["chatty_call_duration_us_median"], 95.5)

    def test_empty_saved_bundle_has_no_invented_operations_or_users(self):
        fixture(self.input, empty=True)
        b = load_bundle(self.input)
        for builder in (db_chatty, db_chatty_calls, db_chatty_fast_calls, db_chatty_duration, db_chatty_changes):
            self.assertEqual(builder(b, self.config), [])
        coverage = db_chatty_coverage(b, self.config)
        self.assertEqual(len(coverage), 4)
        for r in coverage:
            self.assertEqual(r["total_call_count"], 0)
            self.assertEqual(r["observed_operation_count"], 0)
            self.assertEqual(r["observed_known_user_count"], 0)
            self.assertIsNone(r["chatty_call_percent"])

    def test_ambiguous_order_blocks_references_and_partial_quality_is_preserved(self):
        b = saved_series(self.input, [spec(M1, 1, db_count=101), spec(M2, 1, db_count=201)])
        b.calls[1]["start_timestamp"] = b.calls[0]["start_timestamp"]
        b.calls[1]["end_timestamp"] = b.calls[0]["end_timestamp"]
        row = next(r for r in db_chatty_changes(b, self.config) if r["current_measurement_id"] == M2)
        self.assertEqual(row["comparison_state"], "series_chronology_unresolved")
        self.assertIsNone(row["reference_measurement_id"])
        self.assertIsNone(row["db_per_call_avg_delta_absolute"])
        self.assertIn("measurement_order", row["unknown_parameters"])
        fixture(self.input, partial=True)
        partial = db_chatty(load_bundle(self.input), self.config)[0]
        self.assertGreater(partial["calls_from_partial_sources"], 0)
        self.assertIn("source_analysis_incomplete", partial["known_limitations"])

    def test_builders_never_open_original_paths_or_network(self):
        b = saved_series(self.input, [spec(M1, 1, db_count=5001)])
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
                self.assertTrue(builder(b, self.config))

    def test_row_order_independent_and_exact_signatures_not_merged(self):
        b = saved_series(self.input, [spec(M1, 1, signature="A", db_count=101), spec(M2, 1, signature="A2", db_count=101)])
        before = [builder(b, self.config) for builder in BUILDERS]
        b.calls.reverse()
        self.assertEqual(before, [builder(b, self.config) for builder in BUILDERS])
        self.assertEqual(len({r["operation_id"] for r in before[0]}), 2)

    def test_fast_call_table_is_exact_overlapping_subset_not_extra_observations(self):
        b = saved_series(self.input, [spec(M1, .2, db_count=101), spec(M1, 1, db_count=5001),
                                      spec(M1, 1.1, db_count=101), spec(M1, .1, db_count=100)])
        individual = db_chatty_calls(b, self.config)
        fast = db_chatty_fast_calls(b, self.config)
        self.assertEqual(fast, [r for r in individual if r["is_fast_call"]])
        self.assertEqual(len(fast), 2)
        self.assertEqual(len(individual), 3)
        self.assertEqual(self.group(b)["count"], 4)

    def test_cli_reproduction_validation_no_overwrite_and_unchanged_inputs(self):
        saved_series(self.input, [spec(M1, 1, db_count=101), spec(M2, 3, db_count=5001)])
        path = self.root / "config.json"
        path.write_text(json.dumps(self.config), encoding="utf-8")
        before = hashes(self.input)
        results = [self.root / "out1", self.root / "out2"]
        for output in results:
            run(["--analysis-dir", str(self.input), "--config", str(path), "--output-dir", str(output)])
            self.assertEqual(verify(self.input, output)["status"], "PASS")
        self.assertEqual(hashes(results[0]), hashes(results[1]))
        with self.assertRaises(SliceError):
            run(["--analysis-dir", str(self.input), "--config", str(path), "--output-dir", str(results[0])])
        self.assertEqual(before, hashes(self.input))
        with (results[0] / "db_chatty_calls.csv").open(encoding="utf-8-sig", newline="") as f:
            calls = list(csv.DictReader(f))
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
