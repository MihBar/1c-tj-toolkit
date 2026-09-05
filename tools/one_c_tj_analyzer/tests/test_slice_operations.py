"""CALL-derived histories: gaps, users, zero bases and exact populations."""
from __future__ import annotations

import csv
import datetime as dt
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
from slice_operations import (BASES, METRIC_FIELDS, OperationSeries, comparability,
    measurement_comparisons, operation_history, operation_history_all_users, operation_metrics)
from verify_slices import verify
from test_derive_slices import fixture, persist, hashes

M1, M2, M3, M4 = (f"series@2026-08-{d:02d}" for d in (4, 11, 19, 31))


def saved_series(path, specs, order=None):
    """Adapt independent schema fixture while retaining valid mirror/checks."""
    tags = {}
    encoded = []
    for spec in specs:
        identity = (spec.get("signature", "Operation"), spec.get("user", "Alice"), spec.get("dataset_tag", ""))
        tag = tags.setdefault(identity, str(len(tags)))
        encoded.append((tag, spec["measurement_id"], spec["duration_us"]))
    m, calls = fixture(path, encoded)
    order = order or list(dict.fromkeys(spec["measurement_id"] for spec in specs))
    for call, spec in zip(calls, specs):
        end = dt.datetime(2026, 8, 4, 12) + dt.timedelta(days=order.index(spec["measurement_id"]), seconds=call["call_id"])
        call.update(user=spec.get("user", "Alice"), signature=spec.get("signature", "Operation"),
                    start_timestamp=(end - dt.timedelta(microseconds=call["duration_us"])).isoformat(sep=" "), end_timestamp=end.isoformat(sep=" "))
        for k in ("cpu_us", "in_bytes", "out_bytes", "memory_peak", "db_count", "db_duration_us"):
            if k in spec:
                call[k] = spec[k]
    for op in m["operations"]:
        members = [c for c in calls if c["dataset_id"] == op["dataset_id"] and c["measurement_id"] == op["measurement_id"]]
        op.update(user=members[0]["user"], signature=members[0]["signature"], first_timestamp=min(c["end_timestamp"] for c in members), last_timestamp=max(c["end_timestamp"] for c in members))
        for k in ("cpu_us", "in_bytes", "out_bytes", "db_count", "db_duration_us"):
            op[k] = sum(c[k] for c in members)
    for link in m["linkage"]:
        members = [c for c in calls if c["dataset_id"] == link["dataset_id"] and c["measurement_id"] == link["measurement_id"]]
        linked = sum(c["db_count"] for c in members)
        db_time = sum(c["db_duration_us"] for c in members)
        link.update(dbpostgrs_linked_count=linked, dbpostgrs_total_count=linked + 1,
                    dbpostgrs_linked_duration_us=db_time, dbpostgrs_total_duration_us=db_time + 50_000,
                    dbpostgrs_linked_count_percent=round(100 * linked / (linked + 1), 6),
                    dbpostgrs_linked_duration_percent=round(100 * db_time / (db_time + 50_000), 6))
    for ds in m["datasets"]:
        members = [c for c in calls if c["dataset_id"] == ds["dataset_id"]]
        links = [r for r in m["linkage"] if r["dataset_id"] == ds["dataset_id"]]
        ds.update(users=sorted({c["user"] for c in members}), first_timestamp=min(c["end_timestamp"] for c in members), last_timestamp=max(c["end_timestamp"] for c in members))
        ds["event_stats"]["DBPOSTGRS"] = {"count": sum(r["dbpostgrs_total_count"] for r in links), "duration_us": sum(r["dbpostgrs_total_duration_us"] for r in links)}
    persist(path, m, calls)
    return load_bundle(path)


def spec(mid, seconds, user="Alice", signature="Operation", **extra):
    return {"measurement_id": mid, "duration_us": int(seconds * 1_000_000), "user": user, "signature": signature, **extra}


class OperationSliceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "input"
        self.config = normalize_config({"config_version": "1.0", "slices": ["operation_history", "operation_history_all_users", "measurement_comparisons", "comparability"]})

    def comparison(self, bundle, mid, basis, user="Alice", signature="Operation", config=None):
        return next(r for r in measurement_comparisons(bundle, config or self.config) if r["current_measurement_id"] == mid and r["comparison_basis"] == basis and r["user"] == user and r["signature"] == signature)

    def test_gap_keeps_adjacent_and_previous_observation_separate(self):
        b = saved_series(self.input, [spec(M1, 10), spec(M2, 1, signature="Other"), spec(M3, 4)])
        history = operation_history(b, self.config)
        missing = next(r for r in history if r["signature"] == "Operation" and r["measurement_id"] == M2)
        self.assertEqual(missing["observation_label"], "не наблюдалась")
        self.assertEqual(missing["count"], 0)
        self.assertTrue(all(missing[k] is None for k in METRIC_FIELDS))
        prev_observed = self.comparison(b, M3, "previous_observation")
        adjacent = self.comparison(b, M3, "previous_measurement")
        self.assertEqual(prev_observed["reference_measurement_id"], M1)
        self.assertEqual(prev_observed["avg_us_delta_absolute"], -6_000_000)
        self.assertEqual(prev_observed["avg_us_delta_percent"], -60)
        self.assertEqual(adjacent["reference_measurement_id"], M2)
        self.assertEqual(adjacent["reference_count"], 0)
        self.assertIsNone(adjacent["avg_us_delta_absolute"])
        self.assertEqual(adjacent["comparison_state"], "reference_not_observed")
        self.assertEqual(adjacent["sample_count_delta_absolute"], 1)
        self.assertIsNone(adjacent["sample_count_delta_percent"])

    def test_four_bases_and_output_filter_do_not_rebase_series(self):
        b = saved_series(self.input, [spec(M1, 1, signature="Other"), spec(M2, 12), spec(M3, 9), spec(M4, 6)])
        cfg = dict(self.config, measurement_ids=[M4])
        expected = {"series_baseline": M1, "first_observation": M2, "previous_observation": M3, "previous_measurement": M3}
        for basis, reference in expected.items():
            row = self.comparison(b, M4, basis, config=cfg)
            self.assertEqual(row["reference_measurement_id"], reference)
            self.assertEqual(row["current_count"], 1)
        baseline = self.comparison(b, M4, "series_baseline", config=cfg)
        self.assertEqual(baseline["reference_count"], 0)
        self.assertIsNone(baseline["avg_us_delta_percent"])
        self.assertEqual(self.comparison(b, M4, "first_observation", config=cfg)["avg_us_delta_percent"], -50)

    def test_different_users_are_not_substituted(self):
        b = saved_series(self.input, [spec(M1, 10, "Alice"), spec(M2, 2, "Bob")])
        row = self.comparison(b, M2, "series_baseline", user="Bob")
        self.assertEqual(row["reference_count"], 0)
        self.assertEqual(row["current_count"], 1)
        self.assertIsNone(row["avg_us_delta_percent"])
        first = self.comparison(b, M2, "first_observation", user="Bob")
        self.assertEqual(first["reference_measurement_id"], M2)
        comparable = next(r for r in comparability(b, self.config) if r["comparison_id"] == row["comparison_id"])
        self.assertIn("reference_operation_observed_only_for_other_users", comparable["known_differences"])
        self.assertIsNone(comparable["user_match"])
        self.assertIn("role", comparable["unknown_parameters"])

    def test_zero_reference_is_null_not_infinity_including_zero_zero(self):
        b = saved_series(self.input, [spec(M1, 0, db_count=0, db_duration_us=0), spec(M2, 2, db_count=2, db_duration_us=100_000)])
        row = self.comparison(b, M2, "series_baseline")
        self.assertEqual(row["avg_us_delta_absolute"], 2_000_000)
        self.assertIsNone(row["avg_us_delta_percent"])
        self.assertIsNone(row["db_per_call_delta_percent"])
        self.assertIsNone(row["out_bytes_per_call_delta_percent"])
        self.assertIn("avg_us", row["percent_undefined_zero_reference_metrics"])
        self.assertIn("out_bytes_per_call", row["percent_undefined_zero_reference_metrics"])
        self.assertIsNone(row["cpu_percent_of_wall_reference"])

    def test_single_observation_percentiles_are_exact_but_flagged(self):
        b = saved_series(self.input, [spec(M1, 3), spec(M2, 2)])
        h = operation_history(b, self.config)[0]
        for metric in ("avg_us", "median_us", "p95_us", "p99_us", "max_us"):
            self.assertEqual(h[metric], 3_000_000)
        c = self.comparison(b, M2, "series_baseline")
        self.assertEqual(c["sample_size_status"], "below_configured_minimum")
        self.assertEqual(c["interpretation"], "numerical_change_only_not_proven_code_effect")

    def test_pooled_statistics_rebuilt_not_averaged_from_user_groups(self):
        b = saved_series(self.input, [spec(M1, 1, "Alice"), spec(M1, 2, "Alice"), spec(M1, 100, "Bob")])
        pooled = operation_history_all_users(b, self.config)[0]
        users = operation_history(b, self.config)
        self.assertEqual(pooled["count"], 3)
        self.assertEqual(pooled["median_us"], 2_000_000)
        self.assertEqual(pooled["p95_us"], 100_000_000)
        self.assertNotEqual(pooled["p95_us"], sum(r["p95_us"] for r in users) / 2)
        self.assertEqual(pooled["population_scope"], "all_users")
        self.assertIsNone(pooled["user"])
        self.assertEqual(sum(r["count"] for r in users), len(b.calls))

    def test_same_user_multiple_datasets_aggregated_from_calls(self):
        b = saved_series(self.input, [spec(M1, 1, dataset_tag="a"), spec(M1, 2, dataset_tag="a"), spec(M1, 100, dataset_tag="b")])
        rows = operation_history(b, self.config)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["count"], 3)
        self.assertEqual(rows[0]["median_us"], 2_000_000)
        self.assertEqual(rows[0]["p95_us"], 100_000_000)

    def test_thresholds_are_strictly_greater_not_legacy_greater_equal(self):
        b = saved_series(self.input, [spec(M1, t) for t in (1, 5, 10, 30, 31)])
        row = operation_history(b, self.config)[0]
        self.assertEqual([row[f"duration_gt_{s}s_count"] for s in (1, 5, 10, 30)], [4, 3, 2, 1])

    def test_resource_metrics_and_cpu_share_are_ratios_of_sums(self):
        b = saved_series(self.input, [spec(M1, 1, cpu_us=500_000, in_bytes=100, out_bytes=1000, memory_peak=200),
            spec(M1, 3, cpu_us=300_000, in_bytes=300, out_bytes=3000, memory_peak=600)])
        r = operation_history(b, self.config)[0]
        self.assertEqual(r["cpu_percent_of_wall"], 20)
        self.assertEqual(r["in_bytes_per_call"], 200)
        self.assertEqual(r["out_bytes_per_call"], 2000)
        self.assertEqual(r["memory_peak_median"], 400)
        self.assertEqual(r["memory_peak_p95"], 600)
        self.assertEqual(r["db_seconds_per_call"], .1)

    def test_similar_signatures_never_merged(self):
        b = saved_series(self.input, [spec(M1, 1, signature="Module.Operation"), spec(M2, 2, signature="Module.Operation2")])
        rows = operation_history(b, self.config)
        self.assertEqual(len({r["operation_id"] for r in rows}), 2)
        self.assertEqual(len(rows), 4)

    def test_single_measurement_has_no_previous_reference(self):
        b = saved_series(self.input, [spec(M1, 1)])
        self.assertEqual(self.comparison(b, M1, "previous_measurement")["comparison_state"], "no_previous_measurement")
        self.assertEqual(self.comparison(b, M1, "previous_observation")["comparison_state"], "no_previous_observation")
        self.assertIsNone(self.comparison(b, M1, "previous_measurement")["reference_count"])
        self.assertEqual(self.comparison(b, M1, "series_baseline")["avg_us_delta_absolute"], 0)

    def test_comparison_and_comparability_ids_are_one_to_one(self):
        b = saved_series(self.input, [spec(M1, 1), spec(M2, 2)])
        values = measurement_comparisons(b, self.config)
        quality = comparability(b, self.config)
        self.assertEqual(len(values), 8)
        self.assertEqual(len({r["comparison_id"] for r in values}), len(values))
        self.assertEqual([r["comparison_id"] for r in values], [r["comparison_id"] for r in quality])
        self.assertEqual({r["comparison_basis"] for r in values}, set(BASES))

    def test_percentiles_use_nearest_rank_for_p95_and_p99(self):
        template = {"duration_us": 0, "db_count": 0, "db_duration_us": 0, "cpu_us": 0, "in_bytes": 0, "out_bytes": 0, "memory_peak": 0}
        r = operation_metrics([dict(template, duration_us=i) for i in range(1, 101)])
        self.assertEqual(r["median_us"], 50.5)
        self.assertEqual(r["p95_us"], 95)
        self.assertEqual(r["p99_us"], 99)

    def test_declared_order_preserved_and_baseline_can_be_pinned(self):
        b = saved_series(self.input, [spec(M1, 1), spec(M2, 2), spec(M3, 3)])
        cfg = normalize_config({"config_version": "1.0", "operations": {"measurement_order": [M3, M2, M1], "series_baseline_measurement_id": M2}})
        series = OperationSeries(b, cfg)
        self.assertEqual(series.order, [M3, M2, M1])
        self.assertEqual(series.baseline, M2)
        self.assertEqual(self.comparison(b, M1, "previous_measurement", config=cfg)["reference_measurement_id"], M2)

    def test_unknown_baseline_incomplete_order_and_heuristic_config_rejected(self):
        b = saved_series(self.input, [spec(M1, 1), spec(M2, 2)])
        for ops in ({"series_baseline_measurement_id": "missing"}, {"measurement_order": [M1]}):
            cfg = normalize_config({"config_version": "1.0", "operations": ops})
            with self.assertRaises(SliceError):
                operation_history(b, cfg)
        with self.assertRaises(SliceError):
            normalize_config({"config_version": "1.0", "operations": {"fuzzy_matching": True}})

    def test_cli_exports_verified_deterministic_tables_without_input_changes(self):
        saved_series(self.input, [spec(M1, 1), spec(M2, 4, "Bob"), spec(M3, 2)])
        config_path = self.root / "config.json"
        config_path.write_text(json.dumps(self.config), encoding="utf-8")
        before = hashes(self.input)
        outputs = [self.root / "out1", self.root / "out2"]
        for output in outputs:
            answer = run(["--analysis-dir", str(self.input), "--config", str(config_path), "--output-dir", str(output)])
            self.assertEqual(answer["call_count"], 3)
            self.assertEqual(verify(self.input, output)["status"], "PASS")
        self.assertEqual(hashes(outputs[0]), hashes(outputs[1]))
        self.assertEqual(hashes(self.input), before)
        with (outputs[0] / "operation_history.csv").open(encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(sum(int(r["count"]) for r in rows), 3)
        self.assertTrue(any(r["observation_label"] == "не наблюдалась" for r in rows))

    def test_changed_slice_selection_cannot_leave_stale_output_tables(self):
        saved_series(self.input, [spec(M1, 1)])
        config_path = self.root / "config.json"
        config_path.write_text(json.dumps(self.config), encoding="utf-8")
        output = self.root / "out"
        args = ["--analysis-dir", str(self.input), "--config", str(config_path), "--output-dir", str(output)]
        run(args)
        before = hashes(output)
        with self.assertRaisesRegex(SliceError, "selection differs"):
            run(args + ["--overwrite", "--slices", "operation_history"])
        self.assertEqual(hashes(output), before)

    def test_before_first_observation_is_not_a_performance_comparison(self):
        b = saved_series(self.input, [spec(M1, 1, signature="Other"), spec(M2, 4)])
        r = self.comparison(b, M1, "first_observation")
        self.assertEqual(r["comparison_state"], "before_first_observation")
        self.assertEqual(r["reference_relation"], "later")
        self.assertIsNone(r["avg_us_delta_absolute"])

    def test_unresolved_chronology_blocks_relative_references(self):
        b = saved_series(self.input, [spec(M1, 1), spec(M2, 1)])
        # Simulate two overlapping captures with identical first CALL times.
        b.calls[1]["start_timestamp"] = b.calls[0]["start_timestamp"]
        b.calls[1]["end_timestamp"] = b.calls[0]["end_timestamp"]
        r = self.comparison(b, M2, "previous_measurement")
        self.assertFalse(r["series_order_reliable"])
        self.assertIsNone(r["reference_measurement_id"])
        self.assertIsNone(r["avg_us_delta_absolute"])
        cfg = normalize_config({"config_version": "1.0", "operations": {"measurement_order": [M1, M2]}})
        self.assertEqual(self.comparison(b, M2, "previous_measurement", config=cfg)["reference_measurement_id"], M1)

    def test_explicit_order_preserves_an_entire_measurement_without_calls(self):
        b = saved_series(self.input, [spec(M1, 10), spec(M3, 4)])
        b.manifest["datasets"][0]["actual_measurement_ids"].append(M2)
        cfg = normalize_config({"config_version": "1.0", "operations": {"measurement_order": [M1, M2, M3]}})
        r = self.comparison(b, M3, "previous_measurement", config=cfg)
        self.assertEqual(r["reference_measurement_id"], M2)
        self.assertEqual(r["reference_count"], 0)
        self.assertEqual(r["comparison_state"], "reference_not_observed")

    def test_input_row_order_does_not_change_numeric_rows_or_order(self):
        b = saved_series(self.input, [spec(M1, 1), spec(M2, 2), spec(M3, 3)])
        before = measurement_comparisons(b, self.config)
        b.calls.reverse()
        b.tables["datasets"].reverse()
        self.assertEqual(measurement_comparisons(b, self.config), before)

    def test_previous_observation_is_full_series_and_query_order_independent(self):
        b = saved_series(self.input, [
            spec(M1, 0), spec(M2, 2, user="Bob"),
            spec(M2, 3, signature="Other"), spec(M3, 1, user="Bob"), spec(M4, 4),
        ], order=[M1, M2, M3, M4])
        cfg = dict(self.config, measurement_ids=[M4])
        series = OperationSeries(b, cfg)
        expected = {
            ("Operation", "Alice"): [None, M1, M1, M1],
            ("Operation", "Bob"): [None, None, M2, M3],
            ("Other", "Alice"): [None, None, M2, M2],
        }
        for requests in ([M1, M2, M3, M4], [M4, M3, M2, M1], [M3, M1, M4, M2, M4, M1]):
            for mid in requests:
                for (sig, user), references in expected.items():
                    with self.subTest(requests=requests, mid=mid, pair=(sig, user)):
                        series.history(sig, user, mid)
                        reference = references[[M1, M2, M3, M4].index(mid)]
                        self.assertEqual(series.reference(sig, user, mid, "previous_observation"),
                                         (reference, None if reference else "no_previous_observation"))
        self.assertEqual(series.reference("Operation", "Alice", M4, "previous_measurement"), (M3, None))
        rows = measurement_comparisons(b, cfg)
        self.assertEqual({r["current_measurement_id"] for r in rows}, {M4})
        row = next(r for r in rows if r["signature"] == "Operation" and r["user"] == "Alice"
                   and r["comparison_basis"] == "previous_observation")
        self.assertEqual(row["reference_measurement_id"], M1)
        self.assertIsNone(row["avg_us_delta_percent"])

    def test_previous_observation_unknown_chronology_and_explicit_baseline(self):
        b = saved_series(self.input, [spec(M1, 1), spec(M2, 2)])
        for chronology in ("equal", "missing"):
            for call in b.calls:
                call["start_timestamp"] = "2026-08-04 12:00:00" if chronology == "equal" else ""
            if chronology == "missing":
                for table in ("heavy_sql", "errors"):
                    for row in b.tables[table]:
                        row["first_timestamp"] = ""
                for dataset in b.manifest["datasets"]:
                    dataset["first_timestamp"] = ""
            cfg = normalize_config({"config_version": "1.0", "operations": {"series_baseline_measurement_id": M1}})
            series = OperationSeries(b, cfg)
            self.assertFalse(series.reliable)
            for mid in (M2, M1, M2):
                for basis in ("previous_observation", "previous_measurement", "first_observation"):
                    with self.subTest(chronology=chronology, mid=mid, basis=basis):
                        self.assertEqual(series.reference("Operation", "Alice", mid, basis),
                                         (None, "series_chronology_unresolved"))
                self.assertEqual(series.reference("Operation", "Alice", mid, "series_baseline"), (M1, None))

    def test_all_observation_patterns_match_previous_scan_exactly(self):
        # All nonempty presence patterns over four measurements, including
        # leading/trailing gaps, isolated observations and a dense history.
        mids = [M1, M2, M3, M4]
        specs = [spec(mid, (mask + i) % 4, signature=f"Operation{mask // 3}", user=f"User{mask % 3}")
                 for mask in range(1, 16) for i, mid in enumerate(mids) if mask & (1 << i)]
        b = saved_series(self.input, specs, order=mids)
        original_reference = OperationSeries.reference

        def previous_scan(series, sig, user, current, basis):
            if basis == "previous_observation" and series.reliable:
                previous = [m for m in series.observed[(sig, user)]
                            if series.position[m] < series.position[current]]
                return (previous[-1], None) if previous else (None, "no_previous_observation")
            return original_reference(series, sig, user, current, basis)

        def assert_exact(actual, expected):
            self.assertIs(type(actual), type(expected))
            if isinstance(actual, dict):
                self.assertEqual(list(actual), list(expected))
                for key in actual:
                    assert_exact(actual[key], expected[key])
            elif isinstance(actual, (list, tuple)):
                self.assertEqual(len(actual), len(expected))
                for left, right in zip(actual, expected):
                    assert_exact(left, right)
            else:
                self.assertEqual(actual, expected)

        for order in (mids, list(reversed(mids))):
            for selected in (None, [M4], [M3, M1]):
                cfg = normalize_config({"config_version": "1.0", "measurement_ids": selected,
                                        "operations": {"measurement_order": order, "series_baseline_measurement_id": M2}})
                for builder in (operation_history, operation_history_all_users, measurement_comparisons, comparability):
                    with self.subTest(order=order, selected=selected, builder=builder.__name__):
                        actual = builder(b, cfg)
                        with mock.patch.object(OperationSeries, "reference", previous_scan):
                            expected = builder(b, cfg)
                        assert_exact(actual, expected)


if __name__ == "__main__":
    unittest.main()
