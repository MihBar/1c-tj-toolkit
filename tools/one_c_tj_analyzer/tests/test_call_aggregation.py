"""CALL duration and ordering contracts, using in-memory observations."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import statistics
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import analyze_1c_tj as analyzer
from numeric_quality import FIELDS, parse_counter


def make_call(call_id, duration, *, dataset="d", measurement="m", user="u",
              signature="s", end=None, raw=None):
    numeric = {name: parse_counter(name, raw) for name in FIELDS}
    return analyzer.CallRecord(
        call_id=call_id, dataset_id=dataset, measurement_id=measurement,
        user=user, signature=signature, context_sample=f"context {call_id}",
        source="synthetic", process="rphost", end=end, start=None,
        duration_us=duration, thread="1", session="1", connect_id="1",
        numeric_quality=numeric,
        **{name: value["value"] for name, value in numeric.items()},
    )


class CallAggregationTests(unittest.TestCase):
    def aggregate(self, durations):
        return analyzer.aggregate_operations([
            make_call(i, value) for i, value in enumerate(durations)
        ])[0]

    def test_median_mean_variation_types_and_rounding(self):
        cases = [
            ([7], 7.0, 7.0, 0.0),
            ([4, 1], 2.5, 2.5, 0.6),
            ([4, 1, 2], 2.0, 2.333, 0.534522),
            ([9, 2, 2, 2, 9], 2.0, 4.8, 0.714435),
            ([0], 0.0, 0.0, 0.0),
            ([0, 0, 0, 0], 0.0, 0.0, 0.0),
            ([0, 1], 0.5, 0.5, 1.0),
        ]
        for values, median, mean, variation in cases:
            with self.subTest(values=values):
                row = self.aggregate(values)
                for name, expected in (("median_us", median), ("avg_us", mean),
                                       ("coefficient_of_variation", variation)):
                    self.assertEqual(row[name], expected)
                    self.assertIs(type(row[name]), float)
                self.assertEqual(row["duration_us"], sum(values))
                self.assertEqual(row["min_us"], min(values))
                self.assertEqual(row["max_us"], max(values))
                for name in ("duration_us", "min_us", "max_us", "p95_us", "p99_us"):
                    self.assertIs(type(row[name]), int)

    def test_large_integer_median_preserves_float_conversion(self):
        for values in ([2**53 + 1], [2**53 + 3, 2**53 + 1],
                       [2**60 + 7, 0, 2**60 + 1]):
            with self.subTest(values=values):
                row = self.aggregate(values)
                mean = sum(values) / len(values)
                self.assertEqual(row["median_us"], round(float(statistics.median(values)), 3))
                self.assertEqual(row["avg_us"], round(mean, 3))
                self.assertEqual(row["coefficient_of_variation"],
                                 round(statistics.pstdev(values) / mean, 6) if len(values) > 1 else 0.0)

    def test_nearest_rank_small_and_partial_hundreds(self):
        for count, p95, p99 in ((1, 1, 1), (2, 2, 2), (7, 7, 7),
                                (19, 19, 19), (20, 19, 20), (21, 20, 21),
                                (99, 95, 99), (100, 95, 99), (101, 96, 100),
                                (137, 131, 136), (199, 190, 198), (201, 191, 199)):
            with self.subTest(count=count):
                row = self.aggregate(list(range(count, 0, -1)))
                self.assertEqual((row["p95_us"], row["p99_us"]), (p95, p99))
        row = self.aggregate([3] * 100 + [8] * 2)
        self.assertEqual((row["p95_us"], row["p99_us"]), (3, 8))

    def test_inclusive_thresholds_and_priority(self):
        values = [0, 999_999, 1_000_000, 4_999_999, 5_000_000,
                  9_999_999, 10_000_000, 29_999_999, 30_000_000]
        row = self.aggregate(values)
        self.assertEqual([row[f"over_{s}s"] for s in (1, 5, 10, 30)], [7, 5, 3, 1])
        for values, priority, rule in (
            ([0], "P2", "engineering candidate below deterministic P0/P1 thresholds"),
            ([5_000_000], "P1", "engineering candidate: max >=30 s, p95 >=5 s, total >=30 s, DB/call >=500, or output >=10 MiB"),
            ([30_000_000, 30_000_000], "P0", "engineering candidate: repeated >=30 s, max >=120 s, or DB/call >=1000 with p95 >=10 s"),
        ):
            with self.subTest(values=values):
                row = self.aggregate(values)
                self.assertEqual((row["priority"], row["priority_rule"]), (priority, rule))

    def test_dataset_measurement_grouping_and_stable_ties(self):
        keys = [("m2", "d2", "b"), ("m1", "d2", "b"),
                ("m1", "d1", "b"), ("m1", "d1", "a")]
        calls = [make_call(i, 10, measurement=m, dataset=d, user=u)
                 for i, (m, d, u) in enumerate(keys)]
        rows = analyzer.aggregate_operations(calls)
        self.assertEqual([(r["measurement_id"], r["dataset_id"], r["user"]) for r in rows],
                         sorted(keys))
        self.assertEqual(rows, analyzer.aggregate_operations(list(reversed(calls))))
        rows = analyzer.aggregate_operations(calls, scope="measurement")
        self.assertEqual([(r["measurement_id"], r["user"], r["count"]) for r in rows],
                         [("m1", "b", 2), ("m1", "a", 1), ("m2", "b", 1)])
        self.assertEqual(rows[0]["dataset_ids"], ["d1", "d2"])
        self.assertEqual(rows[0]["dataset_id"], "(multiple datasets)")
        self.assertEqual(rows[0]["call_ids"], [1, 2])
        self.assertEqual(rows[0]["context_sample"], "context 1")
        self.assertEqual(json.dumps(rows), json.dumps(analyzer.aggregate_operations(calls, scope="measurement")))

    def test_identical_measurement_order_and_all_deltas(self):
        calls = [
            make_call(3, 6, dataset="d2", measurement="a", end=dt.datetime(2026, 1, 2)),
            make_call(1, 0, measurement="z", end=dt.datetime(2026, 1, 1)),
            make_call(2, 4, dataset="d1", measurement="a", end=dt.datetime(2026, 1, 2)),
            make_call(4, 10, measurement="b"),
        ]
        rows = analyzer.identical_operation_rows(calls)
        self.assertEqual([r["measurement_id"] for r in rows], ["z", "a", "b"])
        self.assertEqual([r["previous_measurement_id"] for r in rows], ["", "z", "a"])
        self.assertEqual([r["comparison_order"] for r in rows], [1, 2, 3])
        self.assertEqual(rows[1]["dataset_ids"], ["d1", "d2"])
        expected = {
            "count": [(None, None), (1, 100.0), (-1, -50.0)],
            "avg_us": [(None, None), (5.0, None), (5.0, 100.0)],
            "median_us": [(None, None), (5.0, None), (5.0, 100.0)],
            "p95_us": [(None, None), (6, None), (4, 66.666667)],
            "max_us": [(None, None), (6, None), (4, 66.666667)],
            "db_per_call": [(None, None), (0.0, None), (0.0, None)],
            "db_seconds_per_call": [(None, None), (0.0, None), (0.0, None)],
            "cpu_percent_of_wall": [(None, None)] * 3,
            "out_bytes_per_call": [(None, None)] * 3,
        }
        for name, deltas in expected.items():
            self.assertEqual([(r[name + "_delta"], r[name + "_delta_percent"]) for r in rows], deltas)
        self.assertEqual(rows, analyzer.identical_operation_rows(calls))

    def test_identical_tied_timestamps_and_different_users(self):
        calls = [make_call(i, 0, measurement=m, user=u, signature=s)
                 for i, (m, u, s) in enumerate((
                     ("b", "u", "s"), ("a", "u", "s"),
                     ("b", "v", "t"), ("a", "u", "t")))]
        rows = analyzer.identical_operation_rows(calls)
        self.assertEqual([(r["signature"], r["user"], r["measurement_id"]) for r in rows],
                         [("s", "u", "a"), ("s", "u", "b"), ("t", "u", "a"), ("t", "v", "b")])
        self.assertEqual([r["comparability_level"] for r in rows], ["B", "B", "C", "C"])
        self.assertEqual(rows, analyzer.identical_operation_rows(list(reversed(calls))))

    def test_numeric_quality_db_sql_and_call_ids(self):
        calls = [make_call(3, 10, raw=None), make_call(1, 20, raw="0"),
                 make_call(2, 30, raw="6")]
        calls[0].db_count, calls[0].db_duration_us = 2, 5
        calls[0].sql = {"select a": [1, 3, 3], "select b": [1, 3, 3]}
        calls[1].sql = {"select a": [1, 0, 0]}
        row = analyzer.aggregate_operations(calls)[0]
        self.assertEqual(row["call_ids"], [1, 2, 3])
        self.assertEqual([r["normalized_sql"] for r in row["top_nested_sql"]], ["select b", "select a"])
        self.assertEqual([r["count"] for r in row["top_nested_sql"]], [1, 2])
        self.assertEqual((row["db_count"], row["db_duration_us"], row["db_per_call"]), (2, 5, 0.666667))
        self.assertEqual((row["cpu_us"], row["cpu_wall_us"], row["cpu_percent_of_wall"]), (6, 50, 12.0))
        self.assertEqual(row["out_bytes_per_call"], 3.0)
        quality = row["numeric_quality"]["cpu_us"]
        self.assertEqual((quality["missing_count"], quality["zero_count"], quality["available_count"]), (1, 1, 2))
        for raw, expected in ((None, None), ("0", 0)):
            row = analyzer.aggregate_operations([make_call(0, 0, raw=raw)])[0]
            self.assertEqual(row["cpu_us"], expected)
            self.assertEqual(row["out_bytes_per_call"], expected)
            self.assertIsNone(row["cpu_percent_of_wall"])

    def test_one_duration_sort_per_group_and_no_sort_in_order_statistics(self):
        values = [9, 1, 4]
        calls = [make_call(i, value, dataset=dataset)
                 for dataset in ("d1", "d2") for i, value in enumerate(values)]
        for scope, expected_sorts in (("dataset", 2), ("measurement", 1)):
            with self.subTest(scope=scope), mock.patch.object(analyzer, "sorted", wraps=sorted, create=True) as sorter, \
                    mock.patch.object(analyzer, "median_value", side_effect=AssertionError("re-sorting median")), \
                    mock.patch.object(analyzer, "nearest_rank", side_effect=AssertionError("re-sorting percentile")):
                analyzer.aggregate_operations(calls, scope=scope)
                duration_sorts = [call for call in sorter.call_args_list
                                  if isinstance(call.args[0], list) and call.args[0]
                                  and all(isinstance(value, int) for value in call.args[0])]
                self.assertEqual(len(duration_sorts), expected_sorts)
        ordered = [1, 4, 9]
        with mock.patch("builtins.sorted", side_effect=AssertionError("unexpected sort")), \
                mock.patch.object(analyzer.statistics, "median", side_effect=AssertionError("hidden sort")):
            self.assertEqual(analyzer.duration_order_statistics(ordered),
                             {"median_us": 4.0, "p95_us": 9, "p99_us": 9, "max_us": 9, "min_us": 1})
        self.assertEqual(ordered, [1, 4, 9])

    def test_empty_input_and_invalid_scope(self):
        self.assertEqual(analyzer.aggregate_operations([]), [])
        self.assertEqual(analyzer.identical_operation_rows([]), [])
        with self.assertRaises(ValueError):
            analyzer.aggregate_operations([], scope="invalid")


if __name__ == "__main__":
    unittest.main()
