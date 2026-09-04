"""Numeric schema contract tests, only small synthetic TJ and saved bundles."""
from __future__ import annotations

import contextlib
import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import analyze_1c_tj as analyzer
from numeric_quality import FIELDS, CounterStats, parse_counter
from slice_input import load_bundle
from slice_config import REGISTERED_SLICES, SliceError, normalize_config
from slice_metrics import data_quality
from slice_operations import operation_history
from derive_slices import run as derive
from verify_analysis import verify as verify_analysis
from verify_slices import verify as verify_slices
from audit_stage1 import Audit


class NumericParsingTests(unittest.TestCase):
    def test_each_counter_distinguishes_missing_empty_invalid_and_zero(self):
        cases = [(None, "missing", None), ("", "empty", None), ("  ", "empty", None),
                 ("garbage", "invalid", None), ("1.2", "invalid", None),
                 ("NaN", "invalid", None), ("Infinity", "invalid", None),
                 ("1_000", "invalid", None), ("0", "valid", 0),
                 (" +20 ", "valid", 20), (str(2**63), "out_of_range", None)]
        for name in FIELDS:
            for raw, state, value in cases:
                with self.subTest(field=name, raw=raw):
                    parsed = parse_counter(name, raw)
                    self.assertEqual((parsed["state"], parsed["value"]), (state, value))
                    self.assertEqual(parsed["raw_value"], raw)

    def test_range_sign_and_large_integer_precision(self):
        for name in FIELDS:
            self.assertEqual(parse_counter(name, str(2**60+1))["value"], 2**60+1)
            self.assertEqual(parse_counter(name, "9"*5000)["state"], "out_of_range")
            self.assertEqual(parse_counter(name, "0"*5000+"20")["value"], 20)
            self.assertEqual(parse_counter(name, "-1")["state"],
                             "valid" if name in {"memory", "memory_peak"} else "out_of_range")
        self.assertEqual(parse_counter("memory", str(-(2**63)))["value"], -(2**63))
        self.assertEqual(parse_counter("memory", str(-(2**63)-1))["state"], "out_of_range")

    def test_mixed_summary_and_no_available_values(self):
        stats = CounterStats()
        for value in ("0", "20", None, "bad"):
            stats.add(parse_counter("in_bytes", value))
        q = stats.as_dict()
        self.assertEqual((q["eligible_count"], q["available_count"], q["mean_denominator"]), (4, 2, 2))
        self.assertEqual((q["sum_known"], q["mean"], q["coverage_percent"]), (20, 10, 50))
        self.assertIsNone(q["sum_complete"])
        for raw in (None, "", "bad"):
            stats = CounterStats(); stats.add(parse_counter("in_bytes", raw))
            for key in ("sum_known", "sum_complete", "mean", "max_known"):
                self.assertIsNone(stats.as_dict()[key])
        stats = CounterStats(); stats.add(parse_counter("in_bytes", "0"))
        self.assertEqual(stats.as_dict()["mean"], 0)
        self.assertEqual(stats.as_dict()["sum_complete"], 0)

    def test_merging_quality_uses_observation_counts_not_means_of_groups(self):
        merged = CounterStats()
        for group in (("0",), ("10", "20", None)):
            stats = CounterStats()
            for raw in group:
                stats.add(parse_counter("rows_affected", raw))
            merged.merge(stats.as_dict())
        self.assertEqual(merged.as_dict()["mean"], 10)
        self.assertEqual(merged.as_dict()["mean_denominator"], 3)
        self.assertEqual(merged.as_dict()["eligible_count"], 4)


class NumericBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tj-numeric-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs, self.out = self.root/"logs", self.root/"analysis"

    def make(self, values=(None, "", "bad", "0", "20", str(2**63)), *, include_db=True, duration_override=None, extra_db=False):
        records = []
        for i, raw in enumerate(values, 1):
            end = i*10
            counter_values = raw if isinstance(raw, dict) else {
                name: "2000000" if name == "cpu_us" and raw == "20" else raw for name in FIELDS}
            numeric = ",".join(spec[0]+"="+counter_values[name]
                               for name, spec in FIELDS.items() if counter_values.get(name) is not None)
            attrs = f"Usr=User,OSThread=7,SessionID={i},Context='Operation'" + (","+numeric if numeric else "")
            duration = i*1_000_000 if duration_override is None else duration_override
            records.append(f"{end//60:02}:{end%60:02}.000000-{duration},CALL,5,{attrs}\n")
            if include_db:
                dbend = end-1
                records.append(f"{dbend//60:02}:{dbend%60:02}.500000-100000,DBPOSTGRS,5,{attrs},Sql='SELECT * FROM t WHERE id = {i}'\n")
        if extra_db:
            records.append("02:00.000000-100,DBPOSTGRS,5,Usr=User,OSThread=99,RowsAffected=bad\n")
        path = self.logs/"capture"/"rphost_1"/"26090310.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(records), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(analyzer.run([str(self.logs), "-o", str(self.out)]), 0)
        self.manifest = json.loads((self.out/"analysis_metrics.json").read_text(encoding="utf-8"))
        return load_bundle(self.out)

    def test_roundtrip_all_counters_and_sql_aggregation(self):
        bundle = self.make()
        self.assertEqual(bundle.manifest["schema_version"], "1.6")
        for field in FIELDS:
            self.assertEqual([c["numeric_quality"][field]["state"] for c in bundle.calls],
                             ["missing", "empty", "invalid", "valid", "valid", "out_of_range"])
            self.assertIsNone(bundle.calls[0][field])
            self.assertEqual(bundle.calls[3][field], 0)
        for quality in (self.manifest["operations"][0]["numeric_quality"], self.manifest["heavy_sql"][0]["numeric_quality"]):
            for field in FIELDS:
                q = quality[field]
                self.assertEqual((q["eligible_count"], q["available_count"], q["mean_denominator"]), (6, 2, 2))
                self.assertEqual((q["missing_count"], q["empty_count"], q["invalid_count"], q["out_of_range_count"]), (1, 1, 1, 1))
                self.assertIsNone(q["sum_complete"])
        op = self.manifest["operations"][0]
        self.assertEqual(op["in_bytes_per_call"], 10)
        self.assertEqual(op["memory_per_call"], 10)
        self.assertEqual(op["memory_peak_median"], 10)
        self.assertEqual(op["rows_affected"], 20)
        self.assertEqual(op["call_rows_affected"], 20)
        self.assertEqual(self.manifest["heavy_sql"][0]["rows_affected_per_event"], 10)
        self.assertEqual(verify_analysis(self.out)[1], 0)

    def test_cpu_percent_and_residual_share_exactly_the_cpu_population(self):
        bundle = self.make()
        op = self.manifest["operations"][0]
        self.assertEqual((op["cpu_us"], op["cpu_wall_us"], op["cpu_available_count"]), (2_000_000, 9_000_000, 2))
        self.assertEqual(op["cpu_percent_of_wall"], round(100*2/9, 4))
        self.assertAlmostEqual(op["cpu_coverage_percent"], 100/3)
        self.assertAlmostEqual(op["cpu_wall_coverage_percent"], 100*9/21)
        self.assertEqual(op["unattributed_us_floor"], 6_800_000)
        config = normalize_config({"config_version": "1.0"})
        h = operation_history(bundle, config)[0]
        self.assertAlmostEqual(h["cpu_percent_of_wall"], 100*2/9)
        self.assertEqual(h["cpu_us_per_call"], 1_000_000)
        self.assertEqual(h["in_bytes_per_call"], 10)
        self.assertEqual(h["numeric_quality"]["in_bytes"]["mean_denominator"], 2)
        self.assertNotIn("legacy_missing_invalid_counter_vs_zero_not_distinguishable", h["known_limitations"])
        q = data_quality(bundle, config)[0]["metric_availability"]["cpu_us"]
        self.assertEqual(q["stored_numeric_count"], 2)
        self.assertEqual(q["raw_missing_count"], 1)
        self.assertTrue(q["raw_missing_vs_zero_distinguishable"])

    def test_each_counter_uses_its_own_available_population(self):
        self.make((
            {"cpu_us": "500000", "memory": "20", "in_bytes": "bad", "out_bytes": "0"},
            {"memory": "", "memory_peak": "40", "in_bytes": "100", "out_bytes": "100", "rows_affected": "3"},
        ))
        op = self.manifest["operations"][0]
        self.assertEqual(op["cpu_percent_of_wall"], 50)
        self.assertEqual(op["cpu_wall_us"], 1_000_000)
        self.assertEqual(op["memory_per_call"], 20)
        self.assertEqual(op["memory_peak_avg"], 40)
        self.assertEqual(op["in_bytes_per_call"], 100)
        self.assertEqual(op["out_bytes_per_call"], 50)
        self.assertEqual(op["numeric_quality"]["in_bytes"]["mean_denominator"], 1)
        self.assertEqual(op["numeric_quality"]["out_bytes"]["mean_denominator"], 2)
        self.assertEqual(op["numeric_quality"]["db_rows"]["mean"], 3)

    def test_all_unknown_values_remain_null_and_undefined(self):
        bundle = self.make((None, "", "bad"))
        for call in bundle.calls:
            for field in FIELDS:
                self.assertIsNone(call[field])
            self.assertIsNone(call["db_rows"])
        op = self.manifest["operations"][0]
        for field in ("cpu_us", "cpu_percent_of_wall", "memory_per_call", "in_bytes_per_call", "out_bytes_per_call", "memory_peak_median", "rows_affected", "unattributed_us_floor", "attribution_overflow_us"):
            self.assertIsNone(op[field], field)
        self.assertEqual(op["cpu_coverage_percent"], 0)

    def test_measured_zero_cpu_and_zero_wall_have_distinct_denominators(self):
        self.make(("0",), include_db=False, duration_override=0)
        op = self.manifest["operations"][0]
        self.assertEqual(op["cpu_available_count"], 1)
        self.assertEqual(op["cpu_coverage_percent"], 100)
        self.assertIsNone(op["cpu_percent_of_wall"])
        self.assertIsNone(op["cpu_wall_coverage_percent"])
        self.assertEqual(op["numeric_quality"]["db_rows"]["eligible_count"], 0)
        self.assertIsNone(op["rows_affected"])

    def test_measured_zero_with_positive_wall_is_a_real_zero_percent(self):
        self.make(("0",))
        op = self.manifest["operations"][0]
        self.assertEqual(op["cpu_percent_of_wall"], 0)
        self.assertEqual(op["in_bytes_per_call"], 0)
        self.assertEqual(op["rows_affected"], 0)
        self.assertEqual(op["numeric_quality"]["cpu_us"]["available_count"], 1)
        self.assertEqual(op["cpu_wall_coverage_percent"], 100)

    def test_unlinked_db_without_sql_still_contributes_numeric_quality(self):
        self.make(("20",), extra_db=True)
        db = self.manifest["datasets"][0]["event_stats"]["DBPOSTGRS"]
        self.assertEqual(db["count"], 2)
        self.assertEqual(db["numeric_quality"]["rows_affected"]["invalid_count"], 1)
        self.assertEqual(db["numeric_quality"]["rows_affected"]["available_count"], 1)
        self.assertEqual(self.manifest["heavy_sql"][0]["numeric_quality"]["rows_affected"]["eligible_count"], 1)

    def test_full_slices_and_independent_audit_from_saved_numeric_bundle(self):
        self.make()
        cfg = self.root/"config.json"
        cfg.write_text(json.dumps({"config_version": "1.0", "slices": list(REGISTERED_SLICES),
            "problems": {"series_id": "numeric_fixture", "rules": [{"rule_id": "cpu", "metric": "operation.cpu_percent_of_wall",
                "operator": ">", "threshold": 10, "min_call_count": 1, "source": "Synthetic test"}]}}), encoding="utf-8")
        slices = self.root/"slices"
        with contextlib.redirect_stdout(io.StringIO()):
            derive(["--analysis-dir", str(self.out), "--config", str(cfg), "--output-dir", str(slices)])
        self.assertEqual(verify_slices(self.out, slices)["status"], "PASS")
        self.assertEqual(Audit(self.out, slices).run()["status"], "PASS")

    def test_incorrect_cpu_denominator_is_rejected_even_with_matching_csv_json(self):
        self.make()
        self.manifest["operations"][0]["cpu_percent_of_wall"] = round(100*2/21, 4)
        self.rewrite_table("operations")
        with self.assertRaisesRegex(SliceError, "cpu_percent_of_wall"):
            load_bundle(self.out)
        self.assertEqual(verify_analysis(self.out)[1], 2)

    def test_incorrect_counter_mean_denominator_is_rejected(self):
        self.make()
        self.manifest["heavy_sql"][0]["numeric_quality"]["rows_affected"]["mean_denominator"] = 6
        self.rewrite_table("heavy_sql")
        with self.assertRaisesRegex(SliceError, "denominator"):
            load_bundle(self.out)

    def test_unknown_observation_cannot_be_replaced_by_zero(self):
        self.make()
        path = self.out/"call_observations.csv"
        with path.open(encoding="utf-8-sig", newline="") as stream:
            rows = list(csv.DictReader(stream))
        rows[0]["cpu_us"] = "0"
        self.write_csv(path, rows)
        with self.assertRaises(SliceError):
            load_bundle(self.out)

    def test_future_schema_is_rejected_by_both_validators(self):
        self.make(("0",))
        self.manifest["schema_version"] = "9.0"
        self.save_manifest()
        self.assertEqual(verify_analysis(self.out)[1], 2)
        with self.assertRaisesRegex(SliceError, "Unsupported input schema"):
            load_bundle(self.out)

    def save_manifest(self):
        (self.out/"analysis_metrics.json").write_text(json.dumps(self.manifest, ensure_ascii=False), encoding="utf-8")

    def rewrite_table(self, name):
        self.save_manifest()
        path = self.out/(name+".csv")
        with path.open(encoding="utf-8-sig", newline="") as stream:
            fields = next(csv.reader(stream))
        rows = [{key: analyzer.csv_scalar(row[key]) for key in fields} for row in self.manifest[name]]
        self.write_csv(path, rows)

    @staticmethod
    def write_csv(path, rows):
        with path.open("w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
            writer.writeheader(); writer.writerows(rows)


if __name__ == "__main__":
    unittest.main()
