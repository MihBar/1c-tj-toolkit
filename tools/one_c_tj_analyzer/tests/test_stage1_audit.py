"""Tests of the independent acceptance oracle, never original TJ fixtures."""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_stage1 import Audit, apdex_score, check, rows, stats
from derive_slices import run
from slice_config import REGISTERED_SLICES, SliceError
from test_slice_operations import saved_series, spec, M1, M2, M3
from test_slice_problems import rule


class Stage1AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tj-stage1-audit-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.output = self.root/"input", self.root/"output"

    def make(self, configured=False):
        saved_series(self.source, [spec(M1,20,db_count=5001), spec(M2,1,signature="Other"),
                                  spec(M3,4), spec(M3,1,"Bob")])
        config = {"config_version":"1.0", "slices":list(REGISTERED_SLICES),
                  "problems":{"series_id":"audit_fixture", "rules":[rule()]}}
        if configured:
            config["apdex"]={"targets":[{"signature":"Operation","t_seconds":1,
                "status":"engineering_proposal","source":"Synthetic test only"}],
                "classes":[{"class_id":"other","signatures":["Other"],"t_seconds":2,
                "status":"business_approved","source":"Synthetic test only, no real SLA"}]}
        config_path=self.root/"config.json"
        config_path.write_text(json.dumps(config),encoding="utf-8")
        run(["--analysis-dir",str(self.source),"--config",str(config_path),"--output-dir",str(self.output)])

    def test_full_result_without_T_and_missing_intermediate_observation(self):
        self.make()
        result=Audit(self.source,self.output).run()
        self.assertEqual(result["status"],"PASS")
        self.assertEqual(result["CALL_count"],4)
        self.assertEqual(result["details"]["apdex_covered_CALLs"],0)
        self.assertGreater(result["details"]["gaps_with_distinct_previous_bases"],0)

    def test_configured_APDEX_and_separate_target_status_populations(self):
        self.make(configured=True)
        result=Audit(self.source,self.output).run()
        self.assertEqual(result["details"]["apdex_covered_CALLs"],4)
        self.assertEqual(result["details"]["apdex_uncovered_CALLs"],0)

    def test_rehashed_incorrect_numeric_output_rejected_independently(self):
        self.make()
        path=self.output/"operation_history.csv"
        table=list(rows(path)); table[0]["p95_us"]="123"
        with path.open("w",encoding="utf-8-sig",newline="") as stream:
            writer=csv.DictWriter(stream,fieldnames=list(table[0]),lineterminator="\n")
            writer.writeheader(); writer.writerows(table)
        manifest_path=self.output/"slice_manifest.json"
        manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["outputs"][path.name]["sha256"]=hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest),encoding="utf-8")
        with self.assertRaisesRegex(SliceError,"p95_us"):
            Audit(self.source,self.output).run()

    def test_oracle_APDEX_boundaries_failure_not_double_counted_and_missing_T(self):
        durations=[0,999999,1000000,1000001,4000000,4000001]
        cs=[{"call_id":i+1,"duration_us":d,"error_count":1} for i,d in enumerate(durations)]
        score=apdex_score(cs,1000000,set())
        self.assertEqual((score["satisfied_count"],score["tolerating_count"],score["frustrated_count"]),(3,2,1))
        self.assertEqual(score["apdex"],2/3)
        with_failures=apdex_score(cs,1000000,{1,6})
        self.assertEqual(with_failures["frustrated_count"],2)
        self.assertEqual(with_failures["apdex_denominator"],6)
        self.assertEqual(with_failures["forced_frustrated_count"],1)
        self.assertIsNone(apdex_score(cs,None,set())["apdex"])

    def test_oracle_individual_percentiles_not_mean_of_group_percentiles(self):
        self.assertEqual(stats([1,2,3,100])["median"],2.5)
        self.assertEqual(stats(list(range(1,101)))["p95"],95)
        self.assertEqual(stats(list(range(1,101)))["p99"],99)
        self.assertEqual(stats([1]*99+[100])["p95"],1)
        self.assertNotEqual(stats([1]*99+[100])["p95"],(1+100)/2)

    def test_large_CALL_id_list_CSV_field_and_limit_restoration(self):
        path=self.root/"large.csv"
        value="x"*200000
        path.write_text("field\n"+value+"\n",encoding="utf-8")
        old=csv.field_size_limit()
        self.assertEqual(list(rows(path))[0]["field"],value)
        self.assertEqual(csv.field_size_limit(),old)

    def test_integer_checks_do_not_round_large_counters_through_float(self):
        value=2**60+1
        check({"counter":str(value)},{"counter":value},"large exact integer")
        with self.assertRaises(SliceError):
            check({"counter":str(value-1)},{"counter":value},"large exact integer")


if __name__=="__main__":
    unittest.main()
