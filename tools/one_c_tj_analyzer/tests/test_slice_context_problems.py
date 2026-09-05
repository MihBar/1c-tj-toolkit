"""Problem views share a build without rebasing discovery or comparisons."""
from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_slice_context as helpers
from test_slice_operations import saved_series, spec, M1, M2, M3, M4
from slice_config import normalize_config, SliceError
from slice_context import CONTEXT_SLICES, PROBLEM_SLICES, SliceCalculationContext
from slice_metrics import SLICE_BUILDERS
from slice_operations import OperationSeries
import slice_db_chatty as db
import slice_apdex as ap
import slice_problems as problems


class ProblemContextTests(unittest.TestCase):
    invoke = helpers.SliceContextTests.invoke

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bundle = saved_series(self.root / "input", [
            spec(M1, 1, db_count=0), spec(M1, 1, db_count=101),
            spec(M1, 20, signature="Gone"), spec(M2, 20, db_count=501),
            spec(M3, 2, signature="Other"), spec(M4, 8, db_count=1001), spec(M4, 8, db_count=101),
        ])

    def config(self, family="mixed", mids=None):
        rules = [
            {"rule_id": "slow", "metric": "operation.avg_us", "threshold": 10000000, "min_call_count": 2},
            {"rule_id": "db", "metric": "db_chatty.calls_above_threshold_percent", "threshold": 10,
             "min_call_count": 1, "db_events_threshold": 101},
            {"rule_id": "ap", "metric": "apdex.deficit", "threshold": .15, "min_call_count": 1},
        ]
        rules = [dict(r, operator=">", source="synthetic") for r in rules
                 if family == "mixed" or r["rule_id"] == family]
        return normalize_config({"config_version": "1.0", "slices": sorted(PROBLEM_SLICES),
            "measurement_ids": mids, "problems": {"series_id": "synthetic", "rules": rules},
            "apdex": {"targets": [{"signature": "Operation", "t_seconds": 2,
                                    "status": "engineering_proposal", "source": "synthetic"}]}})

    def test_single_joint_rule_families_filters_and_repeated_runs(self):
        for family in ("slow", "db", "ap", "mixed"):
            for i, mids in enumerate((None, [M3], [M2, M4])):
                cfg = self.config(family, mids)
                joint = f"joint_{family}_{i}"
                self.invoke(cfg, joint)
                with SliceCalculationContext(self.bundle, cfg) as context:
                    for name in sorted(PROBLEM_SLICES, reverse=True):
                        builder = SLICE_BUILDERS[name][1]
                        self.assertEqual(builder(self.bundle, cfg), builder(self.bundle, cfg, context=context))
                        single = joint + "_" + name
                        self.invoke(cfg, single, [name])
                        self.assertEqual((self.root / single / (name + ".csv")).read_bytes(),
                                         (self.root / joint / (name + ".csv")).read_bytes())
        self.invoke(self.config("slow"), "again")
        for path in (self.root / "joint_slow_0").iterdir():
            self.assertEqual(path.read_bytes(), (self.root / "again" / path.name).read_bytes())

    def test_one_build_and_only_rule_dependencies(self):
        real_problem = problems.ProblemSeries
        for family in ("slow", "db", "ap", "mixed"):
            cfg = self.config(family)
            with ExitStack() as stack:
                op_count = stack.enter_context(mock.patch("slice_operations.OperationSeries", wraps=OperationSeries))
                db_count = stack.enter_context(mock.patch.object(db, "ChattySeries", wraps=db.ChattySeries))
                ap_count = stack.enter_context(mock.patch.object(ap, "ApdexSeries", wraps=ap.ApdexSeries))
                problem_count = stack.enter_context(mock.patch.object(problems, "ProblemSeries", wraps=real_problem))
                build = stack.enter_context(mock.patch.object(real_problem, "build", autospec=True, side_effect=real_problem.build))
                for module, names in ((problems, ("OperationSeries", "ChattySeries", "ApdexSeries")),
                                      (db, ("OperationSeries",)), (ap, ("OperationSeries",))):
                    for name in names:
                        stack.enter_context(mock.patch.object(module, name, side_effect=AssertionError("unshared dependency")))
                with SliceCalculationContext(self.bundle, cfg) as context:
                    self.assertEqual(problem_count.call_count + op_count.call_count, 0)
                    for names in (sorted(PROBLEM_SLICES), sorted(PROBLEM_SLICES, reverse=True)):
                        for name in names:
                            SLICE_BUILDERS[name][1](self.bundle, cfg, context=context)
                    self.assertIs(context._problems.series, context._operations)
                    self.assertIs(context._problems.db, context._chatty)
                    self.assertIs(context._problems.apdex, context._apdex)
                    self.assertEqual(op_count.call_count, 1)
                    self.assertEqual(problem_count.call_count, 1)
                    self.assertEqual(build.call_count, 1)
                    self.assertEqual(db_count.call_count, int(family in ("db", "mixed")))
                    self.assertEqual(ap_count.call_count, int(family in ("ap", "mixed")))
                self.assertIsNone(context._problems)
                self.assertIsNone(context._problem_tables)

    def test_derive_and_prewarmed_dependencies_build_once(self):
        cfg = self.config()
        real_problem = problems.ProblemSeries
        with mock.patch.object(real_problem, "build", autospec=True, side_effect=real_problem.build) as build, \
                mock.patch("slice_operations.OperationSeries", wraps=OperationSeries) as op_count, \
                mock.patch.object(db, "ChattySeries", wraps=db.ChattySeries) as db_count, \
                mock.patch.object(ap, "ApdexSeries", wraps=ap.ApdexSeries) as ap_count:
            self.invoke(cfg, "all_families", sorted(CONTEXT_SLICES))
            for counter in (build, op_count, db_count, ap_count):
                self.assertEqual(counter.call_count, 1)
        with SliceCalculationContext(self.bundle, cfg) as context:
            db.db_chatty(self.bundle, cfg, context=context)
            ap.apdex(self.bundle, cfg, context=context)
            operations, chatty, apdex = context._operations, context._chatty, context._apdex
            problems.problem_registry(self.bundle, cfg, context=context)
            self.assertIs(context._problems.series, operations)
            self.assertIs(context._problems.db, chatty)
            self.assertIs(context._problems.apdex, apdex)
            self.assertIn(101, {key[-1] for key in chatty.cache})
            self.assertNotIn(101, cfg["db_chatty"]["thresholds"])

    def test_full_series_discovery_absence_and_distinct_previous_bases(self):
        for mids in (None, [M3], [M4]):
            cfg = self.config("slow", mids)
            with SliceCalculationContext(self.bundle, cfg) as context:
                registry = problems.problem_registry(self.bundle, cfg, context=context)
                operation = next(r for r in registry if r["signature"] == "Operation")
                self.assertEqual(operation["first_problem_measurement_id"], M2)
                self.assertFalse(operation["first_problem_evaluable"])
                self.assertEqual(operation["measurement_id"], M4)
                self.assertEqual(operation["previous_observation_measurement_id"], M2)
                self.assertEqual(operation["previous_comparable_reference_measurement_id"], M1)
                self.assertEqual(operation["first_problem_reference_measurement_id"], M2)
                gone = next(r for r in registry if r["signature"] == "Gone")
                self.assertTrue(gone["historical_without_latest_check"])
                self.assertEqual(gone["threshold_status"], problems.ABSENT)
                history = problems.problem_history(self.bundle, cfg, context=context)
                if mids == [M3]:
                    self.assertTrue(all(r["measurement_id"] == M3 for r in history))
                    self.assertEqual(problems.problem_new(self.bundle, cfg, context=context), [])
                    absent = next(r for r in history if r["signature"] == "Operation")
                    self.assertEqual(absent["threshold_status"], problems.ABSENT)
                    self.assertIsNone(absent["previous_comparable_delta_absolute"])

    def test_nested_mutations_do_not_escape_views(self):
        cfg = self.config()
        expected = {n: SLICE_BUILDERS[n][1](self.bundle, cfg) for n in CONTEXT_SLICES}
        original = deepcopy((self.bundle, cfg, problems.LIMITATIONS))

        def corrupt(value):
            if isinstance(value, dict):
                for child in list(value.values()):
                    corrupt(child)
                value.clear()
            elif isinstance(value, list):
                for child in list(value):
                    corrupt(child)
                value.append("consumer mutation")

        with SliceCalculationContext(self.bundle, cfg) as context:
            for name in sorted(PROBLEM_SLICES):
                corrupt(SLICE_BUILDERS[name][1](self.bundle, cfg, context=context))
                for other in CONTEXT_SLICES:
                    self.assertEqual(SLICE_BUILDERS[other][1](self.bundle, cfg, context=context), expected[other])
            corrupt(problems.transitions(self.bundle, cfg, "decreased", context=context))
            self.assertEqual(problems.problem_history(self.bundle, cfg, context=context), expected["problem_history"])
        self.assertEqual((self.bundle, cfg, problems.LIMITATIONS), original)

    def test_empty_results_and_configuration_binding(self):
        cfg = self.config("slow")
        cfg["problems"]["rules"][0]["threshold"] = 10**20
        with mock.patch.object(problems.ProblemSeries, "build", autospec=True,
                               side_effect=problems.ProblemSeries.build) as build:
            with SliceCalculationContext(self.bundle, cfg) as context:
                for name in sorted(PROBLEM_SLICES):
                    rows = SLICE_BUILDERS[name][1](self.bundle, cfg, context=context)
                    if name != "problem_rule_coverage":
                        self.assertEqual(rows, [])
                self.assertEqual(build.call_count, 1)
                changed = deepcopy(cfg)
                changed["problems"]["rules"][0]["threshold"] = 1
                with self.assertRaisesRegex(SliceError, "configuration differs"):
                    problems.problem_registry(self.bundle, changed, context=context)

    def test_unused_or_invalid_problem_rules_do_not_eagerly_build(self):
        cfg = self.config()
        cfg["problems"]["rules"] = []
        with mock.patch.object(problems, "ProblemSeries", side_effect=AssertionError("unused problems")):
            self.invoke(cfg, "only_operation", ["operation_history"])
        with mock.patch("slice_operations.OperationSeries", side_effect=AssertionError("rules must be checked first")):
            with self.assertRaisesRegex(SliceError, "nonempty"):
                with SliceCalculationContext(self.bundle, cfg) as context:
                    problems.problem_registry(self.bundle, cfg, context=context)
        self.assertIsNone(context._problem_tables)
        self.assertIsNone(context._bundle)


if __name__ == "__main__":
    unittest.main()
