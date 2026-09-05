"""DB-chatty/APDEX shared dependencies preserve standalone builder contracts."""
from contextlib import ExitStack
from copy import deepcopy
import unittest
from unittest import mock

import test_slice_context as helpers
from test_slice_operations import M2, M3
from slice_config import SliceError, normalize_config
from slice_context import APDEX_SLICES, CHATTY_SLICES, OPERATION_SLICES, SliceCalculationContext
from slice_metrics import SLICE_BUILDERS, data_quality
from slice_operations import OperationSeries
import slice_db_chatty as db
import slice_apdex as ap

# This suite intentionally selects only the families introduced in its stage.
CONTEXT_SLICES = OPERATION_SLICES | CHATTY_SLICES | APDEX_SLICES


class FamilyContextTests(unittest.TestCase):
    setUp = helpers.SliceContextTests.setUp
    invoke = helpers.SliceContextTests.invoke

    def configs(self):
        first = deepcopy(self.config)
        first["slices"] = sorted(CONTEXT_SLICES)
        second = deepcopy(first)
        second["apdex"]["targets"] = [{"signature": "Operation", "t_seconds": 1,
                                        "status": "engineering_proposal", "source": "synthetic"}]
        third = deepcopy(second)
        third["measurement_ids"] = [M2, M3]
        third["db_chatty"].update(thresholds=[10, 101], fast_call_max_seconds=5,
                                  duration_bounds_seconds=[1, 5])
        third["apdex"]["targets"][0].update(t_seconds=2, status="business_approved")
        third["apdex"].update(min_call_count=1, failure_policy="confirmed_failures_frustrated",
                             confirmed_failures={"bundle_id": self.bundle.bundle_id,
                                                 "calls": [{"call_id": 1, "evidence": "synthetic failure"}]})
        return [normalize_config(c) for c in (first, second, third)]

    def test_single_joint_and_sequential_configurations(self):
        for i, cfg in enumerate(self.configs()):
            self.invoke(cfg, f"joint{i}")
            with SliceCalculationContext(self.bundle, cfg) as context:
                for name in sorted(CONTEXT_SLICES, reverse=True):
                    builder = SLICE_BUILDERS[name][1]
                    self.assertEqual(builder(self.bundle, cfg), builder(self.bundle, cfg, context=context))
            for name in sorted(CHATTY_SLICES | APDEX_SLICES):
                output = f"single{i}_{name}"
                self.invoke(cfg, output, [name])
                for path in (self.root / output).glob("*.csv"):
                    self.assertEqual(path.read_bytes(), (self.root / f"joint{i}" / path.name).read_bytes())
        self.invoke(self.configs()[0], "again")
        for path in (self.root / "joint0").iterdir():
            self.assertEqual(path.read_bytes(), (self.root / "again" / path.name).read_bytes())

    def test_each_shared_dependency_and_profile_is_built_once(self):
        cfg = self.configs()[1]
        real_class = ap.ApdexSeries
        with ExitStack() as stack:
            operations = stack.enter_context(mock.patch("slice_operations.OperationSeries", wraps=OperationSeries))
            chatty = stack.enter_context(mock.patch.object(db, "ChattySeries", wraps=db.ChattySeries))
            apdex = stack.enter_context(mock.patch.object(ap, "ApdexSeries", wraps=ap.ApdexSeries))
            quality = stack.enter_context(mock.patch("slice_metrics.data_quality", wraps=data_quality))
            calls = stack.enter_context(mock.patch.object(db, "_db_chatty_calls", wraps=db._db_chatty_calls))
            profiles = stack.enter_context(mock.patch.object(db, "profile", wraps=db.profile))
            scores = stack.enter_context(mock.patch.object(ap, "score", wraps=ap.score))
            overall = stack.enter_context(mock.patch.object(real_class, "overall_tables", autospec=True,
                                                             side_effect=real_class.overall_tables))
            # Fallback constructors would conceal an extra OperationSeries.
            stack.enter_context(mock.patch.object(db, "OperationSeries", side_effect=AssertionError("not shared")))
            stack.enter_context(mock.patch.object(ap, "OperationSeries", side_effect=AssertionError("not shared")))
            with SliceCalculationContext(self.bundle, cfg) as context:
                self.assertEqual(operations.call_count + chatty.call_count + apdex.call_count, 0)
                for names in (sorted(CONTEXT_SLICES, reverse=True), sorted(CONTEXT_SLICES)):
                    for name in names:
                        SLICE_BUILDERS[name][1](self.bundle, cfg, context=context)
                self.assertIs(context._chatty.series, context._operations)
                self.assertIs(context._apdex.series, context._operations)
                self.assertEqual(profiles.call_count, len(context._chatty.cache))
                self.assertEqual(scores.call_count, len(context._apdex.cache))
                self.assertGreater(profiles.call_count, 0)
                self.assertGreater(scores.call_count, 0)
                for counter in (operations, chatty, apdex, quality, calls, overall):
                    self.assertEqual(counter.call_count, 1)
            self.assertIsNone(context._chatty)
            self.assertIsNone(context._apdex)
            self.assertIsNone(context._overall_tables)
            self.assertEqual(context._tables, {})

    def test_derive_shares_series_and_paired_tables(self):
        real_class = ap.ApdexSeries
        with mock.patch("slice_operations.OperationSeries", wraps=OperationSeries) as operations, \
                mock.patch.object(db, "ChattySeries", wraps=db.ChattySeries) as chatty, \
                mock.patch.object(ap, "ApdexSeries", wraps=real_class) as apdex, \
                mock.patch.object(db, "_db_chatty_calls", wraps=db._db_chatty_calls) as calls, \
                mock.patch.object(real_class, "overall_tables", autospec=True, side_effect=real_class.overall_tables) as overall:
            self.invoke(self.configs()[1], "counted")
            for counter in (operations, chatty, apdex, calls, overall):
                self.assertEqual(counter.call_count, 1)

    def test_selection_does_not_initialize_other_families(self):
        cfg = self.configs()[1]
        for selected, forbidden in ((CHATTY_SLICES, "slice_apdex.ApdexSeries"),
                                    (APDEX_SLICES, "slice_db_chatty.ChattySeries")):
            with mock.patch(forbidden, side_effect=AssertionError("unused family")):
                for name in sorted(selected):
                    self.invoke(cfg, "lazy_" + name, [name])
        with mock.patch.object(ap, "ApdexSeries", side_effect=AssertionError("unused APDEX")), \
                mock.patch.object(db, "ChattySeries", side_effect=AssertionError("unused DB")):
            self.invoke(cfg, "only_operation", ["operation_history"])

    def test_changed_settings_are_rejected_before_cached_rows_are_returned(self):
        cfg = self.configs()[1]
        variants = []
        for section, key, value in [
            ("db_chatty", "thresholds", [1]), ("db_chatty", "fast_call_max_seconds", 0),
            ("db_chatty", "duration_bounds_seconds", [2]), ("apdex", "min_call_count", 1),
            ("apdex", "failure_policy", "confirmed_failures_frustrated"),
            ("apdex", "confirmed_failures", {"bundle_id": self.bundle.bundle_id, "calls": []}),
            ("apdex", "classes", [{"class_id": "class", "signatures": ["Other"], "t_seconds": 3,
                                     "status": "business_approved", "source": "synthetic"}]),
        ]:
            changed = deepcopy(cfg)
            changed[section][key] = value
            variants.append(changed)
        for key, value in [("t_seconds", 2), ("source", "another source"), ("status", "business_approved")]:
            changed = deepcopy(cfg)
            changed["apdex"]["targets"][0][key] = value
            variants.append(changed)
        with SliceCalculationContext(self.bundle, cfg) as context:
            for name in CHATTY_SLICES | APDEX_SLICES:
                SLICE_BUILDERS[name][1](self.bundle, cfg, context=context)
            for changed in variants:
                for name in CHATTY_SLICES | APDEX_SLICES:
                    with self.assertRaisesRegex(SliceError, "configuration differs"):
                        SLICE_BUILDERS[name][1](self.bundle, changed, context=context)

    def test_nested_mutations_cannot_corrupt_other_tables_or_series(self):
        cfg = self.configs()[1]
        original_bundle, original_config = deepcopy(self.bundle), deepcopy(cfg)
        expected = {n: SLICE_BUILDERS[n][1](self.bundle, cfg) for n in CONTEXT_SLICES}

        def corrupt(value):
            if isinstance(value, dict):
                for child in list(value.values()):
                    corrupt(child)
                value.clear()
            elif isinstance(value, list):
                for child in list(value):
                    corrupt(child)
                value.append("consumer change")

        with SliceCalculationContext(self.bundle, cfg) as context:
            for name in sorted(CHATTY_SLICES | APDEX_SLICES):
                corrupt(SLICE_BUILDERS[name][1](self.bundle, cfg, context=context))
                for other in CONTEXT_SLICES:
                    self.assertEqual(SLICE_BUILDERS[other][1](self.bundle, cfg, context=context), expected[other])
        self.assertEqual(self.bundle, original_bundle)
        self.assertEqual(cfg, original_config)

    def test_empty_cached_tables_are_not_recomputed(self):
        cfg = self.configs()[0]
        cfg["db_chatty"]["thresholds"] = [1000000]
        with mock.patch.object(db, "_db_chatty_calls", wraps=db._db_chatty_calls) as calls, \
                mock.patch.object(ap.ApdexSeries, "overall_tables", autospec=True,
                                  side_effect=ap.ApdexSeries.overall_tables) as overall:
            with SliceCalculationContext(self.bundle, cfg) as context:
                for _ in range(2):
                    self.assertEqual(db.db_chatty_fast_calls(self.bundle, cfg, context=context), [])
                    self.assertEqual(db.db_chatty_calls(self.bundle, cfg, context=context), [])
                    self.assertEqual(ap.apdex_composition(self.bundle, cfg, context=context), [])
                    ap.apdex_overall(self.bundle, cfg, context=context)
            self.assertEqual(calls.call_count, 1)
            self.assertEqual(overall.call_count, 1)


if __name__ == "__main__":
    unittest.main()
