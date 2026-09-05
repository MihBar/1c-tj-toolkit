"""Shared operation preparation, public ownership and invocation isolation."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_slice_operations import saved_series, spec, M1, M2, M3
from derive_slices import run
from slice_config import SliceError, normalize_config
from slice_context import OPERATION_SLICES, SliceCalculationContext
from slice_input import load_bundle
from slice_metrics import SLICE_BUILDERS, data_quality
from slice_operations import OperationSeries, operation_history


class SliceContextTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bundle = saved_series(self.root / "input", [
            spec(M1, 0, db_count=0), spec(M1, 1, db_count=101),
            spec(M2, 5, user="Bob"), spec(M2, 10, signature="Other"),
            spec(M3, 30, db_count=501),
        ])
        self.config = normalize_config({"config_version": "1.0", "slices": sorted(OPERATION_SLICES)})

    def invoke(self, config, output, selection=None):
        path = self.root / (output + ".json")
        path.write_text(json.dumps(config), encoding="utf-8")
        args = ["--analysis-dir", str(self.root / "input"), "--config", str(path),
                "--output-dir", str(self.root / output)]
        if selection:
            args += ["--slices", *selection]
        return run(args)

    def test_lazy_shared_preparation_and_all_builder_orders(self):
        expected = {n: SLICE_BUILDERS[n][1](self.bundle, self.config) for n in OPERATION_SLICES}
        for names in (sorted(OPERATION_SLICES), sorted(OPERATION_SLICES, reverse=True)):
            with mock.patch("slice_operations.OperationSeries", wraps=OperationSeries) as constructor, \
                    mock.patch("slice_metrics.data_quality", wraps=data_quality) as quality:
                with SliceCalculationContext(self.bundle, self.config) as context:
                    self.assertEqual(constructor.call_count, 0)
                    self.assertEqual(quality.call_count, 0)
                    for name in names:
                        self.assertEqual(SLICE_BUILDERS[name][1](self.bundle, self.config, context=context), expected[name])
                    self.assertEqual(constructor.call_count, 1)
                    self.assertEqual(quality.call_count, 1)

    def test_results_do_not_expose_shared_nested_values(self):
        original_bundle = deepcopy(self.bundle)
        original_config = deepcopy(self.config)

        def corrupt(value):
            if isinstance(value, dict):
                for child in list(value.values()):
                    corrupt(child)
                value["consumer_added"] = True
            elif isinstance(value, list):
                for child in list(value):
                    corrupt(child)
                value.clear()

        expected = {n: SLICE_BUILDERS[n][1](self.bundle, self.config) for n in OPERATION_SLICES}
        with SliceCalculationContext(self.bundle, self.config) as context:
            for name in sorted(OPERATION_SLICES):
                rows = SLICE_BUILDERS[name][1](self.bundle, self.config, context=context)
                corrupt(rows)
                for other in OPERATION_SLICES:
                    self.assertEqual(SLICE_BUILDERS[other][1](self.bundle, self.config, context=context), expected[other])
        self.assertEqual(self.bundle, original_bundle)
        self.assertEqual(self.config, original_config)

    def test_binding_snapshot_and_closed_context(self):
        with SliceCalculationContext(self.bundle, self.config) as context:
            changed = deepcopy(self.config)
            changed["operations"]["min_comparison_count"] += 1
            with self.assertRaisesRegex(SliceError, "configuration differs"):
                operation_history(self.bundle, changed, context=context)
            with self.assertRaisesRegex(SliceError, "another bundle"):
                operation_history(load_bundle(self.root / "input"), self.config, context=context)
            self.assertTrue(operation_history(self.bundle, deepcopy(self.config), context=context))
            self.config["operations"]["min_comparison_count"] += 1
            with self.assertRaisesRegex(SliceError, "configuration differs"):
                operation_history(self.bundle, self.config, context=context)
        self.assertIsNone(context._operations)
        self.assertIsNone(context._bundle)
        self.assertIsNone(context._config)
        with self.assertRaisesRegex(SliceError, "closed"):
            operation_history(self.bundle, self.config, context=context)
        context.close()

    def test_exception_closes_context_and_direct_calls_remain_independent(self):
        with self.assertRaisesRegex(RuntimeError, "consumer failed"):
            with SliceCalculationContext(self.bundle, self.config) as context:
                operation_history(self.bundle, self.config, context=context)
                raise RuntimeError("consumer failed")
        self.assertIsNone(context._operations)
        self.assertIsNone(context._bundle)
        expected = operation_history(self.bundle, self.config)
        self.bundle.calls.reverse()
        self.assertEqual(operation_history(self.bundle, self.config), expected)
        self.assertTrue(OperationSeries(self.bundle, self.config).order)

    def test_derive_single_joint_mixed_and_sequential_configurations(self):
        with mock.patch("slice_operations.OperationSeries", wraps=OperationSeries) as constructor, \
                mock.patch("slice_metrics.data_quality", wraps=data_quality) as quality:
            self.invoke(self.config, "joint")
            self.assertEqual(constructor.call_count, 1)
            self.assertEqual(quality.call_count, 1)
        for name in OPERATION_SLICES:
            self.invoke(self.config, name, [name])
            self.assertEqual((self.root / "joint" / (name + ".csv")).read_bytes(),
                             (self.root / name / (name + ".csv")).read_bytes())
        self.invoke(self.config, "mixed", [*sorted(OPERATION_SLICES), "data_quality", "db_chatty", "apdex"])
        for name in OPERATION_SLICES:
            self.assertEqual((self.root / "joint" / (name + ".csv")).read_bytes(),
                             (self.root / "mixed" / (name + ".csv")).read_bytes())
        changed = deepcopy(self.config)
        changed["measurement_ids"] = [M3]
        changed["operations"].update(measurement_order=[M3, M2, M1], min_comparison_count=1,
                                     series_baseline_measurement_id=M2)
        self.invoke(changed, "changed")
        self.invoke(self.config, "again")
        for path in (self.root / "joint").iterdir():
            self.assertEqual(path.read_bytes(), (self.root / "again" / path.name).read_bytes())
        from derive_slices import csv_bytes
        for name in OPERATION_SLICES:
            fields, builder = SLICE_BUILDERS[name]
            self.assertEqual((self.root / "changed" / (name + ".csv")).read_bytes(),
                             csv_bytes(fields, builder(self.bundle, changed)))

    def test_unmigrated_only_selection_does_not_prepare_operations(self):
        with mock.patch("slice_operations.OperationSeries", side_effect=AssertionError("unexpected preparation")):
            self.invoke(self.config, "quality_only", ["data_quality"])


if __name__ == "__main__":
    unittest.main()
