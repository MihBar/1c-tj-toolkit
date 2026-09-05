"""One-pass export lifetimes and failure boundaries on synthetic bundles."""
from contextlib import contextmanager, ExitStack
import gc
import json
import weakref
import unittest
from unittest import mock

import test_slice_context_problems as helpers
from test_derive_slices import hashes
import derive_slices as derive
import slice_context as contexts
import slice_operations as operations
import slice_db_chatty as db
import slice_apdex as ap
import slice_problems as problems
import slice_metrics as metrics
from slice_config import REGISTERED_SLICES


@contextmanager
def track_calculations():
    counts = dict.fromkeys(("context", "operations", "chatty", "apdex", "problems",
                            "quality", "chatty_calls", "overall", "problem_build"), 0)
    references = []
    with ExitStack() as stack:
        def track(module, name, key, keep_reference=False):
            original = getattr(module, name)

            def wrapper(*args, **kwargs):
                counts[key] += 1
                result = original(*args, **kwargs)
                if keep_reference:
                    references.append(weakref.ref(result))
                return result

            # Plain wrappers do not keep mock call arguments (which include Series).
            stack.enter_context(mock.patch.object(module, name, wrapper))

        track(problems.ProblemSeries, "build", "problem_build")
        track(ap.ApdexSeries, "overall_tables", "overall")
        track(derive, "SliceCalculationContext", "context", True)
        track(operations, "OperationSeries", "operations", True)
        track(db, "ChattySeries", "chatty", True)
        track(ap, "ApdexSeries", "apdex", True)
        track(problems, "ProblemSeries", "problems", True)
        track(metrics, "data_quality", "quality")
        fields, _ = metrics.SLICE_BUILDERS["data_quality"]
        stack.enter_context(mock.patch.dict(metrics.SLICE_BUILDERS,
                                            {"data_quality": (fields, metrics.data_quality)}))
        track(db, "_db_chatty_calls", "chatty_calls")
        yield counts, references


class ContextLifetimeTests(unittest.TestCase):
    setUp = helpers.ProblemContextTests.setUp
    config = helpers.ProblemContextTests.config
    invoke = helpers.ProblemContextTests.invoke

    def test_actual_counts_selections_full_set_and_no_retained_series(self):
        cases = [
            ("quality", ["data_quality"], "mixed", (0, 0, 0, 0, 1, 0, 0, 0)),
            ("operations", sorted(contexts.OPERATION_SLICES), "mixed", (1, 0, 0, 0, 1, 0, 0, 0)),
            ("calls", ["db_chatty_calls", "db_chatty_fast_calls"], "mixed", (1, 1, 0, 0, 1, 1, 0, 0)),
            ("overall", ["apdex_overall"], "mixed", (1, 0, 1, 0, 1, 0, 1, 0)),
            ("problem_op", sorted(contexts.PROBLEM_SLICES), "slow", (1, 0, 0, 1, 1, 0, 0, 1)),
            ("problem_db", sorted(contexts.PROBLEM_SLICES), "db", (1, 1, 0, 1, 1, 0, 0, 1)),
            ("problem_ap", sorted(contexts.PROBLEM_SLICES), "ap", (1, 0, 1, 1, 1, 0, 0, 1)),
            ("full", list(REGISTERED_SLICES), "mixed", (1, 1, 1, 1, 2, 1, 1, 1)),
        ]
        keys = ("operations", "chatty", "apdex", "problems", "quality", "chatty_calls", "overall", "problem_build")
        for output, selection, family, expected in cases:
            with self.subTest(output=output), track_calculations() as (counts, refs):
                self.invoke(self.config(family), output, selection)
                self.assertEqual(counts["context"], 1)
                self.assertEqual(tuple(counts[k] for k in keys), expected)
                gc.collect()
                self.assertTrue(all(ref() is None for ref in refs))
        self.assertEqual({p.name for p in (self.root / "overall").glob("*.csv")},
                         {"apdex_overall.csv", "apdex_composition.csv"})

    def test_release_after_last_consumer_without_rebuilding(self):
        events = []
        original = contexts.SliceCalculationContext._release_completed

        def release(context, remaining):
            original(context, remaining)
            events.append((set(remaining), context._operations is not None, context._chatty is not None,
                           context._apdex is not None, context._problems is not None,
                           context._problem_tables is not None, bool(context._tables),
                           context._overall_tables is not None))

        with mock.patch.object(contexts.SliceCalculationContext, "_release_completed", release):
            self.invoke(self.config(), "release", list(REGISTERED_SLICES))
        # After the first problem output, all dependencies and evaluation cache
        # are gone, but the shared triple remains for the other problem views.
        after_build = next(e for e in events if e[5])
        self.assertEqual(after_build[1:5], (False, False, False, False))
        self.assertFalse(any(events[-1][1:]))
        self.assertTrue(all(not e[6] for e in events if not e[0] & {"db_chatty_calls", "db_chatty_fast_calls"}))
        self.assertTrue(all(not e[7] for e in events if not e[0] & {"apdex_overall", "apdex_composition"}))

    def test_public_results_stay_copies_and_projection_cache_is_absent(self):
        cfg = self.config()
        with contexts.SliceCalculationContext(self.bundle, cfg) as context:
            for name in contexts.CONTEXT_SLICES:
                fields, builder = metrics.SLICE_BUILDERS[name]
                public = builder(self.bundle, cfg, context=context)
                expected = derive.csv_bytes(fields, public)
                borrowed = context._export_rows(name)
                self.assertEqual(derive.csv_bytes(fields, borrowed), expected)
                public.clear()
                self.assertEqual(derive.csv_bytes(fields, context._export_rows(name)), expected)
            self.assertEqual(set(context._tables), {"db_chatty_calls"})

    def test_compute_failure_leaves_new_and_existing_outputs_untouched(self):
        cfg = self.config()
        self.invoke(cfg, "existing", list(REGISTERED_SLICES))
        before = hashes(self.root / "existing")
        input_before = hashes(self.root / "input")
        closed = []
        original = contexts.SliceCalculationContext.close

        def close(context):
            original(context)
            closed.append((context._bundle, context._operations, context._chatty,
                           context._apdex, context._problems, context._problem_tables, dict(context._tables)))

        for output in ("new", "existing"):
            args = ["--analysis-dir", str(self.root / "input"), "--config", str(self.root / "existing.json"),
                    "--output-dir", str(self.root / output)]
            if output == "existing":
                args.append("--overwrite")
            args += ["--slices", *REGISTERED_SLICES]
            with mock.patch.object(problems.ProblemSeries, "build", side_effect=RuntimeError("synthetic failure")), \
                    mock.patch.object(contexts.SliceCalculationContext, "close", close), \
                    mock.patch.object(derive.os, "replace", side_effect=AssertionError("publication started")):
                with self.assertRaisesRegex(RuntimeError, "synthetic failure"):
                    derive.run(args)
        self.assertFalse((self.root / "new").exists())
        self.assertEqual(hashes(self.root / "existing"), before)
        self.assertEqual(hashes(self.root / "input"), input_before)
        self.assertEqual(closed, [(None, None, None, None, None, None, {})] * 2)
        self.assertEqual(list(self.root.glob(".tj-slices-*")), [])

    def test_two_runs_different_configs_and_validate_only(self):
        self.invoke(self.config("slow"), "first")
        second = self.config("ap")
        second["apdex"]["targets"][0]["t_seconds"] = 20
        with track_calculations() as (counts, refs):
            self.invoke(second, "second")
            self.assertEqual((counts["context"], counts["apdex"], counts["problem_build"]), (1, 1, 1))
        self.invoke(self.config("slow"), "again")
        self.assertEqual(hashes(self.root / "first"), hashes(self.root / "again"))
        cfg = self.config()
        cfg["slices"] = list(REGISTERED_SLICES)
        path = self.root / "validation.json"
        path.write_text(json.dumps(cfg), encoding="utf-8")
        with track_calculations() as (counts, refs):
            result = derive.run(["--analysis-dir", str(self.root / "input"), "--config", str(path),
                                 "--validate-only", "--output-dir", str(self.root / "not_written")])
            self.assertEqual(result["status"], "PASS")
            self.assertEqual((counts["context"], counts["problem_build"]), (1, 1))
            gc.collect()
            self.assertTrue(all(ref() is None for ref in refs))
        self.assertFalse((self.root / "not_written").exists())

    def test_discovery_commands_do_not_create_context(self):
        with mock.patch.object(derive, "SliceCalculationContext", side_effect=AssertionError("unexpected context")):
            derive.run(["--list-slices"])
            derive.run(["--list-problem-metrics"])


if __name__ == "__main__":
    unittest.main()
