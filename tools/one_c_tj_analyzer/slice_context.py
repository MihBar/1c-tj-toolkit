"""Invocation-local, lazy dependencies for migrated slice builders.

The bundle is borrowed read-only for the lifetime of the context. Configuration
is snapshotted; callers must create another context after changing either input.
No context or calculated rows are attached to the bundle or stored globally.
"""
from __future__ import annotations

from copy import deepcopy

from slice_config import SliceError, canonical_json


OPERATION_SLICES = frozenset((
    "operation_history", "operation_history_all_users",
    "measurement_comparisons", "comparability",
))
CHATTY_SLICES = frozenset((
    "db_chatty", "db_chatty_calls", "db_chatty_fast_calls",
    "db_chatty_duration", "db_chatty_coverage", "db_chatty_changes",
))
APDEX_SLICES = frozenset((
    "apdex", "apdex_uncovered", "apdex_calls", "apdex_coverage",
    "apdex_overall", "apdex_composition", "apdex_changes",
))
PROBLEM_SLICES = frozenset((
    "problem_registry", "problem_history", "problem_rule_coverage",
    "problem_persisting", "problem_unchecked", "problem_new",
    "problem_improved", "problem_worsened",
))
CONTEXT_SLICES = OPERATION_SLICES | CHATTY_SLICES | APDEX_SLICES | PROBLEM_SLICES


class SliceCalculationContext:
    def __init__(self, bundle, config):
        self._bundle = bundle
        self._config = deepcopy(config)
        self._configuration_json = canonical_json(self._config)
        self._operations = None
        self._chatty = None
        self._apdex = None
        self._tables = {}
        self._overall_tables = None
        self._problems = None
        self._problem_tables = None
        self._closed = False

    def __enter__(self):
        self._require_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def _require_open(self):
        if self._closed:
            raise SliceError("Slice calculation context is closed")

    def close(self):
        self._tables.clear()
        self._overall_tables = None
        self._problem_tables = None
        self._problems = None
        self._chatty = None
        self._apdex = None
        self._operations = None
        self._bundle = None
        self._config = None
        self._configuration_json = None
        self._closed = True

    def _validate(self, bundle, config):
        self._require_open()
        if bundle is not self._bundle:
            raise SliceError("Slice calculation context belongs to another bundle")
        if canonical_json(config) != self._configuration_json:
            raise SliceError("Slice calculation context configuration differs")

    def _get_operations(self):
        if self._operations is None:
            # Delayed import preserves standalone imports of the slice modules.
            from slice_operations import OperationSeries
            self._operations = OperationSeries(self._bundle, self._config)
        return self._operations

    def _operation_rows(self, bundle, config, build):
        self._validate(bundle, config)
        # History rows contain nested mutable lists/dicts. Nothing owned by the
        # shared series may escape through the public list[dict] API.
        return deepcopy(build(self._get_operations()))

    def _get_chatty(self):
        if self._chatty is None:
            from slice_db_chatty import ChattySeries
            self._chatty = ChattySeries(self._bundle, self._config, series=self._get_operations())
        return self._chatty

    def _get_apdex(self):
        if self._apdex is None:
            from slice_apdex import ApdexSeries
            self._apdex = ApdexSeries(self._bundle, self._config, series=self._get_operations())
        return self._apdex

    def _get_problem_tables(self):
        if self._problem_tables is None:
            if self._problems is None:
                from slice_problems import ProblemSeries
                # ProblemSeries retains the existing validation order and asks
                # for DB/APDEX only when those families occur in its rules.
                self._problems = ProblemSeries(self._bundle, self._config, context=self)
            self._problem_tables = self._problems.build()
        return self._problem_tables

    def _family_table(self, name):
        """Borrowed rows: retain shared calculations, not output projections."""
        if name == "db_chatty_fast_calls":
            return [r for r in self._family_table("db_chatty_calls") if r["is_fast_call"]]
        if name == "apdex_uncovered":
            return [g for g in self._get_apdex().groups() if g["t_us"] is None and g["count"]]
        if name in ("apdex_overall", "apdex_composition"):
            if self._overall_tables is None:
                self._overall_tables = self._get_apdex().overall_tables()
            return self._overall_tables[0 if name == "apdex_overall" else 1]
        if name in CHATTY_SLICES:
            import slice_db_chatty
            if name == "db_chatty_calls":
                if name not in self._tables:
                    self._tables[name] = slice_db_chatty._db_chatty_calls(self._get_chatty())
                return self._tables[name]
            return getattr(slice_db_chatty, "_" + name)(self._get_chatty())
        if name in APDEX_SLICES:
            import slice_apdex
            return getattr(slice_apdex, "_" + name)(self._get_apdex())
        if name in PROBLEM_SLICES:
            import slice_problems
            return getattr(slice_problems, "_" + name)(self._get_problem_tables())
        raise SliceError(f"Unsupported context family slice: {name}")

    def _export_rows(self, name):
        """Only derive_slices' read-only serializer may borrow these rows.

        Public builders always copy; their consumers may freely mutate results.
        """
        self._require_open()
        if name in OPERATION_SLICES:
            import slice_operations
            return getattr(slice_operations, "_" + name)(self._get_operations())
        return self._family_table(name)

    def _release_completed(self, remaining):
        """Fixed family lifetimes for derive's one-pass selected-slice loop.

        Arbitrary/repeated public builder calls do not use this release path.
        Pending problem construction keeps its rule dependencies alive even when
        their own exported tables have already been consumed.
        """
        self._require_open()
        pending_problems = bool(remaining & PROBLEM_SLICES)
        needs_problem_build = pending_problems and self._problem_tables is None
        rules = self._config["problems"]["rules"] if needs_problem_build else []
        needs_chatty = bool(remaining & CHATTY_SLICES) or any(r["metric"].startswith("db_chatty.") for r in rules)
        needs_apdex = bool(remaining & APDEX_SLICES) or any(r["metric"].startswith("apdex.") for r in rules)
        if self._problem_tables is not None:
            # The completed tables no longer need the evaluation cache or Series.
            self._problems = None
        if not pending_problems:
            self._problem_tables = None
        if not remaining & {"apdex_overall", "apdex_composition"}:
            self._overall_tables = None
        if not remaining & {"db_chatty_calls", "db_chatty_fast_calls"}:
            self._tables.clear()
        if not needs_chatty:
            self._chatty = None
        if not needs_apdex:
            self._apdex = None
        if not (remaining & OPERATION_SLICES or needs_chatty or needs_apdex or needs_problem_build):
            self._operations = None

    def _family_rows(self, bundle, config, name):
        self._validate(bundle, config)
        return deepcopy(self._family_table(name))


def operation_rows(bundle, config, build, context=None):
    """Keep independent two-argument builder calls independent as well."""
    if context is not None:
        return context._operation_rows(bundle, config, build)
    with SliceCalculationContext(bundle, config) as temporary:
        return temporary._operation_rows(bundle, config, build)


def family_rows(bundle, config, name, context=None):
    if context is not None:
        return context._family_rows(bundle, config, name)
    with SliceCalculationContext(bundle, config) as temporary:
        return temporary._family_rows(bundle, config, name)
