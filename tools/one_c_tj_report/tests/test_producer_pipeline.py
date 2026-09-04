"""End-to-end smoke test using the real analyzer and slice producers.

Only raw synthetic TJ and configuration are prepared by the fixture helper.
Every JSON/CSV consumed by the report is produced by the command-line tools.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from pypdf import PdfReader


REPORT_DIR = Path(__file__).resolve().parents[1]
ANALYZER_DIR = REPORT_DIR.parent / "one_c_tj_analyzer"
EXAMPLES_DIR = REPORT_DIR / "examples"
sys.path.insert(0, str(REPORT_DIR))
sys.path.insert(0, str(EXAMPLES_DIR))

from prepare_pipeline_demo import (  # noqa: E402
    OPERATION_FAST,
    OPERATION_SPARSE,
    SERIES_MEASUREMENTS,
    SINGLE_MEASUREMENT,
    prepare,
)
from report_config import load_config  # noqa: E402
from report_input import load_input  # noqa: E402
from report_model import DisplayState, build_model, format_cell, stable_key  # noqa: E402


def _pdf_text(path: Path) -> str:
    return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)


def _normalized(value: str) -> str:
    return " ".join(value.split())


def _main_cells(model):
    for section in model.main_sections:
        for table in section.tables:
            for row in table.rows:
                yield row, table, section


def _cell(model, source_file: str, field: str, *, non_null: bool = True):
    for row, table, section in _main_cells(model):
        for cell in row.cells:
            if cell.source_file == source_file and cell.field == field:
                if not non_null or cell.value is not None:
                    return cell, row, table, section
    raise AssertionError(f"main cell not found: {source_file}:{field}")


class ProducerPipelineTests(unittest.TestCase):
    maxDiff = None

    def _run(self, *arguments: object, expected: int = 0) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [str(argument) for argument in arguments],
            cwd=self.outside,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
        self.assertEqual(
            result.returncode,
            expected,
            f"command failed ({result.returncode}): {result.args}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        return result

    def _python(self, script: Path, *arguments: object, expected: int = 0):
        return self._run(sys.executable, "-B", script, *arguments, expected=expected)

    def _source_row(self, data, cell):
        name = Path(cell.source_file).stem
        rows = data.tables.get(name, data.slices.get(name))
        self.assertIsNotNone(rows, cell.source_file)
        return next(row for row in rows if stable_key(name, row) == cell.row_key)

    def _assert_source_cell(self, data, cell) -> None:
        source = self._source_row(data, cell)
        value = source
        for part in cell.field.split("/"):
            if not part:
                continue
            value = value[int(part)] if isinstance(value, list) else value[part]
        self.assertEqual(value, cell.value)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="tj-report-producer-pipeline-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.demo = prepare(self.root / "demo")
        self.outside = self.root / "different-working-directory"
        self.outside.mkdir()
        self.analysis_series = self.demo / "analysis" / "series"
        self.analysis_single = self.demo / "analysis" / "single"
        self.slices = self.demo / "slices" / "series"
        self.slices_single = self.demo / "slices" / "single"
        self.reports = self.demo / "reports"
        self.reports.mkdir(parents=True)

    def test_real_producers_verifiers_three_reports_and_failure_atomicity(self):
        analyzer = ANALYZER_DIR / "analyze_1c_tj.py"
        verify_analysis = ANALYZER_DIR / "verify_analysis.py"
        derive = ANALYZER_DIR / "derive_slices.py"
        verify_slices = ANALYZER_DIR / "verify_slices.py"
        audit = ANALYZER_DIR / "audit_stage1.py"

        produced = self._python(
            analyzer,
            self.demo / "raw" / "series",
            "--output-dir",
            self.analysis_series,
            "--capture-id",
            "synthetic-producer-series-test",
            "--archive-mode",
            "never",
            "--salvage-nul-prefix",
        )
        self.assertEqual(json.loads(produced.stdout)["status"], "partial")

        checked = self._python(
            verify_analysis, "--analysis-dir", self.analysis_series
        )
        checked_json = json.loads(checked.stdout)
        self.assertEqual(checked_json["status"], "PASS")
        self.assertEqual(checked_json["observation_state"], "partial")

        calculated = self._python(
            derive,
            "--analysis-dir",
            self.analysis_series,
            "--config",
            self.demo / "configs" / "analytics.series.json",
            "--output-dir",
            self.slices,
        )
        calculated_json = json.loads(calculated.stdout)
        self.assertEqual(calculated_json["status"], "PASS")
        self.assertEqual(len(calculated_json["selected_slices"]), 26)

        checked_slices = self._python(
            verify_slices,
            "--analysis-dir",
            self.analysis_series,
            "--slices-dir",
            self.slices,
        )
        self.assertEqual(json.loads(checked_slices.stdout)["status"], "PASS")

        audited = self._python(
            audit,
            "--analysis-dir",
            self.analysis_series,
            "--slices-dir",
            self.slices,
        )
        audited_json = json.loads(audited.stdout)
        self.assertEqual(audited_json["status"], "PASS")
        self.assertEqual(audited_json["measurement_order"], SERIES_MEASUREMENTS)

        single_produced = self._python(
            analyzer,
            self.demo / "raw" / "single",
            "--output-dir",
            self.analysis_single,
            "--capture-id",
            "synthetic-producer-single-test",
            "--archive-mode",
            "never",
        )
        self.assertEqual(json.loads(single_produced.stdout)["status"], "ok")
        single_checked = self._python(
            verify_analysis, "--analysis-dir", self.analysis_single
        )
        self.assertEqual(json.loads(single_checked.stdout)["status"], "PASS")
        single_calculated = self._python(
            derive,
            "--analysis-dir",
            self.analysis_single,
            "--config",
            self.demo / "configs" / "analytics.single.json",
            "--output-dir",
            self.slices_single,
        )
        self.assertEqual(json.loads(single_calculated.stdout)["status"], "PASS")
        single_slices_checked = self._python(
            verify_slices,
            "--analysis-dir",
            self.analysis_single,
            "--slices-dir",
            self.slices_single,
        )
        self.assertEqual(json.loads(single_slices_checked.stdout)["status"], "PASS")
        single_audited = self._python(
            audit,
            "--analysis-dir",
            self.analysis_single,
            "--slices-dir",
            self.slices_single,
        )
        self.assertEqual(json.loads(single_audited.stdout)["status"], "PASS")

        entrypoints = {
            "overview": REPORT_DIR / "build_report.py",
            "comparison": REPORT_DIR / "build_trend_report.py",
            "history": REPORT_DIR / "build_iteration_history_report.py",
        }
        for kind, script in entrypoints.items():
            self._python(
                script,
                "--analysis-dir",
                self.analysis_series,
                "--slices-dir",
                self.slices,
                "--report-config",
                self.demo / "configs" / f"{kind}.series.json",
                "--output",
                self.reports / f"{kind}.pdf",
            )

        validation = self.demo / "validation"
        validation.mkdir()
        single_pdfs = {}
        for kind, script in entrypoints.items():
            output = validation / (
                "single-no-slices.pdf"
                if kind == "overview"
                else f"single-no-slices-{kind}.pdf"
            )
            self._python(
                script,
                "--analysis-dir",
                self.analysis_single,
                "--report-config",
                self.demo / "configs" / f"{kind}.single-no-slices.json",
                "--output",
                output,
            )
            single_pdfs[kind] = output
        single_with_slice_pdfs = {}
        for kind in ("comparison", "history"):
            output = validation / f"single-with-slices-{kind}.pdf"
            self._python(
                entrypoints[kind],
                "--analysis-dir",
                self.analysis_single,
                "--slices-dir",
                self.slices_single,
                "--report-config",
                self.demo / "configs" / f"{kind}.single-with-slices.json",
                "--output",
                output,
            )
            single_with_slice_pdfs[kind] = output

        data = load_input(self.analysis_series, self.slices)
        self.assertEqual(data.measurement_ids, set(SERIES_MEASUREMENTS))
        self.assertEqual(data.slice_manifest["configuration"]["operations"]["measurement_order"], SERIES_MEASUREMENTS)
        self.assertFalse(data.manifest["analysis_complete"])
        self.assertEqual(len(data.slices), 26)

        models = {}
        texts = {}
        for kind in entrypoints:
            config = load_config(self.demo / "configs" / f"{kind}.series.json")
            models[kind] = build_model(data, config)
            texts[kind] = _pdf_text(self.reports / f"{kind}.pdf")
            self.assertIn("СИНТЕТИЧЕСКИЕ ДАННЫЕ", texts[kind])
            self.assertIn("частичные данные", texts[kind])

        traced = set()
        for model in models.values():
            for row, _table, _section in _main_cells(model):
                for cell in row.cells:
                    if cell.source_file.endswith(".csv"):
                        self._assert_source_cell(data, cell)
                        traced.add((cell.source_file, cell.row_key, cell.field))
        self.assertGreater(len(traced), 100)
        self.assertTrue(
            {
                "operations.csv",
                "heavy_sql.csv",
                "errors.csv",
                "locks.csv",
                "data_quality.csv",
                "measurement_comparisons.csv",
                "comparability.csv",
                "apdex_overall.csv",
                "apdex_composition.csv",
                "apdex_coverage.csv",
                "operation_history.csv",
                "problem_history.csv",
            }
            <= {source for source, _row, _field in traced}
        )

        overview_config = load_config(self.demo / "configs" / "overview.series.json")
        operation_p95 = max(
            (
                cell
                for row, _table, _section in _main_cells(models["overview"])
                for cell in row.cells
                if cell.source_file == "operations.csv"
                and cell.field == "p95_us"
                and cell.value is not None
            ),
            key=lambda cell: cell.value,
        )
        self.assertEqual(operation_p95.value, 3_600_000)
        self.assertEqual(operation_p95.unit, "us")
        self._assert_source_cell(data, operation_p95)
        self.assertIn(
            _normalized(format_cell(operation_p95, overview_config)),
            _normalized(texts["overview"]),
        )
        self.assertRegex(
            _normalized(texts["overview"]),
            re.escape(_normalized(format_cell(operation_p95, overview_config)))
            + r" \[V\d{4}\]",
        )

        overall_section = next(
            section
            for section in models["overview"].main_sections
            if any(
                cell.source_file == "apdex_overall.csv"
                and cell.field == "apdex"
                and cell.value is not None
                for table in section.tables
                for row in table.rows
                for cell in row.cells
            )
        )
        overall = next(
            cell
            for table in overall_section.tables
            for row in table.rows
            for cell in row.cells
            if cell.source_file == "apdex_overall.csv" and cell.field == "apdex"
        )
        overall_source = self._source_row(data, overall)
        self._assert_source_cell(data, overall)
        self.assertEqual(overall.unit, "")
        composition_rows = [
            row
            for table in overall_section.tables
            if table.name == "apdex_composition"
            for row in table.rows
        ]
        coverage_rows = [
            row
            for table in overall_section.tables
            if table.name == "apdex_coverage"
            for row in table.rows
        ]
        self.assertEqual(
            len(composition_rows), int(overall_source["composition_row_count"])
        )
        self.assertEqual(len(coverage_rows), 1)
        for row in composition_rows:
            source = self._source_row(data, row.cells[0])
            self.assertEqual(source["overall_id"], overall_source["overall_id"])
        coverage_source = self._source_row(data, coverage_rows[0].cells[0])
        self.assertEqual(
            (
                coverage_source["population_scope"],
                coverage_source["measurement_ids"],
                coverage_source["failure_policy"],
            ),
            (
                overall_source["population_scope"],
                overall_source["measurement_ids"],
                overall_source["failure_policy"],
            ),
        )
        composition = next(
            cell
            for row in composition_rows
            for cell in row.cells
            if cell.field == "contribution_to_overall_apdex"
        )
        coverage = next(
            cell
            for cell in coverage_rows[0].cells
            if cell.field == "covered_call_count"
        )
        for cell in (overall, composition, coverage):
            self._assert_source_cell(data, cell)
            self.assertIn(
                _normalized(format_cell(cell, overview_config)),
                _normalized(texts["overview"]),
            )
            self.assertRegex(
                _normalized(texts["overview"]),
                re.escape(_normalized(format_cell(cell, overview_config)))
                + r" \[V\d{4}\]",
            )

        comparison_section = next(
            section
            for section in models["comparison"].main_sections
            if any(
                cell.source_file == "measurement_comparisons.csv"
                and cell.field == "p95_us_delta_absolute"
                and cell.value is not None
                for table in section.tables
                for row in table.rows
                for cell in row.cells
            )
            and any(
                cell.source_file == "comparability.csv"
                and cell.field == "comparability_status"
                for table in section.tables
                for row in table.rows
                for cell in row.cells
            )
        )
        delta = next(
            cell
            for table in comparison_section.tables
            for row in table.rows
            for cell in row.cells
            if cell.source_file == "measurement_comparisons.csv"
            and cell.field == "p95_us_delta_absolute"
            and cell.value is not None
        )
        comparable = next(
            cell
            for table in comparison_section.tables
            for row in table.rows
            for cell in row.cells
            if cell.source_file == "comparability.csv"
            and cell.field == "comparability_status"
        )
        delta_source = self._source_row(data, delta)
        comparable_source = self._source_row(data, comparable)
        self.assertEqual(
            delta_source["comparison_id"], comparable_source["comparison_id"]
        )
        side_cells = {
            cell.field: cell
            for table in comparison_section.tables
            for row in table.rows
            for cell in row.cells
            if cell.source_file == "measurement_comparisons.csv"
            and cell.field in {"reference_measurement_id", "current_measurement_id"}
        }
        self.assertEqual(set(side_cells), {"reference_measurement_id", "current_measurement_id"})
        for cell in (delta, comparable, *side_cells.values()):
            self._assert_source_cell(data, cell)
        self.assertEqual(delta.unit, "us")
        comparison_config = load_config(
            self.demo / "configs" / "comparison.series.json"
        )
        self.assertIn(
            _normalized(format_cell(delta, comparison_config)),
            _normalized(texts["comparison"]),
        )
        self.assertRegex(
            _normalized(texts["comparison"]),
            re.escape(_normalized(format_cell(delta, comparison_config)))
            + r" \[V\d{4}\]",
        )
        self.assertIn(str(comparable.value), texts["comparison"])

        order, *_ = _cell(
            models["history"], "operation_history.csv", "measurement_order"
        )
        problem_status, *_ = _cell(
            models["history"], "problem_history.csv", "threshold_status"
        )
        self._assert_source_cell(data, order)
        self._assert_source_cell(data, problem_status)
        self.assertIn(str(problem_status.value), texts["history"])
        self.assertRegex(
            _normalized(texts["history"]),
            re.escape(str(problem_status.value)) + r" \[V\d{4}\]",
        )
        history_groups = {}
        missing_history_value = None
        for row, table, section in _main_cells(models["history"]):
            if table.name != "operation_history":
                continue
            cells = {cell.field: cell.value for cell in row.cells}
            history_groups.setdefault(section.id, []).append(cells["measurement_order"])
            if cells["observation_status"] == "not_observed":
                missing_history_value = next(
                    cell for cell in row.cells if cell.field == "avg_us"
                )
                self.assertEqual(row.state, DisplayState.NO_OBSERVATIONS)
        self.assertTrue(history_groups)
        for orders in history_groups.values():
            self.assertEqual(orders, [1, 2, 3])
        self.assertIsNotNone(missing_history_value)
        self.assertIsNone(missing_history_value.value)
        history_config = load_config(self.demo / "configs" / "history.series.json")
        self.assertEqual(
            format_cell(missing_history_value, history_config), "- (нет наблюдений)"
        )
        history_main = texts["history"].split("ТЕХНИЧЕСКОЕ ПРИЛОЖЕНИЕ", 1)[0]
        self.assertIn("- (нет наблюдений)", history_main)
        missing_pairs = set()
        for row, table, _section in _main_cells(models["history"]):
            if table.name != "operation_history":
                continue
            observation = next(
                cell for cell in row.cells if cell.field == "observation_status"
            )
            if observation.value != "not_observed":
                continue
            source = self._source_row(data, observation)
            self.assertEqual(source["count"], 0)
            self.assertIsNone(source["avg_us"])
            self.assertIsNone(source["p95_us"])
            missing_pairs.add((source["signature"], source["measurement_id"]))
        self.assertEqual(
            missing_pairs,
            {
                (OPERATION_FAST, SERIES_MEASUREMENTS[1]),
                (OPERATION_SPARSE, SERIES_MEASUREMENTS[2]),
            },
        )

        single_data = load_input(self.analysis_single)
        self.assertEqual(single_data.measurement_ids, {SINGLE_MEASUREMENT})
        self.assertFalse(single_data.slices)
        single_config = load_config(
            self.demo / "configs" / "overview.single-no-slices.json"
        )
        single_model = build_model(single_data, single_config)
        self.assertTrue(
            any(
                table.state == DisplayState.NOT_CALCULATED
                for section in single_model.main_sections
                for table in section.tables
            )
        )
        single_texts = {kind: _pdf_text(path) for kind, path in single_pdfs.items()}
        self.assertIn("не рассчитано", single_texts["overview"])
        for kind in ("comparison", "history"):
            config = load_config(
                self.demo / "configs" / f"{kind}.single-no-slices.json"
            )
            model = build_model(single_data, config)
            self.assertTrue(
                any(
                    table.state == DisplayState.NOT_CALCULATED
                    for section in model.main_sections
                    for table in section.tables
                )
            )
            self.assertIn("не рассчитано", single_texts[kind])

        single_with_slices = load_input(self.analysis_single, self.slices_single)
        self.assertEqual(single_with_slices.measurement_ids, {SINGLE_MEASUREMENT})
        self.assertEqual(len(single_with_slices.slices), 26)
        sliced_models = {}
        for kind in ("comparison", "history"):
            config = load_config(
                self.demo / "configs" / f"{kind}.single-with-slices.json"
            )
            model = build_model(single_with_slices, config)
            sliced_models[kind] = model
            text = _pdf_text(single_with_slice_pdfs[kind])
            self.assertIn(SINGLE_MEASUREMENT, text)
        for row in single_with_slices.slices["measurement_comparisons"]:
            self.assertEqual(row["current_measurement_id"], SINGLE_MEASUREMENT)
            self.assertIn(
                row["reference_measurement_id"], {None, SINGLE_MEASUREMENT}
            )
        single_history_orders = [
            cell.value
            for row, table, _section in _main_cells(sliced_models["history"])
            if table.name == "operation_history"
            for cell in row.cells
            if cell.field == "measurement_order"
        ]
        self.assertTrue(single_history_orders)
        self.assertEqual(set(single_history_orders), {1})

        operations = next(
            table
            for section in single_model.sections
            for table in section.tables
            if table.name == "operations"
        )
        sparse = next(
            row
            for row in operations.rows
            if next(cell.value for cell in row.cells if cell.field == "signature")
            == OPERATION_SPARSE
        )
        sparse_cells = {cell.field: cell for cell in sparse.cells}
        self.assertEqual(sparse_cells["db_per_call"].value, 0)
        self.assertEqual(sparse_cells["db_per_call"].state, DisplayState.READY)
        self.assertIsNone(sparse_cells["cpu_us"].value)
        self.assertEqual(sparse_cells["cpu_us"].state, DisplayState.UNAVAILABLE)

        sparse_key = next(
            row.key
            for row, _table, _section in _main_cells(models["overview"])
            if any(
                cell.source_file == "operations.csv"
                and cell.field == "signature"
                and cell.value == OPERATION_SPARSE
                for cell in row.cells
            )
        )
        displayed_zero = next(
            cell
            for row, _table, _section in _main_cells(models["overview"])
            if row.key == sparse_key
            for cell in row.cells
            if cell.source_file == "operations.csv" and cell.field == "db_per_call"
        )
        self.assertEqual(displayed_zero.value, 0)
        self.assertEqual(displayed_zero.state, DisplayState.READY)
        self._assert_source_cell(data, displayed_zero)
        overview_main = texts["overview"].split("ТЕХНИЧЕСКОЕ ПРИЛОЖЕНИЕ", 1)[0]
        label_position = overview_main.index("Сверка остатков с неполными счетчиками")
        zero_context = overview_main[label_position : label_position + 2_000]
        self.assertIn(format_cell(displayed_zero, overview_config), zero_context)

        self.assertEqual(data.slices["problem_unchecked"], [])
        empty_problem_tables = [
            table
            for section in models["comparison"].main_sections
            for table in section.tables
            if table.name == "problem_unchecked"
        ]
        self.assertEqual(len(empty_problem_tables), 1)
        self.assertEqual(empty_problem_tables[0].rows, [])
        self.assertEqual(empty_problem_tables[0].state, DisplayState.NO_OBSERVATIONS)
        comparison_main = texts["comparison"].split(
            "ТЕХНИЧЕСКОЕ ПРИЛОЖЕНИЕ", 1
        )[0]
        empty_position = comparison_main.index("Последний снимок: нет проверки")
        self.assertIn("нет наблюдений", comparison_main[empty_position : empty_position + 500])

        atomic = self.demo / "validation" / "atomic-existing.pdf"
        shutil.copyfile(single_pdfs["overview"], atomic)
        before = hashlib.sha256(atomic.read_bytes()).hexdigest()
        corrupt = self.demo / "validation" / "corrupt-analysis"
        shutil.copytree(self.analysis_single, corrupt)
        with (corrupt / "operations.csv").open("ab") as stream:
            stream.write(b"\ncorrupt")
        failed = self._python(
            entrypoints["overview"],
            "--analysis-dir",
            corrupt,
            "--report-config",
            self.demo / "configs" / "overview.single-no-slices.json",
            "--output",
            atomic,
            "--overwrite",
            expected=2,
        )
        self.assertIn("ERROR:", failed.stderr)
        self.assertEqual(before, hashlib.sha256(atomic.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
