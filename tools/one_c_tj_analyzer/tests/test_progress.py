from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_DIR))

import analyze_1c_tj as analyzer  # noqa: E402
from progress import PHASE_RANGES, ProgressReporter, format_duration, format_units  # noqa: E402


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


def write_log(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "00:00.100000-2000000,CALL,5,Usr=User,OSThread=7,SessionID=10,Context='Module.Method'\n"
        "00:00.050000-200000,DBPOSTGRS,5,Usr=User,OSThread=7,SessionID=10,Sql='SELECT 1'\n"
        "00:00.060000-100,TLOCK,5,Usr=User,OSThread=7,SessionID=10,Context='Module.Method'\n",
        encoding="utf-8-sig",
    )


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ProgressReporterTests(unittest.TestCase):
    def test_jsonl_progress_is_throttled_monotonic_and_has_eta_after_warmup(self) -> None:
        clock = FakeClock()
        stream = io.StringIO()
        reporter = ProgressReporter(
            True, "jsonl", interval=1.0, stream=stream, clock=clock, eta_warmup_seconds=3.0,
        )
        reporter.start("source_inspection", 100, "bytes")
        clock.value = 0.5
        reporter.advance(10)
        clock.value = 1.0
        reporter.advance(15)
        clock.value = 4.0
        reporter.advance(25)
        clock.value = 5.0
        reporter.finish()

        rows = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual(len(rows), 4)
        self.assertEqual([row["phase_progress_percent"] for row in rows], [0.0, 25.0, 50.0, 100.0])
        self.assertEqual(
            [row["overall_progress_percent"] for row in rows],
            sorted(row["overall_progress_percent"] for row in rows),
        )
        self.assertIsNone(rows[1]["eta_seconds"])
        self.assertGreater(rows[2]["eta_seconds"], 0)
        self.assertEqual(rows[-1]["completed_units"], rows[-1]["total_units"])

    def test_disabled_reporter_is_silent(self) -> None:
        stream = io.StringIO()
        reporter = ProgressReporter(False, stream=stream)
        reporter.start("source_discovery")
        reporter.advance()
        reporter.finish()
        self.assertEqual(stream.getvalue(), "")

    def test_human_format_helpers(self) -> None:
        self.assertEqual(format_duration(None), "calculating")
        self.assertEqual(format_duration(3661), "01:01:01")
        self.assertEqual(format_units(1536, "bytes"), "1.5 KiB")
        self.assertEqual(format_units(12, "events"), "12 events")


class AnalyzerProgressIntegrationTests(unittest.TestCase):
    def run_analyzer(self, root: Path, output: Path, *extra: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = analyzer.run([str(root), "--output-dir", str(output), *extra])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_jsonl_progress_covers_pipeline_and_keeps_stdout_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "logs"
            source = root / "measure" / "capture" / "rphost_1" / "26010110.log"
            write_log(source)
            code, stdout, stderr = self.run_analyzer(
                root, Path(temp) / "out", "--progress", "--progress-format", "jsonl",
            )

            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout)["status"], "ok")
            rows = [json.loads(line) for line in stderr.splitlines()]
            self.assertEqual({row["type"] for row in rows}, {"progress"})
            phases = [row["phase"] for row in rows]
            self.assertEqual(set(phases), set(PHASE_RANGES))
            self.assertEqual(rows[-1]["phase"], "result_publication")
            self.assertEqual(rows[-1]["overall_progress_percent"], 100.0)
            self.assertEqual(rows[-1]["eta_seconds"], 0.0)
            self.assertEqual(
                [row["overall_progress_percent"] for row in rows],
                sorted(row["overall_progress_percent"] for row in rows),
            )
            for phase in ("source_inspection", "source_ingestion"):
                finished = [row for row in rows if row["phase"] == phase][-1]
                self.assertGreater(finished["total_units"], 0)
                self.assertEqual(finished["completed_units"], finished["total_units"])

    def test_progress_is_opt_in_and_does_not_change_saved_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "logs"
            write_log(root / "measure" / "capture" / "rphost_1" / "26010110.log")
            plain, reported = Path(temp) / "plain", Path(temp) / "reported"
            code, _, stderr = self.run_analyzer(root, plain)
            self.assertEqual(code, 0)
            self.assertEqual(stderr, "")
            code, _, stderr = self.run_analyzer(root, reported, "--progress")
            self.assertEqual(code, 0)
            self.assertIn("[source_ingestion]", stderr)
            self.assertEqual(
                {path.name: digest(path) for path in plain.iterdir()},
                {path.name: digest(path) for path in reported.iterdir()},
            )

    def test_progress_interval_must_be_finite_and_positive(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "logs"
            root.mkdir()
            for value in ("0", "-1", "nan", "inf"):
                with self.subTest(value=value):
                    with self.assertRaisesRegex(analyzer.AnalyzerError, "finite positive"):
                        analyzer.run([str(root), "--progress-interval", value])


if __name__ == "__main__":
    unittest.main()
