from __future__ import annotations

import csv
import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_DIR))

import analyze_1c_tj as analyzer  # noqa: E402


def write_log(path: Path, user: str, call_duration: int, db_duration: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = (
        f"00:00.100000-{call_duration},CALL,5,Usr={user},OSThread=7,SessionID=10,"
        "CpuTime=500000,Memory=1024,MemoryPeak=4096,InBytes=20,OutBytes=2048,"
        "Context='ОбщийМодуль.Тест.Метод\nВторая строка'\n"
        f"00:00.050000-{db_duration},DBPOSTGRS,5,Usr={user},OSThread=7,SessionID=10,"
        "RowsAffected=12,Sql='SELECT T1.ID FROM Table1 T1 WHERE T1.ID = 123',"
        "Context='ОбщийМодуль.Тест.Метод'\n"
        "00:00.060000-100,TLOCK,5,Usr=" + user + ",OSThread=7,SessionID=10,"
        "Context='ОбщийМодуль.Тест.Метод'\n"
    )
    path.write_text(text, encoding="utf-8-sig")


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AnalyzerTests(unittest.TestCase):
    def test_nested_logs_metrics_and_identical_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "logs"
            write_log(root / "measure_a" / "capture" / "rphost_1" / "26010110.log", "User1", 2_000_000, 200_000)
            write_log(root / "measure_b" / "capture" / "rphost_2" / "26010210.log", "User1", 4_000_000, 300_000)
            output = Path(temp) / "out"
            code = analyzer.run([str(root), "-o", str(output)])
            self.assertEqual(code, 0)
            payload = json.loads((output / "analysis_metrics.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["counts"]["datasets"], 2)
            self.assertEqual(payload["counts"]["operations"], 2)
            self.assertEqual(payload["counts"]["identical_operation_rows"], 2)
            operations = payload["operations"]
            self.assertEqual(sorted(item["db_count"] for item in operations), [1, 1])
            self.assertEqual(sorted(item["lock_count"] for item in operations), [1, 1])
            self.assertEqual({item["signature"] for item in operations}, {"ОбщийМодуль.Тест.Метод"})
            self.assertEqual({item["memory"] for item in operations}, {1024})

    def test_db_linkage_is_isolated_by_process(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "logs"
            write_log(root / "measure" / "capture" / "rphost_1" / "26010110.log", "User", 2_000_000, 200_000)
            write_log(root / "measure" / "capture" / "rphost_2" / "26010110.log", "User", 2_000_000, 300_000)
            output = Path(temp) / "out"
            self.assertEqual(analyzer.run([str(root), "-o", str(output)]), 0)
            payload = json.loads((output / "analysis_metrics.json").read_text(encoding="utf-8"))
            calls = sorted(payload["top_calls"], key=lambda row: row["process"])
            self.assertEqual([row["db_count"] for row in calls], [1, 1])
            self.assertEqual(payload["linkage"][0]["dbpostgrs_linked_count_percent"], 100.0)

    def test_identical_operations_use_actual_time_and_measurement_aggregation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "logs"
            write_log(root / "z_first" / "capture" / "rphost_1" / "26010110.log", "User", 2_000_000, 200_000)
            write_log(root / "a_second" / "capture_1" / "rphost_1" / "26010210.log", "User", 4_000_000, 300_000)
            write_log(root / "a_second" / "capture_2" / "rphost_2" / "26010211.log", "User", 6_000_000, 400_000)
            output = Path(temp) / "out"
            self.assertEqual(analyzer.run([str(root), "-o", str(output)]), 0)
            payload = json.loads((output / "analysis_metrics.json").read_text(encoding="utf-8"))
            rows = payload["identical_operations"]
            self.assertEqual(
                [row["measurement_id"] for row in rows],
                ["z_first@2026-01-01", "a_second@2026-01-02"],
            )
            self.assertEqual(rows[1]["count"], 2)
            self.assertEqual(rows[1]["avg_us"], 5_000_000)
            self.assertEqual(rows[1]["avg_us_delta"], 3_000_000)
            self.assertEqual(rows[1]["avg_us_delta_percent"], 150.0)

    def test_operations_are_split_by_actual_date_inside_one_capture_folder(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "logs"
            write_log(root / "capture" / "user" / "rphost_1" / "26010123.log", "User", 2_000_000, 200_000)
            write_log(root / "capture" / "user" / "rphost_1" / "26010200.log", "User", 4_000_000, 300_000)
            output = Path(temp) / "out"
            self.assertEqual(analyzer.run([str(root), "-o", str(output)]), 0)
            payload = json.loads((output / "analysis_metrics.json").read_text(encoding="utf-8"))
            self.assertEqual(len(payload["operations"]), 2)
            self.assertEqual(
                {row["measurement_id"] for row in payload["operations"]},
                {"capture@2026-01-01", "capture@2026-01-02"},
            )

    def test_multiline_record_and_sql_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "logs"
            write_log(root / "m" / "c" / "rphost_1" / "26010110.log", "User", 2_000_000, 200_000)
            output = Path(temp) / "out"
            self.assertEqual(analyzer.run([str(root), "-o", str(output)]), 0)
            payload = json.loads((output / "analysis_metrics.json").read_text(encoding="utf-8"))
            sql = payload["heavy_sql"][0]
            self.assertIn("where t1 . id = <number>", sql["normalized_sql"])
            self.assertEqual(sql["rows_affected"], 12)

    def test_damaged_nul_file_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "logs"
            good = root / "m" / "c" / "rphost_1" / "26010110.log"
            write_log(good, "User", 2_000_000, 200_000)
            damaged = root / "m" / "c" / "rphost_2" / "26010111.log"
            damaged.parent.mkdir(parents=True, exist_ok=True)
            damaged.write_bytes(good.read_bytes() + b"\x00broken")
            output = Path(temp) / "out"
            self.assertEqual(analyzer.run([str(root), "-o", str(output)]), 0)
            payload = json.loads((output / "analysis_metrics.json").read_text(encoding="utf-8"))
            damaged_rows = [row for row in payload["files"] if row["source"].endswith("26010111.log")]
            self.assertEqual(damaged_rows[0]["status"], "skipped")
            self.assertIsNotNone(damaged_rows[0]["nul_offset"])

    def test_damaged_nul_file_can_salvage_only_complete_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "logs"
            damaged = root / "m" / "c" / "rphost_1" / "26010110.log"
            write_log(damaged, "User", 2_000_000, 200_000)
            damaged.write_bytes(damaged.read_bytes() + b"\x00binary-tail")
            output = Path(temp) / "out"
            self.assertEqual(
                analyzer.run([str(root), "-o", str(output), "--salvage-nul-prefix"]),
                0,
            )
            payload = json.loads((output / "analysis_metrics.json").read_text(encoding="utf-8"))
            source_row = payload["files"][0]
            self.assertEqual(source_row["status"], "partial_nul_salvaged")
            self.assertGreater(source_row["analyzed_bytes"], 0)
            self.assertLess(source_row["analyzed_bytes"], source_row["size_bytes"])
            self.assertEqual(payload["counts"]["call_observations"], 1)
            self.assertFalse(payload["analysis_complete"])

    def test_hash_mode_does_not_merge_independent_logical_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "logs"
            first = root / "measure" / "capture_a" / "rphost_1" / "26010110.log"
            second = root / "measure" / "capture_b" / "rphost_1" / "26010110.log"
            write_log(first, "User", 2_000_000, 200_000)
            second.parent.mkdir(parents=True, exist_ok=True)
            second.write_bytes(first.read_bytes())
            output = Path(temp) / "out"
            self.assertEqual(analyzer.run([str(root), "-o", str(output), "--hash-sources"]), 0)
            payload = json.loads((output / "analysis_metrics.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["counts"]["sources_analyzed"], 2)
            self.assertEqual(payload["counts"]["sources_skipped_as_duplicates"], 0)
            self.assertEqual(len(payload["top_calls"]), 2)

    def test_zip_is_used_when_no_extracted_copy_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "logs"
            root.mkdir()
            source = Path(temp) / "26010110.log"
            write_log(source, "ZipUser", 2_000_000, 200_000)
            archive = root / "measure_zip.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
                stream.write(source, "capture/rphost_1/26010110.log")
            output = Path(temp) / "out"
            self.assertEqual(analyzer.run([str(root), "-o", str(output)]), 0)
            payload = json.loads((output / "analysis_metrics.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["counts"]["sources_analyzed"], 1)
            self.assertEqual(payload["operations"][0]["user"], "ZipUser")

    def test_empty_folder_returns_four_and_writes_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "empty"
            root.mkdir()
            output = Path(temp) / "out"
            self.assertEqual(analyzer.run([str(root), "-o", str(output)]), 4)
            payload = json.loads((output / "analysis_metrics.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["counts"]["sources_analyzed"], 0)

    def test_output_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "logs"
            write_log(root / "m" / "c" / "rphost_1" / "26010110.log", "User", 2_000_000, 200_000)
            output_a = Path(temp) / "out_a"
            output_b = Path(temp) / "out_b"
            self.assertEqual(analyzer.run([str(root), "-o", str(output_a)]), 0)
            self.assertEqual(analyzer.run([str(root), "-o", str(output_b)]), 0)
            names = sorted(path.name for path in output_a.iterdir())
            self.assertEqual(names, sorted(path.name for path in output_b.iterdir()))
            for name in names:
                if name == "analysis_metrics.json":
                    # JSON intentionally records the selected output-independent input path only.
                    self.assertEqual(file_digest(output_a / name), file_digest(output_b / name))
                else:
                    self.assertEqual(file_digest(output_a / name), file_digest(output_b / name))

    def test_csvs_are_parseable_and_have_headers(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "logs"
            write_log(root / "m" / "c" / "rphost_1" / "26010110.log", "User", 2_000_000, 200_000)
            output = Path(temp) / "out"
            self.assertEqual(analyzer.run([str(root), "-o", str(output)]), 0)
            for path in sorted(output.glob("*.csv")):
                with path.open("r", encoding="utf-8-sig", newline="") as stream:
                    rows = list(csv.reader(stream))
                self.assertGreaterEqual(len(rows), 1, path.name)
                self.assertGreaterEqual(len(rows[0]), 1, path.name)


if __name__ == "__main__":
    unittest.main()
