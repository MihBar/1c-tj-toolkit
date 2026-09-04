"""Synthetic saved-bundle tests. No parser, original TJ, archive or PDF input."""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import io
import json
import math
from pathlib import Path
import statistics
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from derive_slices import run
from slice_config import REGISTERED_SLICES, SliceError, load_config, strict_json
from slice_input import CALL_INTS, COUNT_KEYS, HEADERS, REQUIRED_FILES, load_bundle
from slice_metrics import data_quality
from verify_slices import verify

MID = "capture@2026-08-04"


def row(table, **values):
    return dict.fromkeys(HEADERS[table], "") | values


def csv_value(value):
    if value is None:
        return ""
    if isinstance(value, dict) or isinstance(value, list) and any(isinstance(x, (dict, list)) for x in value):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if isinstance(value, list):
        return " | ".join(str(x) for x in sorted(value))
    return str(value)


def write_table(path, name, rows):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=HEADERS[name], lineterminator="\n")
    writer.writeheader()
    for item in rows:
        writer.writerow({k: csv_value(item[k]) for k in HEADERS[name]})
    (path / (name + ".csv")).write_bytes(stream.getvalue().encode("utf-8-sig"))


def persist(path, manifest, calls):
    path.mkdir(exist_ok=True)
    source_lines = ["\t".join((r["source"], str(r["size_bytes"]), r["sha256"] or "UNHASHED", r["status"])) for r in sorted(manifest["files"], key=lambda r: r["source"].lower())]
    manifest["source_set_hash_sha256"] = hashlib.sha256("\n".join(source_lines).encode()).hexdigest()
    for name in HEADERS:
        write_table(path, name, calls if name == "call_observations" else manifest[name])
    (path / "analysis_metrics.json").write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def fixture(path, specs=None, *, extra_db=1, partial=False, empty=False):
    if specs is None:
        specs = [("a", MID, 2_000_000), ("a", MID, 4_000_000), ("a", MID, 8_000_000)]
    if empty:
        specs = []
    calls = []
    for cid, (tag, mid, duration) in enumerate(specs, 1):
        end = dt.datetime(2026, 8, 4, 10, cid)
        calls.append(row("call_observations", **dict.fromkeys(CALL_INTS, 0), call_id=cid,
            measurement_id=mid, dataset_id="capture/" + tag, user="User", signature="Operation",
            start_timestamp=(end - dt.timedelta(microseconds=duration)).isoformat(sep=" "),
            end_timestamp=end.isoformat(sep=" "), process="rphost_1",
            source="C:/DO_NOT_OPEN/source.tar::" + tag + ".log", context_sample="Operation"))
        calls[-1].update(duration_us=duration, cpu_us=duration // 4, db_count=1, db_duration_us=100_000)
    files, datasets, operations, linkage = [], [], [], []
    for did in sorted({c["dataset_id"] for c in calls}):
        members = [c for c in calls if c["dataset_id"] == did]
        durs = [c["duration_us"] for c in members]
        source = members[0]["source"]
        files.append(row("files", source=source, resolved_source="C:/DO_NOT_OPEN/source.tar", kind="tar", member=did + ".log", size_bytes=100,
            analyzed_bytes=50 if partial else 100, dataset_id=did, measurement_id="capture", process="rphost_1",
            status="partial_nul_salvaged" if partial else "valid", reason="damaged prefix" if partial else "", nul_offset=60 if partial else None,
            sha256="a" * 64, records=len(members) * 2 + extra_db, parse_errors=0))
        ds_linkage = []
        for mid in sorted({c["measurement_id"] for c in members}):
            group = [c for c in members if c["measurement_id"] == mid]
            values = [c["duration_us"] for c in group]
            op = row("operations", measurement_id=mid, dataset_id=did, user="User", signature="Operation", count=len(group),
                first_timestamp=min(c["end_timestamp"] for c in group), last_timestamp=max(c["end_timestamp"] for c in group),
                avg_us=round(sum(values) / len(values), 3), median_us=float(statistics.median(values)), p95_us=sorted(values)[math.ceil(.95 * len(values)) - 1],
                p99_us=max(values), max_us=max(values), min_us=min(values), priority="P2", priority_rule="fixture", priority_basis="fixture",
                context_sample="Operation")
            for k in CALL_INTS:
                if k in op:
                    op[k] = sum(c[k] for c in group)
            op["rows_affected"] = 0
            for s in (1, 5, 10, 30):
                op[f"over_{s}s"] = sum(v >= s * 1_000_000 for v in values)
            op["call_ids"] = [c["call_id"] for c in group]
            operations.append(op)
            link = dict.fromkeys(HEADERS["linkage"], 0)
            link.update(measurement_id=mid, dataset_id=did, call_count=len(group),
                dbpostgrs_total_count=len(group) + extra_db, dbpostgrs_linked_count=len(group),
                dbpostgrs_total_duration_us=len(group) * 100_000 + extra_db * 50_000,
                dbpostgrs_linked_duration_us=len(group) * 100_000, unlinked_no_containing_call=extra_db)
            for category in ("dbpostgrs", "sdbl", "lock", "error"):
                total, linked = link[category + "_total_count"], link[category + "_linked_count"]
                link[category + "_linked_count_percent"] = round(100 * linked / total, 6) if total else None
            link["dbpostgrs_linked_duration_percent"] = round(100 * link["dbpostgrs_linked_duration_us"] / link["dbpostgrs_total_duration_us"], 6)
            linkage.append(link)
            ds_linkage.append(link)
        datasets.append(row("datasets", dataset_id=did, measurement_id="capture", actual_measurement_ids=sorted({c["measurement_id"] for c in members}),
            files_analyzed=1, bytes_analyzed=100, records=len(members) * 2 + extra_db, parse_errors=0,
            first_timestamp=min(c["end_timestamp"] for c in members), last_timestamp=max(c["end_timestamp"] for c in members),
            users=["User"], sessions=["session"], connect_ids=[], processes=["rphost_1"], day_events=len(members), night_events=0,
            background_events=0, events_without_absolute_timestamp=0, active_minutes_with_events=1, busiest_db_minute_count=1,
            top_call_signatures=[], event_stats={"CALL": {"count": len(members), "duration_us": sum(durs)},
                "DBPOSTGRS": {"count": sum(r["dbpostgrs_total_count"] for r in ds_linkage), "duration_us": sum(r["dbpostgrs_total_duration_us"] for r in ds_linkage)}}))
    manifest = {
        "schema_version": "1.2", "analyzer_version": "1.2.0", "analysis_complete": not partial,
        "absolute_timestamps_complete": True, "source_content_hashes_complete": bool(files), "salvage_nul_prefix": partial,
        "input_root": "C:/DO_NOT_OPEN", "units": {"duration_fields": "microseconds unless field name explicitly contains seconds", "io_fields": "bytes", "memory_fields": "bytes as recorded by the technological journal"},
        "method": {"db_to_call_link": "legacy fixture method"}, "warnings": [{"type": "partial_nul_prefix_salvage"}] if partial else [], "archive_inventory": [],
        "files": files, "datasets": datasets, "operations": operations, "identical_operations": [], "heavy_sql": [], "errors": [], "locks": [], "linkage": linkage,
        "top_calls": calls[:1],
    }
    manifest["counts"] = {key: len(calls if name == "call_observations" else manifest[name]) for name, key in COUNT_KEYS.items()}
    manifest["counts"].update(sources_analyzed=len(files), sources_skipped=0, sources_skipped_as_duplicates=0)
    persist(path, manifest, calls)
    return manifest, calls


def hashes(path):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in path.iterdir() if p.is_file()}


class SavedResultSlicesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "input"
        self.output = self.root / "output"
        self.config = self.root / "config.json"
        self.config.write_text('{"config_version":"1.0","slices":["data_quality"]}', encoding="utf-8")
        self.manifest, self.calls = fixture(self.input)

    def args(self, output=None):
        return ["--analysis-dir", str(self.input), "--output-dir", str(output or self.output), "--config", str(self.config)]

    def test_load_valid_bundle_without_double_counting(self):
        b = load_bundle(self.input)
        self.assertEqual(len(b.calls), 3)
        self.assertEqual(len(b.tables["top_calls"]), 1)
        self.assertEqual(len(b.checks), 8)

    def test_missing_input_file_is_rejected(self):
        (self.input / "errors.csv").unlink()
        with self.assertRaises(SliceError):
            load_bundle(self.input)

    def test_unknown_schema_and_manifest_fields(self):
        for field, value in [("schema_version", "2.0"), ("schema_version", "1.1"), ("analysis_complete", "false"), ("method", {})]:
            with self.subTest(field=field, value=value):
                m = json.loads(json.dumps(self.manifest)); m[field] = value
                persist(self.input, m, self.calls)
                with self.assertRaises(SliceError):
                    load_bundle(self.input)

    def test_missing_duplicate_and_malformed_csv_columns(self):
        original = (self.input / "call_observations.csv").read_text(encoding="utf-8-sig")
        for bad in [original.replace("cpu_us", "absent_cpu", 1), original.replace("cpu_us", "duration_us", 1), original + "extra,column\n"]:
            with self.subTest(header=bad[:80]):
                (self.input / "call_observations.csv").write_text(bad, encoding="utf-8-sig")
                with self.assertRaises(SliceError):
                    load_bundle(self.input)

    def test_duplicate_id_is_rejected(self):
        self.calls[2]["call_id"] = self.calls[1]["call_id"]
        persist(self.input, self.manifest, self.calls)
        with self.assertRaisesRegex(SliceError, "duplicate key"):
            load_bundle(self.input)

    def test_missing_negative_or_nonfinite_call_metric(self):
        for value in ("", -1, "NaN", "Infinity", "--1"):
            with self.subTest(value=value):
                self.calls[1]["db_count"] = value
                persist(self.input, self.manifest, self.calls)
                with self.assertRaises(SliceError):
                    load_bundle(self.input)

    def test_csv_json_mismatch_is_rejected(self):
        path = self.input / "operations.csv"
        path.write_text(path.read_text(encoding="utf-8-sig").replace("Operation", "Other", 1), encoding="utf-8-sig")
        with self.assertRaisesRegex(SliceError, "CSV/JSON mismatch"):
            load_bundle(self.input)

    def test_wrong_call_membership_rejected_even_when_union_matches(self):
        m, calls = fixture(self.input, [("a", MID, 100), ("b", MID, 100)])
        m["operations"][0]["call_ids"], m["operations"][1]["call_ids"] = m["operations"][1]["call_ids"], m["operations"][0]["call_ids"]
        persist(self.input, m, calls)
        with self.assertRaisesRegex(SliceError, "membership mismatch"):
            load_bundle(self.input)

    def test_wrong_operation_statistic_rejected(self):
        self.manifest["operations"][0]["p95_us"] += 1
        persist(self.input, self.manifest, self.calls)
        with self.assertRaisesRegex(SliceError, "operation.p95_us"):
            load_bundle(self.input)

    def test_wrong_linkage_percentage_rejected(self):
        self.manifest["linkage"][0]["dbpostgrs_linked_count_percent"] = 90
        persist(self.input, self.manifest, self.calls)
        with self.assertRaisesRegex(SliceError, "linked_count_percent"):
            load_bundle(self.input)

    def test_unknown_or_skipped_call_source_rejected(self):
        self.calls[1]["source"] = "unknown"
        persist(self.input, self.manifest, self.calls)
        with self.assertRaisesRegex(SliceError, "unknown/skipped source"):
            load_bundle(self.input)

    def test_top_calls_must_be_exact_subset(self):
        self.manifest["top_calls"] = [dict(self.calls[0], out_bytes=99)]
        persist(self.input, self.manifest, self.calls)
        with self.assertRaisesRegex(SliceError, "exact subset"):
            load_bundle(self.input)

    def test_no_recorded_source_access_even_stat_or_resolve(self):
        originals = {name: getattr(Path, name) for name in ("open", "stat", "exists", "is_file", "resolve")}
        read_paths = []
        def guard(name):
            def wrapped(path, *args, **kwargs):
                self.assertNotIn("DO_NOT_OPEN", str(path))
                if name == "open":
                    read_paths.append(str(path))
                return originals[name](path, *args, **kwargs)
            return wrapped
        import contextlib
        with contextlib.ExitStack() as stack:
            for name in originals:
                stack.enter_context(mock.patch.object(Path, name, guard(name)))
            stack.enter_context(mock.patch("socket.socket", side_effect=AssertionError("network forbidden")))
            bundle = load_bundle(self.input)
        self.assertEqual(len(bundle.calls), 3)
        self.assertEqual({Path(p).name for p in read_paths}, set(REQUIRED_FILES))

    def test_symlink_outside_bundle_rejected_before_read(self):
        source = self.input / "files.csv"
        outside = self.root / "outside.csv"
        outside.write_bytes(source.read_bytes())
        source.unlink()
        try:
            source.symlink_to(outside)
        except OSError:
            self.skipTest("Host does not permit symlinks")
        with self.assertRaisesRegex(SliceError, "escapes input"):
            load_bundle(self.input)

    def test_quality_preserves_zero_ambiguity_and_partial_scope(self):
        fixture(self.input, partial=True)
        b = load_bundle(self.input)
        cfg, _ = load_config(self.config)
        q = data_quality(b, cfg)[0]
        self.assertFalse(q["bundle_analysis_complete"])
        self.assertEqual(q["calls_from_partial_sources"], 3)
        self.assertEqual(q["source_completeness"], "not_established_from_saved_results")
        self.assertEqual(q["related_file_scope"], "capture_not_day_or_operation_nonadditive_between_measurements")
        self.assertIsNone(q["metric_availability"]["out_bytes"]["raw_missing_count"])
        self.assertEqual(q["metric_availability"]["out_bytes"]["stored_zero_count"], 3)
        self.assertFalse(q["metric_availability"]["out_bytes"]["raw_missing_vs_zero_distinguishable"])

    def test_coverage_uses_weighted_totals_not_average_percentages(self):
        fixture(self.input, [("a", MID, 100)] + [("b", MID, 100)] * 9)
        b = load_bundle(self.input); cfg, _ = load_config(self.config)
        q = data_quality(b, cfg)[0]
        self.assertEqual(q["db_linked_count_percent"], 83.333333)
        self.assertEqual(q["call_count"], 10)

    def test_missing_times_remain_unavailable(self):
        for c in self.calls:
            c.update(start_timestamp="", end_timestamp="", measurement_id="capture@unknown-date")
        self.manifest["absolute_timestamps_complete"] = False
        self.manifest["files"][0]["status"] = "valid_no_timestamp"
        ds = self.manifest["datasets"][0]; ds.update(actual_measurement_ids=[], events_without_absolute_timestamp=3)
        self.manifest["operations"][0]["measurement_id"] = "capture@unknown-date"
        self.manifest["linkage"][0].update(measurement_id="capture@unknown-date", calls_without_absolute_time=3)
        persist(self.input, self.manifest, self.calls)
        b = load_bundle(self.input); cfg, _ = load_config(self.config)
        q = data_quality(b, cfg)[0]
        self.assertIsNone(q["observed_call_start"])
        self.assertEqual(q["calls_without_time"], 3)
        self.assertEqual(q["order_basis"], "identifier_tiebreak_no_call_time")

    def test_empty_saved_bundle_produces_header_and_manifest(self):
        fixture(self.input, empty=True)
        answer = run(self.args())
        self.assertEqual(answer["call_count"], 0)
        self.assertEqual(answer["row_counts"]["data_quality.csv"], 0)
        with (self.output / "data_quality.csv").open(encoding="utf-8-sig") as f:
            self.assertTrue(csv.DictReader(f).fieldnames)

    def test_no_db_events_denominator_is_null(self):
        for c in self.calls:
            c.update(db_count=0, db_duration_us=0)
        op = self.manifest["operations"][0]; op.update(db_count=0, db_duration_us=0)
        link = self.manifest["linkage"][0]
        for k in list(link):
            if k.startswith("dbpostgrs"):
                link[k] = None if k.endswith("percent") else 0
        link["unlinked_no_containing_call"] = 0
        self.manifest["datasets"][0]["event_stats"]["DBPOSTGRS"] = {"count": 0, "duration_us": 0}
        persist(self.input, self.manifest, self.calls)
        b = load_bundle(self.input); cfg, _ = load_config(self.config)
        q = data_quality(b, cfg)[0]
        self.assertIsNone(q["db_linked_count_percent"])
        self.assertIsNone(q["db_linked_duration_percent"])

    def test_input_unchanged_and_output_byte_deterministic(self):
        before = hashes(self.input)
        run(self.args())
        other = self.root / "second"
        run(self.args(other))
        self.assertEqual(hashes(self.output), hashes(other))
        self.assertEqual(before, hashes(self.input))
        manifest = json.loads((self.output / "slice_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(set(manifest["input_files"]), set(REQUIRED_FILES))
        self.assertEqual(manifest["population"]["count"], 3)
        self.assertTrue(manifest["input_files_unchanged"])

    def test_validate_only_writes_nothing(self):
        answer = run(self.args() + ["--validate-only"])
        self.assertTrue(answer["validation_only"])
        self.assertFalse(self.output.exists())

    def test_overwrite_requires_permission_and_recognized_output(self):
        run(self.args())
        before = hashes(self.output)
        with self.assertRaisesRegex(SliceError, "not empty"):
            run(self.args())
        self.assertEqual(before, hashes(self.output))
        run(self.args() + ["--overwrite"])
        self.assertEqual(before, hashes(self.output))
        (self.output / "user_notes.txt").write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(SliceError, "unrelated files"):
            run(self.args() + ["--overwrite"])
        self.assertEqual((self.output / "user_notes.txt").read_text(), "keep")

    def test_output_must_not_overlap_input(self):
        for out in (self.input, self.input / "nested", self.root):
            with self.subTest(out=out), self.assertRaisesRegex(SliceError, "disjoint"):
                run(self.args(out) + ["--overwrite"])

    def test_invalid_configuration_and_selection(self):
        variants = [
            '{"config_version":"1.0","unexpected":1}',
            '{"config_version":"2.0"}',
            '{"config_version":"1.0","slices":["unimplemented_test_slice"]}',
            '{"config_version":"1.0","slices":["data_quality","data_quality"]}',
            '{"config_version":"1.0","data_quality":{"min_call_count":true}}',
            '{"config_version":"1.0","data_quality":{"db_linkage_warning_percent":101}}',
            '{"config_version":"1.0","measurement_ids":["absent"]}',
            '{"config_version":"1.0","expected_bundle_id":"' + '0' * 64 + '"}',
        ]
        for text in variants:
            with self.subTest(config=text):
                self.config.write_text(text, encoding="utf-8")
                with self.assertRaises(SliceError):
                    run(self.args())
                self.assertFalse(self.output.exists())

    def test_cli_selection_and_list(self):
        self.assertEqual(run(["--list-slices"])["available_slices"], list(REGISTERED_SLICES))
        self.assertEqual(run(self.args() + ["--slices", "data_quality"])["selected_slices"], ["data_quality"])
        with self.assertRaises(SliceError):
            run(self.args() + ["--slices", "apdex"])

    def test_mutation_after_load_detected(self):
        b = load_bundle(self.input)
        p = self.input / "call_observations.csv"
        p.write_bytes(p.read_bytes() + b"\n")
        with self.assertRaisesRegex(SliceError, "changed"):
            b.assert_unchanged()

    def test_strict_json_rejects_duplicate_keys_and_nonfinite(self):
        for value in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":1e999}'):
            with self.subTest(value=value), self.assertRaises(SliceError):
                strict_json(value, "test")

    def test_verifier_recalculates_and_rejects_tampering(self):
        run(self.args())
        self.assertEqual(verify(self.input, self.output)["status"], "PASS")
        path = self.output / "data_quality.csv"
        path.write_bytes(path.read_bytes() + b"tampered")
        with self.assertRaisesRegex(SliceError, "differs"):
            verify(self.input, self.output)

    def test_verifier_rejects_metadata_tampering(self):
        run(self.args())
        path = self.output / "slice_manifest.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["population"]["count"] += 1
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(SliceError, "Population"):
            verify(self.input, self.output)

    def test_nonempty_measurement_filter_and_stable_row_order(self):
        earlier = "capture@2026-08-03"
        m, calls = fixture(self.input, [("a", MID, 100), ("b", earlier, 100)])
        # Deliberately different from lexical identifier ordering. Use stored
        # timestamps, not directory labels or the order of CSV rows.
        persist(self.input, m, list(reversed(calls)))
        cfg, _ = load_config(self.config)
        quality = data_quality(load_bundle(self.input), cfg)
        self.assertEqual([r["measurement_id"] for r in quality], [MID, earlier])
        cfg["measurement_ids"] = [earlier]
        self.assertEqual([r["measurement_id"] for r in data_quality(load_bundle(self.input), cfg)], [earlier])

    def test_measurement_without_call_does_not_disappear(self):
        other = "capture@2026-08-05"
        self.manifest["datasets"][0]["actual_measurement_ids"].append(other)
        persist(self.input, self.manifest, self.calls)
        cfg, _ = load_config(self.config)
        quality = data_quality(load_bundle(self.input), cfg)
        q = next(r for r in quality if r["measurement_id"] == other)
        self.assertEqual(q["call_count"], 0)
        self.assertIsNone(q["observed_call_start"])
        self.assertEqual(q["sample_size_status"], "no_calls")

    def test_capture_gaps_not_falsely_assigned_to_individual_day(self):
        skipped = row("files", source="C:/DO_NOT_OPEN/extra.log", resolved_source="C:/DO_NOT_OPEN/extra.log",
            kind="file", size_bytes=100, analyzed_bytes=0, dataset_id="capture/unknown-user", measurement_id="capture",
            status="skipped", reason="no technological-journal header in first 256 KiB", sha256="b" * 64, records=0, parse_errors=0)
        self.manifest["files"].append(skipped)
        self.manifest["counts"]["sources_discovered"] += 1
        self.manifest["counts"]["sources_skipped"] += 1
        self.manifest["analysis_complete"] = False
        persist(self.input, self.manifest, self.calls)
        cfg, _ = load_config(self.config)
        q = data_quality(load_bundle(self.input), cfg)[0]
        self.assertEqual(q["related_capture_nonempty_skipped_files"], 1)
        self.assertEqual(q["calls_from_partial_sources"], 0)
        self.assertIn("capture_not_day", q["related_file_scope"])

    def test_invalid_input_leaves_existing_output_untouched(self):
        run(self.args())
        before = hashes(self.output)
        self.calls[1]["duration_us"] = 0
        persist(self.input, self.manifest, self.calls)
        with self.assertRaises(SliceError):
            run(self.args() + ["--overwrite"])
        self.assertEqual(hashes(self.output), before)

    def test_input_identity_pin(self):
        b = load_bundle(self.input)
        self.config.write_text(json.dumps({"config_version": "1.0", "expected_bundle_id": b.bundle_id}), encoding="utf-8")
        self.assertEqual(run(self.args())["bundle_id"], b.bundle_id)


if __name__ == "__main__":
    unittest.main()
