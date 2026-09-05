"""Auxiliary owner/aggregate equivalence to the independent IntervalIndex."""
from __future__ import annotations

import contextlib
import csv
import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import analyze_1c_tj as analyzer
import event_linking_sweep as kernel
import test_stored_linking as support
from stored_linking import auxiliary_rows, stored_links
from event_store import timestamp
from test_event_detail import call, db, record


@contextlib.contextmanager
def interval_rows(store):
    """Old IntervalIndex owner selection; no sweep summaries or candidates."""
    connection = store.connection
    calls = [SimpleNamespace(call_id=c["legacy_call_id"], dataset_id=c["dataset_id"],
                             user=c["user"], process=c["process"], thread=c["thread"], session=c["session"],
                             start=timestamp(c["start_time_us"]), end=timestamp(c["end_time_us"]), duration_us=c["duration_us"])
             for c in connection.execute("SELECT e.*,c.legacy_call_id FROM events e JOIN call_events c USING(event_id)")]
    indexes = analyzer.build_indexes(calls)

    def rows():
        for row in connection.execute("SELECT * FROM events WHERE event_type IN ('SDBL','TLOCK','TTIMEOUT','TDEADLOCK') ORDER BY source_version_id,byte_start"):
            owner = None
            if row["end_time_us"] is not None and row["thread"]:
                index = indexes.get((row["dataset_id"], row["user"], row["process"], row["thread"]))
                if index is not None:
                    owner = index.find(timestamp(row["end_time_us"]), row["session"])
            yield {**dict(row), "linked_call_id": owner.call_id if owner is not None else None}
    yield rows()


class AuxiliarySweepTests(unittest.TestCase):
    setUp = support.StoredLinkingTests.setUp
    write = support.StoredLinkingTests.write
    run_bundle = support.StoredLinkingTests.run_bundle
    compare_bundles = support.StoredLinkingTests.compare_bundles

    def fixture(self):
        def aux(kind, t, duration=7, **attrs):
            return record(kind, t, duration, **(dict(Usr="User", OSThread="7", SessionID="A", Context="Lock") | attrs))

        kinds = ("SDBL", "TLOCK", "TTIMEOUT", "TDEADLOCK")
        rows = [call(1_000_000, 1_000_000)]
        rows += [call(2*i+1, 1, Context="Short") for i in range(400)]
        rows += [call(950_000, 50_000, SessionID="B"), call(950_000, 50_000, SessionID="B"),
                 call(900_000, 0, SessionID="Z"), call(975_000, 100_000, SessionID="B")]
        for kind in kinds:
            for t in (0, 1, 798, 799, 800, 899_999, 900_000, 950_000, 975_000, 1_000_000, 1_000_001):
                for session in ("A", "B", "Z", "absent", None, ""):
                    rows.append(aux(kind, t, 0 if t == 0 else 123, SessionID=session))
            rows += [aux(kind, 900_001, OSThread=None), aux(kind, 900_001, OSThread=""),
                     aux(kind, 900_001, OSThread="other"), aux(kind, 900_001, Usr=None)]
        # Byte/source order deliberately opposes time order, including >30 SQL
        # contexts and first samples, plus distinct lock roots and full tails.
        rows += [aux("TLOCK", 900_100-i, Context=f"Root-{i}\nTail-{i}") +
                 db(900_100-i, Context=f"SqlContext-{i}", Sql=f"SELECT {i}") for i in range(45)]
        self.write("".join(rows))
        self.write("".join(aux(k, 3_599_999_999) for k in kinds), "capture/rphost_1/26090323.log")
        self.write(call(1_000_000, 2_000_000) + "".join(aux(k, 1_000_000) for k in kinds),
                   "capture/rphost_1/26090400.log")
        self.write(call() + "".join(aux(k, 500_000, OSThread=None) for k in kinds),
                   "other/rphost_1/unknown.log")
        self.write(call() + "".join(aux(k, 500_000) for k in kinds), "capture/rphost_2/26090310.log")

    def test_owners_counts_durations_linkage_and_full_exports_match_interval_index(self):
        self.fixture()
        with patch.object(analyzer, "auxiliary_rows", interval_rows):
            old = self.run_bundle("interval")
        # Neither production auxiliary linkage nor its verifier may enumerate
        # candidates. DB linkage/evidence is checked separately by existing tests.
        original_links = stored_links
        work = kernel.WorkCounters()

        def checked_links(connection, kind, **kwargs):
            if kind != "aux":
                yield from original_links(connection, kind, **kwargs)
                return
            self.assertIs(kwargs["include_evidence"], False)
            with patch.object(kernel.ActiveCalls, "candidates", side_effect=AssertionError("aux candidate scan")):
                yield from original_links(connection, kind, work=work, **kwargs)

        with patch("stored_linking.stored_links", checked_links), \
             patch.object(analyzer, "build_indexes", side_effect=AssertionError("legacy index in producer")):
            new = self.run_bundle("sweep")
        self.assertEqual(work.candidates_visited, 0)
        self.compare_bundles(old, new)
        with contextlib.closing(sqlite3.connect(new / "analysis.sqlite")) as connection:
            connection.row_factory = sqlite3.Row
            store = SimpleNamespace(connection=connection, tick=lambda: None)
            with interval_rows(store) as rows:
                expected_rows = list(rows)
                expected = [(r["event_id"], r["linked_call_id"]) for r in expected_rows]
            with auxiliary_rows(store) as rows:
                actual = [(r["event_id"], r["linked_call_id"]) for r in rows]
            self.assertEqual(actual, expected)  # exact replay order as well as owners
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_temp_master WHERE name='auxiliary_owners'").fetchone())
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name LIKE '%auxiliary%'").fetchone())
            # Both sides of midnight must count against the same enclosing CALL.
            with auxiliary_rows(store) as rows:
                midnight = [r for r in rows if r["measurement_id"].endswith("2026-09-04")]
            self.assertEqual(len(midnight), 4)
            self.assertTrue(all(r["linked_call_id"] is not None for r in midnight))
        # Independent accounting oracle, not just two invocations of the same
        # aggregation code with different owner providers.
        with (new / "call_observations.csv").open(encoding="utf-8-sig", newline="") as stream:
            for c in csv.DictReader(stream):
                owned = [r for r in expected_rows if r["linked_call_id"] == int(c["call_id"])]
                locks = [r for r in owned if r["event_type"] != "SDBL"]
                self.assertEqual(int(c["sdbl_count"]), sum(r["event_type"] == "SDBL" for r in owned))
                self.assertEqual(int(c["lock_count"]), len(locks))
                self.assertEqual(int(c["lock_duration_us"]), sum(r["duration_us"] for r in locks))
        manifest = json.loads((new / "analysis_metrics.json").read_text(encoding="utf-8"))
        for link in manifest["linkage"]:
            rows = [r for r in expected_rows if (r["dataset_id"], r["measurement_id"]) ==
                    (link["dataset_id"], link["measurement_id"])]
            for category in ("sdbl", "lock"):
                members = [r for r in rows if (r["event_type"] == "SDBL") == (category == "sdbl")]
                self.assertEqual(link[category + "_total_count"], len(members))
                self.assertEqual(link[category + "_linked_count"], sum(r["linked_call_id"] is not None for r in members))
        self.assertTrue(any(len(row["contexts"]) == 30 for row in manifest["heavy_sql"]))

    def test_temp_owner_table_is_removed_on_failure_and_empty_input(self):
        self.write(call())
        output = self.run_bundle("empty")
        with contextlib.closing(sqlite3.connect(output / "analysis.sqlite")) as connection:
            connection.row_factory = sqlite3.Row
            store = SimpleNamespace(connection=connection, tick=lambda: None)
            with auxiliary_rows(store) as rows:
                self.assertEqual(list(rows), [])
            with self.assertRaisesRegex(RuntimeError, "consumer failed"):
                with auxiliary_rows(store):
                    raise RuntimeError("consumer failed")
            with patch("stored_linking.stored_links", side_effect=RuntimeError("sweep failed")):
                with self.assertRaisesRegex(RuntimeError, "sweep failed"):
                    with auxiliary_rows(store):
                        pass
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_temp_master WHERE name='auxiliary_owners'").fetchone())


if __name__ == "__main__":
    unittest.main()
