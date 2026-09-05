"""Full legacy/sweep bundle equivalence, bounded readers and saved verification."""
from __future__ import annotations

import contextlib
import io
import json
import random
import sqlite3
import sys
import tempfile
import unittest
import weakref
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import analyze_1c_tj as analyzer
import event_linking as legacy
import event_linking_sweep as kernel
from error_rules import error_decision, error_candidates, membership, INCIDENT_RULES_VERSION
from event_store import EventStore, insert
from slice_config import SliceError
from slice_input import load_bundle
from source_identity import file_hash
from stored_linking import CALL_SCAN, stored_links
from test_event_detail import call, db, record
from test_error_detail import error


def legacy_db(store):
    """Frozen old producer loop: SQL interval query and old selection/evidence."""
    store.commit()
    for event in store.connection.execute("SELECT e.* FROM events e JOIN db_events d USING(event_id) ORDER BY e.event_id"):
        rows = legacy.candidates(store.connection, event)
        decision = legacy.decide(store.connection, event, rows)
        insert(store.connection, "link_decisions", decision)
        for evidence in legacy.candidate_evidence(store.connection, event, decision, rows):
            insert(store.connection, "link_candidates", evidence)
        store.tick()
        if store.on_db_link:
            store.on_db_link(1)
    store.commit()


def legacy_errors(store):
    """Old error producer, including the unchanged membership construction."""
    connection = store.connection
    store.commit()
    for event in connection.execute("SELECT e.*,r.raw_message,r.message_state FROM events e JOIN error_events r USING(event_id) ORDER BY e.event_id"):
        rows = legacy.candidates(connection, event)
        decision = error_decision(connection, event, rows)
        insert(connection, "error_link_decisions", decision)
        connect_relation = None
        for evidence in error_candidates(connection, event, decision, rows):
            insert(connection, "error_link_candidates", evidence)
            if evidence["selected"]:
                connect_relation = evidence["connect_relation"]
        member = membership(event, decision, connect_relation)
        insert(connection, "suspected_incidents", {
            "incident_id": member["incident_id"], "incident_rules_version": INCIDENT_RULES_VERSION,
            "group_key_json": member["group_key_json"], "hypothesis_status": "unconfirmed",
            "root_cause": None, "cancellation_initiator": None}, ignore=True)
        insert(connection, "error_incident_members", member)
        store.tick()
        if store.on_error_link:
            store.on_error_link(1)
    store.commit()


class GuardedCursor:
    """Cursor proxy rejects whole-result fetching and records target lookahead."""
    def __init__(self, cursor, owner, target=False):
        self.cursor, self.owner, self.target = cursor, owner, target
        self.closed = False

    def execute(self, *args):
        self.cursor.execute(*args)
        return self

    def __iter__(self):
        return self

    def __next__(self):
        row = next(self.cursor)
        if self.target:
            self.owner.target_reads += 1
        return row

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        raise AssertionError("Unbounded SQLite fetch")

    def fetchmany(self, size=1):
        raise AssertionError("Adapter should use cursor iteration, not fetchmany")

    def close(self):
        self.closed = True
        self.cursor.close()


class GuardedConnection:
    def __init__(self, connection):
        self.connection = connection
        self.cursors = []
        self.target_reads = 0

    def execute(self, sql, *args):
        cursor = GuardedCursor(self.connection.execute(sql, *args), self,
                               sql.startswith("SELECT e.event_id FROM"))
        if sql.startswith("SELECT"):
            self.cursors.append(cursor)
        return cursor

    def cursor(self):
        cursor = GuardedCursor(self.connection.cursor(), self)
        self.cursors.append(cursor)
        return cursor


class StoredLinkingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="tj-sweep-bundle-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.logs = self.root / "logs"

    def write(self, text, name="capture/rphost_1/26090310.log"):
        path = self.logs / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))

    def run_bundle(self, name, old=False):
        output = self.root / name
        with contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            if old:
                stack.enter_context(patch.object(EventStore, "link_db", legacy_db))
                stack.enter_context(patch.object(analyzer, "link_errors", legacy_errors))
            self.assertEqual(analyzer.run([str(self.logs), "-o", str(output), "--top-calls", "2"]), 0)
        return output

    def compare_bundles(self, old, new):
        self.assertEqual({p.name for p in old.iterdir()}, {p.name for p in new.iterdir()})
        for path in old.iterdir():
            if path.name not in ("analysis.sqlite", "analysis_metrics.json"):
                self.assertEqual(path.read_bytes(), (new / path.name).read_bytes(), path.name)
        left, right = [json.loads((p / "analysis_metrics.json").read_text(encoding="utf-8")) for p in (old, new)]
        # Only physical SQLite checksum/size may differ. Every analytic value,
        # rule version, count, descriptor of other artifacts must remain exact.
        for manifest in (left, right):
            for field in ("sha256", "size_bytes"):
                del manifest["artifacts"]["analysis.sqlite"][field]
        self.assertEqual(left, right)
        with contextlib.closing(sqlite3.connect(old / "analysis.sqlite")) as a, contextlib.closing(sqlite3.connect(new / "analysis.sqlite")) as b:
            schema = "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
            self.assertEqual(a.execute(schema).fetchall(), b.execute(schema).fetchall())
            self.assertEqual(a.execute("PRAGMA user_version").fetchone(), b.execute("PRAGMA user_version").fetchone())
            for name, in a.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')"):
                fields = [r[1] for r in a.execute(f'PRAGMA table_info("{name}")')]
                order = ",".join(f'"{f}"' for f in fields)
                sql = f'SELECT * FROM "{name}" ORDER BY {order}'
                self.assertEqual(a.execute(sql).fetchall(), b.execute(sql).fetchall(), name)
        # Each artifact hash and derived bundle ID is independently validated.
        a, b = load_bundle(old), load_bundle(new)
        if file_hash(old / "analysis.sqlite") != file_hash(new / "analysis.sqlite"):
            self.assertNotEqual(a.bundle_id, b.bundle_id)

    def mixed_fixture(self, seed):
        rng = random.Random(seed)
        rows = [call(), call(8_000_000, 2_000_000), call(), call(5_000_000, 0),
                call(15_000_000, 10_000_000, SessionID="B"),
                db(0, 0), db(10_000_000), db(10_000_001), db(5_000_000, 9_000_000),
                error(1_000_000), error(2_000_000, event="QERR"),
                call(25_000_000, 5_000_000, Context="Unique", **{"t:connectID": "A"}),
                error(21_000_000, Context="Unique", **{"t:connectID": "A"}),
                error(22_000_000, event="QERR", Context="Unique", **{"t:connectID": "A"}),
                error(23_000_000, Context="Unique", **{"t:connectID": "B"}),
                call(30_000_000, 5_000_000, Usr=None), db(29_000_000, Usr="  ")]
        for i in range(40):
            attrs = dict(Usr=rng.choice(("User", "Other", None)), OSThread=rng.choice(("7", "8", None, "", " ")),
                         SessionID=rng.choice(("A", "B", None, "", " ")), **{"t:connectID": rng.choice(("A", "B", None))})
            t = rng.randrange(1, 15) * 1_000_000
            rows.append(call(t, rng.randrange(0, 16) * 1_000_000, **attrs))
            rows.append(db(t, rng.randrange(0, 16) * 1_000_000, Sql="SELECT 1" if i % 2 else None, **attrs))
            rows.append(error(t, event="EXCP" if i % 2 else "QERR", **attrs))
        rows += [record(kind, 4_000_000, Usr="User", OSThread="7", SessionID="A", Context="Lock")
                 for kind in ("SDBL", "TLOCK", "TTIMEOUT", "TDEADLOCK")]
        rng.shuffle(rows)
        self.write("".join(rows))
        self.write(call() + db() + error(), "other/rphost_1/26090310.log")
        self.write(call() + db() + error(), "capture/rphost_2/26090310.log")
        self.write(db(3_599_000_000) + error(3_599_999_999), "capture/rphost_1/26090323.log")
        self.write(call(1_000_000, 2_000_000) + error(1_000_000), "capture/rphost_1/26090400.log")
        self.write(call() + db() + error(), "capture/rphost_1/unknown.log")

    def test_complete_bundles_equal_for_fixed_random_seeds(self):
        for seed in (7, 42, 2026):
            with self.subTest(seed=seed):
                self.mixed_fixture(seed)
                self.compare_bundles(self.run_bundle(f"old-{seed}", old=True), self.run_bundle(f"new-{seed}"))

    def test_many_candidates_and_batch_commits_preserve_full_exports(self):
        self.write("".join(call(10_000_000 + i, 10_000_000 + i) for i in range(130)) +
                   "".join(db() + error(event="QERR" if i % 2 else "EXCP") for i in range(12)))
        old, new = self.run_bundle("old", old=True), self.run_bundle("new")
        self.compare_bundles(old, new)
        with contextlib.closing(sqlite3.connect(new / "analysis.sqlite")) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM link_candidates").fetchone()[0], 1560)
            self.assertEqual(connection.execute("SELECT count(*) FROM error_link_candidates").fetchone()[0], 1560)

    def test_verification_has_no_legacy_interval_queries_and_uses_pk_evidence(self):
        self.mixed_fixture(7)
        output = self.run_bundle("new")
        original_connect = sqlite3.connect
        statements = []

        def connect(*args, **kwargs):
            connection = original_connect(*args, **kwargs)
            connection.set_trace_callback(statements.append)
            return connection

        self.logs.rename(self.root / "offline")
        with patch.object(sqlite3, "connect", connect), \
             patch.object(legacy, "candidates", side_effect=AssertionError("legacy lookup")):
            load_bundle(output)
        self.assertEqual(statements.count(CALL_SCAN), 3)  # DB, errors, auxiliary verification
        self.assertFalse(any("ORDER BY c.legacy_call_id" in s for s in statements))
        self.assertFalse(any("AND e.start_time_us<=" in s for s in statements))
        self.assertTrue(any("FROM link_candidates WHERE event_id=" in s and "AND call_event_id=" in s for s in statements))
        self.assertTrue(any("FROM error_link_candidates WHERE event_id=" in s and "AND call_event_id=" in s for s in statements))

    def test_bounded_target_reading_evidence_and_release_of_previous_scopes(self):
        self.write("".join(call(Usr=user) + db(Usr=user) + db(Usr=user) for user in ("a", "b", "c")))
        output = self.run_bundle("new")
        with contextlib.closing(sqlite3.connect(output / "analysis.sqlite")) as connection:
            connection.row_factory = sqlite3.Row
            guarded = GuardedConnection(connection)
            references = []
            original = kernel.ActiveCalls

            def active(*args, **kwargs):
                self.assertTrue(all(ref() is None for ref in references), "previous scope retained")
                value = original(*args, **kwargs)
                references.append(weakref.ref(value))
                return value

            with patch.object(kernel, "ActiveCalls", active):
                rows = stored_links(guarded, "db")
                event, decision, evidence = next(rows)
                self.assertEqual(guarded.target_reads, 1)
                self.assertNotIsInstance(evidence, (list, tuple))
                self.assertEqual(next(evidence)["selected"], 1)
                for event, decision, evidence in rows:
                    self.assertEqual(len(list(evidence)), 1)
                self.assertTrue(all(ref() is None for ref in references))
            self.assertTrue(all(cursor.closed for cursor in guarded.cursors))
            # Early close must also release CALL arrays and all database cursors.
            guarded = GuardedConnection(connection)
            with patch.object(kernel, "ActiveCalls", active):
                rows = stored_links(guarded, "db")
                event, decision, evidence = next(rows)
                rows.close()
                self.assertTrue(all(ref() is None for ref in references))
                self.assertTrue(all(cursor.closed for cursor in guarded.cursors))

    def test_rehashed_extra_missing_and_changed_candidates_are_rejected(self):
        self.write(call() + call(30_000_000, 1_000_000) + db() + error())
        output = self.run_bundle("new")
        baseline = (output / "analysis.sqlite").read_bytes()
        for table in ("link_candidates", "error_link_candidates"):
            for mutation in ("missing", "changed", "extra"):
                with self.subTest(table=table, mutation=mutation):
                    (output / "analysis.sqlite").write_bytes(baseline)
                    with contextlib.closing(sqlite3.connect(output / "analysis.sqlite")) as connection:
                        if mutation == "missing":
                            connection.execute(f"DELETE FROM {table}")
                        elif mutation == "changed":
                            connection.execute(f"UPDATE {table} SET full_interval_contained=0")
                        else:
                            connection.execute(f"INSERT INTO {table} SELECT k.event_id,c.event_id,k.session_relation,k.connect_relation,"
                                               f"0,0,0,'excluded_by_session_preference' FROM {table} k CROSS JOIN call_events c "
                                               "WHERE c.event_id<>k.call_event_id")
                        connection.commit()
                    manifest = json.loads((output / "analysis_metrics.json").read_text(encoding="utf-8"))
                    manifest["artifacts"]["analysis.sqlite"].update(sha256=file_hash(output / "analysis.sqlite"),
                        size_bytes=(output / "analysis.sqlite").stat().st_size)
                    (output / "analysis_metrics.json").write_text(json.dumps(manifest), encoding="utf-8")
                    with self.assertRaisesRegex(SliceError, "candidate evidence"):
                        load_bundle(output)


if __name__ == "__main__":
    unittest.main()
