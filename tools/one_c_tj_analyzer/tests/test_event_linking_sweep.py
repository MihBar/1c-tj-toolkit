"""Independent SQL/IntervalIndex differential and structural sweep tests."""
from __future__ import annotations

import datetime as dt
import random
import sqlite3
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import event_linking as legacy
from analyze_1c_tj import build_indexes
from error_rules import error_candidates, error_decision
from event_linking_sweep import (
    ActiveCalls, WorkCounters, call_order, event_order, link_events, scope_key, sweep_sorted,
)


DAY = 86_400_000_000
TYPES = ("DBPOSTGRS", "EXCP", "QERR", "SDBL", "TLOCK", "TTIMEOUT", "TDEADLOCK")


def observation(event_id="event", end=50, duration=5, **overrides):
    row = dict(event_id=event_id, event_type="DBPOSTGRS", dataset_id="dataset", user="User",
               usr_raw="User", process="rphost_1", thread="7", session="A", connect_id="conn",
               start_time_us=end - duration if end is not None else None, end_time_us=end,
               duration_us=duration, measurement_id="measurement", source_version_id="file-one")
    row.update(overrides)
    return row


def call(call_id=1, start=0, end=100, **overrides):
    row = observation(f"call-{call_id}", end, end - start if end is not None else 0,
                      event_type="CALL", legacy_call_id=call_id)
    row.update(overrides)
    return row


class SweepTests(unittest.TestCase):
    def oracle_connection(self, calls):
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.row_factory = sqlite3.Row
        connection.executescript("""
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY, event_type TEXT, dataset_id TEXT, user TEXT,
                usr_raw TEXT, process TEXT, thread TEXT, session TEXT, connect_id TEXT,
                start_time_us INTEGER, end_time_us INTEGER, duration_us INTEGER,
                measurement_id TEXT, source_version_id TEXT
            );
            CREATE TABLE call_events (event_id TEXT PRIMARY KEY, legacy_call_id INTEGER UNIQUE);
        """)
        fields = [row[1] for row in connection.execute("PRAGMA table_info(events)")]
        for row in calls:
            connection.execute("INSERT INTO events VALUES (" + ",".join("?" for _ in fields) + ")",
                               [row[field] for field in fields])
            connection.execute("INSERT INTO call_events VALUES (?,?)", (row["event_id"], row["legacy_call_id"]))
        return connection

    def assert_equivalent(self, calls, events):
        """Neither legacy oracle receives candidates or summaries from the sweep."""
        connection = self.oracle_connection(calls)
        epoch = dt.datetime(1970, 1, 1)
        indexes = build_indexes([
            SimpleNamespace(call_id=c["legacy_call_id"], duration_us=c["duration_us"],
                            dataset_id=c["dataset_id"], user=c["user"], process=c["process"],
                            thread=c["thread"], session=c["session"],
                            start=epoch + dt.timedelta(microseconds=c["start_time_us"]) if c["start_time_us"] is not None else None,
                            end=epoch + dt.timedelta(microseconds=c["end_time_us"]) if c["end_time_us"] is not None else None)
            for c in calls
        ])
        original_calls, original_events = [dict(c) for c in calls], [dict(e) for e in events]
        actual = list(link_events(calls, events))
        self.assertEqual(calls, original_calls)
        self.assertEqual(events, original_events)
        self.assertEqual([r.decision["event_id"] for r in actual], [e["event_id"] for e in sorted(events, key=event_order)])
        self.assertEqual(len(actual), len(events))
        actual_by_id = {r.decision["event_id"]: r for r in actual}
        self.assertEqual(len(actual_by_id), len(events))
        call_by_id = {c["event_id"]: c for c in calls}
        for event in events:
            with self.subTest(event=event):
                rows = legacy.candidates(connection, event)
                if event["event_type"] in ("EXCP", "QERR"):
                    decision = error_decision(connection, event, rows)
                    evidence = tuple(error_candidates(connection, event, decision, rows))
                else:
                    decision = legacy.decide(connection, event, rows)
                    evidence = tuple(legacy.candidate_evidence(connection, event, decision, rows))
                result = actual_by_id[event["event_id"]]
                self.assertEqual(result.decision, decision)
                self.assertEqual(result.evidence, evidence)
                # Independent direct predicate checks completeness, not just owner.
                expected_ids = [c["event_id"] for c in sorted(calls, key=lambda c: c["legacy_call_id"])
                                if event["end_time_us"] is not None and event["thread"]
                                and c["start_time_us"] is not None and c["end_time_us"] is not None
                                and all(c[k] == event[k] for k in ("dataset_id", "user", "process", "thread"))
                                and c["start_time_us"] <= event["end_time_us"] <= c["end_time_us"]]
                ids = [r["call_event_id"] for r in result.evidence]
                self.assertEqual(ids, expected_ids)
                self.assertEqual(len(ids), len(set(ids)))
                self.assertEqual(len(ids), decision["candidate_count"])
                self.assertEqual(sum(r["eligible"] for r in result.evidence), decision["eligible_count"])
                self.assertEqual(sum(r["selected"] for r in result.evidence), int(decision["parent_event_id"] is not None))
                owner = None
                if event["end_time_us"] is not None and event["thread"]:
                    index = indexes.get((event["dataset_id"], event["user"], event["process"], event["thread"]))
                    if index:
                        owner = index.find(epoch + dt.timedelta(microseconds=event["end_time_us"]), event["session"])
                self.assertEqual(owner.call_id if owner else None,
                                 call_by_id[decision["parent_event_id"]]["legacy_call_id"] if decision["parent_event_id"] is not None else None)
        # Detached evidence survives advancing to later events and other scopes.
        self.assertEqual(actual, list(sweep_sorted(iter(sorted(calls, key=call_order)), iter(sorted(events, key=event_order)))))
        return actual_by_id

    def test_boundaries_zero_nested_intersections_ties_and_outside_start(self):
        calls = [call(91, -10, 110), call(40, 0, 100), call(2, 0, 100),
                 call(71, 20, 80), call(8, 60, 130), call(6, 50, 50)]
        cases = [(t, d) for t in (-11, -10, 0, 19, 20, 49, 50, 51, 60, 80, 100, 110, 130, 131) for d in (0, 1, 150)]
        events = [observation(f"{kind}-{i}", t, d, event_type=kind)
                  for kind in TYPES for i, (t, d) in enumerate(cases)]
        random.Random(9001).shuffle(events)
        results = self.assert_equivalent(calls, events)
        exact = results[f"DBPOSTGRS-{cases.index((50, 1))}"]
        self.assertIn("call-6", [r["call_event_id"] for r in exact.evidence])
        self.assertTrue(any(r["full_interval_contained"] == 0 for r in exact.evidence))

    def test_zero_duration_call_is_selected_only_at_its_exact_time(self):
        for kind in TYPES:
            with self.subTest(kind=kind):
                results = self.assert_equivalent([call(1, 0, 0)],
                    [observation(str(t), t, 0, event_type=kind) for t in (-1, 0, 1)])
                self.assertEqual(results["0"].decision["parent_event_id"], "call-1")
                self.assertEqual(results["0"].evidence[0]["full_interval_contained"], 1)
                self.assertEqual(results["-1"].evidence, ())
                self.assertEqual(results["1"].evidence, ())

    def test_session_missing_identity_connect_relations_and_scopes(self):
        calls = [call(1, session="B"), call(2, 20, 80, session="A", connect_id="other"),
                 call(3, 30, 70, session=None, connect_id=None), call(4, session="", connect_id=""),
                 call(5, session=" ", connect_id=" ")]
        variants = [dict(dataset_id="other"), dict(user="Other"), dict(process="rphost_2"),
                    dict(thread="8"), dict(thread=None), dict(thread=""), dict(thread=" "),
                    dict(user="(not specified)", usr_raw=None), dict(user="(not specified)", usr_raw="   "),
                    dict(process=""), dict(end_time_us=None, start_time_us=None),
                    dict(end_time_us=None, start_time_us=None, thread=None)]
        calls += [call(20 + i, **variant) for i, variant in enumerate(variants)]
        events = []
        for kind in TYPES:
            for session in ("A", "B", "C", None, "", " "):
                for connect in ("conn", "other", None, "", " "):
                    for variant in [{}] + variants:
                        events.append(observation(f"event-{len(events)}", event_type=kind, session=session,
                                                  connect_id=connect, **variant))
        random.Random(17).shuffle(calls)
        random.Random(18).shuffle(events)
        self.assert_equivalent(calls, events)

    def test_file_hour_day_boundaries_and_later_call_record(self):
        calls = [call(13, DAY - 2, DAY + 3, measurement_id="next-day", source_version_id="next-file"),
                 call(2, 3_600_000_000 - 2, 3_600_000_000 + 3, source_version_id="next-hour")]
        events = [observation(f"{kind}-{i}-{t}", t, duration=10, event_type=kind,
                              measurement_id="previous-day", source_version_id="previous-file")
                  for kind in TYPES for i, c in enumerate(calls)
                  for t in (c["start_time_us"], c["end_time_us"] - 1, c["end_time_us"], c["end_time_us"] + 1)]
        results = self.assert_equivalent(calls, list(reversed(events)))
        self.assertEqual(results[f"EXCP-0-{DAY - 2}"].decision["parent_event_id"], "call-13")
        self.assertEqual(results[f"DBPOSTGRS-0-{DAY + 3}"].evidence[0]["full_interval_contained"], 0)

    def test_empty_inputs_and_scopes_without_calls_or_events(self):
        self.assert_equivalent([], [])
        self.assert_equivalent([call()], [])
        self.assert_equivalent([], [observation(), observation("no-time", None)])
        self.assert_equivalent([call(1, dataset_id="a"), call(2, dataset_id="c"), call(3, dataset_id="z")],
                               [observation("b", dataset_id="b"), observation("c", dataset_id="c"),
                                observation("d", dataset_id="d")])

    def test_reproducible_random_small_sets(self):
        for seed in (0, 1, 7, 42, 103, 2026, 65537, 9001):
            with self.subTest(seed=seed):
                rng = random.Random(seed)

                def identity():
                    user = rng.choice(("User", "Other", "(not specified)"))
                    return dict(dataset_id=rng.choice(("dataset", "other")), user=user,
                                usr_raw=rng.choice((None, "", "  ")) if user == "(not specified)" else user,
                                process=rng.choice(("rphost_1", "")), thread=rng.choice(("7", "8", "", None, " ")),
                                session=rng.choice(("A", "B", None, "", " ")), connect_id=rng.choice(("conn", "other", None, "")))

                calls = []
                for call_id in rng.sample(range(1, 1000), 45):
                    start = rng.randint(-10, 10)
                    calls.append(call(call_id, start, start + rng.randint(0, 25), **identity()))
                calls += [call(1001, None, None), call(1002, -100, 100)]
                events = []
                for i in range(120):
                    donor = rng.choice(calls)
                    attrs = identity() if i % 3 else {k: donor[k] for k in
                        ("dataset_id", "user", "usr_raw", "process", "thread", "session", "connect_id")}
                    t = rng.choice((None, donor["start_time_us"], donor["end_time_us"], rng.randint(-20, 40)))
                    events.append(observation(f"event-{i}", t, rng.randint(0, 35), event_type=rng.choice(TYPES), **attrs))
                rng.shuffle(calls)
                rng.shuffle(events)
                self.assert_equivalent(calls, events)

    def assert_tree(self, tree):
        for node in range(1, tree.size):
            self.assertEqual(tree.count[node], tree.count[node * 2] + tree.count[node * 2 + 1])
            ranks = [x for x in (tree.best[node * 2], tree.best[node * 2 + 1]) if x is not None]
            self.assertEqual(tree.best[node], max(ranks) if ranks else None)
        for node in range(tree.size, 2 * tree.size):
            self.assertEqual(tree.count[node], int(tree.best[node] is not None))

    def assert_structure(self, active, t):
        expected = [i for i, c in enumerate(active.calls) if c["start_time_us"] <= t <= c["end_time_us"]]
        before = active.work.candidates_visited
        self.assertEqual(list(active.candidates()), [active.calls[i] for i in expected])
        self.assertEqual(active.work.candidates_visited - before, len(expected))
        self.assertEqual(active.head, expected[0] if expected else -1)
        for j, position in enumerate(expected):
            self.assertEqual(active.prev[position], expected[j - 1] if j else -1)
            self.assertEqual(active.next[position], expected[j + 1] if j + 1 < len(expected) else -1)
        ranks = lambda positions: [(active.calls[i]["duration_us"], -active.calls[i]["legacy_call_id"], i) for i in positions]
        for position in range(len(active.calls)):
            leaf = active.tree.size + position
            self.assertEqual(active.tree.count[leaf], int(position in expected))
            self.assertEqual(active.tree.best[leaf], ranks([position])[0] if position in expected else None)
            if position not in expected:
                self.assertEqual((active.prev[position], active.next[position]), (-1, -1))
            self.assertEqual(active.tree.predecessor(position), max((i for i in expected if i < position), default=-1))
        self.assert_tree(active.tree)
        visits = active.work.tree_nodes_visited
        for session in (None, "", "A", "B", " ", "unseen"):
            matching = [i for i in expected if session and active.calls[i]["session"] == session]
            summary = active.summary(session)
            self.assertEqual((summary.candidate_count, summary.session_match_count), (len(expected), len(matching)))
            self.assertEqual(summary.best_event_id, active.calls[max(ranks(expected))[2]]["event_id"] if expected else None)
            self.assertEqual(summary.best_session_event_id, active.calls[max(ranks(matching))[2]]["event_id"] if matching else None)
        self.assertEqual(active.work.tree_nodes_visited, visits)  # root reads, no tree walk
        for session, tree in active.sessions.items():
            members = [i for i, c in enumerate(active.calls) if c["session"] == session]
            for local, position in enumerate(members):
                self.assertEqual(tree.best[tree.size + local], ranks([position])[0] if position in expected else None)
            self.assert_tree(tree)
        self.assertLessEqual(sum(tree.size for tree in active.sessions.values()), 2 * len(active.calls))

    def test_structure_at_every_transition_with_nonmonotone_call_ids(self):
        rng = random.Random(411)
        calls = [call(i, start, start + rng.randrange(12), session=rng.choice(("A", "B", "", None, " ")))
                 for i, start in zip(rng.sample(range(1000), 45), [rng.randrange(-10, 20) for _ in range(45)])]
        calls += [call(1001, None, None)]
        active = ActiveCalls(calls)
        for t in range(-11, 34):
            active.advance(t)
            self.assert_structure(active, t)
            cursors = (active.start_cursor, active.end_cursor)
            active.advance(t)
            self.assertEqual((active.start_cursor, active.end_cursor), cursors)
            self.assert_structure(active, t)
        self.assertEqual((active.work.activations, active.work.removals), (45, 45))

    def test_long_call_over_many_short_calls_no_sort_or_owner_scan(self):
        calls = [call(1, -1, 10000)] + [call(i + 2, i * 2, i * 2 + 1, session="B") for i in range(600)]
        events = [observation(f"e-{i}", i * 2 + 1, session="absent") for i in range(601)]
        self.assert_equivalent(list(reversed(calls)), list(reversed(events)))
        active = ActiveCalls(calls)
        # Sorting is allowed only during preparation. Owner lookup cannot even
        # request a candidate iterator, and every tree update has a log bound.
        with patch("builtins.sorted", side_effect=AssertionError("sort during sweep")), \
             patch.object(active, "candidates", side_effect=AssertionError("owner scan")):
            for e in events:
                active.advance(e["end_time_us"])
                self.assertEqual(active.summary("absent").best_event_id, "call-1")
            active.advance(10001)
        self.assertEqual(active.work.candidates_visited, 0)
        self.assertEqual((active.work.activations, active.work.removals), (len(calls), len(calls)))
        self.assertLessEqual(active.work.tree_nodes_visited, 8 * len(calls) * (active.tree.size.bit_length() + 1))
        self.assert_structure(active, 10001)

    def test_large_active_population_linear_enumeration_and_owner_only(self):
        calls = [call(i + 1, -i, 1000 + i, session="A" if i == 0 else f"session-{i}") for i in range(513)]
        active = ActiveCalls(calls)
        active.advance(0)
        visits = active.work.tree_nodes_visited
        with patch("builtins.sorted", side_effect=AssertionError("sort during enumeration")):
            self.assertEqual([c["legacy_call_id"] for c in active.candidates()], list(range(1, 514)))
        self.assertEqual(active.work.tree_nodes_visited, visits)
        self.assertEqual(active.work.candidates_visited, 513)
        self.assertEqual(active.summary("A").session_match_count, 1)
        self.assert_structure(active, 0)
        work = WorkCounters()
        with patch.object(ActiveCalls, "candidates", side_effect=AssertionError("owner-only enumeration")):
            results = list(link_events(calls, [observation(f"e-{i}", i) for i in range(20)], include_evidence=False, work=work))
        self.assertEqual(work.candidates_visited, 0)
        self.assertTrue(all(r.decision["parent_event_id"] == "call-1" and not r.evidence for r in results))

    def test_big_time_jump_eagerly_removes_even_nonwinning_calls(self):
        active = ActiveCalls([call(1, -1, 100), call(2, 2, 3), call(3, 5, 5), call(4, 7, 9)])
        active.advance(0)
        active.advance(20)
        self.assert_structure(active, 20)
        self.assertEqual((active.work.activations, active.work.removals), (4, 3))
        active.advance(101)
        self.assert_structure(active, 101)

    def test_candidate_view_invalidates_and_bad_order_or_identity_fails(self):
        active = ActiveCalls([call()])
        active.advance(0)
        started, unstarted = active.candidates(), active.candidates()
        next(started)
        active.advance(1)
        for view in (started, unstarted):
            with self.assertRaisesRegex(RuntimeError, "expired"):
                next(view)
        with self.assertRaises(ValueError):
            active.advance(0)
        with self.assertRaises(ValueError):
            active.advance(None)
        with self.assertRaises(ValueError):
            ActiveCalls([call(), call(2, dataset_id="other")])
        with self.assertRaises(ValueError):
            ActiveCalls([call(), call()])
        with self.assertRaises(ValueError):
            ActiveCalls([call(start=10, end=0)])
        with self.assertRaises(ValueError):
            list(link_events([call(), call(dataset_id="other")], []))
        with self.assertRaises(ValueError):
            list(link_events([], [observation(), observation()]))
        with self.assertRaises(ValueError):
            list(sweep_sorted([call(2), call(1)], [observation()]))
        with self.assertRaises(ValueError):
            list(sweep_sorted([call()], [observation("later", 10), observation("earlier", 0)]))

    def test_new_kernel_does_not_delegate_selection_or_evidence_to_legacy(self):
        with patch.object(legacy, "candidates", side_effect=AssertionError("legacy candidate query")), \
             patch.object(legacy, "decide", side_effect=AssertionError("legacy decision")), \
             patch.object(legacy, "candidate_evidence", side_effect=AssertionError("legacy evidence")):
            results = list(link_events([call()], [observation(event_type="QERR")]))
        self.assertEqual(results[0].decision["parent_event_id"], "call-1")
        self.assertEqual(len(results[0].evidence), 1)

    def test_sorted_interface_is_lazy_in_events_and_does_not_read_later_scopes(self):
        read_calls, read_events = [], []

        def calls():
            for c in [call(1, dataset_id="a"), call(2, dataset_id="b"), call(3, dataset_id="c")]:
                read_calls.append(c["event_id"])
                yield c

        def events():
            for e in [observation("first", dataset_id="a"), observation("second", dataset_id="b")]:
                read_events.append(e["event_id"])
                yield e

        results = sweep_sorted(calls(), events())
        first = next(results)
        self.assertEqual(first.decision["parent_event_id"], "call-1")
        self.assertEqual(read_calls, ["call-1", "call-2"])  # one groupby lookahead
        self.assertEqual(read_events, ["first"])
        second = next(results)
        self.assertEqual(second.decision["parent_event_id"], "call-2")
        self.assertEqual(first.evidence[0]["call_event_id"], "call-1")
        self.assertEqual(read_events, ["first", "second"])


if __name__ == "__main__":
    unittest.main()
