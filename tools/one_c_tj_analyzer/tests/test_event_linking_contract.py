"""Characterization tests for the versioned CALL owner linkage contract."""
from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_DIR))

from error_rules import ERROR_LINKAGE_VERSION, error_candidates, error_decision  # noqa: E402
from error_store import link_errors  # noqa: E402
from event_linking import (  # noqa: E402
    LINKAGE_RULES_VERSION,
    candidates,
    candidate_evidence,
    decide,
)
from event_store import EventStore  # noqa: E402
from stored_linking import CALL_SCAN  # noqa: E402


EVENT_TYPES = ("DBPOSTGRS", "EXCP")


def event(event_type: str, **overrides):
    row = {
        "event_id": "observed-event",
        "event_type": event_type,
        "dataset_id": "dataset",
        "user": "User",
        "usr_raw": "User",
        "process": "rphost_1",
        "thread": "7",
        "start_time_us": 45,
        "end_time_us": 50,
        "duration_us": 5,
        "session": "A",
        "connect_id": "connection",
    }
    row.update(overrides)
    return row


class LinkageContractTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            CREATE TABLE events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                dataset_id TEXT NOT NULL,
                user TEXT NOT NULL,
                usr_raw TEXT,
                process TEXT NOT NULL,
                thread TEXT,
                start_time_us INTEGER,
                end_time_us INTEGER,
                duration_us INTEGER NOT NULL,
                session TEXT,
                connect_id TEXT
            );
            CREATE TABLE call_events (
                event_id TEXT PRIMARY KEY,
                legacy_call_id INTEGER NOT NULL UNIQUE
            );
            """
        )
        self.addCleanup(self.connection.close)

    def add_call(
        self,
        legacy_call_id: int,
        *,
        start: int = 0,
        end: int = 100,
        duration: int = 100,
        session: str | None = "A",
        connect_id: str | None = "connection",
    ) -> str:
        event_id = f"call-{legacy_call_id}"
        self.connection.execute(
            "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                "CALL",
                "dataset",
                "User",
                "User",
                "rphost_1",
                "7",
                start,
                end,
                duration,
                session,
                connect_id,
            ),
        )
        self.connection.execute(
            "INSERT INTO call_events(event_id,legacy_call_id) VALUES (?,?)",
            (event_id, legacy_call_id),
        )
        return event_id

    def link(self, observed):
        candidate_rows = candidates(self.connection, observed)
        if observed["event_type"] == "DBPOSTGRS":
            decision = decide(self.connection, observed, candidate_rows)
            evidence = list(candidate_evidence(self.connection, observed, decision, candidate_rows))
        else:
            decision = error_decision(self.connection, observed, candidate_rows)
            evidence = list(error_candidates(self.connection, observed, decision, candidate_rows))
        return decision, evidence

    def assert_both_event_types(self, expected_decision, expected_evidence):
        results = {}
        for event_type in EVENT_TYPES:
            with self.subTest(event_type=event_type):
                decision, evidence = self.link(event(event_type))
                expected = {
                    **expected_decision,
                    "event_id": "observed-event",
                    "linkage_rules_version": (
                        LINKAGE_RULES_VERSION if event_type == "DBPOSTGRS" else ERROR_LINKAGE_VERSION
                    ),
                    "selection_rule": "duration_desc_legacy_call_id_asc",
                }
                self.assertEqual(decision, expected)
                self.assertEqual(evidence, expected_evidence)
                results[event_type] = ({k: v for k, v in decision.items() if k != "linkage_rules_version"}, evidence)
        self.assertEqual(results["DBPOSTGRS"], results["EXCP"])

    def test_no_candidates_is_unlinked_with_zero_counts_and_no_evidence(self):
        self.assert_both_event_types(
            {
                "parent_event_id": None,
                "status": "unlinked",
                "reason_code": "no_containing_call",
                "candidate_count": 0,
                "eligible_count": 0,
                "session_match_count": 0,
                "fallback_applied": 0,
            },
            [],
        )

    def test_one_matching_candidate_is_linked_unique(self):
        self.add_call(4)
        self.assert_both_event_types(
            {
                "parent_event_id": "call-4",
                "status": "linked_unique",
                "reason_code": "same_session_unique",
                "candidate_count": 1,
                "eligible_count": 1,
                "session_match_count": 1,
                "fallback_applied": 0,
            },
            [
                {
                    "event_id": "observed-event",
                    "call_event_id": "call-4",
                    "session_relation": "match",
                    "connect_relation": "match",
                    "full_interval_contained": 1,
                    "eligible": 1,
                    "selected": 1,
                    "reason_code": "selected_legacy_rule",
                }
            ],
        )

    def test_matching_nonempty_session_is_preferred_and_candidate_rows_keep_legacy_order(self):
        # Insert in the opposite order and give the nonmatching CALL a longer
        # duration. Candidate evidence must still be ordered by legacy_call_id,
        # while the matching nonempty SessionID controls eligibility and choice.
        self.add_call(10, duration=100, session="A")
        self.add_call(2, duration=50, session="B")
        expected_evidence = [
            {
                "event_id": "observed-event",
                "call_event_id": "call-2",
                "session_relation": "match",
                "connect_relation": "match",
                "full_interval_contained": 1,
                "eligible": 1,
                "selected": 1,
                "reason_code": "selected_legacy_rule",
            },
            {
                "event_id": "observed-event",
                "call_event_id": "call-10",
                "session_relation": "conflict",
                "connect_relation": "match",
                "full_interval_contained": 1,
                "eligible": 0,
                "selected": 0,
                "reason_code": "excluded_by_session_preference",
            },
        ]
        results = {}
        for event_type in EVENT_TYPES:
            with self.subTest(event_type=event_type):
                decision, evidence = self.link(event(event_type, session="B"))
                self.assertEqual(decision["parent_event_id"], "call-2")
                self.assertEqual(decision["status"], "linked_unique")
                self.assertEqual(decision["reason_code"], "same_session_unique")
                self.assertEqual(
                    (decision["candidate_count"], decision["eligible_count"], decision["session_match_count"]),
                    (2, 1, 1),
                )
                self.assertEqual(decision["fallback_applied"], 0)
                self.assertEqual(evidence, expected_evidence)
                results[event_type] = (
                    {k: v for k, v in decision.items() if k != "linkage_rules_version"},
                    evidence,
                )
        self.assertEqual(results["DBPOSTGRS"], results["EXCP"])

    def test_missing_session_falls_back_to_all_candidates_and_longest_duration_wins(self):
        self.add_call(8, duration=100, session="A")
        self.add_call(9, duration=200, session="B")
        for event_type in EVENT_TYPES:
            with self.subTest(event_type=event_type):
                decision, evidence = self.link(event(event_type, session=None))
                self.assertEqual(decision["parent_event_id"], "call-9")
                self.assertEqual(decision["status"], "ambiguous")
                self.assertEqual(decision["reason_code"], "multiple_candidates_legacy_longest")
                self.assertEqual(
                    (decision["candidate_count"], decision["eligible_count"], decision["session_match_count"]),
                    (2, 2, 0),
                )
                self.assertEqual(decision["fallback_applied"], 1)
                self.assertEqual([row["call_event_id"] for row in evidence], ["call-8", "call-9"])
                self.assertEqual([row["eligible"] for row in evidence], [1, 1])
                self.assertEqual([row["selected"] for row in evidence], [0, 1])
                expected_relation = "db_missing" if event_type == "DBPOSTGRS" else "event_missing"
                self.assertEqual([row["session_relation"] for row in evidence], [expected_relation, expected_relation])

    def test_equal_duration_chooses_smallest_legacy_call_id(self):
        self.add_call(11, duration=100)
        self.add_call(3, duration=100)
        for event_type in EVENT_TYPES:
            with self.subTest(event_type=event_type):
                decision, evidence = self.link(event(event_type))
                self.assertEqual(decision["parent_event_id"], "call-3")
                self.assertEqual(decision["status"], "ambiguous")
                self.assertEqual(
                    (decision["candidate_count"], decision["eligible_count"], decision["session_match_count"]),
                    (2, 2, 2),
                )
                self.assertEqual([row["call_event_id"] for row in evidence], ["call-3", "call-11"])
                self.assertEqual([row["selected"] for row in evidence], [1, 0])

    def test_both_interval_boundaries_are_inclusive(self):
        self.add_call(1, start=50, end=80, duration=30)
        self.add_call(2, start=0, end=50, duration=50)
        self.add_call(3, start=51, end=80, duration=29)
        self.add_call(4, start=0, end=49, duration=49)
        for event_type in EVENT_TYPES:
            with self.subTest(event_type=event_type):
                decision, evidence = self.link(event(event_type))
                self.assertEqual(decision["parent_event_id"], "call-2")
                self.assertEqual(
                    (decision["candidate_count"], decision["eligible_count"], decision["session_match_count"]),
                    (2, 2, 2),
                )
                self.assertEqual([row["call_event_id"] for row in evidence], ["call-1", "call-2"])

    def test_store_uses_one_call_scan_per_phase_without_event_candidate_queries(self):
        with tempfile.TemporaryDirectory(prefix="tj-link-query-test-") as temp:
            store = EventStore(Path(temp) / "analysis.sqlite")
            connection = store.connection
            connection.execute(
                "INSERT INTO source_streams VALUES (?,?,?,?,?,?)",
                ("source", "capture", "origin", "rphost_1", "logical", "explicit"),
            )
            connection.execute(
                "INSERT INTO source_versions VALUES (?,?,?,?,?,?,?,?)",
                ("version", "source", "hash", "full_uncompressed", 30, 30, "utf-8", "included",),
            )

            def add_stored_event(event_id, event_type, byte_start, start, end, duration):
                connection.execute(
                    "INSERT INTO events (event_id,source_version_id,byte_start,byte_end,record_ordinal,line_start,line_end,"
                    "raw_record_sha256,event_type,level,raw_timestamp,start_time_us,end_time_us,time_state,duration_raw,"
                    "duration_us,duration_state,dataset_id,measurement_id,user,usr_raw,process,thread,session,connect_id,"
                    "context,attributes_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (event_id, "version", byte_start, byte_start + 10, byte_start // 10 + 1,
                     byte_start // 10 + 1, byte_start // 10 + 1, event_id, event_type, 5, "00:00.000000",
                     start, end, "local_naive", str(duration), duration, "valid", "dataset", "measurement",
                     "User", "User", "rphost_1", "7", "A", "connection", "Operation", "{}"),
                )

            add_stored_event("call", "CALL", 0, 0, 100, 100)
            add_stored_event("db", "DBPOSTGRS", 10, 49, 50, 1)
            add_stored_event("error", "EXCP", 20, 59, 60, 1)
            connection.execute("INSERT INTO call_events VALUES (?,?,?,?)", ("call", 1, "Operation", "1.0"))
            connection.execute("INSERT INTO db_events VALUES (?,?,?)", ("db", None, "missing"))
            connection.execute(
                "INSERT INTO error_events VALUES (?,?,?,?,?,?,?,?,?)",
                ("error", "Descr", "Failure", "present", "Failure", "signature", "full_message/v2", "other", None),
            )
            connection.commit()

            statements = []
            connection.set_trace_callback(statements.append)
            store.link_db()
            link_errors(store)
            connection.set_trace_callback(None)

            candidate_queries = [
                statement for statement in statements
                if statement.startswith("SELECT e.*, c.legacy_call_id FROM events e JOIN call_events c USING(event_id)")
            ]
            db_decision_count = connection.execute("SELECT count(*) FROM link_decisions").fetchone()[0]
            error_decision_count = connection.execute("SELECT count(*) FROM error_link_decisions").fetchone()[0]
            store.close()
            self.assertEqual(len(candidate_queries), 0)
            self.assertEqual(statements.count(CALL_SCAN), 2)
            self.assertEqual(db_decision_count, 1)
            self.assertEqual(error_decision_count, 1)


if __name__ == "__main__":
    unittest.main()
