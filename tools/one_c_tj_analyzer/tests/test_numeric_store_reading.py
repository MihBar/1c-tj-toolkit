"""Regression contract for replacing per-event numeric_values reads with a stream."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
import tempfile
import unittest

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from event_store import EventStore
from numeric_quality import FIELDS, parse_counter
import analyze_1c_tj as analyzer


def numeric_payload(row) -> dict:
    """Map a stored row exactly as EventStore.numeric() does."""
    return {
        "state": row["state"],
        "raw_value": row["raw_value"],
        "value": row["value_int"],
        "unit": row["unit"],
        "reason": row["reason_code"],
    }


def stream_db_numeric(connection):
    """Test-only model of the proposed two-cursor ordered merge."""
    events = connection.execute(
        "SELECT e.source_version_id,e.byte_start,e.event_id "
        "FROM events e JOIN db_events d USING(event_id) "
        "ORDER BY e.source_version_id,e.byte_start"
    )
    values = iter(connection.execute(
        "SELECT e.source_version_id,e.byte_start,n.* "
        "FROM events e JOIN db_events d USING(event_id) "
        "JOIN numeric_values n USING(event_id) "
        "ORDER BY e.source_version_id,e.byte_start,n.field_name"
    ))
    current = next(values, None)
    for event in events:
        key = (event["source_version_id"], event["byte_start"], event["event_id"])
        quality = {}
        while current is not None:
            current_key = (
                current["source_version_id"], current["byte_start"], current["event_id"]
            )
            if current_key != key:
                break
            quality[current["field_name"]] = numeric_payload(current)
            current = next(values, None)
        yield event["event_id"], quality
    if current is not None:
        raise AssertionError("numeric cursor contains a row outside the DB event stream")


class NumericStoreReadingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tj-numeric-store-test-")
        self.addCleanup(self.temp.cleanup)
        self.store = EventStore(Path(self.temp.name) / "analysis.sqlite")
        self.addCleanup(self.store.close)
        self.connection = self.store.connection
        self.connection.execute(
            "INSERT INTO source_streams VALUES (?,?,?,?,?,?)",
            ("source", "capture", "origin", "rphost_1", "logical", "explicit"),
        )
        self.connection.execute(
            "INSERT INTO source_versions VALUES (?,?,?,?,?,?,?,?)",
            ("version", "source", "hash", "full_uncompressed", 100, 100, "utf-8", "included"),
        )
        self.connection.execute(
            "INSERT INTO source_locations VALUES (?,?,?,?,?,?,?)",
            ("location", "version", "loose", "C:/synthetic.log", None, None, "synthetic.log"),
        )
        for ordinal, event_id in enumerate(("event-a", "event-b", "event-c", "event-d"), 1):
            byte_start = ordinal * 10
            self.connection.execute(
                "INSERT INTO events (event_id,source_version_id,byte_start,byte_end,record_ordinal,line_start,line_end,"
                "raw_record_sha256,event_type,level,raw_timestamp,start_time_us,end_time_us,time_state,duration_raw,"
                "duration_us,duration_state,dataset_id,measurement_id,user,usr_raw,process,thread,session,connect_id,"
                "context,attributes_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (event_id, "version", byte_start, byte_start + 5, ordinal, ordinal, ordinal,
                 event_id, "DBPOSTGRS", 5, "00:00.000000", ordinal, ordinal + 1,
                 "local_naive", "1", 1, "valid", "dataset", "measurement", "User", "User",
                 "rphost_1", "7", "A", None, "Operation", "{}"),
            )
            self.connection.execute("INSERT INTO db_events VALUES (?,?,?)", (event_id, None, "missing"))
            self.connection.execute(
                "INSERT INTO link_decisions VALUES (?,?,?,?,?,?,?,?,?,?)",
                (event_id, "legacy_end_longest/v1", None, "unlinked", "no_containing_call",
                 0, 0, 0, 0, "none",),
            )

        self.insert_numeric("event-a", {
            "cpu_us": "0",
            "memory": "-1",
            "memory_peak": "",
            "in_bytes": "not-an-integer",
            "out_bytes": str(2**63),
            "rows_affected": None,
        })
        self.insert_numeric("event-b", {"cpu_us": "17", "rows_affected": "3"})
        # event-c intentionally has no numeric_values rows at all.
        self.insert_numeric("event-d", {"memory": "9", "out_bytes": None})
        self.connection.commit()

    def insert_numeric(self, event_id: str, values: dict[str, str | None]) -> None:
        for name, raw_value in values.items():
            parsed = parse_counter(name, raw_value)
            self.connection.execute(
                "INSERT INTO numeric_values VALUES (?,?,?,?,?,?,?)",
                (event_id, name, parsed["raw_value"], parsed["value"], parsed["state"],
                 parsed["unit"], parsed["reason"]),
            )

    def insert_auxiliary_event(self, event_id: str, event_type: str, byte_start: int) -> None:
        self.connection.execute(
            "INSERT INTO events (event_id,source_version_id,byte_start,byte_end,record_ordinal,line_start,line_end,"
            "raw_record_sha256,event_type,level,raw_timestamp,start_time_us,end_time_us,time_state,duration_raw,"
            "duration_us,duration_state,dataset_id,measurement_id,user,usr_raw,process,thread,session,connect_id,"
            "context,attributes_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, "version", byte_start, byte_start + 5, byte_start, byte_start, byte_start,
             event_id, event_type, 5, "00:00.000000", byte_start, byte_start + 1,
             "local_naive", "1", 1, "valid", "dataset", "measurement", "User", "User",
             "rphost_1", "7", "A", None, "Shared", "{}"),
        )

    def test_complete_numeric_quality_preserves_raw_states_units_reasons_and_zero(self):
        quality = self.store.numeric("event-a")

        self.assertEqual(list(quality), sorted(FIELDS))
        self.assertEqual(set(quality), set(FIELDS))
        self.assertEqual(quality, {
            "cpu_us": {"state": "valid", "raw_value": "0", "value": 0, "unit": "us", "reason": None},
            "in_bytes": {"state": "invalid", "raw_value": "not-an-integer", "value": None,
                         "unit": "bytes", "reason": "not_an_integer"},
            "memory": {"state": "valid", "raw_value": "-1", "value": -1, "unit": "bytes", "reason": None},
            "memory_peak": {"state": "empty", "raw_value": "", "value": None, "unit": "bytes", "reason": None},
            "out_bytes": {"state": "out_of_range", "raw_value": str(2**63), "value": None,
                          "unit": "bytes", "reason": "outside_supported_range"},
            "rows_affected": {"state": "missing", "raw_value": None, "value": None,
                              "unit": "rows", "reason": None},
        })
        self.assertIs(quality["cpu_us"]["value"], 0)
        for name in ("memory_peak", "in_bytes", "out_bytes", "rows_affected"):
            self.assertIsNone(quality[name]["value"], name)
        stored = self.connection.execute(
            "SELECT field_name,value_int,state FROM numeric_values "
            "WHERE event_id='event-a' AND field_name IN ('cpu_us','rows_affected') "
            "ORDER BY field_name"
        ).fetchall()
        self.assertEqual(
            [(row["field_name"], row["value_int"], row["state"]) for row in stored],
            [("cpu_us", 0, "valid"), ("rows_affected", None, "missing")],
        )

    def test_stream_keeps_empty_and_partial_events_separate_and_matches_point_reads(self):
        streamed = list(stream_db_numeric(self.connection))
        expected = [
            (event_id, self.store.numeric(event_id))
            for event_id in ("event-a", "event-b", "event-c", "event-d")
        ]

        self.assertEqual(streamed, expected)
        self.assertEqual(streamed[2], ("event-c", {}))
        self.assertEqual(list(streamed[1][1]), ["cpu_us", "rows_affected"])
        self.assertEqual(list(streamed[3][1]), ["memory", "out_bytes"])
        self.assertNotIn("memory", streamed[1][1])
        self.assertNotIn("rows_affected", streamed[3][1])
        self.assertEqual(streamed[1][1]["cpu_us"]["raw_value"], "17")
        self.assertEqual(streamed[3][1]["memory"]["raw_value"], "9")

    def test_db_rows_uses_a_bounded_number_of_numeric_values_queries(self):
        """DB export uses one numeric stream rather than one query per event."""
        event_ids = ("event-a", "event-b", "event-c", "event-d")
        expected_quality = {event_id: self.store.numeric(event_id) for event_id in event_ids}
        statements = []
        self.connection.set_trace_callback(statements.append)
        try:
            rows = list(self.store.db_rows())
        finally:
            self.connection.set_trace_callback(None)

        numeric_queries = [
            statement for statement in statements
            if statement.lstrip().upper().startswith("SELECT")
            and "NUMERIC_VALUES" in statement.upper()
        ]
        self.assertEqual(len(rows), 4)
        self.assertEqual([row["event_id"] for row in rows], list(event_ids))
        self.assertEqual(
            [row["numeric_quality"] for row in rows],
            [expected_quality[event_id] for event_id in event_ids],
        )
        self.assertEqual(
            len(numeric_queries), 1,
            f"numeric_values was queried {len(numeric_queries)} times for {len(rows)} DB events",
        )

    def test_auxiliary_events_use_one_numeric_stream_without_cross_event_mixing(self):
        auxiliary = (
            ("aux-a", "TLOCK", 50, {"cpu_us": "0", "rows_affected": None}),
            ("aux-b", "SDBL", 60, {"cpu_us": "17"}),
            ("aux-c", "TTIMEOUT", 70, {"memory": "", "in_bytes": "bad"}),
            ("aux-d", "TLOCK", 80, {"cpu_us": str(2**63), "rows_affected": "5"}),
            ("aux-e", "TDEADLOCK", 90, {}),
        )
        for event_id, event_type, byte_start, values in auxiliary:
            self.insert_auxiliary_event(event_id, event_type, byte_start)
            self.insert_numeric(event_id, values)
        self.connection.commit()

        call_numeric = {name: parse_counter(name, None) for name in FIELDS}
        call = analyzer.CallRecord(
            call_id=1, dataset_id="dataset", measurement_id="measurement", user="User",
            signature="Operation", context_sample="Operation", source="synthetic.log", process="rphost_1",
            end=dt.datetime(1970, 1, 1, 0, 0, 0, 100), start=dt.datetime(1970, 1, 1), duration_us=100,
            cpu_us=None, memory=None, memory_peak=None, in_bytes=None, out_bytes=None, rows_affected=None,
            thread="7", session="A", connect_id="", numeric_quality=call_numeric,
        )

        statements = []
        self.connection.set_trace_callback(statements.append)
        try:
            _, lock_groups, linkage = analyzer.analyze_pass_two([call], self.store)
        finally:
            self.connection.set_trace_callback(None)

        auxiliary_numeric_queries = [
            statement for statement in statements
            if statement.lstrip().upper().startswith("SELECT")
            and "FROM EVENTS E JOIN NUMERIC_VALUES N" in statement.upper()
            and "WHERE E.EVENT_TYPE IN" in statement.upper()
        ]
        point_numeric_queries = [
            statement for statement in statements
            if "FROM NUMERIC_VALUES WHERE EVENT_ID=" in statement.upper()
        ]
        self.assertEqual(len(auxiliary_numeric_queries), 1)
        self.assertEqual(point_numeric_queries, [])
        self.assertEqual(linkage[("dataset", "measurement")]["sdbl_total_count"], 1)
        self.assertEqual(linkage[("dataset", "measurement")]["lock_total_count"], 4)
        self.assertEqual((call.sdbl_count, call.lock_count, call.lock_duration_us), (1, 4, 4))
        operation = analyzer.aggregate_operations([call])[0]
        self.assertEqual(
            (operation["sdbl_count"], operation["lock_count"], operation["lock_duration_us"]),
            (1, 4, 4),
        )

        tlock = lock_groups[("measurement", "TLOCK", "Shared")].as_dict()["numeric_quality"]
        self.assertEqual(tlock["cpu_us"]["eligible_count"], 2)
        self.assertEqual(tlock["cpu_us"]["available_count"], 1)
        self.assertEqual(tlock["cpu_us"]["zero_count"], 1)
        self.assertEqual(tlock["cpu_us"]["sum_known"], 0)
        self.assertEqual(tlock["cpu_us"]["out_of_range_count"], 1)
        self.assertEqual(tlock["rows_affected"]["missing_count"], 1)
        self.assertEqual(tlock["rows_affected"]["sum_known"], 5)
        self.assertEqual(tlock["memory"]["eligible_count"], 0)

        timeout = lock_groups[("measurement", "TTIMEOUT", "Shared")].as_dict()["numeric_quality"]
        self.assertEqual(timeout["memory"]["empty_count"], 1)
        self.assertEqual(timeout["in_bytes"]["invalid_count"], 1)
        self.assertIsNone(timeout["memory"]["sum_known"])

        deadlock = lock_groups[("measurement", "TDEADLOCK", "Shared")].as_dict()["numeric_quality"]
        self.assertTrue(all(summary["eligible_count"] == 0 for summary in deadlock.values()))

        legacy_groups = {}
        for row in self.connection.execute(
            "SELECT * FROM events WHERE event_type IN ('SDBL','TLOCK','TTIMEOUT','TDEADLOCK') "
            "ORDER BY source_version_id,byte_start"
        ):
            if row["event_type"] == "SDBL":
                continue
            key = (row["measurement_id"], row["event_type"], row["context"])
            group = legacy_groups.setdefault(key, analyzer.LockGroup(event=row["event_type"]))
            group.add(row["duration_us"], self.store.numeric(row["event_id"]))
            group.users.add(row["user"])
            group.contexts.add(row["context"])
            group.linked_call_count += 1
        self.assertEqual(analyzer.lock_rows(lock_groups), analyzer.lock_rows(legacy_groups))


if __name__ == "__main__":
    unittest.main()
