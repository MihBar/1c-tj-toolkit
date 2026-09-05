"""Recheck raw messages, every link and every incident hypothesis from saved data."""
from __future__ import annotations

import json

from error_rules import (ERROR_METADATA, INCIDENT_RULES_VERSION, message_fields, classify_error,
                         membership)
from error_store import ERROR_EXPORTS, export_rows, error_groups, error_summary
from stored_linking import stored_links, verify_candidates


def verify_errors(root, manifest, calls, connection, require, compare_csv):
    for key, value in ERROR_METADATA.items():
        require(manifest.get(key) == value, "error rules/version mismatch: " + key)
    population = connection.execute("SELECT count(*) FROM events WHERE event_type IN ('EXCP','QERR')").fetchone()[0]
    for table in ("error_events", "error_link_decisions", "error_incident_members", "error_observations"):
        require(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == population, "incomplete error population: " + table)
    evidence_count = 0
    for event, expected, evidence in stored_links(connection, "error"):
        require(event["event_type"] in ("EXCP", "QERR"), "unexpected error event type")
        fields = message_fields(json.loads(event["attributes_json"]))
        require(all(event[k] == v for k, v in fields.items()), "error message/signature mismatch")
        require(event["category"] == classify_error(event["raw_message"] or ""), "error text category mismatch")
        actual = connection.execute("SELECT * FROM error_link_decisions WHERE event_id=?", (event["event_id"],)).fetchone()
        require(actual is not None and dict(actual) == expected, "error link decision mismatch")
        count, connect_relation = verify_candidates(connection, "error_link_candidates", evidence, require, "error candidate evidence mismatch")
        evidence_count += count
        expected_member = membership(event, expected, connect_relation)
        member = connection.execute("SELECT * FROM error_incident_members WHERE event_id=?", (event["event_id"],)).fetchone()
        require(member is not None and dict(member) == expected_member, "incident membership/evidence mismatch")
        incident = connection.execute("SELECT * FROM suspected_incidents WHERE incident_id=?", (expected_member["incident_id"],)).fetchone()
        require(incident is not None and dict(incident) == {
            "incident_id": expected_member["incident_id"], "incident_rules_version": INCIDENT_RULES_VERSION,
            "group_key_json": expected_member["group_key_json"], "hypothesis_status": "unconfirmed",
            "root_cause": None, "cancellation_initiator": None}, "incident hypothesis/attribution mismatch")
    require(connection.execute("SELECT count(*) FROM error_link_candidates").fetchone()[0] == evidence_count,
            "error candidate evidence mismatch")
    require(connection.execute(
        "SELECT 1 FROM suspected_incidents i WHERE NOT EXISTS (SELECT 1 FROM error_incident_members m WHERE m.incident_id=i.incident_id) LIMIT 1"
    ).fetchone() is None, "empty incident")
    summary = error_summary(connection)
    require(manifest.get("error_summary") == summary, "error summary mismatch")
    require(manifest["errors"] == error_groups(connection), "error group counts/signatures mismatch")
    for key, field in (("error_events", "event_count"), ("affected_calls", "affected_call_count"), ("suspected_incidents", "suspected_incident_count")):
        require(manifest["counts"].get(key) == summary[field], "error count mismatch: " + key)
    for call in calls:
        count = connection.execute("SELECT count(*) FROM error_link_decisions WHERE parent_event_id=?", (call["event_id"],)).fetchone()[0]
        require(count == call["error_count"], "CALL error event count mismatch")
    for row in manifest["linkage"]:
        counts = connection.execute(
            "SELECT count(*),count(k.parent_event_id) FROM error_events r JOIN events e USING(event_id) JOIN error_link_decisions k USING(event_id) "
            "WHERE e.measurement_id=? AND e.dataset_id=?", (row["measurement_id"], row["dataset_id"])).fetchone()
        require(tuple(counts) == (row["error_total_count"], row["error_linked_count"]), "error linkage sums mismatch")
    for table, filename, order in ERROR_EXPORTS:
        fields = [r[1] for r in connection.execute(f"PRAGMA table_info({table})")]
        count = compare_csv(root/filename, fields, export_rows(connection, table, order))
        require(count == manifest["artifacts"][filename]["row_count"], "error export count mismatch: " + filename)
