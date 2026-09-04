"""Stream error events, persist each decision, and aggregate on disk."""
from __future__ import annotations

from event_store import insert, export_csv, timestamp
from event_linking import candidates
from error_rules import (ERROR_SIGNATURE_VERSION, INCIDENT_RULES_VERSION, clean,
                         error_decision, error_candidates, membership)

ERROR_EXPORTS = (
    ("error_observations", "error_observations.csv", "source_version_id,byte_start"),
    ("error_link_decisions", "error_event_links.csv", "event_id"),
    ("error_link_candidates", "error_link_candidates.csv", "event_id,call_event_id"),
    ("error_incidents", "error_incidents.csv", "incident_id"),
    ("error_incident_members", "error_incident_members.csv", "event_id"),
)


def link_errors(store):
    connection = store.connection
    connection.commit()
    for event in connection.execute("SELECT e.*,r.raw_message,r.message_state FROM events e JOIN error_events r USING(event_id) ORDER BY e.event_id"):
        candidate_rows = candidates(connection, event)
        decision = error_decision(connection, event, candidate_rows)
        insert(connection, "error_link_decisions", decision)
        connect_relation = None
        for candidate in error_candidates(connection, event, decision, candidate_rows):
            insert(connection, "error_link_candidates", candidate)
            if candidate["selected"]:
                connect_relation = candidate["connect_relation"]
        member = membership(event, decision, connect_relation)
        insert(connection, "suspected_incidents", {
            "incident_id": member["incident_id"], "incident_rules_version": INCIDENT_RULES_VERSION,
            "group_key_json": member["group_key_json"], "hypothesis_status": "unconfirmed",
            "root_cause": None, "cancellation_initiator": None}, ignore=True)
        insert(connection, "error_incident_members", member)
        store.tick()
        if store.on_error_link is not None:
            store.on_error_link(1)
    connection.commit()


def error_rows(connection):
    return connection.execute("SELECT * FROM error_observations ORDER BY source_version_id,byte_start")


def export_rows(connection, table, order):
    return (dict(r) for r in connection.execute(f"SELECT * FROM {table} ORDER BY {order}"))


def export_errors(store, output):
    counts = {}
    for table, filename, order in ERROR_EXPORTS:
        fields = [r[1] for r in store.connection.execute(f"PRAGMA table_info({table})")]
        counts[filename] = export_csv(output/filename, fields, export_rows(store.connection, table, order))
    return counts


def error_summary(connection):
    result = dict(connection.execute(
        "SELECT count(*) AS event_count,count(k.parent_event_id) AS linked_error_event_count,"
        "count(*)-count(k.parent_event_id) AS unlinked_error_event_count,"
        "count(DISTINCT k.parent_event_id) AS affected_call_count,"
        "count(DISTINCT m.incident_id) AS suspected_incident_count,"
        "count(CASE WHEN k.status='ambiguous' THEN 1 END) AS ambiguous_linked_error_event_count,"
        "count(CASE WHEN k.status='linked_by_rule' THEN 1 END) AS fallback_linked_error_event_count "
        "FROM error_events r JOIN error_link_decisions k USING(event_id) JOIN error_incident_members m USING(event_id)"
    ).fetchone())
    return {**result, "incident_rules_version": INCIDENT_RULES_VERSION,
            "affected_call_semantics": "distinct selected CALL owners, including ambiguous/fallback assignments; not confirmed business failures",
            "incident_semantics": "unconfirmed hypotheses, not proven independent root incidents"}


def error_groups(connection):
    result = []
    query = (
        "SELECT measurement_id,event_type,signature_id,signature,"
        "min(event_id) AS sample_id,count(*) AS event_count,count(call_event_id) AS linked_error_event_count,"
        "count(DISTINCT call_event_id) AS affected_call_count,count(DISTINCT incident_id) AS suspected_incident_count,"
        "min(end_time_us) AS first_time,max(end_time_us) AS last_time "
        "FROM error_observations GROUP BY measurement_id,event_type,signature_id"
    )
    for row in connection.execute(query):
        key = (row["measurement_id"], row["event_type"], row["signature_id"])
        # Distinct values/sorting use SQLite; only the legacy preview lists enter RAM.
        values = {}
        for name, field in (("users", "user"), ("contexts", "context")):
            values[name] = [r[0] for r in connection.execute(
                f"SELECT DISTINCT {field} FROM error_observations WHERE measurement_id=? AND event_type=? AND signature_id=? "
                f"AND {field} IS NOT NULL AND {field}<>'' ORDER BY {field}" + (" LIMIT 30" if name == "contexts" else ""), key)]
        sample = connection.execute("SELECT raw_message,category FROM error_events WHERE event_id=?", (row["sample_id"],)).fetchone()
        result.append({"measurement_id": row["measurement_id"], "event": row["event_type"],
                       "category": sample["category"], "signature": row["signature"], "signature_id": row["signature_id"],
                       "error_signature_version": ERROR_SIGNATURE_VERSION, "sample": clean(sample["raw_message"])[:2400],
                       "event_count": row["event_count"], "linked_error_event_count": row["linked_error_event_count"],
                       "unlinked_error_event_count": row["event_count"]-row["linked_error_event_count"],
                       "affected_call_count": row["affected_call_count"], "suspected_incident_count": row["suspected_incident_count"],
                       "incident_rules_version": INCIDENT_RULES_VERSION, **values,
                       "first_timestamp": str(timestamp(row["first_time"])) if row["first_time"] is not None else "",
                       "last_timestamp": str(timestamp(row["last_time"])) if row["last_time"] is not None else ""})
    return sorted(result, key=lambda r: (r["suspected_incident_count"], r["event_count"], r["signature"], r["measurement_id"], r["event"]), reverse=True)
