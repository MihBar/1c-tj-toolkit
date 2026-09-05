"""SQLite cursor adapter for the time sweep; no persistent schema changes.

Two ordered scans per linkage phase: narrow CALL rows and target identities.
SQLite owns the external sorts (temp_store=FILE); Python retains only one CALL
scope and cursor lookahead, one hydrated target, and one evidence row. No
fetchall/list of targets or active candidates. CALL memory is O(max C_scope),
not O(active_count): the kernel also holds inactive coordinates for that scope.
The existing analyzer's separate CallRecord population is outside this adapter.

Target hydration uses a primary-key lookup, O(E log N), to avoid sorting SQL,
messages and full Context payloads. Verification evidence uses composite-PK
lookups, O(K log K), never a per-event interval search or candidate sort.
"""
from __future__ import annotations

from contextlib import closing, contextmanager

from event_linking_sweep import sweep_views_sorted


CALL_SCAN = (
    "SELECT e.event_id,e.event_type,e.dataset_id,e.user,e.process,e.thread,"
    "e.start_time_us,e.end_time_us,e.duration_us,e.session,e.connect_id,c.legacy_call_id "
    "FROM events e JOIN call_events c USING(event_id) WHERE e.event_type='CALL' "
    "AND e.end_time_us IS NOT NULL AND e.thread IS NOT NULL AND e.thread<>'' "
    "ORDER BY e.dataset_id,e.user,e.process,coalesce(e.thread,''),c.legacy_call_id"
)
TARGET_ORDER = "e.dataset_id,e.user,e.process,coalesce(e.thread,''),e.end_time_us,e.event_id"
TARGETS = {
    "db": ("events e JOIN db_events d USING(event_id)", "e.*", ""),
    "error": ("events e JOIN error_events r USING(event_id)", "e.*,r.*", ""),
    "aux": ("events e", "e.*", " WHERE e.event_type IN ('SDBL','TLOCK','TTIMEOUT','TDEADLOCK')"),
}


def stored_links(connection, kind, *, include_evidence=True, work=None):
    """Read original events, not stored decisions. Also works on immutable DBs.

    SQL identifiers are fixed program constants. SQLite BINARY text ordering
    and NULL-first integer ordering match the kernel's scope/event keys.
    Separate read cursors remain open across bounded writer commits; base event
    tables are immutable throughout linking. Cursors close even on failure.
    """
    source, projection, where = TARGETS[kind]
    connection.execute("PRAGMA temp_store=FILE")
    connection.execute("PRAGMA cache_size=-8192")
    with closing(connection.execute(CALL_SCAN)) as calls, \
         closing(connection.execute(f"SELECT e.event_id FROM {source}{where} ORDER BY {TARGET_ORDER}")) as targets, \
         closing(connection.cursor()) as lookup:
        def events():
            for row in targets:
                event = lookup.execute(f"SELECT {projection} FROM {source} WHERE e.event_id=?", (row[0],)).fetchone()
                if event is None:
                    raise ValueError("Stored linkage target disappeared")
                yield event

        with closing(sweep_views_sorted(calls, events(), include_evidence=include_evidence, work=work)) as sweep:
            yield from sweep


def verify_candidates(connection, table, evidence, require, message):
    """Check every expected PK once; caller checks total rows to reject extras."""
    if table not in ("link_candidates", "error_link_candidates"):
        raise ValueError("Unknown candidate table")
    count, selected_connect = 0, None
    for expected in evidence:
        actual = connection.execute(f"SELECT * FROM {table} WHERE event_id=? AND call_event_id=?",
                                    (expected["event_id"], expected["call_event_id"])).fetchone()
        require(actual is not None and dict(actual) == expected, message)
        count += 1
        if expected["selected"]:
            selected_connect = expected["connect_relation"]
    return count, selected_connect


@contextmanager
def auxiliary_rows(store):
    """Owner-only sweep, then replay in original numeric/aggregation order.

    O(E_aux) temporary disk rows, no public schema/artifact. Scope/time order
    must not change first samples or bounded context collections downstream.
    """
    connection = store.connection
    # Changing temp_store discards existing TEMP objects; configure it before
    # creating our spool, including for callers using a fresh connection.
    connection.execute("PRAGMA temp_store=FILE")
    connection.execute("CREATE TEMP TABLE auxiliary_owners(event_id TEXT PRIMARY KEY, parent_event_id TEXT)")
    try:
        with closing(stored_links(connection, "aux", include_evidence=False)) as links:
            for event, decision, _ in links:
                connection.execute("INSERT INTO temp.auxiliary_owners VALUES (?,?)",
                                   (event["event_id"], decision["parent_event_id"]))
                store.tick()
        query = (
            "SELECT e.*,c.legacy_call_id AS linked_call_id FROM events e "
            "JOIN temp.auxiliary_owners a USING(event_id) "
            "LEFT JOIN call_events c ON c.event_id=a.parent_event_id "
            "ORDER BY e.source_version_id,e.byte_start"
        )
        with closing(connection.execute(query)) as rows:
            yield rows
    finally:
        connection.execute("DROP TABLE temp.auxiliary_owners")
