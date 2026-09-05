"""Disk-backed event detail. No list of DB events or full SQL dictionary in RAM."""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import sqlite3

from event_linking import LINKAGE_RULES, LINKAGE_RULES_VERSION
from stored_linking import stored_links
from numeric_quality import FIELDS, NUMERIC_RULES_VERSION
from record_stream import PARSER_VERSION
from source_identity import SOURCE_IDENTITY_VERSION, EVENT_IDENTITY_VERSION, identity, canonical, file_hash
from sql_normalization import SQL_NORMALIZATION_VERSION, normalize_sql, sql_fingerprint, normalization_status
from error_rules import ERROR_METADATA, ERROR_VERSIONS, ERROR_TYPES, message_fields, classify_error

STORAGE_SCHEMA_VERSION = "1.1"
LEGACY_DETAIL_FILES = ("analysis.sqlite", "source_map.json", "db_observations.csv", "event_links.csv", "link_candidates.csv")
ERROR_DETAIL_FILES = ("error_observations.csv", "error_event_links.csv", "error_link_candidates.csv", "error_incidents.csv", "error_incident_members.csv")
DETAIL_FILES = LEGACY_DETAIL_FILES + ERROR_DETAIL_FILES
CALL_DETAIL_FIELDS = ["event_id", "source_id", "source_version_id", "byte_start", "byte_end", "record_ordinal",
                      "line_start", "line_end", "raw_record_sha256", "thread", "session", "connect_id"]
VERSIONS = {"storage_schema_version": STORAGE_SCHEMA_VERSION, "parser_version": PARSER_VERSION,
            "source_identity_version": SOURCE_IDENTITY_VERSION, "event_identity_version": EVENT_IDENTITY_VERSION,
            "time_semantics_version": "local_naive_microseconds/v1", "call_signature_version": "1.0",
            "linkage_rules_version": LINKAGE_RULES_VERSION, "numeric_rules_version": NUMERIC_RULES_VERSION,
            "sql_normalization_version": SQL_NORMALIZATION_VERSION}
LEGACY_VERSIONS = {**VERSIONS, "storage_schema_version": "1.0"}
VERSIONS.update(ERROR_VERSIONS)

def detail_files(schema):
    return DETAIL_FILES if schema == "1.6" else LEGACY_DETAIL_FILES


EPOCH = dt.datetime(1970, 1, 1)


def time_us(value):
    if value is None:
        return None
    delta = value - EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def timestamp(value):
    return EPOCH + dt.timedelta(microseconds=value) if value is not None else None


def insert(connection, table, row, *, ignore=False):
    # Table/column names are program constants, never values from journal input.
    fields = list(row)
    connection.execute(f"INSERT {'OR IGNORE ' if ignore else ''}INTO {table} ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})", list(row.values()))


class EventStore:
    def __init__(self, path: Path):
        self.path = path
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA temp_store=FILE")
        self.connection.execute("PRAGMA cache_size=-8192")
        self.connection.execute("PRAGMA journal_mode=DELETE")
        self.connection.executescript(Path(__file__).with_name("event_schema.sql").read_text(encoding="utf-8"))
        self.connection.executescript(Path(__file__).with_name("error_schema.sql").read_text(encoding="utf-8"))
        self.pending = 0
        self._sql_text_ids = set()
        self._pending_sql_text_ids = set()
        self.on_db_link = None
        self.on_error_link = None
        for key, value in {**VERSIONS, **ERROR_METADATA, "linkage_rules": LINKAGE_RULES, "publication_state": "building"}.items():
            insert(self.connection, "metadata", {"key": key, "value": canonical(value)})

    def tick(self):
        self.pending += 1
        if self.pending >= 1000:
            self.commit()
            self.pending = 0

    def commit(self):
        self.connection.commit()
        self._pending_sql_text_ids.clear()

    def add_sources(self, health):
        for item in health:
            source = item.source
            insert(self.connection, "source_streams", {"source_id": source.stable_id, "capture_id": source.capture_id,
                   "origin_id": source.origin_id, "process_scope": source.process_scope,
                   "logical_log_key": source.logical_log_key, "identity_status": source.identity_status}, ignore=True)
            insert(self.connection, "source_versions", {"source_version_id": source.version_id, "source_id": source.stable_id,
                   "content_sha256": item.sha256 or None, "hash_scope": "full_uncompressed" if item.sha256 else "unavailable",
                   "size_bytes": source.size, "analyzed_bytes": item.analyzed_bytes, "encoding": "utf-8",
                   "status": item.status}, ignore=True)
            insert(self.connection, "source_locations", {"location_id": identity("location/v1", source.source_id),
                   "source_version_id": source.version_id, "kind": source.kind, "path": str(source.path.resolve()),
                   "member": source.member or None, "member_ordinal": source.member_ordinal, "display_path": source.display_path})
            if item.reason.startswith("read error"):
                self.issue(source, 0, source.size, "inspection_read_error", item.reason)
            if item.nul_offset is not None:
                self.issue(source, item.analyzed_bytes, source.size, "nul_excluded_range", item.reason)
            elif item.status == "skipped" and source.size:
                self.issue(source, 0, source.size, "source_skipped", item.reason)

    def issue(self, source, start, end, code, description):
        insert(self.connection, "parse_issues", {"issue_id": identity("issue/v1", source.version_id, start, end, code),
               "source_version_id": source.version_id, "byte_start": start, "byte_end": end,
               "code": code, "description": description}, ignore=True)

    def add_event(self, source, record, match, attrs, end, measurement_id, numeric, call=None):
        event_id = identity("event/v1", source.stable_id, record.byte_start, record.raw_record_sha256)
        duration = int(match.group("duration"))
        if duration > 2**63-1:
            raise ValueError("Event duration exceeds signed 64-bit storage range")
        end_us = time_us(end)
        row = {"event_id": event_id, "source_version_id": source.version_id,
               "byte_start": record.byte_start, "byte_end": record.byte_end, "record_ordinal": record.record_ordinal,
               "line_start": record.line_start, "line_end": record.line_end, "raw_record_sha256": record.raw_record_sha256,
               "event_type": match.group("event").strip(), "level": int(match.group("level")),
               "raw_timestamp": record.text.split("-", 1)[0], "start_time_us": end_us-duration if end_us is not None else None,
               "end_time_us": end_us, "time_state": "local_naive" if end_us is not None else "unavailable",
               "duration_raw": match.group("duration"), "duration_us": duration, "duration_state": "valid",
               "dataset_id": source.dataset_id, "measurement_id": measurement_id,
               "user": attrs.get("Usr", "").strip() or "(not specified)", "usr_raw": attrs.get("Usr"),
               "process": source.process, "thread": attrs.get("OSThread"), "session": attrs.get("SessionID"),
               "connect_id": attrs.get("t:connectID"), "dbpid": attrs.get("Dbpid"), "context": attrs.get("Context"),
               "attributes_json": canonical({k: v for k, v in attrs.items() if k not in {"Sql", "Context", *(v[0] for v in FIELDS.values())}})}
        insert(self.connection, "events", row)
        for name, value in numeric.items():
            insert(self.connection, "numeric_values", {"event_id": event_id, "field_name": name,
                   "raw_value": value["raw_value"], "value_int": value["value"], "state": value["state"],
                   "unit": value["unit"], "reason_code": value["reason"]})
        if call is not None:
            call.provenance = {key: row[key] for key in CALL_DETAIL_FIELDS if key in row}
            call.provenance["source_id"] = source.stable_id
            insert(self.connection, "call_events", {"event_id": event_id, "legacy_call_id": call.call_id,
                   "signature": call.signature, "call_signature_version": "1.0"})
        elif row["event_type"] == "DBPOSTGRS":
            sql = attrs.get("Sql")
            state = "missing" if sql is None else "empty" if not sql else "present"
            text_id = self.add_sql(sql)
            insert(self.connection, "db_events", {"event_id": event_id, "sql_text_id": text_id, "sql_presence_state": state})
        elif row["event_type"] in ERROR_TYPES:
            fields = message_fields(attrs)
            insert(self.connection, "error_events", {"event_id": event_id, **fields,
                   "category": classify_error(fields["raw_message"] or ""), "sql_text_id": self.add_sql(attrs.get("Sql"))})
        self.tick()
        return event_id

    def add_sql(self, sql):
        text_id = None
        if sql:
            text_id = identity("sql-text/v1", sql)
            # A transaction ended directly through the exposed connection. Its
            # pending SQL may have been committed or rolled back, so recheck it
            # lazily. Direct DML of SQL dictionary tables, or starting another
            # transaction before this check, remains unsupported; the analyzer
            # itself commits only through EventStore and never rolls back/reuses.
            if self._pending_sql_text_ids and not self.connection.in_transaction:
                self._sql_text_ids.difference_update(self._pending_sql_text_ids)
                self._pending_sql_text_ids.clear()
            if text_id in self._sql_text_ids:
                return text_id
            if self.connection.execute("SELECT 1 FROM sql_texts WHERE sql_text_id=?", (text_id,)).fetchone() is None:
                normalized = normalize_sql(sql)
                fingerprint = sql_fingerprint(normalized)
                pattern_id = identity("sql-pattern/v1", SQL_NORMALIZATION_VERSION, fingerprint)
                status = normalization_status(normalized)
                insert(self.connection, "sql_texts", {"sql_text_id": text_id, "sql_text": sql,
                       "sql_text_sha256": hashlib.sha256(sql.encode()).hexdigest()})
                insert(self.connection, "sql_patterns", {"pattern_id": pattern_id, "normalization_version": SQL_NORMALIZATION_VERSION,
                       "normalized_sql": normalized, "sql_fingerprint_sha256": fingerprint, "normalization_status": status}, ignore=True)
                insert(self.connection, "sql_normalizations", {"sql_text_id": text_id, "normalization_version": SQL_NORMALIZATION_VERSION,
                       "pattern_id": pattern_id, "state": status})
                self._pending_sql_text_ids.add(text_id)
            self._sql_text_ids.add(text_id)
        return text_id

    def link_db(self):
        self.commit()
        for event, decision, evidence in stored_links(self.connection, "db"):
            insert(self.connection, "link_decisions", decision)
            for candidate in evidence:
                insert(self.connection, "link_candidates", candidate)
                self.tick()
            self.tick()
            if self.on_db_link is not None:
                self.on_db_link(1)
        self.commit()

    def numeric(self, event_id):
        return {r["field_name"]: {"state": r["state"], "raw_value": r["raw_value"], "value": r["value_int"],
                                  "unit": r["unit"], "reason": r["reason_code"]}
                for r in self.connection.execute("SELECT * FROM numeric_values WHERE event_id=? ORDER BY field_name", (event_id,))}

    def _db_numeric_groups(self):
        """Yield one bounded numeric_values group per DB event that has stored values."""
        query = (
            "SELECT o.source_version_id,o.byte_start,o.event_id,n.field_name,n.raw_value,n.value_int,n.state,n.unit,n.reason_code "
            "FROM db_observations o JOIN numeric_values n ON n.event_id=o.event_id "
            "ORDER BY o.source_version_id,o.byte_start,n.field_name"
        )
        current_key = None
        current_values = None
        for row in self.connection.execute(query):
            key = (row["source_version_id"], row["byte_start"], row["event_id"])
            if key != current_key:
                if current_key is not None:
                    yield current_key, current_values
                current_key, current_values = key, {}
            current_values[row["field_name"]] = {
                "state": row["state"], "raw_value": row["raw_value"], "value": row["value_int"],
                "unit": row["unit"], "reason": row["reason_code"],
            }
        if current_key is not None:
            yield current_key, current_values

    def _event_numeric_groups(self, event_types):
        """Yield bounded numeric groups in stored event order for selected types."""
        placeholders = ",".join("?" for _ in event_types)
        query = (
            "SELECT e.source_version_id,e.byte_start,e.event_id,n.field_name,n.raw_value,n.value_int,n.state,n.unit,n.reason_code "
            "FROM events e JOIN numeric_values n ON n.event_id=e.event_id "
            f"WHERE e.event_type IN ({placeholders}) "
            "ORDER BY e.source_version_id,e.byte_start,n.field_name"
        )
        current_key = None
        current_values = None
        for row in self.connection.execute(query, tuple(event_types)):
            key = (row["source_version_id"], row["byte_start"], row["event_id"])
            if key != current_key:
                if current_key is not None:
                    yield current_key, current_values
                current_key, current_values = key, {}
            current_values[row["field_name"]] = {
                "state": row["state"], "raw_value": row["raw_value"], "value": row["value_int"],
                "unit": row["unit"], "reason": row["reason_code"],
            }
        if current_key is not None:
            yield current_key, current_values

    def db_rows(self, include_sql=False):
        query = "SELECT o.*"
        if include_sql:
            query += ",t.sql_text,p.normalized_sql FROM db_observations o LEFT JOIN sql_texts t USING(sql_text_id) LEFT JOIN sql_patterns p USING(pattern_id)"
        else:
            query += " FROM db_observations o"
        numeric_groups = iter(self._db_numeric_groups())
        numeric_group = next(numeric_groups, None)
        for row in self.connection.execute(query + " ORDER BY o.source_version_id,o.byte_start"):
            row_key = (row["source_version_id"], row["byte_start"], row["event_id"])
            if numeric_group is not None and numeric_group[0] < row_key:
                raise ValueError("DB numeric stream is not aligned with DB observations")
            result = dict(row)
            if numeric_group is not None and numeric_group[0] == row_key:
                result["numeric_quality"] = numeric_group[1]
                numeric_group = next(numeric_groups, None)
            else:
                result["numeric_quality"] = {}
            result.update({key: value["value"] for key, value in result["numeric_quality"].items()})
            result["start_timestamp"] = str(timestamp(row["start_time_us"])) if row["start_time_us"] is not None else None
            result["end_timestamp"] = str(timestamp(row["end_time_us"])) if row["end_time_us"] is not None else None
            yield result
        if numeric_group is not None:
            raise ValueError("DB numeric stream contains an event outside DB observations")

    def finish(self, health, source_map, output: Path):
        for item in health:
            if item.status != "skipped_duplicate":
                self.connection.execute("UPDATE source_versions SET status=?,analyzed_bytes=? WHERE source_version_id=?",
                                        (item.status, item.analyzed_bytes, item.source.version_id))
        self.connection.execute("UPDATE metadata SET value=? WHERE key='publication_state'", (canonical("complete"),))
        self.commit()
        if self.connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or self.connection.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("Event store integrity check failed")
        db_fields = [r[1] for r in self.connection.execute("PRAGMA table_info(db_observations)")]
        db_fields += [*FIELDS, "numeric_quality", "start_timestamp", "end_timestamp"]
        counts = {"db_observations.csv": export_csv(output/"db_observations.csv", db_fields, self.db_rows())}
        for table, filename in (("link_decisions", "event_links.csv"), ("link_candidates", "link_candidates.csv")):
            fields = [r[1] for r in self.connection.execute(f"PRAGMA table_info({table})")]
            order = "event_id,call_event_id" if table == "link_candidates" else "event_id"
            counts[filename] = export_csv(output/filename, fields, (dict(r) for r in self.connection.execute(f"SELECT * FROM {table} ORDER BY {order}")))
        from error_store import export_errors
        counts.update(export_errors(self, output))
        (output/"source_map.json").write_text(canonical(source_map)+"\n", encoding="utf-8", newline="\n")
        counts["source_map.json"] = len(source_map["sources"])
        counts["analysis.sqlite"] = self.connection.execute("SELECT count(*) FROM events").fetchone()[0]
        self.close()
        return {name: {"sha256": file_hash(output/name), "size_bytes": (output/name).stat().st_size,
                       "row_count": counts[name]} for name in DETAIL_FILES}

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        self._sql_text_ids.clear()
        self._pending_sql_text_ids.clear()


def export_csv(path, fields, rows):
    count = 0
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: canonical(v) if isinstance(v, (dict, list)) else v for k, v in row.items()})
            count += 1
    return count
