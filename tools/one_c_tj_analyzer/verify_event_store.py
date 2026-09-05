"""Verify saved detail without opening any recorded journal/source path."""
from __future__ import annotations

from collections import defaultdict
import csv
import hashlib
import itertools
import json
import sqlite3

from event_store import DETAIL_FILES, CALL_DETAIL_FIELDS, VERSIONS, LEGACY_VERSIONS, detail_files, EventStore
from error_rules import ERROR_METADATA
from verify_error_store import verify_errors
from verify_populations import identities, source_coverage, verify_populations
from event_linking import LINKAGE_RULES
from stored_linking import stored_links, verify_candidates
from numeric_quality import FIELDS, CounterStats, parse_counter
from source_identity import identity, canonical, file_hash
from sql_normalization import SQL_NORMALIZATION_VERSION, normalize_sql, sql_fingerprint, normalization_status


def require(condition, message):
    if not condition:
        raise ValueError("Event detail: " + message)


def safe_path(root, name):
    require(name in DETAIL_FILES, "unknown artifact")
    path = root/name
    require(path.resolve(strict=True).parent == root and path.is_file(), "artifact escapes result directory")
    return path


def descriptors(root, manifest):
    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, dict) and set(artifacts) == set(detail_files(manifest["schema_version"])), "missing/unknown artifacts")
    hashes = {}
    for name in detail_files(manifest["schema_version"]):
        path = safe_path(root, name)
        hashes[name] = {"sha256": file_hash(path), "size_bytes": path.stat().st_size}
        require(all(artifacts[name].get(k) == v for k, v in hashes[name].items()), "artifact checksum/size mismatch: " + name)
        require(type(artifacts[name].get("row_count")) is int and artifacts[name]["row_count"] >= 0, "invalid artifact row count")
    return hashes


def compare_csv(path, fields, expected):
    old_limit = csv.field_size_limit()
    csv.field_size_limit(16 * 1024 * 1024)
    count = 0
    try:
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream, strict=True)
            require(reader.fieldnames == fields, "CSV header mismatch: " + path.name)
            for actual, row in itertools.zip_longest(reader, expected):
                require(actual is not None and row is not None, "CSV row count mismatch: " + path.name)
                values = {k: "" if row.get(k) is None else canonical(row[k]) if isinstance(row[k], (dict, list)) else str(row[k]) for k in fields}
                require(actual == values, "CSV differs from SQLite: " + path.name)
                count += 1
    finally:
        csv.field_size_limit(old_limit)
    return count


def verify_detail(root, manifest, calls):
    require(manifest.get("publication_state") == "complete", "incomplete publication")
    require(manifest.get("source_processing_complete") == manifest.get("analysis_complete"), "source completeness mismatch")
    has_errors = manifest["schema_version"] == "1.6"
    versions = VERSIONS if has_errors else LEGACY_VERSIONS
    scope = ["CALL", "DBPOSTGRS", "EXCP", "QERR"] if has_errors else ["CALL", "DBPOSTGRS"]
    require(manifest.get("event_detail_scope") == scope, "unsupported detail scope")
    require(all(manifest.get(k) == v for k, v in versions.items()), "unsupported version")
    require(manifest.get("linkage_rules") == LINKAGE_RULES, "linkage rules mismatch")
    hashes = descriptors(root, manifest)
    source_map = json.loads(safe_path(root, "source_map.json").read_text(encoding="utf-8"))
    require(source_map.get("capture_id") == manifest.get("capture_id"), "capture identity mismatch")
    require(len(source_map["sources"]) == manifest["artifacts"]["source_map.json"]["row_count"], "source map count mismatch")
    connection = sqlite3.connect(safe_path(root, "analysis.sqlite").as_uri() + "?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    store = EventStore.__new__(EventStore)
    store.connection = connection
    try:
        require(connection.execute("PRAGMA user_version").fetchone()[0] == (2 if has_errors else 1), "unsupported storage schema")
        require(connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "SQLite integrity check failed")
        identities(connection, has_errors, require)
        require(connection.execute("PRAGMA foreign_key_check").fetchone() is None, "broken foreign key")
        metadata = {r[0]: json.loads(r[1]) for r in connection.execute("SELECT key,value FROM metadata")}
        require(all(metadata.get(k) == v for k, v in {**versions, **(ERROR_METADATA if has_errors else {}), "linkage_rules": LINKAGE_RULES, "publication_state": "complete"}.items()), "SQLite metadata mismatch")
        for row in connection.execute("SELECT * FROM source_streams"):
            require(row["source_id"] == identity("source/v1", row["capture_id"], row["origin_id"], row["process_scope"], row["logical_log_key"]), "source identity mismatch")
        for row in connection.execute("SELECT * FROM source_versions"):
            require(row["source_version_id"] == identity("source-version/v1", row["source_id"], row["content_sha256"] or "unreadable"), "source version identity mismatch")
        for entry in source_map["sources"]:
            require(entry["source_id"] == identity("source/v1", source_map["capture_id"], entry["origin_id"], entry["process_scope"], entry["logical_log_key"]), "source map identity mismatch")
            require(connection.execute("SELECT 1 FROM source_streams WHERE source_id=?", (entry["source_id"],)).fetchone(), "source map references unknown stream")
        event_count = 0
        for row in connection.execute("SELECT e.*,v.source_id,v.size_bytes FROM events e JOIN source_versions v USING(source_version_id)"):
            event_count += 1
            require(len(row["raw_record_sha256"]) == 64 and all(c in "0123456789abcdef" for c in row["raw_record_sha256"]), "invalid raw record hash")
            require(row["event_id"] == identity("event/v1", row["source_id"], row["byte_start"], row["raw_record_sha256"]), "event identity mismatch")
            require(0 <= row["byte_start"] < row["byte_end"] <= row["size_bytes"], "invalid source byte range")
            require(1 <= row["line_start"] <= row["line_end"] and row["record_ordinal"] >= 1, "invalid record position")
            require(int(row["duration_raw"]) == row["duration_us"] and row["duration_state"] == "valid", "invalid duration")
            if row["end_time_us"] is not None:
                require(row["end_time_us"] - row["start_time_us"] == row["duration_us"], "duration/interval mismatch")
            numeric = store.numeric(row["event_id"])
            require(set(numeric) == set(FIELDS), "missing/extra numeric fields")
            for name, value in numeric.items():
                require(value == parse_counter(name, value["raw_value"]), "numeric state/value mismatch")
        require(event_count == manifest["artifacts"]["analysis.sqlite"]["row_count"], "stored event count mismatch")
        require(connection.execute("SELECT count(*) FROM call_events").fetchone()[0] == len(calls), "CALL count mismatch")
        call_map = {int(c["call_id"]): c for c in calls}
        for row in connection.execute("SELECT e.*,c.legacy_call_id,c.signature,v.source_id FROM events e JOIN call_events c USING(event_id) JOIN source_versions v USING(source_version_id)"):
            call = call_map[row["legacy_call_id"]]
            for field in CALL_DETAIL_FIELDS:
                expected = "" if row[field] is None else str(row[field])
                require(str(call[field]) == expected, "CALL provenance mismatch: " + field)
            for field in ("dataset_id", "measurement_id", "user", "process", "signature", "duration_us"):
                require(str(call[field]) == str(row[field]), "CALL field mismatch: " + field)
            require(call["numeric_quality"] == store.numeric(row["event_id"]), "CALL counter mismatch")
            from event_store import timestamp
            for field, source_field in (("start_timestamp", "start_time_us"), ("end_timestamp", "end_time_us")):
                expected = str(timestamp(row[source_field])) if row[source_field] is not None else ""
                require(call[field] == expected, "CALL stored timestamp mismatch")
        for table in ("sql_patterns", "sql_normalizations"):
            require(connection.execute(f"SELECT 1 FROM {table} WHERE normalization_version<>? LIMIT 1", (SQL_NORMALIZATION_VERSION,)).fetchone() is None, "mixed SQL normalization versions")
        for row in connection.execute("SELECT t.*,n.normalization_version,n.state,p.* FROM sql_texts t JOIN sql_normalizations n USING(sql_text_id) JOIN sql_patterns p USING(pattern_id)"):
            sql = row["sql_text"]
            require(row["normalization_version"] == SQL_NORMALIZATION_VERSION, "mixed SQL normalization versions")
            require(row["sql_text_id"] == identity("sql-text/v1", sql) and row["sql_text_sha256"] == hashlib.sha256(sql.encode()).hexdigest(), "SQL text identity mismatch")
            normalized = normalize_sql(sql)
            require(normalized == row["normalized_sql"] and row["sql_fingerprint_sha256"] == sql_fingerprint(normalized), "SQL fingerprint/full text mismatch")
            require(row["pattern_id"] == identity("sql-pattern/v1", SQL_NORMALIZATION_VERSION, row["sql_fingerprint_sha256"]), "SQL pattern identity mismatch")
            require(row["normalization_status"] == row["state"] == normalization_status(normalized), "SQL normalization status mismatch")
        require(connection.execute("SELECT count(*) FROM sql_texts").fetchone()[0] == connection.execute("SELECT count(*) FROM sql_normalizations").fetchone()[0], "SQL dictionary normalization coverage mismatch")
        db_count = connection.execute("SELECT count(*) FROM db_events").fetchone()[0]
        require(db_count == connection.execute("SELECT count(*) FROM link_decisions").fetchone()[0] == manifest["counts"]["db_observations"], "missing DB events/decisions")
        per_call, per_link, per_sql = defaultdict(lambda: [0, 0, CounterStats()]), defaultdict(lambda: [0, 0, 0, 0]), defaultdict(lambda: [0, 0])
        evidence_count = 0
        for event, expected, evidence in stored_links(connection, "db"):
            actual = dict(connection.execute("SELECT * FROM link_decisions WHERE event_id=?", (event["event_id"],)).fetchone())
            require(actual == expected, "link decision disagrees with legacy rule")
            count, _ = verify_candidates(connection, "link_candidates", evidence, require, "incomplete/incorrect candidate evidence")
            evidence_count += count
        require(connection.execute("SELECT count(*) FROM link_candidates").fetchone()[0] == evidence_count,
                "incomplete/incorrect candidate evidence")
        # Each row is one DB event: SQL dictionaries and candidate tables never
        # become additional observations in this accounting path.
        observed = 0
        for row in store.db_rows():
            observed += 1
            item = per_link[(row["measurement_id"], row["dataset_id"])]
            item[0] += 1
            item[1] += row["duration_us"]
            if row["call_id"] is not None:
                item[2] += 1
                item[3] += row["duration_us"]
                target = per_call[row["call_id"]]
                target[0] += 1
                target[1] += row["duration_us"]
                target[2].add(row["numeric_quality"]["rows_affected"])
            if row["sql_text_id"] is not None:
                group = per_sql[(row["measurement_id"], row["sql_fingerprint_sha256"])]
                group[0] += 1
                group[1] += row["duration_us"]
        require(observed == db_count, "DB observation join multiplied/dropped events")
        for call_id, call in call_map.items():
            count, duration, rows = per_call[call_id]
            require((count, duration) == (call["db_count"], call["db_duration_us"]), "CALL DB sums mismatch")
            require(rows.as_dict() == call["db_rows_quality"], "CALL DB row quality mismatch")
        for row in manifest["linkage"]:
            expected = per_link[(row["measurement_id"], row["dataset_id"])]
            require(expected == [row[k] for k in ("dbpostgrs_total_count", "dbpostgrs_total_duration_us", "dbpostgrs_linked_count", "dbpostgrs_linked_duration_us")], "DB linkage sums mismatch")
        require(set(per_sql) == {(r["measurement_id"], r["sql_fingerprint_sha256"]) for r in manifest["heavy_sql"]}, "SQL aggregate keys mismatch")
        for row in manifest["heavy_sql"]:
            require(per_sql[(row["measurement_id"], row["sql_fingerprint_sha256"])] == [row["count"], row["duration_us"]], "SQL aggregate sums mismatch")
        fields = [r[1] for r in connection.execute("PRAGMA table_info(db_observations)")] + [*FIELDS, "numeric_quality", "start_timestamp", "end_timestamp"]
        count = compare_csv(root/"db_observations.csv", fields, store.db_rows())
        require(count == db_count == manifest["artifacts"]["db_observations.csv"]["row_count"], "DB export count mismatch")
        for table, name, key in (("link_decisions", "event_links.csv", "event_links"), ("link_candidates", "link_candidates.csv", "link_candidates")):
            fields = [r[1] for r in connection.execute(f"PRAGMA table_info({table})")]
            order = "event_id,call_event_id" if table == "link_candidates" else "event_id"
            count = compare_csv(root/name, fields, (dict(r) for r in connection.execute(f"SELECT * FROM {table} ORDER BY {order}")))
            require(count == manifest["artifacts"][name]["row_count"] == manifest["counts"][key], "link export count mismatch")
        if has_errors:
            verify_errors(root, manifest, calls, connection, require, compare_csv)
        source_coverage(connection, manifest, require)
        verify_populations(connection, manifest, calls, require)
    finally:
        connection.close()
    require(hashes == descriptors(root, manifest), "detail changed during verification")
    return hashes
