PRAGMA foreign_keys = ON;
PRAGMA user_version = 2;
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE source_streams (
 source_id TEXT PRIMARY KEY, capture_id TEXT NOT NULL, origin_id TEXT NOT NULL,
 process_scope TEXT NOT NULL, logical_log_key TEXT NOT NULL, identity_status TEXT NOT NULL
);
CREATE TABLE source_versions (
 source_version_id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES source_streams,
 content_sha256 TEXT, hash_scope TEXT NOT NULL, size_bytes INTEGER NOT NULL,
 analyzed_bytes INTEGER NOT NULL, encoding TEXT NOT NULL, status TEXT NOT NULL,
 UNIQUE(source_id, content_sha256)
);
CREATE TABLE source_locations (
 location_id TEXT PRIMARY KEY, source_version_id TEXT NOT NULL REFERENCES source_versions,
 kind TEXT NOT NULL, path TEXT NOT NULL, member TEXT, member_ordinal INTEGER,
 display_path TEXT NOT NULL UNIQUE
);
CREATE TABLE events (
 event_id TEXT PRIMARY KEY, source_version_id TEXT NOT NULL REFERENCES source_versions,
 byte_start INTEGER NOT NULL CHECK(byte_start>=0), byte_end INTEGER NOT NULL CHECK(byte_end>byte_start),
 record_ordinal INTEGER NOT NULL, line_start INTEGER NOT NULL, line_end INTEGER NOT NULL,
 raw_record_sha256 TEXT NOT NULL, event_type TEXT NOT NULL, level INTEGER NOT NULL,
 raw_timestamp TEXT NOT NULL, start_time_us INTEGER, end_time_us INTEGER, time_state TEXT NOT NULL,
 duration_raw TEXT NOT NULL, duration_us INTEGER NOT NULL CHECK(duration_us>=0), duration_state TEXT NOT NULL,
 dataset_id TEXT NOT NULL, measurement_id TEXT NOT NULL, user TEXT NOT NULL, usr_raw TEXT,
 process TEXT NOT NULL, thread TEXT, session TEXT, connect_id TEXT, dbpid TEXT,
 context TEXT, attributes_json TEXT NOT NULL,
 UNIQUE(source_version_id,byte_start), CHECK((start_time_us IS NULL)=(end_time_us IS NULL))
);
CREATE INDEX events_lookup ON events(event_type,dataset_id,user,process,thread,start_time_us,end_time_us);
CREATE INDEX events_distribution ON events(event_type,dataset_id,duration_us);
CREATE TABLE call_events (
 event_id TEXT PRIMARY KEY REFERENCES events, legacy_call_id INTEGER NOT NULL UNIQUE,
 signature TEXT NOT NULL, call_signature_version TEXT NOT NULL
);
CREATE TABLE sql_texts (sql_text_id TEXT PRIMARY KEY, sql_text TEXT NOT NULL, sql_text_sha256 TEXT NOT NULL UNIQUE);
CREATE TABLE sql_patterns (
 pattern_id TEXT PRIMARY KEY, normalization_version TEXT NOT NULL, normalized_sql TEXT NOT NULL,
 sql_fingerprint_sha256 TEXT NOT NULL, normalization_status TEXT NOT NULL,
 UNIQUE(normalization_version,sql_fingerprint_sha256)
);
CREATE TABLE sql_normalizations (
 sql_text_id TEXT REFERENCES sql_texts, normalization_version TEXT NOT NULL,
 pattern_id TEXT NOT NULL REFERENCES sql_patterns, state TEXT NOT NULL,
 PRIMARY KEY(sql_text_id,normalization_version)
);
CREATE TABLE db_events (
 event_id TEXT PRIMARY KEY REFERENCES events, sql_text_id TEXT REFERENCES sql_texts,
 sql_presence_state TEXT NOT NULL CHECK(sql_presence_state IN ('missing','empty','present')),
 CHECK((sql_presence_state='present')=(sql_text_id IS NOT NULL))
);
CREATE INDEX db_sql_text ON db_events(sql_text_id,event_id);
CREATE TABLE numeric_values (
 event_id TEXT REFERENCES events, field_name TEXT NOT NULL, raw_value TEXT, value_int INTEGER,
 state TEXT NOT NULL CHECK(state IN ('valid','missing','empty','invalid','out_of_range')),
 unit TEXT NOT NULL, reason_code TEXT, PRIMARY KEY(event_id,field_name),
 CHECK((state='valid')=(value_int IS NOT NULL))
);
CREATE TABLE link_decisions (
 event_id TEXT PRIMARY KEY REFERENCES db_events, linkage_rules_version TEXT NOT NULL,
 parent_event_id TEXT REFERENCES call_events,
 status TEXT NOT NULL CHECK(status IN ('linked_unique','linked_by_rule','ambiguous','unlinked')),
 reason_code TEXT NOT NULL, candidate_count INTEGER NOT NULL, eligible_count INTEGER NOT NULL,
 session_match_count INTEGER NOT NULL, fallback_applied INTEGER NOT NULL CHECK(fallback_applied IN (0,1)),
 selection_rule TEXT NOT NULL,
 CHECK((status='unlinked')=(parent_event_id IS NULL))
);
CREATE INDEX links_parent ON link_decisions(parent_event_id,event_id);
CREATE TABLE link_candidates (
 event_id TEXT REFERENCES link_decisions, call_event_id TEXT REFERENCES call_events,
 session_relation TEXT NOT NULL, connect_relation TEXT NOT NULL,
 full_interval_contained INTEGER NOT NULL CHECK(full_interval_contained IN (0,1)),
 eligible INTEGER NOT NULL CHECK(eligible IN (0,1)), selected INTEGER NOT NULL CHECK(selected IN (0,1)),
 reason_code TEXT NOT NULL, PRIMARY KEY(event_id,call_event_id)
);
CREATE UNIQUE INDEX one_selected_candidate ON link_candidates(event_id) WHERE selected=1;
CREATE TABLE parse_issues (
 issue_id TEXT PRIMARY KEY, source_version_id TEXT REFERENCES source_versions,
 byte_start INTEGER NOT NULL, byte_end INTEGER NOT NULL, code TEXT NOT NULL, description TEXT NOT NULL
);
CREATE VIEW db_observations AS
 SELECT e.*, v.source_id, l.display_path AS source, d.sql_text_id, d.sql_presence_state,
 p.pattern_id,p.sql_fingerprint_sha256,p.normalization_version AS sql_normalization_version,
 p.normalization_status AS sql_normalization_status,
 k.parent_event_id AS call_event_id,c.legacy_call_id AS call_id,k.status AS linkage_status,
 k.reason_code AS linkage_reason,k.linkage_rules_version,k.candidate_count,k.eligible_count,k.fallback_applied
 FROM db_events d JOIN events e USING(event_id)
 JOIN source_versions v USING(source_version_id)
 JOIN source_locations l ON l.location_id=(SELECT min(l2.location_id) FROM source_locations l2 WHERE l2.source_version_id=v.source_version_id)
 LEFT JOIN sql_normalizations n ON n.sql_text_id=d.sql_text_id
 LEFT JOIN sql_patterns p ON p.pattern_id=n.pattern_id
 JOIN link_decisions k USING(event_id) LEFT JOIN call_events c ON c.event_id=k.parent_event_id;
