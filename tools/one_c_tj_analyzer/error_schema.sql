CREATE TABLE error_events (
 event_id TEXT PRIMARY KEY REFERENCES events,
 message_field TEXT, raw_message TEXT, message_state TEXT NOT NULL CHECK(message_state IN ('missing','empty','present')),
 signature TEXT NOT NULL, signature_id TEXT NOT NULL, error_signature_version TEXT NOT NULL,
 category TEXT NOT NULL, sql_text_id TEXT REFERENCES sql_texts
);
CREATE INDEX errors_signature ON error_events(signature_id,event_id);
CREATE TABLE error_link_decisions (
 event_id TEXT PRIMARY KEY REFERENCES error_events, linkage_rules_version TEXT NOT NULL,
 parent_event_id TEXT REFERENCES call_events,
 status TEXT NOT NULL CHECK(status IN ('linked_unique','linked_by_rule','ambiguous','unlinked')),
 reason_code TEXT NOT NULL, candidate_count INTEGER NOT NULL, eligible_count INTEGER NOT NULL,
 session_match_count INTEGER NOT NULL, fallback_applied INTEGER NOT NULL CHECK(fallback_applied IN (0,1)),
 selection_rule TEXT NOT NULL, CHECK((status='unlinked')=(parent_event_id IS NULL))
);
CREATE INDEX error_links_parent ON error_link_decisions(parent_event_id,event_id);
CREATE TABLE error_link_candidates (
 event_id TEXT REFERENCES error_link_decisions, call_event_id TEXT REFERENCES call_events,
 session_relation TEXT NOT NULL, connect_relation TEXT NOT NULL,
 full_interval_contained INTEGER NOT NULL CHECK(full_interval_contained IN (0,1)),
 eligible INTEGER NOT NULL CHECK(eligible IN (0,1)), selected INTEGER NOT NULL CHECK(selected IN (0,1)),
 reason_code TEXT NOT NULL, PRIMARY KEY(event_id,call_event_id)
);
CREATE UNIQUE INDEX one_selected_error_candidate ON error_link_candidates(event_id) WHERE selected=1;
CREATE TABLE suspected_incidents (
 incident_id TEXT PRIMARY KEY, incident_rules_version TEXT NOT NULL, group_key_json TEXT NOT NULL,
 hypothesis_status TEXT NOT NULL CHECK(hypothesis_status='unconfirmed'),
 root_cause TEXT CHECK(root_cause IS NULL), cancellation_initiator TEXT CHECK(cancellation_initiator IS NULL)
);
CREATE TABLE error_incident_members (
 event_id TEXT PRIMARY KEY REFERENCES error_events, incident_id TEXT NOT NULL REFERENCES suspected_incidents,
 incident_rules_version TEXT NOT NULL, reason_code TEXT NOT NULL, message_role TEXT NOT NULL,
 group_key_json TEXT NOT NULL, evidence_json TEXT NOT NULL
);
CREATE INDEX incident_members_group ON error_incident_members(incident_id,event_id);
CREATE VIEW error_observations AS
 SELECT e.*,v.source_id,l.display_path AS source,
 r.message_field,r.raw_message,r.message_state,r.signature,r.signature_id,r.error_signature_version,r.category,r.sql_text_id,
 k.parent_event_id AS call_event_id,c.legacy_call_id AS call_id,k.status AS linkage_status,
 k.reason_code AS linkage_reason,k.linkage_rules_version,k.candidate_count,k.eligible_count,k.fallback_applied,
 m.incident_id,m.incident_rules_version,m.reason_code AS incident_reason,m.message_role
 FROM error_events r JOIN events e USING(event_id)
 JOIN source_versions v USING(source_version_id)
 JOIN source_locations l ON l.location_id=(SELECT min(l2.location_id) FROM source_locations l2 WHERE l2.source_version_id=v.source_version_id)
 JOIN error_link_decisions k USING(event_id)
 LEFT JOIN call_events c ON c.event_id=k.parent_event_id
 JOIN error_incident_members m USING(event_id);
CREATE VIEW error_incidents AS
 SELECT i.*,min(m.event_id) AS representative_event_id,count(*) AS event_count,
 count(DISTINCT k.parent_event_id) AS affected_call_count,
 min(e.end_time_us) AS first_time_us,max(e.end_time_us) AS last_time_us
 FROM suspected_incidents i JOIN error_incident_members m USING(incident_id)
 JOIN events e ON e.event_id=m.event_id JOIN error_link_decisions k ON k.event_id=m.event_id
 GROUP BY i.incident_id;
