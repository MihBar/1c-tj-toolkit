"""Auditable reproduction of the existing CALL owner selection, unchanged."""
from __future__ import annotations

LINKAGE_RULES_VERSION = "legacy_end_longest/v1"
LINKAGE_RULES = {
    "version": LINKAGE_RULES_VERSION,
    "scope": ["dataset_id", "user", "process", "thread"],
    "required": ["end_time_us", "thread"],
    "interval": "CALL.start <= DB.end <= CALL.end (both boundaries inclusive)",
    "session": "prefer equal nonempty DB.SessionID if any such candidate exists; otherwise keep all",
    "winner": ["duration_us descending", "legacy_call_id ascending"],
    "connect_id": "diagnostic only; not used to exclude candidates",
    "missing_user": "same legacy '(not specified)' bucket",
    "ambiguous": "multiple candidates after session preference; retain legacy selected owner",
    "measurement_boundary": "does not exclude cross-midnight matches",
    "accounting": "one selected parent per DB; no propagation to enclosing CALLs",
}


def relation(left, right):
    if not left and not right:
        return "both_missing"
    if not left:
        return "db_missing"
    if not right:
        return "call_missing"
    return "match" if left == right else "conflict"


def candidates(connection, event):
    return connection.execute(
        "SELECT e.*, c.legacy_call_id FROM events e JOIN call_events c USING(event_id) "
        "WHERE e.event_type='CALL' AND e.dataset_id=? AND e.user=? AND e.process=? AND e.thread=? "
        "AND e.start_time_us<=? AND e.end_time_us>=? ORDER BY c.legacy_call_id",
        (event["dataset_id"], event["user"], event["process"], event["thread"], event["end_time_us"], event["end_time_us"]))


def decide(connection, event):
    result = {"event_id": event["event_id"], "linkage_rules_version": LINKAGE_RULES_VERSION,
              "parent_event_id": None, "status": "unlinked", "reason_code": "no_containing_call",
              "candidate_count": 0, "eligible_count": 0, "session_match_count": 0,
              "fallback_applied": 0, "selection_rule": "duration_desc_legacy_call_id_asc"}
    if event["end_time_us"] is None:
        result["reason_code"] = "missing_timestamp"
        return result
    if not event["thread"]:
        result["reason_code"] = "missing_thread"
        return result
    best, best_session = None, None
    for candidate in candidates(connection, event):
        result["candidate_count"] += 1
        rank = (candidate["duration_us"], -candidate["legacy_call_id"])
        if best is None or rank > best[0]:
            best = (rank, candidate["event_id"])
        if event["session"] and event["session"] == candidate["session"]:
            result["session_match_count"] += 1
            if best_session is None or rank > best_session[0]:
                best_session = (rank, candidate["event_id"])
    if best is None:
        return result
    matches = result["session_match_count"]
    result["parent_event_id"] = (best_session or best)[1]
    result["eligible_count"] = matches or result["candidate_count"]
    result["fallback_applied"] = int(not matches or not (event["usr_raw"] or "").strip() or not event["process"])
    if result["eligible_count"] > 1:
        result.update(status="ambiguous", reason_code="multiple_candidates_legacy_longest")
    elif result["fallback_applied"]:
        reason = "missing_session" if not event["session"] else "session_no_match"
        if matches:
            reason = "missing_user_or_process"
        result.update(status="linked_by_rule", reason_code=reason)
    else:
        result.update(status="linked_unique", reason_code="same_session_unique")
    return result


def candidate_evidence(connection, event, decision):
    if not decision["candidate_count"]:
        return
    for candidate in candidates(connection, event):
        session_relation = relation(event["session"], candidate["session"])
        eligible = not decision["session_match_count"] or session_relation == "match"
        selected = candidate["event_id"] == decision["parent_event_id"]
        yield {"event_id": event["event_id"], "call_event_id": candidate["event_id"],
               "session_relation": session_relation, "connect_relation": relation(event["connect_id"], candidate["connect_id"]),
               "full_interval_contained": int(candidate["start_time_us"] <= event["start_time_us"] <= event["end_time_us"] <= candidate["end_time_us"]),
               "eligible": int(eligible), "selected": int(selected),
               "reason_code": "selected_legacy_rule" if selected else "excluded_by_session_preference" if not eligible else "not_selected_duration_or_legacy_order"}
