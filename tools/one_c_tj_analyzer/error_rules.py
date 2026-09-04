"""Versioned error signatures, CALL evidence and conservative incident hypotheses."""
from __future__ import annotations

import re

from event_linking import LINKAGE_RULES, decide, candidate_evidence
from source_identity import canonical, identity

ERROR_TYPES = ("EXCP", "QERR")
ERROR_SIGNATURE_VERSION = "full_message/v2"
ERROR_LINKAGE_VERSION = "legacy_end_longest_error/v1"
INCIDENT_RULES_VERSION = "same_call_exact_payload/v1"
ERROR_LINKAGE_RULES = {
    **LINKAGE_RULES, "version": ERROR_LINKAGE_VERSION,
    "interval": "CALL.start <= error.end <= CALL.end (both boundaries inclusive)",
    "session": "prefer equal nonempty error.SessionID if any such candidate exists; otherwise keep all",
    "accounting": "one selected parent per error event; no propagation to enclosing CALLs",
}
# Only these exact leading strings may be removed. Arbitrary 'caused by'
# substrings, stack frames, numbers and UUIDs are never stripped for grouping.
WRAPPERS = (
    "Ошибка при вызове метода контекста (Выполнить)\nпо причине:\n",
    "Ошибка при вызове метода контекста (Execute)\nпо причине:\n",
    "Ошибка выполнения запроса:\n",
    "Ошибка при выполнении запроса:\n",
    "Error calling context method (Execute)\nCaused by:\n",
    "Error executing query:\n",
)
INCIDENT_RULES = {
    "version": INCIDENT_RULES_VERSION,
    "scope": list(ERROR_TYPES),
    "required": "linked_unique CALL; nonblank user/process/thread/session/full Context; nonempty message; no conflicting ConnectID",
    "key": ["call_event_id", "dataset_id", "user", "process", "thread", "session", "connect_id", "full_context_sha256", "exact_payload_sha256"],
    "message_transform": "CRLF/CR to LF, trim outer whitespace; repeatedly strip only exact leading wrappers",
    "wrappers": list(WRAPPERS),
    "time_window": None,
    "missing_or_ambiguous": "singleton per event",
    "interpretation": "suspected incident only; identical payload in one CALL is not proof of a common root cause",
    "attribution": "root cause and cancellation initiator remain unknown",
}
ERROR_VERSIONS = {"error_signature_version": ERROR_SIGNATURE_VERSION,
                  "error_linkage_rules_version": ERROR_LINKAGE_VERSION,
                  "incident_rules_version": INCIDENT_RULES_VERSION}
ERROR_METADATA = {**ERROR_VERSIONS, "error_linkage_rules": ERROR_LINKAGE_RULES, "incident_rules": INCIDENT_RULES}
ERROR_GROUP_FIELDS = "measurement_id event category signature signature_id error_signature_version sample event_count linked_error_event_count unlinked_error_event_count affected_call_count suspected_incident_count incident_rules_version users contexts first_timestamp last_timestamp".split()


def clean(text):
    return re.sub(r"\s+", " ", text or "").strip()


def normalize_error(text):
    value = clean(text)
    value = re.sub(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b", "<uuid>", value)
    value = re.sub(r"\b\d{4}[-/.]\d{1,2}[-/.]\d{1,2}(?:[ T]\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?)?\b", "<date>", value)
    return re.sub(r"\b\d{2,}\b", "#", value)


def message_fields(attrs):
    fields = ("Descr", "Description", "DBMS")
    name = next((k for k in fields if attrs.get(k)), next((k for k in fields if k in attrs), None))
    message = attrs.get(name) if name else None
    state = "missing" if message is None else "empty" if not message.strip() else "present"
    signature = normalize_error(message or "")
    return {"message_field": name, "raw_message": message, "message_state": state,
            "signature": signature, "signature_id": identity("error-signature/v2", ERROR_SIGNATURE_VERSION, state, signature),
            "error_signature_version": ERROR_SIGNATURE_VERSION}


def error_decision(connection, event, candidate_rows=None):
    return {**decide(connection, event, candidate_rows), "linkage_rules_version": ERROR_LINKAGE_VERSION}


def error_candidates(connection, event, decision, candidate_rows=None):
    for row in candidate_evidence(connection, event, decision, candidate_rows):
        yield {k: "event_missing" if k in {"session_relation", "connect_relation"} and v == "db_missing" else v for k, v in row.items()}


def membership(event, decision, connect_relation):
    payload = (event["raw_message"] or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    wrappers = []
    while payload:
        prefix = next((p for p in WRAPPERS if payload.startswith(p)), None)
        if prefix is None:
            break
        wrappers.append(prefix)
        payload = payload[len(prefix):].strip()
    reason = "same_call_exact_payload"
    if decision["status"] != "linked_unique":
        reason = "singleton_" + decision["status"]
    elif any(not (event[k] or "").strip() for k in ("usr_raw", "process", "thread", "session", "context")):
        reason = "singleton_missing_identity_or_context"
    elif event["message_state"] != "present" or not payload:
        reason = "singleton_missing_payload"
    elif connect_relation == "conflict":
        reason = "singleton_connect_conflict"
    eligible = reason == "same_call_exact_payload"
    key = {k: event[k] for k in ("dataset_id", "user", "process", "thread", "session", "connect_id")}
    key.update(call_event_id=decision["parent_event_id"],
               full_context_sha256=identity("error-context/v1", event["context"]),
               exact_payload_sha256=identity("error-payload/v1", payload))
    group_key = key if eligible else {"singleton_event_id": event["event_id"]}
    incident_id = identity("suspected-incident/v1", INCIDENT_RULES_VERSION, group_key)
    evidence = {"scope": key, "linkage_status": decision["status"], "connect_relation": connect_relation,
                "stripped_wrappers": wrappers, "time_proximity_used": False, "common_root_cause_proven": False}
    return {"event_id": event["event_id"], "incident_id": incident_id, "incident_rules_version": INCIDENT_RULES_VERSION,
            "reason_code": reason, "message_role": "known_wrapper" if wrappers else "unwrapped_message",
            "group_key_json": canonical(group_key), "evidence_json": canonical(evidence)}


def classify_error(text: str) -> str:
    value = clean(text)[:6000].casefold()
    rules = (
        ("statement_cancelled", ("canceling statement due to user request", "отмена выполнения запроса", "запрос отменен", "запрос отменён")),
        ("permission_denied", ("permission denied", "недостаточно прав", "нарушение прав доступа", "нет прав")),
        ("session_missing_or_deleted", ("сеанс отсутствует", "сеанс удален", "сеанс удалён", "session does not exist", "session was deleted")),
        ("passive_service", ("пассивн", "passive service")),
        ("form_error", ("ошибка формы", "управляемаяформа", "обычнаяформа", "formexception")),
        ("external_resource", ("ошибка работы с ресурсом", "выполнении запроса post", "выполнении запроса get", "http")),
        ("postgresql_reported", ("postgres", "sqlstate", "dbpostgrs")),
    )
    for category, markers in rules:
        if any(marker in value for marker in markers):
            return category
    return "other_application_or_platform_error"
