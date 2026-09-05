"""CALL linkage kernel, shared by stored linkage and verification.

``link_events`` accepts arbitrary input order and yields results in scope/time/ID
order (not input order). It sorts references in O((C+E) log(C+E)) preparation
time, using O(C+E) memory. ``sweep_sorted`` instead consumes already sorted
streams and retains only one CALL scope plus one result: O(max C_scope + A_event).
Both accept stored event mappings; CALL rows must include legacy_call_id, as in
events JOIN call_events. Inputs must satisfy the existing storage contract and
have unique event IDs / legacy CALL IDs; callers must not mutate them mid-sweep.

Active updates cost O(log C_scope); counts and best ranks are cached in segment
trees. Evidence walks a maintained linked list in legacy ID order: O(K), with no
per-event sort or scan of expired CALLs. Session dictionary lookup is expected
O(1). SQLite sorting, persistence, export, and verification are outside this
in-memory kernel's O((C+E) log(C+E) + K) bound. A result materializes evidence for
one event; include_evidence=False never enumerates active CALLs.

Legacy decide/candidate_evidence deliberately remain untouched as an independent
differential oracle. Only rule version constants are shared with that path.
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import groupby

from event_linking import LINKAGE_RULES_VERSION
from error_rules import ERROR_LINKAGE_VERSION


def scope_key(row):
    # None and empty threads both fail the required-field gate, never link.
    return (row["dataset_id"], row["user"], row["process"], row["thread"] or "")


def call_order(row):
    return scope_key(row), row["legacy_call_id"]


def event_order(row):
    end = row["end_time_us"]
    return scope_key(row), end is not None, end if end is not None else 0, row["event_id"]


@dataclass
class WorkCounters:
    """Operation counts for structural tests, independent of wall-clock timing."""

    activations: int = 0
    removals: int = 0
    tree_nodes_visited: int = 0
    candidates_visited: int = 0


class _RankTree:
    def __init__(self, length, work):
        self.size = 1 << (max(1, length) - 1).bit_length()
        self.count = [0] * (2 * self.size)
        self.best = [None] * (2 * self.size)
        self.work = work

    def set(self, position, rank):
        node = self.size + position
        self.count[node] = int(rank is not None)
        self.best[node] = rank
        self.work.tree_nodes_visited += 1
        node //= 2
        while node:
            self.work.tree_nodes_visited += 1
            left, right = node * 2, node * 2 + 1
            self.count[node] = self.count[left] + self.count[right]
            a, b = self.best[left], self.best[right]
            self.best[node] = b if a is None else a if b is None else max(a, b)
            node //= 2

    def predecessor(self, position):
        """Rightmost active leaf strictly before position, in O(log size)."""
        node = self.size + position
        while node > 1:
            self.work.tree_nodes_visited += 1
            if node % 2 and self.count[node - 1]:
                node -= 1
                while node < self.size:
                    self.work.tree_nodes_visited += 1
                    right = node * 2 + 1
                    node = right if self.count[right] else right - 1
                return node - self.size
            node //= 2
        return -1


@dataclass(frozen=True)
class CandidateSummary:
    candidate_count: int = 0
    session_match_count: int = 0
    best_event_id: str | None = None
    best_session_event_id: str | None = None


class _CandidateIterator:
    """Explicit close drops the scope even when a consumer retains this view.

    In particular, closing an unstarted generator need not immediately clear
    all its argument references on every supported Python runtime.
    """
    def __init__(self, active):
        self.active = active
        self.generation = active.generation
        self.position = active.head

    def __iter__(self):
        return self

    def __next__(self):
        active = self.active
        if active is None:
            raise StopIteration
        if self.generation != active.generation:
            self.close()
            raise RuntimeError("Candidate view expired after sweep advance")
        if self.position == -1:
            self.close()
            raise StopIteration
        position = self.position
        self.position = active.next[position]
        active.work.candidates_visited += 1
        return active.calls[position]

    def close(self):
        self.active = None


class ActiveCalls:
    """Monotone sweep of one scope, with ordered enumeration and eager deletion.

    CALLs without absolute time or thread are never activated. Arrays include
    all usable CALLs in this scope, not just active ones. Session trees together
    have at most C leaves before power-of-two padding. No lazy tombstones remain
    in the active list or tree aggregates after expiration.
    """

    def __init__(self, calls, *, work=None):
        rows = list(calls)
        scopes = {scope_key(row) for row in rows}
        if len(scopes) > 1:
            raise ValueError("ActiveCalls requires one search scope")
        self.scope = next(iter(scopes), None)
        if len({row["legacy_call_id"] for row in rows}) != len(rows) or len({row["event_id"] for row in rows}) != len(rows):
            raise ValueError("Duplicate CALL identity")
        for row in rows:
            start, end = row["start_time_us"], row["end_time_us"]
            if row["event_type"] != "CALL" or (start is None) != (end is None) or (end is not None and start > end):
                raise ValueError("Invalid CALL interval/type")
        self.calls = sorted((row for row in rows if row["thread"] and row["end_time_us"] is not None),
                            key=lambda row: row["legacy_call_id"])
        self.work = work if work is not None else WorkCounters()
        self.tree = _RankTree(len(self.calls), self.work)
        self.prev = [-1] * len(self.calls)
        self.next = [-1] * len(self.calls)
        self.head = -1
        groups = {}
        self.session_positions = [None] * len(self.calls)
        for position, row in enumerate(self.calls):
            if row["session"]:
                members = groups.setdefault(row["session"], [])
                self.session_positions[position] = len(members)
                members.append(position)
        self.sessions = {session: _RankTree(len(members), self.work) for session, members in groups.items()}
        self.starts = sorted(range(len(self.calls)), key=lambda i: (self.calls[i]["start_time_us"], self.calls[i]["legacy_call_id"]))
        self.ends = sorted(range(len(self.calls)), key=lambda i: (self.calls[i]["end_time_us"], self.calls[i]["legacy_call_id"]))
        self.start_cursor = self.end_cursor = 0
        self.time = None
        self.generation = 0

    def _set(self, position, active):
        row = self.calls[position]
        rank = (row["duration_us"], -row["legacy_call_id"], position) if active else None
        self.tree.set(position, rank)
        if row["session"]:
            self.sessions[row["session"]].set(self.session_positions[position], rank)

    def advance(self, timestamp):
        if timestamp is None or (self.time is not None and timestamp < self.time):
            raise ValueError("Sweep time must be nondecreasing and nonmissing")
        self.generation += 1
        self.time = timestamp
        while self.start_cursor < len(self.starts):
            position = self.starts[self.start_cursor]
            if self.calls[position]["start_time_us"] > timestamp:
                break
            before = self.tree.predecessor(position)
            after = self.head if before == -1 else self.next[before]
            self.prev[position], self.next[position] = before, after
            if before == -1:
                self.head = position
            else:
                self.next[before] = position
            if after != -1:
                self.prev[after] = position
            self._set(position, True)
            self.work.activations += 1
            self.start_cursor += 1
        # Strict < preserves end-inclusive matching, including zero duration.
        while self.end_cursor < len(self.ends):
            position = self.ends[self.end_cursor]
            if self.calls[position]["end_time_us"] >= timestamp:
                break
            before, after = self.prev[position], self.next[position]
            if before == -1:
                self.head = after
            else:
                self.next[before] = after
            if after != -1:
                self.prev[after] = before
            self.prev[position] = self.next[position] = -1
            self._set(position, False)
            self.work.removals += 1
            self.end_cursor += 1

    def summary(self, session):
        matched = self.sessions.get(session) if session else None
        best = self.tree.best[1]
        best_session = matched.best[1] if matched is not None else None
        return CandidateSummary(
            self.tree.count[1], matched.count[1] if matched is not None else 0,
            self.calls[best[2]]["event_id"] if best is not None else None,
            self.calls[best_session[2]]["event_id"] if best_session is not None else None,
        )

    def candidates(self):
        """Live ordered view; advancing invalidates even an unstarted iterator."""
        return _CandidateIterator(self)


def decision_from_summary(event, summary):
    """Apply the existing rule to aggregate facts, without enumerating CALLs."""
    error = event["event_type"] in ("EXCP", "QERR")
    result = {"event_id": event["event_id"],
              "linkage_rules_version": ERROR_LINKAGE_VERSION if error else LINKAGE_RULES_VERSION,
              "parent_event_id": None, "status": "unlinked", "reason_code": "no_containing_call",
              "candidate_count": 0, "eligible_count": 0, "session_match_count": 0,
              "fallback_applied": 0, "selection_rule": "duration_desc_legacy_call_id_asc"}
    if event["end_time_us"] is None:
        result["reason_code"] = "missing_timestamp"
    elif not event["thread"]:
        result["reason_code"] = "missing_thread"
    elif summary.candidate_count:
        matches = summary.session_match_count
        result.update(candidate_count=summary.candidate_count, session_match_count=matches,
                      eligible_count=matches or summary.candidate_count,
                      parent_event_id=summary.best_session_event_id if matches else summary.best_event_id,
                      fallback_applied=int(not matches or not (event["usr_raw"] or "").strip() or not event["process"]))
        if result["eligible_count"] > 1:
            result.update(status="ambiguous", reason_code="multiple_candidates_legacy_longest")
        elif result["fallback_applied"]:
            reason = "missing_user_or_process" if matches else "missing_session" if not event["session"] else "session_no_match"
            result.update(status="linked_by_rule", reason_code=reason)
        else:
            result.update(status="linked_unique", reason_code="same_session_unique")
    return result


def _relation(event_value, call_value, missing):
    if not event_value:
        return "both_missing" if not call_value else missing
    if not call_value:
        return "call_missing"
    return "match" if event_value == call_value else "conflict"


def evidence_from_candidates(event, decision, candidate_rows):
    """Format every temporal candidate, including session-excluded CALLs."""
    if not decision["candidate_count"]:
        return
    missing = "event_missing" if event["event_type"] in ("EXCP", "QERR") else "db_missing"
    for call in candidate_rows:
        session = _relation(event["session"], call["session"], missing)
        eligible = not decision["session_match_count"] or session == "match"
        selected = call["event_id"] == decision["parent_event_id"]
        yield {"event_id": event["event_id"], "call_event_id": call["event_id"],
               "session_relation": session, "connect_relation": _relation(event["connect_id"], call["connect_id"], missing),
               "full_interval_contained": int(call["start_time_us"] <= event["start_time_us"] <= event["end_time_us"] <= call["end_time_us"]),
               "eligible": int(eligible), "selected": int(selected),
               "reason_code": "selected_legacy_rule" if selected else "excluded_by_session_preference" if not eligible else "not_selected_duration_or_legacy_order"}


@dataclass(frozen=True)
class LinkResult:
    decision: dict
    evidence: tuple


def _checked_order(rows, key):
    previous = None
    for row in rows:
        current = key(row)
        if previous is not None and current <= previous:
            raise ValueError("Sweep input must have strictly increasing scope/order keys")
        previous = current
        yield row


def sweep_sorted(calls, events, *, include_evidence=True, work=None):
    """Consume call_order/event_order streams; yield detached per-event results.

    This function never accesses SQLite or changes input mappings. Only CALL
    rows belong in calls; event rows are target observations, not CALLs. Schema
    identity uniqueness is a caller precondition (checked per CALL scope here).
    Empty/missing timestamp and thread produce decisions but no evidence.
    """
    for event, decision, evidence in sweep_views_sorted(calls, events, include_evidence=include_evidence, work=work):
        yield LinkResult(decision, tuple(evidence))


def sweep_views_sorted(calls, events, *, include_evidence=True, work=None):
    """Yield (event, decision, live evidence) with no candidate materialization.

    Consume evidence before requesting the next event. It is closed on advance
    or generator close so neither an exhausted view nor the next scope retains
    the previous ActiveCalls. The detached sweep_sorted API wraps this primitive.
    """
    call_groups = iter(groupby(_checked_order(calls, call_order), scope_key))
    call_group = next(call_groups, None)
    for scope, group in groupby(_checked_order(events, event_order), scope_key):
        while call_group is not None and call_group[0] < scope:
            call_group = next(call_groups, None)
        active = ActiveCalls(call_group[1] if call_group is not None and call_group[0] == scope else (), work=work)
        for event in group:
            usable = event["end_time_us"] is not None and bool(event["thread"])
            if usable:
                active.advance(event["end_time_us"])
            summary = active.summary(event["session"]) if usable else CandidateSummary()
            decision = decision_from_summary(event, summary)
            candidate_rows = active.candidates() if include_evidence else None
            evidence = evidence_from_candidates(event, decision, candidate_rows) if include_evidence else iter(())
            try:
                yield event, decision, evidence
            finally:
                if include_evidence:
                    evidence.close()
                    candidate_rows.close()
            del evidence, candidate_rows
        # Release BEFORE constructing the next scope, including its arrays.
        del active


def link_events(calls, events, *, include_evidence=True, work=None):
    """Convenience batch adapter for arbitrary input order; see module costs."""
    calls, events = list(calls), list(events)
    if len({row["legacy_call_id"] for row in calls}) != len(calls) or len({row["event_id"] for row in calls}) != len(calls):
        raise ValueError("Duplicate CALL identity")
    if len({row["event_id"] for row in events}) != len(events):
        raise ValueError("Duplicate target event identity")
    return sweep_sorted(sorted(calls, key=call_order), sorted(events, key=event_order),
                        include_evidence=include_evidence, work=work)
