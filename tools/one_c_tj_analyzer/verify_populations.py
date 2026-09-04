"""Exact checks against saved observations; SQLite sorts, Python streams sums."""
from __future__ import annotations

from collections import defaultdict
import re

from event_linking import decide
from numeric_quality import CounterStats, FIELDS, operation_counters, QUALITY_CSV_FIELDS

CHECKS = ["explicit_unique_ids_and_references", "source_positions_and_completeness",
          "sql_dictionary_complete_and_referenced", "exact_event_sql_lock_percentiles",
          "counter_coverage_reconciled_with_events", "auxiliary_links_and_no_double_count",
          "nested_sql_preview_reconciled_with_db_events", "identical_operations_from_individual_calls"]


def context_root(value):
    for line in (value or "").splitlines():
        text = re.sub(r"\s+", " ", line).strip()
        if text:
            return text if len(text) <= 900 else text[:897] + "..."
    return ""


def identities(connection, has_errors, require):
    keys = {table: [key] for table, key in (
        ("source_streams", "source_id"), ("source_versions", "source_version_id"), ("source_locations", "location_id"),
        ("events", "event_id"), ("call_events", "event_id"), ("db_events", "event_id"), ("sql_texts", "sql_text_id"),
        ("sql_patterns", "pattern_id"), ("link_decisions", "event_id"), ("parse_issues", "issue_id"))}
    keys.update(sql_normalizations=["sql_text_id", "normalization_version"], numeric_values=["event_id", "field_name"],
                link_candidates=["event_id", "call_event_id"])
    refs = [("events", "source_version_id", "source_versions", "source_version_id"),
            ("source_versions", "source_id", "source_streams", "source_id"),
            ("source_locations", "source_version_id", "source_versions", "source_version_id"),
            ("call_events", "event_id", "events", "event_id"), ("db_events", "event_id", "events", "event_id"),
            ("db_events", "sql_text_id", "sql_texts", "sql_text_id"),
            ("sql_normalizations", "sql_text_id", "sql_texts", "sql_text_id"),
            ("sql_normalizations", "pattern_id", "sql_patterns", "pattern_id"),
            ("numeric_values", "event_id", "events", "event_id"), ("link_decisions", "event_id", "db_events", "event_id"),
            ("link_decisions", "parent_event_id", "call_events", "event_id"),
            ("link_candidates", "event_id", "link_decisions", "event_id"), ("link_candidates", "call_event_id", "call_events", "event_id"),
            ("parse_issues", "source_version_id", "source_versions", "source_version_id")]
    if has_errors:
        keys.update({t: ["event_id"] for t in ("error_events", "error_link_decisions", "error_incident_members")})
        keys.update(error_link_candidates=["event_id", "call_event_id"], suspected_incidents=["incident_id"])
        refs.extend([("error_events", "event_id", "events", "event_id"), ("error_events", "sql_text_id", "sql_texts", "sql_text_id"),
                     ("error_link_decisions", "event_id", "error_events", "event_id"), ("error_link_decisions", "parent_event_id", "call_events", "event_id"),
                     ("error_link_candidates", "event_id", "error_link_decisions", "event_id"), ("error_link_candidates", "call_event_id", "call_events", "event_id"),
                     ("error_incident_members", "event_id", "error_events", "event_id"), ("error_incident_members", "incident_id", "suspected_incidents", "incident_id")])
    # Do not rely exclusively on constraints declared by the supplied database.
    for table, fields in keys.items():
        invalid = " OR ".join(f"{f} IS NULL OR {f}=''" for f in fields)
        require(connection.execute(f"SELECT 1 FROM {table} GROUP BY {','.join(fields)} HAVING count(*)<>1 OR {invalid} LIMIT 1").fetchone() is None,
                "duplicate/null identity: " + table)
    for table, field, target, target_field in refs:
        require(connection.execute(f"SELECT 1 FROM {table} a LEFT JOIN {target} b ON a.{field}=b.{target_field} WHERE a.{field} IS NOT NULL AND b.{target_field} IS NULL LIMIT 1").fetchone() is None,
                "broken explicit reference: " + table + "." + field)
    for table, event_type in (("call_events", "CALL"), ("db_events", "DBPOSTGRS")):
        require(connection.execute(f"SELECT 1 FROM events e LEFT JOIN {table} d USING(event_id) WHERE e.event_type=? AND d.event_id IS NULL LIMIT 1", (event_type,)).fetchone() is None,
                "missing specialized event: " + event_type)
        require(connection.execute(f"SELECT 1 FROM {table} d JOIN events e USING(event_id) WHERE e.event_type<>? LIMIT 1", (event_type,)).fetchone() is None,
                "incorrect specialized event type: " + table)
    require(connection.execute("SELECT 1 FROM source_versions GROUP BY source_id HAVING count(DISTINCT CASE WHEN source_version_id IN (SELECT source_version_id FROM events) THEN source_version_id END)>1 LIMIT 1").fetchone() is None,
            "multiple consumed versions of one logical source")
    require(connection.execute("SELECT 1 FROM call_events GROUP BY legacy_call_id HAVING count(*)<>1 OR legacy_call_id IS NULL LIMIT 1").fetchone() is None, "duplicate CALL numeric id")
    require(connection.execute("SELECT 1 FROM sql_texts t LEFT JOIN sql_normalizations n USING(sql_text_id) WHERE n.sql_text_id IS NULL LIMIT 1").fetchone() is None, "SQL text has no normalization")
    require(connection.execute("SELECT 1 FROM sql_patterns p LEFT JOIN sql_normalizations n USING(pattern_id) WHERE n.pattern_id IS NULL LIMIT 1").fetchone() is None, "unreferenced SQL pattern")
    error_ref = " AND NOT EXISTS (SELECT 1 FROM error_events r WHERE r.sql_text_id=t.sql_text_id)" if has_errors else ""
    require(connection.execute("SELECT 1 FROM sql_texts t WHERE NOT EXISTS (SELECT 1 FROM db_events d WHERE d.sql_text_id=t.sql_text_id)" + error_ref + " LIMIT 1").fetchone() is None, "unreferenced SQL text")


def source_coverage(connection, manifest, require):
    from source_identity import identity
    files = {r["source"]: r for r in manifest["files"]}
    require(len(files) == connection.execute("SELECT count(*) FROM source_locations").fetchone()[0], "source location coverage mismatch")
    for row in connection.execute("SELECT l.*,v.source_id,v.size_bytes,v.status,v.analyzed_bytes,v.content_sha256 FROM source_locations l JOIN source_versions v USING(source_version_id)"):
        item = files.get(row["display_path"])
        require(item is not None, "source location missing from manifest")
        require(row["location_id"] == identity("location/v1", row["display_path"]), "location identity mismatch")
        for key in ("source_id", "source_version_id", "kind", "member_ordinal", "size_bytes"):
            require(item[key] == row[key], "source field mismatch: " + key)
        require((item["member"] or None) == row["member"] and (item["sha256"] or None) == row["content_sha256"], "source locator/hash mismatch")
        if item["status"] != "skipped_duplicate":
            require(item["status"] == row["status"] and item["analyzed_bytes"] == row["analyzed_bytes"], "source processing status mismatch")
            count = connection.execute("SELECT count(*) FROM events WHERE source_version_id=?", (row["source_version_id"],)).fetchone()[0]
            require(count + item["parse_errors"] == item["records"], "source record coverage mismatch")
        else:
            require(item["records"] == item["parse_errors"] == 0, "duplicate source counted twice")
    previous = {}
    for row in connection.execute("SELECT e.*,v.source_id,v.analyzed_bytes FROM events e JOIN source_versions v USING(source_version_id) ORDER BY v.source_id,e.byte_start"):
        require(row["byte_end"] <= row["analyzed_bytes"], "event exceeds processed source prefix")
        old = previous.get(row["source_id"])
        if old:
            require(old[0] <= row["byte_start"] and old[1] < row["record_ordinal"] and old[2] < row["line_start"], "overlapping/repeated event position")
        previous[row["source_id"]] = (row["byte_end"], row["record_ordinal"], row["line_end"])
        require(row["time_state"] == ("unavailable" if row["end_time_us"] is None else "local_naive"), "time state mismatch")
    material_issue = False
    for row in connection.execute("SELECT i.*,v.size_bytes,v.status FROM parse_issues i JOIN source_versions v USING(source_version_id)"):
        require(0 <= row["byte_start"] <= row["byte_end"] <= row["size_bytes"], "invalid diagnostic byte range")
        require(row["issue_id"] == identity("issue/v1", row["source_version_id"], row["byte_start"], row["byte_end"], row["code"]), "diagnostic identity mismatch")
        require(row["status"] in {"skipped", "partial_read_error", "partial_nul_salvaged"}, "diagnostic hidden by complete source status")
        material_issue = True
    require(not material_issue or not manifest["source_processing_complete"], "diagnostics hidden by completeness flag")
    for dataset in manifest["datasets"]:
        selected = [r for r in manifest["files"] if r["dataset_id"] == dataset["dataset_id"] and r["status"] in {"valid", "valid_no_timestamp", "partial_read_error", "partial_nul_salvaged"}]
        for key, expected in (("files_analyzed", len(selected)), ("bytes_analyzed", sum(r["analyzed_bytes"] for r in selected)),
                              ("records", sum(r["records"] for r in selected)), ("parse_errors", sum(r["parse_errors"] for r in selected))):
            require(dataset[key] == expected, "dataset source totals mismatch: " + key)
        missing = connection.execute("SELECT count(*) FROM events WHERE dataset_id=? AND end_time_us IS NULL", (dataset["dataset_id"],)).fetchone()[0]
        require(dataset["events_without_absolute_timestamp"] == missing, "unknown time population mismatch")


def exact_stats(connection, selection, params, require):
    query = " FROM events e JOIN (" + selection + ") p ON p.event_id=e.event_id"
    count, distinct = connection.execute("SELECT count(*),count(DISTINCT e.event_id)" + query, params).fetchone()
    require(count == distinct, "aggregate population duplicates events")
    ranks = {(count-1)//2, count//2, (95*count+99)//100-1, (99*count+99)//100-1}
    picked, total, maximum, over, middle_band = {}, 0, 0, [0]*4, 0
    for index, row in enumerate(connection.execute("SELECT e.duration_us" + query + " ORDER BY e.duration_us,e.event_id", params)):
        value = row[0]
        total += value
        maximum = value
        if index in ranks:
            picked[index] = value
        for i, seconds in enumerate((1,5,10,30)):
            over[i] += value >= seconds*1_000_000
        middle_band += 500_000 <= value <= 2_000_000
    quality = {name: CounterStats() for name in FIELDS}
    for row in connection.execute("SELECT n.field_name,n.state,n.value_int FROM numeric_values n JOIN (" + selection + ") p ON p.event_id=n.event_id", params):
        quality[row["field_name"]].add({"state": row["state"], "value": row["value_int"]})
    require(all(sum(s.counts.values()) == count for s in quality.values()), "counter coverage differs from event population")
    return {"count": count, "duration_us": total, "avg_us": round(total/count,3) if count else 0.0,
            "median_us": round(float((picked[(count-1)//2]+picked[count//2])/2),3) if count else 0.0,
            "p95_us": picked[(95*count+99)//100-1] if count else 0,
            "p99_us": picked[(99*count+99)//100-1] if count else 0, "max_us": maximum,
            **{f"over_{s}s": over[i] for i,s in enumerate((1,5,10,30))},
            "numeric_quality": {name: stats.as_dict() for name,stats in quality.items()}, "count_0_5_to_2s": middle_band}


def compare_stats(actual, expected, label, require):
    for key, value in expected.items():
        if key != "count_0_5_to_2s" or key in actual:
            if type(value) is int:
                require(type(actual.get(key)) is int, label + ": expected integer " + key)
            require(actual.get(key) == value, label + ": exact observation mismatch: " + key)


def identical_operations(manifest, calls, require):
    import statistics
    by_signature, groups = defaultdict(set), defaultdict(list)
    for call in calls:
        by_signature[call["signature"]].add(call["measurement_id"])
        groups[(call["signature"], call["user"], call["measurement_id"])].append(call)
    expected_keys = {key for key in groups if len(by_signature[key[0]]) >= 2}
    require(expected_keys == {(r['signature'], r['user'], r['measurement_id']) for r in manifest['identical_operations']}, "identical operation population mismatch")
    history = defaultdict(list)
    for row in manifest['identical_operations']:
        members = groups[(row['signature'],row['user'],row['measurement_id'])]
        durations = sorted(c['duration_us'] for c in members)
        count = len(durations)
        times = sorted(c['end_timestamp'] for c in members if c['end_timestamp'])
        counters = operation_counters(members)
        dataset_ids = sorted({c['dataset_id'] for c in members})
        expected = {'count': count, 'avg_us': round(sum(durations)/count,3), 'median_us': round(float(statistics.median(durations)),3),
                    'p95_us': durations[(95*count+99)//100-1], 'max_us': durations[-1],
                    'db_per_call': round(sum(c['db_count'] for c in members)/count,6),
                    'db_seconds_per_call': round(sum(c['db_duration_us'] for c in members)/count/1_000_000,6),
                    'cpu_percent_of_wall': counters['cpu_percent_of_wall'], 'out_bytes_per_call': counters['out_bytes_per_call'],
                    'dataset_ids': dataset_ids, 'dataset_id': dataset_ids[0] if len(dataset_ids)==1 else '(multiple datasets)',
                    'first_timestamp': times[0] if times else '', 'last_timestamp': times[-1] if times else '',
                    **{k:counters[k] for k in QUALITY_CSV_FIELDS['identical_operations.csv']}}
        for key, value in expected.items():
            require(row.get(key)==value, 'identical operation exact CALL mismatch: '+key)
        history[(row['signature'],row['user'])].append(row)
    for rows in history.values():
        ordered=sorted(rows,key=lambda r:(r['first_timestamp'] or '9999-12-31 23:59:59',r['measurement_id']))
        previous=None
        for index,row in enumerate(ordered,1):
            require(row['comparison_order']==index, 'identical operation chronology mismatch')
            require(row['previous_measurement_id']==(previous['measurement_id'] if previous else '') and row['previous_first_timestamp']==(previous['first_timestamp'] if previous else ''), 'identical operation predecessor mismatch')
            for key in ('count','avg_us','median_us','p95_us','max_us','db_per_call','db_seconds_per_call','cpu_percent_of_wall','out_bytes_per_call'):
                delta=row[key]-previous[key] if previous and row[key] is not None and previous[key] is not None else None
                percent=round(delta/previous[key]*100,6) if delta is not None and previous[key] else None
                require(row.get(key+'_delta')==delta and row.get(key+'_delta_percent')==percent, 'identical operation delta mismatch: '+key)
            previous=row


def verify_populations(connection, manifest, calls, require):
    connection.execute("PRAGMA temp_store=FILE")
    connection.create_function("tj_context_root", 1, context_root, deterministic=True)
    # Auxiliary CALL assignments are recomputed from the unchanged owner rule.
    connection.execute("CREATE TEMP TABLE checked_aux(event_id TEXT PRIMARY KEY,parent_event_id TEXT,category TEXT,context TEXT)")
    per_call, per_link = defaultdict(lambda: [0,0,0]), defaultdict(lambda: [0,0,0,0])
    for event in connection.execute("SELECT * FROM events WHERE event_type IN ('SDBL','TLOCK','TTIMEOUT','TDEADLOCK')"):
        decision = decide(connection, event)
        category = "sdbl" if event["event_type"] == "SDBL" else "lock"
        parent = decision["parent_event_id"]
        connection.execute("INSERT INTO checked_aux VALUES(?,?,?,?)", (event["event_id"], parent, category, context_root(event["context"]) or "(context unavailable)"))
        link = per_link[(event["measurement_id"],event["dataset_id"])]
        index = 0 if category == "sdbl" else 2
        link[index] += 1
        link[index+1] += parent is not None
        if parent:
            target = per_call[parent]
            target[0 if category == "sdbl" else 1] += 1
            if category == "lock":
                target[2] += event["duration_us"]
    for call in calls:
        require(per_call[call["event_id"]] == [call[k] for k in ("sdbl_count", "lock_count", "lock_duration_us")], "CALL auxiliary contribution mismatch")
    for row in manifest["linkage"]:
        require(per_link[(row["measurement_id"],row["dataset_id"]) ] == [row[k] for k in ("sdbl_total_count","sdbl_linked_count","lock_total_count","lock_linked_count")], "auxiliary linkage totals mismatch")
    for dataset in manifest["datasets"]:
        types = {r[0] for r in connection.execute("SELECT DISTINCT event_type FROM events WHERE dataset_id=?", (dataset["dataset_id"],))}
        require(types == set(dataset["event_stats"]), "dataset event type coverage mismatch")
        for event_type, actual in dataset["event_stats"].items():
            expected = exact_stats(connection, "SELECT event_id FROM events WHERE dataset_id=? AND event_type=?", (dataset["dataset_id"],event_type), require)
            compare_stats(actual, expected, "dataset."+event_type, require)
    for row in manifest["heavy_sql"]:
        selection = "SELECT e.event_id FROM events e JOIN db_events d USING(event_id) JOIN sql_normalizations n USING(sql_text_id) JOIN sql_patterns p USING(pattern_id) WHERE e.measurement_id=? AND p.sql_fingerprint_sha256=?"
        expected = exact_stats(connection, selection, (row["measurement_id"],row["sql_fingerprint_sha256"]), require)
        compare_stats(row, expected, "SQL", require)
    lock_keys = {tuple(r) for r in connection.execute("SELECT DISTINCT e.measurement_id,e.event_type,a.context FROM checked_aux a JOIN events e USING(event_id) WHERE a.category='lock'")}
    require(lock_keys == {(r['measurement_id'],r['event'],r['context']) for r in manifest["locks"]}, "lock group coverage mismatch")
    for row in manifest["locks"]:
        selection = "SELECT e.event_id FROM events e JOIN checked_aux a USING(event_id) WHERE e.measurement_id=? AND e.event_type=? AND a.context=?"
        params = (row["measurement_id"],row["event"],row["context"])
        compare_stats(row, exact_stats(connection, selection, params, require), "lock", require)
        count = connection.execute("SELECT count(*) FROM checked_aux WHERE parent_event_id IS NOT NULL AND event_id IN ("+selection+")", params).fetchone()[0]
        require(row["linked_call_count"] == count, "lock linked event count mismatch")
    connection.execute("CREATE TEMP TABLE checked_operation(call_event_id TEXT PRIMARY KEY,operation_index INTEGER)")
    call_ids = {c["call_id"]:c["event_id"] for c in calls}
    for index, operation in enumerate(manifest["operations"]):
        connection.executemany("INSERT INTO checked_operation VALUES(?,?)", ((call_ids[i],index) for i in operation['call_ids']))
    for index, operation in enumerate(manifest["operations"]):
        # Streaming sums avoid signed-64-bit SQLite SUM overflow for durations.
        totals = defaultdict(lambda: [0,0,0])
        for row in connection.execute("SELECT p.normalized_sql,e.duration_us FROM db_events d JOIN events e USING(event_id) JOIN link_decisions k USING(event_id) JOIN checked_operation o ON o.call_event_id=k.parent_event_id JOIN sql_normalizations n USING(sql_text_id) JOIN sql_patterns p USING(pattern_id) WHERE o.operation_index=?", (index,)):
            item=totals[row[0]]; item[0]+=1; item[1]+=row[1]; item[2]=max(item[2],row[1])
        expected=sorted(totals.items(),key=lambda item:(item[1][1],item[1][2],item[0]),reverse=True)[:10]
        require(len(expected)==len(operation['top_nested_sql']), "nested SQL preview coverage mismatch")
        for (sql, metrics), actual in zip(expected,operation['top_nested_sql']):
            require(sql==actual['normalized_sql'] and metrics==[actual[k] for k in ('count','duration_us','max_us')], "nested SQL counted more than once or omitted")
    identical_operations(manifest, calls, require)
