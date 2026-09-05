"""Bounded baseline of real verifier blocks on disposable synthetic SQLite data.

No analyzer invocation, input bundle argument, production edits, or third-party dependencies.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
import ctypes
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "tools/one_c_tj_analyzer"
sys.path.insert(0, str(SRC))
from numeric_quality import CounterStats, FIELDS, parse_counter
from source_identity import identity
from verify_populations import exact_stats, compare_stats
from verify_additive import additive_groups, AdditiveStats


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True).strip()


def extract_blocks():
    """Select complete original AST statements; fail closed if selectors drift."""
    specs = [
        ("source_counts", "verify_populations.py", "source_coverage", "source location missing from manifest"),
        ("dataset_sources", "verify_populations.py", "source_coverage", "unknown time population mismatch"),
        ("dataset_stats", "verify_populations.py", "verify_populations", "dataset event type coverage mismatch"),
        ("heavy_sql", "verify_populations.py", "verify_populations", 'compare_stats(row, expected, "SQL"'),
        ("locks", "verify_populations.py", "verify_populations", "lock linked event count mismatch"),
        ("nested_sql", "verify_populations.py", "verify_populations", "nested SQL preview coverage mismatch"),
        ("error_calls", "verify_error_store.py", "verify_errors", "CALL error event count mismatch"),
        ("error_linkage", "verify_error_store.py", "verify_errors", "error linkage sums mismatch"),
    ]
    blocks, provenance = {}, {}
    setup_names = {"source_counts": "source_counts", "dataset_sources": "missing_times",
                   "error_calls": "error_counts", "error_linkage": "error_linkage_counts",
                   "dataset_stats": "dataset_additive", "heavy_sql": "sql_additive", "locks": "lock_additive"}
    for name, filename, function, marker in specs:
        source = (SRC / filename).read_text(encoding="utf-8")
        fn = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == function)
        nodes = [n for n in fn.body if isinstance(n, ast.For) and marker in ast.get_source_segment(source, n)]
        require(len(nodes) == 1, f"source selector changed: {name}")
        node = nodes[0]
        setup = [n for n in fn.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == setup_names.get(name) for t in n.targets)]
        require(len(setup) == (1 if name in setup_names else 0), f"setup selector changed: {name}")
        selected = setup + [node]
        segment = '\n'.join(ast.get_source_segment(source, n) for n in selected)
        blocks[name] = compile(ast.Module(body=selected, type_ignores=[]), str(SRC / filename), "exec")
        provenance[name] = {"file": str((SRC / filename).relative_to(ROOT)), "function": function,
                            "line": selected[0].lineno, "end_line": node.end_lineno,
                            "sha256": hashlib.sha256(segment.encode()).hexdigest(), "source": segment}
    return blocks, provenance


def oracle_stats(rows):
    values = sorted(r["duration_us"] for r in rows)
    n = len(values)
    quality = {f: CounterStats() for f in FIELDS}
    for row in rows:
        for f in FIELDS:
            quality[f].add(row["numeric"][f])
    return dict(count=n, duration_us=sum(values), avg_us=round(sum(values)/n, 3) if n else 0.0,
                median_us=round(float(statistics.median(values)), 3) if n else 0.0,
                p95_us=values[(95*n+99)//100-1] if n else 0,
                p99_us=values[(99*n+99)//100-1] if n else 0, max_us=max(values, default=0),
                **{f"over_{s}s": sum(v >= s*1_000_000 for v in values) for s in (1, 5, 10, 30)},
                count_0_5_to_2s=sum(500_000 <= v <= 2_000_000 for v in values),
                numeric_quality={f: q.as_dict() for f, q in quality.items()})


def build(path, units, distribution):
    groups = 4 if distribution == "few_large" else 48
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA temp_store=FILE")
    con.execute("PRAGMA cache_size=-8192")
    con.execute("PRAGMA threads=1")
    con.executescript((SRC / "event_schema.sql").read_text())
    con.executescript((SRC / "error_schema.sql").read_text())
    logical = hashlib.sha256()

    def insert(table, row):
        logical.update(json.dumps([table, row], sort_keys=True).encode())
        con.execute(f"INSERT INTO {table} ({','.join(row)}) VALUES ({','.join('?' for _ in row)})", tuple(row.values()))

    files, rows, calls = [], [], []
    for g in range(groups + 1):  # last group is empty, but has a source and a CALL
        source, version, location = f"s{g:03}", f"v{g:03}", f"synthetic/{g:03}"
        insert("source_streams", dict(source_id=source, capture_id="benchmark", origin_id="synthetic",
               process_scope="p", logical_log_key=location, identity_status="synthetic"))
        insert("source_versions", dict(source_version_id=version, source_id=source, content_sha256="a"*64,
               hash_scope="full", size_bytes=1_000_000, analyzed_bytes=1_000_000, encoding="utf-8", status="valid"))
        insert("source_locations", dict(location_id=identity("location/v1", location), source_version_id=version,
               kind="file", path=location, member=None, member_ordinal=None, display_path=location))
        files.append(dict(source=location, source_id=source, source_version_id=version, dataset_id=f"d{g:03}",
               kind="file", member=None, member_ordinal=None, size_bytes=1_000_000, analyzed_bytes=1_000_000,
               sha256="a"*64, status="valid", parse_errors=0, records=0))
        insert("sql_texts", dict(sql_text_id=f"sql{g}", sql_text=f"select column_{g} from synthetic", sql_text_sha256=digest(g)))
        insert("sql_patterns", dict(pattern_id=f"p{g}", normalization_version="benchmark", normalized_sql=f"select column_{g} from synthetic",
               sql_fingerprint_sha256=digest(g), normalization_status="normalized"))
        insert("sql_normalizations", dict(sql_text_id=f"sql{g}", normalization_version="benchmark", pattern_id=f"p{g}", state="normalized"))

    positions = Counter()
    def event(kind, g, i):
        pos = positions[g]
        positions[g] += 1
        duration = (0, 499999, 500000, 1000000, 2000000, 5000000, 10000000, 30000000)[i % 8]
        end = None if i % 17 == 0 else 100_000_000 + i * 100
        row = dict(event_id=f"{kind}-{i:06}", source_version_id=f"v{g:03}", byte_start=pos*10, byte_end=pos*10+10,
                   record_ordinal=pos+1, line_start=pos+1, line_end=pos+1, raw_record_sha256="b"*64,
                   event_type=kind, level=0, raw_timestamp="synthetic", start_time_us=None if end is None else end-duration,
                   end_time_us=end, time_state="unavailable" if end is None else "local_naive", duration_raw=str(duration),
                   duration_us=duration, duration_state="valid", dataset_id=f"d{g:03}", measurement_id="m0", user="synthetic",
                   process="p", thread="1", context=f"context {g}", attributes_json="{}")
        insert("events", row)
        numeric = {}
        for j, f in enumerate(FIELDS):
            raw = (None, "", "bad", "9223372036854775808", "0", str(i % 101))[(i+j) % 6]
            numeric[f] = q = parse_counter(f, raw)
            insert("numeric_values", dict(event_id=row["event_id"], field_name=f, raw_value=q["raw_value"],
                   value_int=q["value"], state=q["state"], unit=q["unit"], reason_code=q["reason"]))
        row["numeric"] = numeric
        rows.append(row)
        return row

    for g in range(groups+1):
        row = event("CALL", g, g)
        insert("call_events", dict(event_id=row["event_id"], legacy_call_id=g+1, signature=f"op{g}", call_signature_version="benchmark"))
        calls.append(dict(call_id=g+1, event_id=row["event_id"], error_count=0))
    con.execute("CREATE TEMP TABLE checked_aux(event_id TEXT PRIMARY KEY,parent_event_id TEXT,category TEXT,context TEXT)")
    con.execute("CREATE TEMP TABLE checked_operation(call_event_id TEXT PRIMARY KEY,operation_index INTEGER)")
    con.executemany("INSERT INTO checked_operation VALUES (?,?)", [(c["event_id"], g) for g, c in enumerate(calls)])
    sql_groups, lock_groups, nested = defaultdict(list), defaultdict(list), defaultdict(lambda: defaultdict(list))
    errors, linked = Counter(), Counter()
    weights = Counter()
    for i in range(units):
        if distribution == "skewed":
            g = i if i < groups else (0 if (i-groups) % 10 < 8 else 1+((i-groups)//10*2+(i-groups)%10-8) % (groups-1))
        else:
            g = i % groups
        weights[g] += 1
        parent = None if i % 11 == 0 else calls[g]["event_id"]
        for kind in ("DBPOSTGRS", "EXCP", "TLOCK"):
            row = event(kind, g, i)
            eid = row["event_id"]
            if kind == "TLOCK":
                con.execute("INSERT INTO checked_aux VALUES (?,?,?,?)", (eid, parent, "lock", row["context"]))
                row["parent"] = parent
                lock_groups[g].append(row)
                continue
            if kind == "DBPOSTGRS":
                has_sql = i % 13 != 0
                insert("db_events", dict(event_id=eid, sql_text_id=f"sql{g}" if has_sql else None, sql_presence_state="present" if has_sql else "missing"))
                if has_sql:
                    sql_groups[g].append(row)
                    if parent is not None:
                        nested[g][f"select column_{g} from synthetic"].append(row["duration_us"])
                table = "link_decisions"
            else:
                insert("error_events", dict(event_id=eid, message_state="missing", signature=f"err{g}", signature_id=f"err{g}", error_signature_version="benchmark", category="synthetic"))
                errors[g] += 1
                if parent is not None:
                    calls[g]["error_count"] += 1
                    linked[g] += 1
                table = "error_link_decisions"
            insert(table, dict(event_id=eid, linkage_rules_version="benchmark", parent_event_id=parent,
                   status="linked_unique" if parent else "unlinked", reason_code="synthetic", candidate_count=int(parent is not None),
                   eligible_count=int(parent is not None), session_match_count=0, fallback_applied=0, selection_rule="synthetic"))

    datasets = []
    for g in range(groups+1):
        selected = [r for r in rows if r["dataset_id"] == f"d{g:03}"]
        files[g]["records"] = len(selected)
        datasets.append(dict(dataset_id=f"d{g:03}", files_analyzed=1, bytes_analyzed=1_000_000, records=len(selected), parse_errors=0,
            events_without_absolute_timestamp=sum(r["end_time_us"] is None for r in selected),
            event_stats={t: oracle_stats([r for r in selected if r["event_type"] == t]) for t in sorted({r["event_type"] for r in selected})}))
    manifest = dict(files=files, datasets=datasets,
        heavy_sql=[dict(measurement_id="m0", sql_fingerprint_sha256=digest(g), **oracle_stats(rr)) for g, rr in sorted(sql_groups.items())],
        locks=[dict(measurement_id="m0", event="TLOCK", context=f"context {g}", linked_call_count=sum(r["parent"] is not None for r in rr), **oracle_stats(rr)) for g, rr in sorted(lock_groups.items())],
        linkage=[dict(measurement_id="m0", dataset_id=f"d{g:03}", error_total_count=errors[g], error_linked_count=linked[g]) for g in range(groups+1)],
        operations=[dict(call_ids=[calls[g]["call_id"]], top_nested_sql=[dict(normalized_sql=s, count=len(v), duration_us=sum(v), max_us=max(v))
            for s, v in sorted(nested[g].items(), key=lambda kv: (sum(kv[1]), max(kv[1]), kv[0]), reverse=True)[:10]]) for g in range(groups+1)])
    con.commit()
    require(con.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "fixture integrity")
    require(con.execute("PRAGMA foreign_key_check").fetchone() is None, "fixture references")
    return con, dict(connection=con, manifest=manifest, files={r["source"]: r for r in files}, calls=calls,
                     require=require, exact_stats=exact_stats, compare_stats=compare_stats, identity=identity, defaultdict=defaultdict,
                     additive_groups=additive_groups, AdditiveStats=AdditiveStats), dict(
        units_per_aux_type=units, distribution=distribution, populated_groups=groups, extra_empty_call_group=1,
        event_count=len(rows), numeric_count=len(rows)*len(FIELDS), units_by_group=dict(sorted(weights.items())),
        logical_insert_sha256=logical.hexdigest(), manifest_sha256=digest(manifest),
        sqlite_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), sqlite_bytes=path.stat().st_size)


class Queries:
    def __init__(self, connection):
        self.connection, self.statements, self.count = connection, {}, 0

    def execute(self, sql, params=()):
        self.count += 1
        item = self.statements.setdefault(sql, {"count": 0, "first_params": list(params), "last_params": []})
        item["count"] += 1
        item["last_params"] = list(params)
        return self.connection.execute(sql, params)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New directory; existing directories are refused")
    parser.add_argument("--sizes", type=int, nargs="+", default=[240, 720])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--budget-seconds", type=int, default=60)
    parser.add_argument("--reference-counts", type=Path, help="Compare only four count blocks against a frozen baseline JSON")
    parser.add_argument("--reference-additive", type=Path, help="Compare dataset/SQL/lock blocks against a frozen baseline JSON")
    args = parser.parse_args()
    require(not (args.reference_counts and args.reference_additive), 'select only one reference mode')
    require(1 <= len(args.sizes) <= 2 and all(96 <= n <= 960 for n in args.sizes), "sizes must be 96..960, at most two")
    require(1 <= args.repeats <= 5 and 5 <= args.budget_seconds <= 120, "bounded repeats/budget required")
    args.output.mkdir(parents=True, exist_ok=False)
    priority = "unchanged"
    if sys.platform == "win32":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.SetPriorityClass.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        require(kernel.SetPriorityClass(kernel.GetCurrentProcess(), 0x4000), "cannot lower own process priority")
        priority = "BELOW_NORMAL_PRIORITY_CLASS"
    started = time.perf_counter()
    deadline = started + args.budget_seconds
    def budget():
        require(time.perf_counter() < deadline, "benchmark wall-time budget exceeded")
    blocks, provenance = extract_blocks()
    reference_hash = None
    reference_path = args.reference_counts or args.reference_additive
    if reference_path:
        reference = json.loads(reference_path.read_text(encoding='utf-8'))
        reference_hash = hashlib.sha256(reference_path.read_bytes()).hexdigest()
        selected_blocks, selected_provenance = {}, {}
        names = ('dataset_stats', 'heavy_sql', 'locks') if args.reference_additive else ('source_counts', 'dataset_sources', 'error_calls', 'error_linkage')
        for name in names:
            old = reference['blocks'][name]
            require(hashlib.sha256(old['source'].encode()).hexdigest() == old['sha256'], 'reference block hash mismatch')
            selected_blocks[name+'_before'] = compile(old['source'], '<frozen-baseline>', 'exec')
            selected_blocks[name+'_after'] = blocks[name]
            selected_provenance[name+'_before'] = old
            selected_provenance[name+'_after'] = provenance[name]
        blocks, provenance = selected_blocks, selected_provenance
    result = dict(format_version=1, status="running", started_utc=datetime.now(timezone.utc).isoformat(), revision=git("rev-parse", "HEAD"),
        git_status_before=git("status", "--short"), python=sys.version, sqlite=sqlite3.sqlite_version,
        platform=platform.platform(), priority=priority, parameters=dict(sizes=args.sizes, repeats=args.repeats, budget_seconds=args.budget_seconds),
        protocol="one warmup, uninstrumented timed repeats, separate query-count/EXPLAIN pass; warm cache; no ANALYZE",
        source_sha256={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(SRC.glob('*.py'))} |
                      {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(SRC.glob('*.sql'))},
        harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), reference_sha256=reference_hash,
        reference_mode='additive' if args.reference_additive else 'counts' if args.reference_counts else None,
        blocks=provenance, scenarios=[])
    try:
        with tempfile.TemporaryDirectory(prefix="tj-verifier-benchmark-") as temporary:
            for units in args.sizes:
                for distribution in ("few_large", "many_small", "skewed"):
                    budget()
                    con, env, data = build(Path(temporary)/f"{units}-{distribution}.sqlite", units, distribution)
                    try:
                        con.set_progress_handler(lambda: int(time.perf_counter() >= deadline), 1000)
                        scenario = dict(data=data, pragmas={k: con.execute('PRAGMA '+k).fetchone()[0] for k in ('cache_size','temp_store','threads','automatic_index')}, measurements={})
                        result['scenarios'].append(scenario)
                        for name, code in blocks.items():
                            budget()
                            exec(code, env)  # warmup also validates against independently assembled fixture expectations
                            samples, cpu = [], []
                            for _ in range(args.repeats):
                                budget()
                                t, c = time.perf_counter_ns(), time.process_time_ns()
                                exec(code, env)
                                cpu.append((time.process_time_ns()-c)/1e6)
                                samples.append((time.perf_counter_ns()-t)/1e6)
                            recorder = Queries(con)
                            env['connection'] = recorder
                            exec(code, env)
                            env['connection'] = con
                            plans = []
                            for sql, info in recorder.statements.items():
                                plans.append(dict(sql=sql, **info, first_plan=[list(r) for r in con.execute('EXPLAIN QUERY PLAN '+sql, info['first_params'])],
                                                  last_plan=[list(r) for r in con.execute('EXPLAIN QUERY PLAN '+sql, info['last_params'])]))
                            scenario['measurements'][name] = dict(wall_ms=samples, cpu_ms=cpu, median_ms=statistics.median(samples),
                                min_ms=min(samples), max_ms=max(samples), sql_queries=recorder.count, plans=plans)
                            time.sleep(0.05)
                        print(f"{units} {distribution}: {data['event_count']} events; " + ', '.join(f"{k}={v['median_ms']:.1f}ms/{v['sql_queries']}q" for k,v in scenario['measurements'].items()), flush=True)
                    finally:
                        con.close()
        result['status'] = 'complete'
    except Exception as exc:
        result['status'], result['error'] = 'failed', repr(exc)
        raise
    finally:
        result['elapsed_seconds'] = time.perf_counter()-started
        result['git_status_after'] = git('status','--short')
        (args.output/'results.json').write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')


if __name__ == '__main__':
    main()
