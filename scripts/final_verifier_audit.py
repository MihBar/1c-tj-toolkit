"""Bounded, isolated full-verifier comparison with the actual Git baseline."""
import argparse
import contextlib
import csv
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'tools/one_c_tj_analyzer'
REVISION = '9ed05c88dd52c4ebb9739f46f1370c9ca86563db'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    return {p.name: sha(p) for p in sorted(root.iterdir()) if p.is_file()}


def priority():
    if sys.platform == 'win32':
        k = ctypes.WinDLL('kernel32', use_last_error=True)
        k.GetCurrentProcess.restype = ctypes.c_void_p
        k.SetPriorityClass.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        assert k.SetPriorityClass(k.GetCurrentProcess(), 0x4000)


def memory():
    # Query the live worker, not a terminated Process object. Includes interpreter,
    # imports and verification; peak is absolute process working set, not a delta.
    if sys.platform != 'win32':
        import resource
        return {'peak_rss_bytes': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == 'darwin' else 1024)}
    class Counters(ctypes.Structure):
        _fields_ = [('cb', ctypes.c_ulong), ('faults', ctypes.c_ulong)] + [(name, ctypes.c_size_t) for name in
            ('peak_ws','ws','peak_paged','paged','peak_nonpaged','nonpaged','pagefile','peak_pagefile','private')]
    k = ctypes.WinDLL('kernel32')
    k.GetCurrentProcess.restype = ctypes.c_void_p
    ps = ctypes.WinDLL('psapi')
    ps.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
    c = Counters(); c.cb = ctypes.sizeof(c)
    assert ps.GetProcessMemoryInfo(k.GetCurrentProcess(), ctypes.byref(c), c.cb)
    return {'peak_rss_bytes': c.peak_ws, 'rss_bytes': c.ws, 'private_bytes': c.private}


def typed(value):
    if isinstance(value, dict):
        return ['dict', {k: typed(v) for k, v in value.items()}]
    if isinstance(value, list):
        return ['list', [typed(v) for v in value]]
    return [type(value).__name__, value]


def worker(args):
    priority()
    sys.path.insert(0, str(args.source))
    from verify_analysis import verify
    bundle = args.bundle.resolve()
    before = inventory(bundle)
    audit = {'source_open_attempts': 0, 'bundle_write_attempts': 0, 'sqlite_uris': []}
    def guard(event, values):
        if event == 'open' and isinstance(values[0], (str, bytes, os.PathLike)):
            p = Path(os.fsdecode(values[0])).resolve()
            if p.suffix == '.log':
                audit['source_open_attempts'] += 1
                raise RuntimeError('source read prohibited')
            if p.is_relative_to(bundle) and (values[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)):
                audit['bundle_write_attempts'] += 1
                raise RuntimeError('bundle write prohibited')
        elif event == 'sqlite3.connect':
            uri = str(values[0])
            audit['sqlite_uris'].append(uri.replace(str(bundle), '<bundle>').replace(bundle.as_uri(), '<bundle-uri>'))
            assert 'mode=ro' in uri and 'immutable=1' in uri, uri
    sys.addaudithook(guard)
    queries = [0]
    if args.measure == 'queries':
        connect = sqlite3.connect
        def traced(*a, **kw):
            con = connect(*a, **kw)
            def trace(sql):
                queries[0] += 1
            con.set_trace_callback(trace)
            return con
        sqlite3.connect = traced
    samples, cpu, results = [], [], []
    before_memory = memory()
    for _ in range(3 if args.measure == 'time' else 1):
        t, c = time.perf_counter_ns(), time.process_time_ns()
        result, code = verify(bundle)
        samples.append((time.perf_counter_ns()-t)/1e6)
        cpu.append((time.process_time_ns()-c)/1e6)
        result = dict(result)
        if 'analysis_dir' in result:
            result['analysis_dir'] = '<same fixture>'
        results.append([code, result])
    assert all(typed(r) == typed(results[0]) for r in results)
    peak = memory()
    assert inventory(bundle) == before, 'input bundle changed'
    print(json.dumps(dict(measure=args.measure, wall_ms=samples, cpu_ms=cpu,
        sql_queries=queries[0] if args.measure == 'queries' else None, memory_before=before_memory, memory_after=peak,
        input_sha256=before, unchanged=True, audit=audit, result=results[0],
        typed_result_sha256=hashlib.sha256(json.dumps(typed(results[0]), sort_keys=True).encode()).hexdigest())))


def make_bundle(root, name):
    sys.path.insert(0, str(SOURCE))
    import analyze_1c_tj as analyzer
    groups = 4 if name == 'few_large' else 24
    logs, bundle = root/'logs', root/'bundle'
    def record(kind, end, duration, attrs):
        return f'00:{end//1000000:02}.{end%1000000:06}-{duration},{kind},5,' + ','.join(f"{k}='{v}'" for k,v in attrs.items())+'\n'
    texts = {g: [] for g in range(groups)}
    for g in texts:
        attrs = dict(Usr='Synthetic', OSThread='1', SessionID='A', Context=f'Operation {g}')
        texts[g].append(record('CALL', 50_000_000, 50_000_000, attrs))
    for i in range(96):
        g = i % groups if name != 'skewed' else (i if i < groups else 0 if (i-groups)%5 else 1+(i//5)%(groups-1))
        attrs = dict(Usr='Synthetic', OSThread='1', SessionID='A', Context=f'Operation {g}')
        texts[g].append(record('DBPOSTGRS', 1_000_000+i*10000, 100+(i%5)*1000, dict(attrs, Sql=f'SELECT column_{g} FROM synthetic', RowsAffected=0)))
        texts[g].append(record('TLOCK', 2_000_000+i*10000, 100+(i%5)*1000, attrs))
        texts[g].append(record('EXCP', 3_000_000+i*10000, 100, dict(attrs, Descr=f'Synthetic failure {g}')))
    for g, lines in texts.items():
        path = logs/'capture'/f'group{g:02}'/'rphost_1'/'26090310.log'
        path.parent.mkdir(parents=True)
        path.write_text(''.join(lines), encoding='utf-8')
    unknown = logs/'capture'/'unknown'/'rphost_1'/'unknown.log'
    unknown.parent.mkdir(parents=True)
    unknown.write_text(record('EXCP', 1_000_000, 100, dict(Descr='Unknown time')), encoding='utf-8')
    with contextlib.redirect_stdout(io.StringIO()):
        assert analyzer.run([str(logs), '-o', str(bundle)]) == 0
    # Only the freshly generated, owned temporary directory is removed.
    assert logs.resolve().is_relative_to(root.resolve())
    shutil.rmtree(logs)
    return bundle


def mutate(bundle, case):
    manifest_path = bundle/'analysis_metrics.json'
    m = json.loads(manifest_path.read_text(encoding='utf-8'))
    sql = {
        'missing_event': 'DELETE FROM events WHERE event_id=(SELECT min(event_id) FROM events)',
        'duplicate_event': 'PRAGMA legacy_alter_table=ON; CREATE TABLE copied AS SELECT * FROM events; INSERT INTO copied SELECT * FROM events LIMIT 1; DROP TABLE events; ALTER TABLE copied RENAME TO events;',
        'unknown_link': "UPDATE link_decisions SET parent_event_id='unknown'",
        'wrong_link': 'UPDATE link_decisions SET parent_event_id=(SELECT max(event_id) FROM call_events)',
        'missing_numeric': 'DELETE FROM numeric_values WHERE rowid=(SELECT min(rowid) FROM numeric_values)',
        'wrong_counter': "UPDATE numeric_values SET value_int=999 WHERE state='valid' AND field_name='rows_affected'",
        'missing_normalization': 'DELETE FROM sql_normalizations',
    }.get(case)
    if sql:
        with contextlib.closing(sqlite3.connect(bundle/'analysis.sqlite')) as con:
            con.executescript(sql)
            con.commit()
    table = None
    if case in ('sql_sum','sql_double_fault','wrong_group'):
        table = 'heavy_sql'
        row = m[table][0]
        if case == 'sql_sum': row['duration_us'] += 1
        elif case == 'wrong_group': row['measurement_id'] = 'unknown'
        else:
            row['median_us'] += 1
            row['max_us'] += 1
    elif case == 'source_count':
        table = 'files'; m[table][0]['records'] += 1
    elif case == 'missing_export':
        (bundle/'locks.csv').unlink()
    if table:
        from slice_input import scalar
        path = bundle/(table+'.csv')
        with path.open(encoding='utf-8-sig', newline='') as f:
            fields = next(csv.reader(f))
        with path.open('w', encoding='utf-8-sig', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fields); writer.writeheader()
            writer.writerows({k: scalar(row.get(k)) for k in fields} for row in m[table])
    for name, descriptor in m['artifacts'].items():
        if (bundle/name).is_file():
            descriptor.update(sha256=sha(bundle/name), size_bytes=(bundle/name).stat().st_size)
    manifest_path.write_text(json.dumps(m, ensure_ascii=False), encoding='utf-8')


def main(args):
    priority()
    args.output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    deadline = started + 180
    result = dict(revision=REVISION, status='running', python=sys.version, sqlite=sqlite3.sqlite_version,
        current_sources={p.name: sha(p) for p in SOURCE.glob('*.py')}, scenarios=[], corruptions=[])
    def run(source, bundle, measure):
        remaining = deadline-time.monotonic()
        assert remaining > 0, 'audit budget exhausted'
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '--worker', '--source', str(source), '--bundle', str(bundle), '--measure', measure]
        output = subprocess.check_output(command, text=True, encoding='utf-8', timeout=min(30, remaining))
        return json.loads(output)
    try:
        with tempfile.TemporaryDirectory(prefix='tj-final-audit-') as temporary:
            temp = Path(temporary)
            original = temp/'original'; original.mkdir()
            names = subprocess.check_output(['git','-C',str(ROOT),'ls-tree','--name-only',REVISION+':tools/one_c_tj_analyzer'], text=True).splitlines()
            for name in names:
                if Path(name).suffix in ('.py','.sql'):
                    (original/name).write_bytes(subprocess.check_output(['git','-C',str(ROOT),'show',f'{REVISION}:tools/one_c_tj_analyzer/{name}']))
            result['baseline_sources'] = inventory(original)
            for name in ('few_large','many_small','skewed'):
                bundle = make_bundle(temp/name, name)
                m = json.loads((bundle/'analysis_metrics.json').read_text(encoding='utf-8'))
                scenario = dict(distribution=name, counts=m['counts'], source_count=len(m['files']), dataset_count=len(m['datasets']),
                                before=[], after=[])
                for order in (('before','after'), ('after','before')):
                    for variant in order:
                        scenario[variant].append(run(original if variant == 'before' else SOURCE, bundle, 'time'))
                for variant in ('before','after'):
                    scenario[variant].append(run(original if variant == 'before' else SOURCE, bundle, 'queries'))
                signatures = {r['typed_result_sha256'] for variant in ('before','after') for r in scenario[variant]}
                assert len(signatures) == 1 and scenario['after'][0]['result'][0] == 0, 'full result differs'
                result['scenarios'].append(scenario)
                print('verified '+name, flush=True)
                if name == 'few_large':
                    reference_bundle = bundle
            for case in ('missing_event','duplicate_event','unknown_link','wrong_link','missing_numeric','wrong_counter','missing_normalization','sql_sum','wrong_group','source_count','missing_export','sql_double_fault'):
                target = temp/('corrupt-'+case)
                shutil.copytree(reference_bundle, target)
                mutate(target, case)
                old, new = run(original, target, 'queries'), run(SOURCE, target, 'queries')
                assert old['result'][0] != 0 and new['result'][0] != 0, 'corruption accepted: '+case
                result['corruptions'].append(dict(case=case, before=old, after=new,
                    same_diagnostic=old['result'] == new['result']))
            result['status'] = 'complete'
    finally:
        result['elapsed_seconds'] = time.monotonic()-started
        (args.output/'results.json').write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path)
    p.add_argument('--worker', action='store_true')
    p.add_argument('--source', type=Path)
    p.add_argument('--bundle', type=Path)
    p.add_argument('--measure', choices=['time','queries'])
    args = p.parse_args()
    worker(args) if args.worker else main(args)
