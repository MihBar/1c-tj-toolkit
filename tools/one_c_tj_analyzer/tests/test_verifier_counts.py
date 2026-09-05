"""Saved-bundle equivalence against the frozen pre-optimization count loops."""
import ast
import contextlib
import copy
import inspect
import io
import json
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import analyze_1c_tj as analyzer
import verify_event_store
import verify_populations
import verify_error_store
from slice_input import load_bundle
from source_identity import file_hash
from test_event_detail import call, db, record


def legacy_function(module, name, blocks, setup_names):
    """Restore only the four frozen loops; keep all surrounding integrity checks."""
    fn = ast.parse(inspect.getsource(getattr(module, name))).body[0]
    body = []
    for node in fn.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in setup_names for t in node.targets):
            continue
        if isinstance(node, ast.For):
            for marker, source in blocks:
                if marker in ast.unparse(node):
                    node = ast.parse(source).body[0]
                    break
        body.append(node)
    fn.body = body
    namespace = vars(module).copy()
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])), '<legacy-counts>', 'exec'), namespace)
    return namespace[name]


class VerifierCountsTests(unittest.TestCase):
    def test_saved_bundle_acceptance_and_corruption_equivalence(self):
        baseline_path = Path(__file__).resolve().parents[3] / 'tools/one_c_tj_analyzer/tests/fixtures/verifier_baseline_blocks.json'
        baseline = json.loads(baseline_path.read_text(encoding='utf-8'))['blocks']
        old_source = legacy_function(verify_populations, 'source_coverage', [
            ('source location missing from manifest', baseline['source_counts']['source']),
            ('unknown time population mismatch', baseline['dataset_sources']['source'])], {'source_counts', 'missing_times'})
        old_errors = legacy_function(verify_error_store, 'verify_errors', [
            ('CALL error event count mismatch', baseline['error_calls']['source']),
            ('error linkage sums mismatch', baseline['error_linkage']['source'])], {'error_counts', 'error_linkage_counts'})
        old_populations = legacy_function(verify_populations, 'verify_populations', [
            ('dataset event type coverage mismatch', baseline['dataset_stats']['source']),
            ('compare_stats(row, expected,', baseline['heavy_sql']['source']),
            ('lock linked event count mismatch', baseline['locks']['source'])], {'dataset_additive', 'sql_additive', 'lock_additive'})
        with tempfile.TemporaryDirectory(prefix='tj-count-bundle-') as temporary:
            root = Path(temporary)
            logs, output = root/'logs', root/'output'
            source = logs/'capture/rphost_1/26090310.log'
            source.parent.mkdir(parents=True)
            source.write_text(call() + db(RowsAffected=0) + record('TLOCK', 2_000_000, Usr='User', OSThread='7', SessionID='A', Context='Lock') + record('EXCP', 2_000_000, Usr='User', OSThread='7', SessionID='A', Descr='Synthetic error') + call(30_000_000, 1_000_000), encoding='utf-8')
            (source.parent/'unknown.log').write_text(record('EXCP', 2_000_000, Descr='Unknown time'), encoding='utf-8')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(analyzer.run([str(logs), '-o', str(output)]), 0)
            bundle = load_bundle(output)
            saved_db = root/'original.sqlite'
            shutil.copyfile(output/'analysis.sqlite', saved_db)
            # Reads after generation must depend exclusively on saved results.
            shutil.rmtree(logs)

            cases = [
                ('valid', None),
                ('source_records', None), ('missing_source', None), ('extra_source', None),
                ('unknown_time', None), ('call_errors', None), ('linkage_errors', None),
                ('dataset_duration', None), ('sql_duration', None), ('lock_max', None), ('sql_p95', None), ('sql_quality', None),
                ('missing_numeric', 'DELETE FROM numeric_values WHERE rowid=(SELECT min(rowid) FROM numeric_values)'),
                ('missing_error_link', 'DELETE FROM error_link_decisions'),
                ('unknown_parent', "UPDATE error_link_decisions SET parent_event_id='unknown' WHERE parent_event_id IS NOT NULL"),
                ('unknown_source', "UPDATE events SET source_version_id='unknown' WHERE event_id=(SELECT min(event_id) FROM events)"),
                ('extra_event', "INSERT INTO events SELECT event_id||'-extra',source_version_id,byte_start+10000,byte_end+10000,record_ordinal+10000,line_start+10000,line_end+10000,raw_record_sha256,event_type,level,raw_timestamp,start_time_us,end_time_us,time_state,duration_raw,duration_us,duration_state,dataset_id,measurement_id,user,usr_raw,process,thread,session,connect_id,dbpid,context,attributes_json FROM events LIMIT 1"),
                ('duplicate_event', 'PRAGMA legacy_alter_table=ON; CREATE TABLE duplicate_events AS SELECT * FROM events; INSERT INTO duplicate_events SELECT * FROM events LIMIT 1; DROP TABLE events; ALTER TABLE duplicate_events RENAME TO events;'),
            ]
            for case, sql in cases:
                with self.subTest(case=case):
                    shutil.copyfile(saved_db, output/'analysis.sqlite')
                    manifest, calls = copy.deepcopy(bundle.manifest), copy.deepcopy(bundle.calls)
                    if sql:
                        with contextlib.closing(sqlite3.connect(output/'analysis.sqlite')) as con:
                            con.executescript(sql)
                            con.commit()
                    if case == 'source_records':
                        manifest['files'][0]['records'] += 1
                    elif case == 'missing_source':
                        manifest['files'].pop()
                    elif case == 'extra_source':
                        extra = copy.deepcopy(manifest['files'][0]); extra['source'] = 'extra'
                        manifest['files'].append(extra)
                    elif case == 'unknown_time':
                        manifest['datasets'][0]['events_without_absolute_timestamp'] += 1
                    elif case == 'call_errors':
                        calls[0]['error_count'] += 1
                    elif case == 'linkage_errors':
                        manifest['linkage'][0]['error_total_count'] += 1
                    elif case == 'dataset_duration':
                        next(d for d in manifest['datasets'] if 'DBPOSTGRS' in d['event_stats'])['event_stats']['DBPOSTGRS']['duration_us'] += 1
                    elif case == 'sql_duration':
                        manifest['heavy_sql'][0]['duration_us'] += 1
                    elif case == 'lock_max':
                        manifest['locks'][0]['max_us'] += 1
                    elif case == 'sql_p95':
                        manifest['heavy_sql'][0]['p95_us'] += 1
                    elif case == 'sql_quality':
                        manifest['heavy_sql'][0]['numeric_quality']['cpu_us']['available_count'] += 1
                    for filename, info in manifest['artifacts'].items():
                        info.update(sha256=file_hash(output/filename), size_bytes=(output/filename).stat().st_size)
                    outcomes = []
                    for source_fn, error_fn, population_fn in ((old_source, old_errors, old_populations), (verify_populations.source_coverage, verify_error_store.verify_errors, verify_populations.verify_populations)):
                        with patch.object(verify_event_store, 'source_coverage', source_fn), patch.object(verify_event_store, 'verify_errors', error_fn), patch.object(verify_event_store, 'verify_populations', population_fn):
                            try:
                                hashes = verify_event_store.verify_detail(output.resolve(), manifest, calls)
                                outcomes.append(('ok', hashes))
                            except ValueError as exc:
                                outcomes.append(('error', str(exc)))
                    self.assertEqual(outcomes[0], outcomes[1])
                    self.assertEqual(outcomes[1][0], 'ok' if case == 'valid' else 'error')


if __name__ == '__main__':
    unittest.main()
