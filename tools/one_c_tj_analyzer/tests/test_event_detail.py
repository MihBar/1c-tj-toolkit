"""Full DB detail and unchanged legacy linkage, using tiny synthetic journals."""
from __future__ import annotations

import contextlib
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import analyze_1c_tj as analyzer
from event_linking import LINKAGE_RULES_VERSION
from event_store import DETAIL_FILES
from slice_input import load_bundle
from slice_config import SliceError
from source_identity import file_hash
from verify_analysis import verify


def record(event, end, duration=100, **attrs):
    minute, remainder = divmod(end, 60_000_000)
    second, micros = divmod(remainder, 1_000_000)
    fields = ','.join(k + "='" + str(v).replace("'", "''") + "'" for k, v in attrs.items() if v is not None)
    return f'{minute:02}:{second:02}.{micros:06}-{duration},{event},5,{fields}\n'


def call(end=10_000_000, duration=10_000_000, **attrs):
    return record('CALL', end, duration, **(dict(Usr='User', OSThread='7', SessionID='A', Context='Operation') | attrs))


def db(end=5_000_000, duration=100, **attrs):
    return record('DBPOSTGRS', end, duration, **(dict(Usr='User', OSThread='7', SessionID='A', Sql='SELECT 1') | attrs))


class EventDetailTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='tj-detail-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs, self.output = self.root/'logs', self.root/'output'

    def write(self, text, relative='capture/rphost_1/26090310.log'):
        path = self.logs/relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode('utf-8'))
        return path

    def run_analyzer(self, *options, output=None):
        output = output or self.output
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(analyzer.run([str(self.logs), '-o', str(output), *map(str, options)]), 0)
        return json.loads((output/'analysis_metrics.json').read_text(encoding='utf-8'))

    @contextlib.contextmanager
    def connection(self, output=None):
        connection = sqlite3.connect((output or self.output)/'analysis.sqlite')
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    def decisions(self):
        with self.connection() as connection:
            return [dict(r) for r in connection.execute('SELECT e.raw_timestamp,e.duration_us,k.*,c.legacy_call_id FROM link_decisions k JOIN events e USING(event_id) LEFT JOIN call_events c ON c.event_id=k.parent_event_id ORDER BY e.byte_start')]

    def test_all_events_survive_top_ten_limit_and_sql_dictionary_deduplicates(self):
        self.write(call() + ''.join(db(Sql=f'SELECT field{i} FROM physical') for i in range(15)) +
                   db(Sql='SELECT field0 FROM physical') + db(Sql=None) + db(Sql=''))
        manifest = self.run_analyzer()
        self.assertEqual(manifest['schema_version'], '1.6')
        self.assertEqual(manifest['counts']['db_observations'], 18)
        self.assertEqual(manifest['operations'][0]['db_count'], 18)
        self.assertEqual(len(manifest['operations'][0]['top_nested_sql']), 10)
        with self.connection() as connection:
            self.assertEqual(connection.execute('SELECT count(*) FROM db_events').fetchone()[0], 18)
            self.assertEqual(connection.execute('SELECT count(*) FROM sql_texts').fetchone()[0], 15)
            self.assertEqual(connection.execute('SELECT count(*) FROM db_observations WHERE call_event_id IS NOT NULL').fetchone()[0], 18)
            self.assertEqual(connection.execute("SELECT count(*) FROM db_events WHERE sql_presence_state IN ('missing','empty')").fetchone()[0], 2)
            self.assertEqual(connection.execute("SELECT count(*) FROM events WHERE attributes_json LIKE '%SELECT%'").fetchone()[0], 0)
        with (self.output/'db_observations.csv').open(encoding='utf-8-sig', newline='') as stream:
            self.assertEqual(len(list(csv.DictReader(stream))), 18)
        self.assertEqual(verify(self.output)[1], 0)

    def test_nested_calls_boundaries_and_db_start_outside_call_keep_legacy_owner(self):
        self.write(call() + call(8_000_000, 2_000_000, Context='Inner') +
                   db(7_000_000) + db(8_000_000) + db(0, 0) + db(10_000_000) + db(10_000_001) + db(7_000_000, 9_000_000))
        manifest = self.run_analyzer()
        decisions = self.decisions()
        self.assertEqual([r['legacy_call_id'] for r in decisions], [1, 1, 1, 1, None, 1])
        self.assertEqual([r['status'] for r in decisions], ['ambiguous','ambiguous','linked_unique','linked_unique','unlinked','ambiguous'])
        self.assertTrue(all(r['linkage_rules_version'] == LINKAGE_RULES_VERSION for r in decisions))
        with self.connection() as connection:
            self.assertEqual(connection.execute('SELECT full_interval_contained FROM link_candidates WHERE event_id=? AND selected=1', (decisions[-1]['event_id'],)).fetchone()[0], 0)
        self.assertEqual(sum(r['db_count'] for r in manifest['operations']), 5)
        self.assertEqual(sum(r['db_duration_us'] for r in manifest['operations']), 9_000_300)

    def test_intersections_ties_and_session_preference(self):
        self.write(call(12_000_000, 10_000_000, SessionID='A') +
                   call(14_000_000, 10_000_000, SessionID='B', Context='Other') +
                   db(7_000_000, SessionID='B') + db(7_000_000, SessionID='C') + db(7_000_000, SessionID=None))
        self.run_analyzer()
        decisions = self.decisions()
        self.assertEqual([r['legacy_call_id'] for r in decisions], [2, 1, 1])
        self.assertEqual([r['status'] for r in decisions], ['linked_unique','ambiguous','ambiguous'])
        self.assertEqual([r['fallback_applied'] for r in decisions], [0, 1, 1])
        self.assertEqual([r['eligible_count'] for r in decisions], [1, 2, 2])

    def test_fallback_session_conflict_and_connect_id_diagnostic(self):
        self.write(call(**{'t:connectID': 'connection-A'}) + db(SessionID='B', **{'t:connectID': 'connection-B'}) + db(SessionID=None))
        self.run_analyzer()
        self.assertEqual([(r['status'],r['reason_code'],r['legacy_call_id']) for r in self.decisions()],
                         [('linked_by_rule','session_no_match',1), ('linked_by_rule','missing_session',1)])
        with self.connection() as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM link_candidates WHERE session_relation='conflict' AND connect_relation='conflict' AND selected=1").fetchone()[0], 1)

    def test_process_thread_user_scope_and_missing_identifiers(self):
        self.write(call() + db(OSThread='8') + db(OSThread=None) + db(Usr='Other') + db(Usr=None) +
                   call(9_000_000, 1_000_000, Usr=None) + db(8_500_000, Usr='   '))
        self.write(db(), 'capture/rphost_2/26090310.log')
        self.run_analyzer()
        decisions = self.decisions()
        self.assertEqual(sum(r['parent_event_id'] is not None for r in decisions), 1)
        self.assertIn('missing_thread', {r['reason_code'] for r in decisions})
        self.assertIn('missing_user_or_process', {r['reason_code'] for r in decisions})

    def test_unknown_timestamp_and_absent_sql_are_preserved(self):
        self.write(call() + db(Sql=None), 'capture/rphost_1/unknown.log')
        self.run_analyzer()
        self.assertEqual(self.decisions()[0]['reason_code'], 'missing_timestamp')
        with self.connection() as connection:
            row = connection.execute('SELECT * FROM db_observations').fetchone()
            self.assertIsNone(row['end_time_us'])
            self.assertEqual(row['raw_timestamp'], '00:05.000000')
            self.assertEqual(row['sql_presence_state'], 'missing')

    def test_link_across_midnight_keeps_db_and_call_measurements(self):
        self.write(db(3_599_500_000), 'capture/rphost_1/26090323.log')
        self.write(call(1_000_000, 2_000_000), 'capture/rphost_1/26090400.log')
        self.run_analyzer()
        with self.connection() as connection:
            row = connection.execute('SELECT o.measurement_id,e.measurement_id FROM db_observations o JOIN events e ON e.event_id=o.call_event_id').fetchone()
            self.assertEqual(tuple(row), ('capture@2026-09-03', 'capture@2026-09-04'))
        load_bundle(self.output)

    def test_full_context_counters_sql_and_source_bytes(self):
        sql = 'SELECT ' + "'Юникод, ''кавычки'' -- SQL'" + ' AS value\nFROM physical\n' + ' ' * 3000 + 'WHERE field=1'
        context = 'Контекст\n' + 'длинный контекст ' * 500
        raw = '\ufeff' + (call() + db(Sql=sql, Context=context, CpuTime='0', Memory='-1', MemoryPeak='', InBytes='bad', OutBytes=None, RowsAffected='20', Dbpid='123')).replace('\n', '\r\n')
        path = self.write(raw)
        original = path.read_bytes()
        self.run_analyzer()
        with self.connection() as connection:
            for row in connection.execute('SELECT * FROM events'):
                self.assertEqual(hashlib.sha256(original[row['byte_start']:row['byte_end']]).hexdigest(), row['raw_record_sha256'])
            row = connection.execute('SELECT * FROM db_observations').fetchone()
            self.assertEqual(row['context'], context.replace('\n', '\r\n'))
            self.assertEqual(row['dbpid'], '123')
            self.assertEqual(connection.execute('SELECT sql_text FROM sql_texts').fetchone()[0], sql.replace('\n', '\r\n'))
            counters = {r['field_name']: (r['state'], r['value_int']) for r in connection.execute('SELECT * FROM numeric_values WHERE event_id=?', (row['event_id'],))}
            self.assertEqual(counters, {'cpu_us':('valid',0), 'memory':('valid',-1), 'memory_peak':('empty',None),
                                        'in_bytes':('invalid',None), 'out_bytes':('missing',None), 'rows_affected':('valid',20)})

    def test_record_coordinates_for_cr_only_lines(self):
        path = self.write((call() + db()).replace('\n', '\r'))
        self.run_analyzer()
        with self.connection() as connection:
            rows = list(connection.execute('SELECT * FROM events ORDER BY byte_start'))
            self.assertEqual([(r['line_start'], r['line_end']) for r in rows], [(1,1),(2,2)])
            self.assertEqual(rows[-1]['byte_end'], len(path.read_bytes()))

    def test_event_ids_survive_append_added_file_and_root_relocation_with_map(self):
        path = self.write(call() + db())
        self.run_analyzer('--capture-id', 'stable-capture')
        with self.connection() as connection:
            original = {r[0] for r in connection.execute('SELECT event_id FROM events')}
        path.write_bytes(path.read_bytes() + db(6_000_000).encode())
        self.write(db(), 'earlier/rphost_1/26090309.log')
        second = self.root/'second'
        self.run_analyzer('--source-map', self.output/'source_map.json', output=second)
        with self.connection(second) as connection:
            self.assertTrue(original <= {r[0] for r in connection.execute('SELECT event_id FROM events')})
        self.logs.rename(self.root/'moved')
        self.logs = self.root/'moved'
        third = self.root/'third'
        self.run_analyzer('--source-map', second/'source_map.json', output=third)
        with self.connection(second) as a, self.connection(third) as b:
            self.assertEqual(list(a.execute('SELECT event_id FROM events ORDER BY event_id')), list(b.execute('SELECT event_id FROM events ORDER BY event_id')))

    def test_same_bytes_are_not_deduplicated_across_independent_logical_sources(self):
        self.write(call() + db())
        self.write(call() + db(), 'another/rphost_1/26090310.log')
        manifest = self.run_analyzer('--hash-sources')
        self.assertEqual(manifest['counts']['db_observations'], 2)
        self.assertEqual(manifest['counts']['sources_skipped_as_duplicates'], 0)

    def test_archive_and_loose_copy_merge_only_with_explicit_source_map(self):
        path = self.write(call() + db())
        with zipfile.ZipFile(self.logs/'copy.zip', 'w') as archive:
            archive.writestr('rphost_1/26090310.log', path.read_bytes())
        self.run_analyzer('--archive-mode', 'always')
        mapping = json.loads((self.output/'source_map.json').read_text())
        first = mapping['sources'][0]
        for entry in mapping['sources']:
            for key in ('origin_id','process_scope','logical_log_key'):
                entry[key] = first[key]
        map_path = self.root/'map.json'
        map_path.write_text(json.dumps(mapping), encoding='utf-8')
        out = self.root/'dedup'
        manifest = self.run_analyzer('--source-map', map_path, '--archive-mode', 'always', output=out)
        self.assertEqual(manifest['counts']['db_observations'], 1)
        self.assertEqual(manifest['counts']['sources_skipped_as_duplicates'], 1)
        with self.connection(out) as connection:
            self.assertEqual(connection.execute('SELECT count(*) FROM source_locations').fetchone()[0], 2)

    def test_duplicate_archive_member_names_are_addressed_by_ordinal(self):
        self.logs.mkdir()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(self.logs/'capture.zip','w') as archive:
                archive.writestr('rphost_1/26090310.log', db(Sql='SELECT one'))
                archive.writestr('rphost_1/26090310.log', db(Sql='SELECT two'))
        self.run_analyzer()
        with self.connection() as connection:
            self.assertEqual({r[0] for r in connection.execute('SELECT sql_text FROM sql_texts')}, {'SELECT one','SELECT two'})
            self.assertEqual({r[0] for r in connection.execute('SELECT member_ordinal FROM source_locations')}, {0,1})

    def test_gzip_coordinates_use_uncompressed_bytes(self):
        self.logs.mkdir()
        raw = (call() + ''.join(db(i*10000) for i in range(50))).encode()
        with gzip.open(self.logs/'26090310.log.gz','wb') as stream:
            stream.write(raw)
        self.run_analyzer()
        with self.connection() as connection:
            self.assertEqual(connection.execute('SELECT size_bytes FROM source_versions').fetchone()[0], len(raw))
            for row in connection.execute('SELECT * FROM events'):
                self.assertEqual(hashlib.sha256(raw[row['byte_start']:row['byte_end']]).hexdigest(), row['raw_record_sha256'])

    def test_primary_key_prevents_duplicate_db_contributions(self):
        self.write(call() + db())
        self.run_analyzer()
        with self.connection() as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute('INSERT INTO db_events SELECT * FROM db_events')

    def test_streaming_batches_do_not_drop_or_repeat_events(self):
        self.write(call() + ''.join(db(i) for i in range(1005)))
        manifest = self.run_analyzer()
        self.assertEqual(manifest['counts']['db_observations'], 1005)
        self.assertEqual(manifest['operations'][0]['db_count'], 1005)
        with self.connection() as connection:
            self.assertEqual(connection.execute('SELECT count(*) FROM link_candidates WHERE selected=1').fetchone()[0], 1005)
            self.assertEqual(connection.execute('SELECT count(*) FROM sql_texts').fetchone()[0], 1)

    def test_saved_bundle_works_without_sources_and_rejects_tampered_evidence(self):
        self.write(call() + db())
        manifest = self.run_analyzer()
        self.logs.rename(self.root/'offline')
        load_bundle(self.output)
        with self.connection() as connection:
            connection.execute('DELETE FROM link_candidates')
            connection.commit()
        path = self.output/'analysis.sqlite'
        manifest['artifacts']['analysis.sqlite']['sha256'] = file_hash(path)
        manifest['artifacts']['analysis.sqlite']['size_bytes'] = path.stat().st_size
        (self.output/'analysis_metrics.json').write_text(json.dumps(manifest), encoding='utf-8')
        with self.assertRaisesRegex(SliceError, 'candidate evidence'):
            load_bundle(self.output)

    def test_failed_validation_preserves_previously_published_bundle(self):
        self.write(call() + db())
        self.run_analyzer()
        before = {p.name: file_hash(p) for p in self.output.iterdir()}
        with patch('slice_input.load_bundle', side_effect=SliceError('injected validation failure')):
            with self.assertRaisesRegex(SliceError, 'injected'):
                self.run_analyzer('--overwrite')
        self.assertEqual(before, {p.name: file_hash(p) for p in self.output.iterdir()})

    def test_invalid_source_map_is_rejected_before_publication(self):
        self.write(call() + db())
        mapping = self.root/'invalid-map.json'
        mapping.write_text('{}', encoding='utf-8')
        with self.assertRaisesRegex(analyzer.AnalyzerError, 'source identity'):
            self.run_analyzer('--source-map', mapping)
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
