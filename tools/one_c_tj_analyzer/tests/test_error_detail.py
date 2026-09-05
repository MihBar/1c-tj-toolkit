"""Synthetic error populations: observations, distinct CALLs and hypotheses."""
from __future__ import annotations

import contextlib
import csv
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import analyze_1c_tj as analyzer
from error_rules import INCIDENT_RULES_VERSION, ERROR_LINKAGE_VERSION, WRAPPERS
from event_store import LEGACY_DETAIL_FILES, LEGACY_VERSIONS
from slice_input import load_bundle, HEADERS
from slice_config import SliceError
from source_identity import file_hash
from test_event_detail import call, db, record


def error(end=5_000_000, event='EXCP', **attrs):
    return record(event, end, **(dict(Usr='User', OSThread='7', SessionID='A', Context='Operation', Descr='Failure 123') | attrs))


class ErrorDetailTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='tj-error-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs, self.output = self.root/'logs', self.root/'output'

    def write(self, text, relative='capture/rphost_1/26090310.log'):
        path = self.logs/relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode('utf-8'))
        return path

    def run_analyzer(self, *options):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(analyzer.run([str(self.logs), '-o', str(self.output), *options]), 0)
        return json.loads((self.output/'analysis_metrics.json').read_text(encoding='utf-8'))

    @contextlib.contextmanager
    def connection(self):
        connection = sqlite3.connect(self.output/'analysis.sqlite')
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    def rows(self, table='error_observations'):
        with self.connection() as connection:
            return [dict(r) for r in connection.execute('SELECT * FROM '+table)]

    def assert_counts(self, manifest, events, calls, incidents):
        summary = manifest['error_summary']
        self.assertEqual((summary['event_count'], summary['affected_call_count'], summary['suspected_incident_count']), (events, calls, incidents))
        self.assertEqual(summary['event_count'], summary['linked_error_event_count'] + summary['unlinked_error_event_count'])

    def rewrite_manifest(self, manifest):
        for filename, info in manifest['artifacts'].items():
            info.update(sha256=file_hash(self.output/filename), size_bytes=(self.output/filename).stat().st_size)
        (self.output/'analysis_metrics.json').write_text(json.dumps(manifest, ensure_ascii=False), encoding='utf-8')

    def test_repeats_and_wrappers_one_call_three_events_one_hypothesis(self):
        self.write(call() + error(1_000_000) + error(8_000_000) +
                   error(9_000_000, event='QERR', Descr=WRAPPERS[0]+WRAPPERS[2]+'Failure 123'))
        manifest = self.run_analyzer()
        self.assert_counts(manifest, 3, 1, 1)
        self.assertEqual(manifest['operations'][0]['error_count'], 3)
        self.assertEqual(manifest['schema_version'], '1.6')
        self.assertTrue(all('linked_call_count' not in r and 'incident_count' not in r for r in manifest['errors']))
        self.assertEqual(sum(r['suspected_incident_count'] for r in manifest['errors']), 2)  # non-additive distinct counts
        members = self.rows('error_incident_members')
        self.assertEqual(len({r['incident_id'] for r in members}), 1)
        evidence = [json.loads(r['evidence_json']) for r in members]
        self.assertEqual(sum(len(e['stripped_wrappers']) for e in evidence), 2)
        self.assertTrue(all(not e['time_proximity_used'] and not e['common_root_cause_proven'] for e in evidence))

    def test_same_signature_different_full_payloads_stay_separate(self):
        self.write(call() + error(Descr='Failure 123') + error(Descr='Failure 456'))
        manifest = self.run_analyzer()
        self.assert_counts(manifest, 2, 1, 2)
        self.assertEqual(len(manifest['errors']), 1)
        group = manifest['errors'][0]
        self.assertEqual((group['linked_error_event_count'], group['affected_call_count']), (2, 1))

    def test_identical_errors_in_adjacent_calls_never_merge(self):
        self.write(call(5_000_000, 5_000_000) + call(10_000_000, 5_000_000) + error(4_900_000) + error(5_100_000))
        manifest = self.run_analyzer()
        self.assert_counts(manifest, 2, 2, 2)
        self.assertEqual(manifest['errors'][0]['affected_call_count'], 2)

    def test_sessions_and_threads_are_independent(self):
        self.write(call() + call(SessionID='B') + call(OSThread='8') +
                   error() + error(SessionID='B') + error(OSThread='8'))
        self.assert_counts(self.run_analyzer(), 3, 3, 3)

    def test_unlinked_missing_timestamp_and_missing_message_are_preserved(self):
        self.write(error() + error() + error(Descr=None) + error(Descr=''), 'capture/rphost_1/unknown.log')
        manifest = self.run_analyzer()
        self.assert_counts(manifest, 4, 0, 4)
        rows = self.rows()
        self.assertTrue(all(r['linkage_reason'] == 'missing_timestamp' for r in rows))
        self.assertEqual({r['message_state'] for r in rows}, {'present', 'missing', 'empty'})
        self.assertEqual(manifest['error_summary']['unlinked_error_event_count'], 4)

    def test_nested_ambiguous_links_keep_legacy_owner_but_do_not_merge(self):
        self.write(call() + call(8_000_000, 2_000_000, Context='Inner') + error(7_000_000) + error(7_000_001))
        manifest = self.run_analyzer()
        self.assert_counts(manifest, 2, 1, 2)
        rows = self.rows()
        self.assertTrue(all(r['call_id'] == 1 and r['linkage_status'] == 'ambiguous' and r['incident_reason'] == 'singleton_ambiguous' for r in rows))
        self.assertTrue(all(r['linkage_rules_version'] == ERROR_LINKAGE_VERSION for r in rows))
        self.assertEqual(sum(r['error_count'] for r in manifest['operations']), 2)

    def test_missing_identity_and_session_fallback_are_singletons(self):
        self.write(call() + error(SessionID=None) + error(SessionID=None) + error(OSThread=None) + error(Context=''))
        manifest = self.run_analyzer()
        self.assert_counts(manifest, 4, 1, 4)
        self.assertEqual(manifest['error_summary']['fallback_linked_error_event_count'], 2)
        self.assertEqual(manifest['error_summary']['unlinked_error_event_count'], 1)

    def test_connect_conflict_blocks_grouping_without_changing_call_choice(self):
        self.write(call(**{'t:connectID':'A'}) + error(**{'t:connectID':'B'}) + error(**{'t:connectID':'B'}))
        self.assert_counts(self.run_analyzer(), 2, 1, 2)
        self.assertTrue(all(r['incident_reason'] == 'singleton_connect_conflict' for r in self.rows()))

    def test_full_context_and_unknown_or_embedded_wrappers_are_not_erased(self):
        self.write(call() + error() + error(Context='Operation\nDifferent frame') +
                   error(Descr='Unknown wrapper:\nFailure 123') + error(Descr='Quoted '+WRAPPERS[2]+'Failure 123'))
        self.assert_counts(self.run_analyzer(), 4, 1, 4)

    def test_full_message_tail_and_provenance_survive_export(self):
        prefix = 'Длинное сообщение ' * 400
        path = self.write(call() + error(Descr=prefix+'alpha') + error(Descr=prefix+'beta') +
                          error(Descr=None, Sql='SELECT 1'))
        manifest = self.run_analyzer()
        self.assert_counts(manifest, 3, 1, 3)
        rows = self.rows()
        self.assertEqual(len({r['signature_id'] for r in rows}), 3)
        raw = path.read_bytes()
        for row in rows:
            import hashlib
            self.assertEqual(hashlib.sha256(raw[row['byte_start']:row['byte_end']]).hexdigest(), row['raw_record_sha256'])
        self.assertEqual({r['raw_message'] for r in rows}, {prefix+'alpha', prefix+'beta', None})
        self.assertEqual(sum(r['sql_text_id'] is not None for r in rows), 1)
        self.assertEqual(manifest['counts']['db_observations'], 0)
        with (self.output/'error_observations.csv').open(encoding='utf-8-sig', newline='') as stream:
            self.assertEqual(len(list(csv.DictReader(stream))), 3)

    def test_boundaries_and_cross_midnight_use_error_measurement(self):
        self.write(error(3_599_000_000) + error(3_599_999_999), 'capture/rphost_1/26090323.log')
        self.write(call(1_000_000, 2_000_000) + error(1_000_000) + error(1_000_001), 'capture/rphost_1/26090400.log')
        manifest = self.run_analyzer()
        self.assert_counts(manifest, 4, 1, 2)
        self.assertEqual(manifest['error_summary']['linked_error_event_count'], 3)
        self.assertEqual(sum(r['error_count'] for r in manifest['operations']), 3)

    def test_cancel_text_does_not_identify_initiator_or_root_cause(self):
        self.write(call() + error(Descr='canceling statement due to user request'))
        manifest = self.run_analyzer()
        self.assertEqual(manifest['errors'][0]['category'], 'statement_cancelled')
        incident = self.rows('error_incidents')[0]
        self.assertEqual(incident['hypothesis_status'], 'unconfirmed')
        self.assertIsNone(incident['root_cause'])
        self.assertIsNone(incident['cancellation_initiator'])

    def test_batch_boundary_keeps_each_event_once_and_ids_stable(self):
        self.write(call() + ''.join(error(1_000_000+i) for i in range(1005)))
        self.assert_counts(self.run_analyzer(), 1005, 1, 1)
        before = {(r['event_id'], r['incident_id']) for r in self.rows()}
        self.run_analyzer('--overwrite')
        self.assertEqual(before, {(r['event_id'], r['incident_id']) for r in self.rows()})

    def test_tampered_evidence_rejected_after_hash_refresh_without_source_reads(self):
        self.write(call() + error() + error())
        manifest = self.run_analyzer()
        self.logs.rename(self.root/'offline-logs')
        load_bundle(self.output)
        with self.connection() as connection:
            connection.execute("UPDATE error_incident_members SET evidence_json='{}'")
            connection.commit()
        self.rewrite_manifest(manifest)
        with self.assertRaisesRegex(SliceError, 'membership/evidence'):
            load_bundle(self.output)

    def test_unknown_incident_version_is_rejected(self):
        self.write(call() + error())
        manifest = self.run_analyzer()
        manifest['incident_rules_version'] = INCIDENT_RULES_VERSION+'/unknown'
        self.rewrite_manifest(manifest)
        with self.assertRaisesRegex(SliceError, 'version'):
            load_bundle(self.output)

    def test_legacy_counter_names_cannot_be_added_to_new_error_export(self):
        self.write(call() + error())
        self.run_analyzer()
        path = self.output/'errors.csv'
        with path.open(encoding='utf-8-sig', newline='') as stream:
            reader = csv.DictReader(stream)
            fields, rows = reader.fieldnames, list(reader)
        with path.open('w', encoding='utf-8-sig', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields+['linked_call_count'])
            writer.writeheader()
            writer.writerows(rows)
        with self.assertRaisesRegex(SliceError, 'Legacy error counters'):
            load_bundle(self.output)

    def test_schema_15_saved_bundle_still_loads_with_legacy_error_headers(self):
        self.write(call() + db())
        manifest = self.run_analyzer()
        with self.connection() as connection:
            for name in ('error_incidents', 'error_observations'):
                connection.execute('DROP VIEW '+name)
            for name in ('error_incident_members', 'suspected_incidents', 'error_link_candidates', 'error_link_decisions', 'error_events'):
                connection.execute('DROP TABLE '+name)
            connection.execute('PRAGMA user_version=1')
            connection.execute("DELETE FROM metadata WHERE key LIKE 'error_%' OR key LIKE 'incident_%'")
            connection.execute("UPDATE metadata SET value='\"1.0\"' WHERE key='storage_schema_version'")
            connection.commit()
        for key in list(manifest):
            if key.startswith(('error_', 'incident_')):
                manifest.pop(key)
        manifest.update(LEGACY_VERSIONS, schema_version='1.5', analyzer_version='1.5.0', event_detail_scope=['CALL','DBPOSTGRS'])
        manifest.pop('verification', None)  # Not present in the legacy writer.
        manifest['artifacts'] = {k:v for k,v in manifest['artifacts'].items() if k in LEGACY_DETAIL_FILES}
        with (self.output/'errors.csv').open('w', encoding='utf-8-sig', newline='') as stream:
            csv.writer(stream).writerow(HEADERS['errors'])
        self.rewrite_manifest(manifest)
        self.assertEqual(load_bundle(self.output).manifest['schema_version'], '1.5')
        manifest['incident_rules_version'] = INCIDENT_RULES_VERSION
        self.rewrite_manifest(manifest)
        with self.assertRaisesRegex(SliceError, 'Legacy schema'):
            load_bundle(self.output)


if __name__ == '__main__':
    unittest.main()
