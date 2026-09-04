"""Saved-evidence mutations and small synthetic I/O failure scenarios."""
from __future__ import annotations

import contextlib
import csv
import gzip
import io
import json
from pathlib import Path
import sqlite3
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import analyze_1c_tj as analyzer
from event_store import EventStore
from numeric_quality import CounterStats, parse_counter
from slice_input import load_bundle, scalar
from slice_config import SliceError
from source_identity import file_hash
from verify_analysis import verify
from verify_analysis import read_csv as verifier_read_csv
from record_stream import RecordStream
from test_event_detail import call, db, record


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='tj-integrity-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.logs, self.output = self.root/'logs', self.root/'result'

    def write(self, text, relative='capture/nested/rphost_1/26090310.log'):
        path=self.logs/relative
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(text.encode() if isinstance(text,str) else text)
        return path

    def run_analyzer(self, *options, expected=0):
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(analyzer.run([str(self.logs),'-o',str(self.output),*options]),expected)
        self.console=json.loads(stdout.getvalue())
        self.manifest=json.loads((self.output/'analysis_metrics.json').read_text(encoding='utf-8'))
        return self.manifest

    def fixture(self):
        self.write(call(CpuTime=100) + ''.join(db(duration=i*100,RowsAffected=0 if i%2 else None) for i in range(1,31)) +
                   ''.join(record('TLOCK',5_000_000,duration=i*100,Usr='User',OSThread='7',SessionID='A',Context='Operation') for i in range(1,31)))
        self.run_analyzer()

    def save(self, table=None):
        if table:
            path=self.output/(table+'.csv')
            with path.open(encoding='utf-8-sig',newline='') as stream:
                fields=next(csv.reader(stream))
            with path.open('w',encoding='utf-8-sig',newline='') as stream:
                writer=csv.DictWriter(stream,fieldnames=fields)
                writer.writeheader()
                writer.writerows({k:scalar(row[k]) for k in fields} for row in self.manifest[table])
        for name, info in self.manifest['artifacts'].items():
            info.update(sha256=file_hash(self.output/name),size_bytes=(self.output/name).stat().st_size)
        (self.output/'analysis_metrics.json').write_text(json.dumps(self.manifest,ensure_ascii=False),encoding='utf-8')

    def mutate_db(self, sql):
        with contextlib.closing(sqlite3.connect(self.output/'analysis.sqlite')) as connection:
            connection.executescript(sql)
        self.save()

    def test_sql_percentile_is_checked_even_when_monotonic_and_mirrors_agree(self):
        self.fixture()
        self.manifest['heavy_sql'][0]['p95_us']+=1
        self.save('heavy_sql')
        with self.assertRaisesRegex(SliceError,'SQL.*p95_us'):
            load_bundle(self.output)
        self.assertEqual(verify(self.output)[1],2)

    def test_dataset_median_is_recomputed_from_events(self):
        self.fixture()
        self.manifest['datasets'][0]['event_stats']['DBPOSTGRS']['median_us']+=1
        self.save('datasets')
        with self.assertRaisesRegex(SliceError,'dataset.DBPOSTGRS.*median_us'):
            load_bundle(self.output)

    def test_lock_percentile_is_recomputed_from_events(self):
        self.fixture()
        self.manifest['locks'][0]['p99_us']-=1
        self.save('locks')
        with self.assertRaisesRegex(SliceError,'lock.*p99_us'):
            load_bundle(self.output)

    def test_counter_coverage_cannot_be_forged_as_internally_consistent_summary(self):
        self.fixture()
        stats=CounterStats()
        for _ in range(30): stats.add(parse_counter('rows_affected','0'))
        self.manifest['heavy_sql'][0]['numeric_quality']['rows_affected']=stats.as_dict()
        self.save('heavy_sql')
        with self.assertRaisesRegex(SliceError,'SQL.*numeric_quality'):
            load_bundle(self.output)

    def test_missing_sql_normalization_cannot_drop_events_from_join(self):
        self.fixture()
        self.mutate_db('DELETE FROM sql_normalizations')
        with self.assertRaisesRegex(SliceError,'no normalization'):
            load_bundle(self.output)

    def test_dictionary_reference_must_exist(self):
        self.fixture()
        self.mutate_db('DELETE FROM sql_texts')
        with self.assertRaises(SliceError):
            load_bundle(self.output)

    def test_unreferenced_dictionary_pattern_is_rejected(self):
        self.fixture()
        self.mutate_db("INSERT INTO sql_patterns SELECT 'unused',normalization_version,normalized_sql,'unused',normalization_status FROM sql_patterns LIMIT 1")
        with self.assertRaisesRegex(SliceError,'unreferenced SQL pattern'):
            load_bundle(self.output)

    def test_specialized_db_population_cannot_be_removed(self):
        self.fixture()
        self.mutate_db('DELETE FROM link_candidates; DELETE FROM link_decisions; DELETE FROM db_events')
        with self.assertRaisesRegex(SliceError,'missing specialized event'):
            load_bundle(self.output)

    def test_duplicate_saved_event_id_is_rejected(self):
        self.fixture()
        # Remove declared constraints deliberately: verifier must check identities.
        self.mutate_db('PRAGMA legacy_alter_table=ON; CREATE TABLE duplicate_events AS SELECT * FROM events; INSERT INTO duplicate_events SELECT * FROM events LIMIT 1; DROP TABLE events; ALTER TABLE duplicate_events RENAME TO events;')
        with self.assertRaisesRegex(SliceError,'duplicate/null identity: events'):
            load_bundle(self.output)

    def test_broken_call_parent_is_rejected(self):
        self.fixture()
        self.mutate_db("UPDATE link_decisions SET parent_event_id='missing'")
        with self.assertRaises(SliceError):
            load_bundle(self.output)

    def test_nested_sql_preview_cannot_double_count(self):
        self.fixture()
        self.manifest['operations'][0]['top_nested_sql'][0]['duration_us']*=2
        self.save()
        with self.assertRaisesRegex(SliceError,'nested SQL counted'):
            load_bundle(self.output)

    def test_pooled_percentiles_are_not_averages_of_subgroup_percentiles(self):
        self.write(call(duration=1)+call(duration=100)+db(duration=1)+db(duration=100),'series/a/rphost_1/26090310.log')
        self.write((call(duration=1)+db(duration=1))*198,'series/b/rphost_1/26090310.log')
        self.write(call(duration=1),'series/c/rphost_1/26090410.log')
        self.run_analyzer()
        self.assertEqual(self.manifest['heavy_sql'][0]['p95_us'],1)
        first=self.manifest['identical_operations'][0]
        self.assertEqual(first['count'],200)
        self.assertEqual(first['p95_us'],1)
        first['p95_us']=2  # close to a weighted average of the two subgroup p95s
        self.save('identical_operations')
        with self.assertRaisesRegex(SliceError,'identical operation.*p95_us'):
            load_bundle(self.output)

    def test_inspection_read_failure_is_persisted(self):
        self.write(call())
        for failure in (OSError('inspection read failed'), RuntimeError('ZIP password required')):
            with self.subTest(error=type(failure).__name__):
                with patch.object(analyzer.SourceRef,'open_binary',side_effect=failure):
                    self.run_analyzer('--overwrite',expected=4)
                result,code=verify(self.output)
                self.assertEqual(code,0)
                self.assertFalse(result['completeness']['source_processing_complete'])
                self.assertEqual(result['completeness']['parse_issue_counts']['inspection_read_error'],1)

    def test_verifier_contract_contains_only_declared_fields(self):
        self.write(call())
        self.run_analyzer()
        result,code=verify(self.output)
        self.assertEqual(code,0)
        self.assertEqual(result['verifier_version'],'1.2.0')
        self.assertEqual(set(result), {
            'analysis_complete', 'analysis_dir', 'analyzer_version', 'checks',
            'completeness', 'observation_state', 'output_sha256',
            'percentile_validation', 'schema_version', 'status',
            'verification_scope', 'verifier_version',
        })
        self.assertEqual(set(result['checks']), {
            'auxiliary_links_and_no_double_count',
            'auxiliary_table_keys_and_sql_fingerprints',
            'counter_coverage_reconciled_with_events',
            'csv_json_mirrors_and_counts',
            'dataset_event_distributions', 'dataset_event_totals',
            'error_events_distinct_calls_and_versioned_incident_hypotheses',
            'exact_event_sql_lock_percentiles',
            'explicit_unique_ids_and_references',
            'full_db_events_dictionary_link_decisions_candidates_and_accounting',
            'heavy_sql_percentiles_and_thresholds',
            'identical_operations_from_individual_calls',
            'linkage_counts_times_and_percentages',
            'locks_percentiles_and_thresholds',
            'nested_sql_preview_reconciled_with_db_events',
            'numeric_states_coverage_available_denominators_and_paired_cpu',
            'operation_membership_sums_and_percentiles',
            'operations_percentiles_and_thresholds', 'required_output_files',
            'schema_and_required_fields', 'source_metadata_without_source_access',
            'source_positions_and_completeness',
            'sql_dictionary_complete_and_referenced',
            'unique_calls_and_exact_top_subset',
        })

    def test_ingestion_failure_keeps_only_completed_records_and_marks_prefix(self):
        raw=call()+db()+record('TLOCK',5_000_000,Usr='User',OSThread='7',SessionID='A')
        self.write(raw)
        original=analyzer.SourceRef.open_binary
        opened=0
        class FailingReader(io.BytesIO):
            def read(self,size=-1):
                if self.tell(): raise OSError('ingestion read failed')
                return super().read(size)
        @contextlib.contextmanager
        def open_source(source):
            nonlocal opened
            opened+=1
            if opened==2:
                with FailingReader(raw.encode()) as stream: yield stream
            else:
                with original(source) as stream: yield stream
        with patch.object(analyzer.SourceRef,'open_binary',open_source):
            self.run_analyzer()
        self.assertEqual(opened,2)
        self.assertEqual(self.console['status'],'partial')
        self.assertEqual(self.manifest['files'][0]['analyzed_bytes'],len((call()+db()).encode()))
        self.assertEqual(self.manifest['datasets'][0]['bytes_analyzed'],self.manifest['files'][0]['analyzed_bytes'])
        self.assertEqual(self.manifest['operations'][0]['db_count'],1)
        self.assertEqual(self.manifest['operations'][0]['lock_count'],0)
        result,code=verify(self.output)
        self.assertEqual(code,0)
        self.assertEqual(result['observation_state'],'partial')
        self.assertEqual(result['completeness']['parse_issue_counts']['ingestion_read_error'],1)

    def test_aggregation_never_reopens_source_after_ingestion(self):
        path=self.write(call()+db()+record('TLOCK',5_000_000,Usr='User',OSThread='7',SessionID='A'))
        original=EventStore.link_db
        def offline(store):
            path.rename(path.with_suffix('.offline'))
            return original(store)
        with patch.object(EventStore,'link_db',offline):
            self.run_analyzer()
        self.assertEqual(self.manifest['operations'][0]['lock_count'],1)
        self.assertEqual(verify(self.output)[1],0)

    def test_saved_store_read_failure_aborts_publication_with_phase(self):
        self.fixture()
        before={p.name:file_hash(p) for p in self.output.iterdir()}
        with patch.object(analyzer,'analyze_pass_two',side_effect=sqlite3.DatabaseError('injected read failure')):
            with self.assertRaisesRegex(analyzer.AnalyzerError,'stored_event_aggregation failed'):
                self.run_analyzer('--overwrite')
        self.assertEqual(before,{p.name:file_hash(p) for p in self.output.iterdir()})

    def test_discovery_permission_failure_is_not_silent(self):
        # Windows temp paths can use a short name or a junction. The analyzer
        # resolves its input root before walking, so use the same identity here.
        path=self.write(call()).resolve()
        logs=self.logs.resolve()
        original=analyzer.os.walk
        def walk(root,**kwargs):
            if Path(root)==logs:
                kwargs['onerror'](PermissionError(13,'denied',str(root/'blocked')))
                yield str(path.parent),[],[path.name]
            else:
                yield from original(root,**kwargs)
        with patch.object(analyzer.os,'walk',walk):
            self.run_analyzer()
        self.assertFalse(self.manifest['analysis_complete'])
        self.assertEqual(verify(self.output)[0]['completeness']['warning_counts']['discovery_error'],1)

    def test_empty_bom_empty_gzip_and_small_corruption_have_distinct_diagnostics(self):
        self.write(call())
        self.write(b'','empty.log')
        self.write(b'\xef\xbb\xbf','bom.log')
        self.write(b'bad','bad.log')
        self.write(gzip.compress(b''),'empty.log.gz')
        self.write(b'not a zip','bad.zip')
        self.run_analyzer()
        files={Path(r['resolved_source']).name:r for r in self.manifest['files']}
        self.assertEqual(files['bad.log']['reason'],'no technological-journal header in first 256 KiB')
        self.assertEqual(files['empty.log.gz']['reason'],'empty file')
        self.assertEqual(files['bom.log']['reason'],'empty/BOM marker file')
        self.assertFalse(self.manifest['analysis_complete'])
        self.assertEqual(verify(self.output)[1],0)

    def test_invalid_calendar_and_replacement_utf8_are_reported(self):
        self.write(call()+db(),'capture/rphost_1/26133299.log')
        self.write((call()+db()).encode().replace(b'User',b'U\xffer'),'other/rphost_2/26090310.log')
        self.run_analyzer()
        self.assertFalse(self.manifest['absolute_timestamps_complete'])
        self.assertFalse(self.manifest['analysis_complete'])
        result,code=verify(self.output)
        self.assertEqual(code,0)
        self.assertEqual(result['completeness']['events_without_absolute_timestamp'],2)
        self.assertEqual(result['completeness']['parse_issue_counts']['invalid_utf8'],2)

    def test_tar_members_and_complete_bundle_are_repeatable_byte_for_byte(self):
        self.logs.mkdir()
        with tarfile.open(self.logs/'capture.tgz','w:gz') as archive:
            for name,text in [('nested/rphost_1/26090310.log',call()+db()),('empty.log','')]:
                data=text.encode(); info=tarfile.TarInfo(name);info.size=len(data)
                archive.addfile(info,io.BytesIO(data))
        self.run_analyzer('--archive-mode','always')
        before={p.name:file_hash(p) for p in self.output.iterdir()}
        self.run_analyzer('--archive-mode','always','--overwrite')
        self.assertEqual(len(before),21)
        self.assertEqual(before,{p.name:file_hash(p) for p in self.output.iterdir()})
        self.assertEqual(verify(self.output)[1],0)

    def test_discovery_rejects_file_symlink_before_read(self):
        outside = self.root/'outside.log'
        outside.write_text(call(), encoding='utf-8')
        link = self.logs/'capture'/'rphost_1'/'26090310.log'
        link.parent.mkdir(parents=True)
        try:
            link.symlink_to(outside)
        except OSError:
            self.skipTest('Host does not permit symlinks')
        self.run_analyzer(expected=4)
        self.assertEqual(self.manifest['counts']['sources_discovered'], 0)
        self.assertEqual(self.manifest['warnings'][0]['type'], 'symlink_skipped')

    def test_open_rechecks_link_components_before_read(self):
        path = self.write(call())
        source = analyzer.SourceRef('loose', path, size=path.stat().st_size, input_root=self.logs)
        original = analyzer.is_link_or_reparse
        with patch.object(analyzer, 'is_link_or_reparse', side_effect=lambda candidate: candidate == path or original(candidate)), \
             patch.object(Path, 'open', side_effect=AssertionError('source bytes must not be opened')):
            with self.assertRaisesRegex(OSError, 'link/reparse point'):
                with source.open_binary():
                    pass

    def test_archive_member_count_limit_is_diagnostic(self):
        self.logs.mkdir()
        with zipfile.ZipFile(self.logs/'capture.zip', 'w') as archive:
            archive.writestr('a.log', call())
            archive.writestr('b.log', call())
        with patch.object(analyzer, 'MAX_ARCHIVE_MEMBERS', 1):
            self.run_analyzer('--archive-mode', 'always', expected=4)
        self.assertTrue(any(w['type'] == 'archive_error' and 'more than 1 members' in w['message']
                            for w in self.manifest['warnings']))

    def test_tar_member_count_limit_is_checked_while_enumerating(self):
        self.logs.mkdir()
        with tarfile.open(self.logs/'capture.tar', 'w') as archive:
            for name in ('a.log', 'b.log'):
                data = call().encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        with patch.object(analyzer, 'MAX_ARCHIVE_MEMBERS', 1):
            self.run_analyzer('--archive-mode', 'always', expected=4)
        self.assertTrue(any(w['type'] == 'archive_error' and 'more than 1 members' in w['message']
                            for w in self.manifest['warnings']))

    def test_tar_link_member_is_rejected_again_at_open(self):
        self.logs.mkdir()
        path = self.logs/'capture.tar'
        with tarfile.open(path, 'w') as archive:
            info = tarfile.TarInfo('linked.log')
            info.type = tarfile.SYMTYPE
            info.linkname = 'outside.log'
            archive.addfile(info)
        source = analyzer.SourceRef('tar', path, 'linked.log', member_ordinal=0)
        with self.assertRaisesRegex(OSError, 'type or size is not allowed'):
            with source.open_binary() as stream:
                stream.read()

    def test_record_stream_rejects_oversized_record_without_truncation(self):
        path = self.write(call(Context='x'*300))
        source = analyzer.SourceRef('loose', path, size=path.stat().st_size)
        with self.assertRaisesRegex(RuntimeError, 'TJ (?:line|record) exceeds 128 byte limit'):
            list(RecordStream(source, max_record_bytes=128))

    def test_verifier_csv_uses_shared_public_field_limit_and_restores_it(self):
        path = self.root/'large.csv'
        value = 'x'*200_000
        path.write_text('field\n'+value+'\n', encoding='utf-8')
        previous = csv.field_size_limit()
        self.assertEqual(verifier_read_csv(path)[0]['field'], value)
        self.assertEqual(csv.field_size_limit(), previous)
        path.write_text('a,a\n1,2\n', encoding='utf-8')
        with self.assertRaisesRegex(Exception, 'duplicate columns'):
            verifier_read_csv(path)
        self.assertEqual(csv.field_size_limit(), previous)


if __name__=='__main__':
    unittest.main()
