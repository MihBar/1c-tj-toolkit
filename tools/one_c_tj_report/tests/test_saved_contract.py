"""Regressions against frozen outputs of analyzer 1.6.1 / slices 1.8.0.

No analyzer, calculator, raw journal or network is used to run these tests.
"""
import csv
import json
from decimal import Decimal
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_report import REPORT_DIR, config_fixture, write_json, write_csv, fixture
from report_config import load_config
from report_input import load_input, descriptor, parse_value
from report_model import build_model, format_cell, DisplayState, stable_key
from report_schema import canonical, digest, ReportError
from report_layout import render_pdf

FIXTURE = Path(__file__).parent/'fixtures/current'


def values(row):
    return {cell.field:cell.value for cell in row.cells}


class SavedContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        shutil.copytree(FIXTURE,self.root/'saved')
        self.analysis = self.root/'saved/analysis'
        self.slices = self.root/'saved/slices'
        (self.analysis/'analysis.sqlite.bin').rename(self.analysis/'analysis.sqlite')
        self.data = load_input(self.analysis,self.slices)
        self.mids = sorted(self.data.measurement_ids)

    def model(self, sections, **options):
        config = config_fixture(self.root,sections=['provenance',*sections],**options)
        return build_model(self.data,config),config

    def mutate_slice(self,name,change):
        path = self.slices/(name+'.csv')
        with path.open(encoding='utf-8-sig',newline='') as f:
            reader = csv.DictReader(f)
            columns,rows = reader.fieldnames,list(reader)
        change(rows)
        write_csv(path,columns,rows)
        manifest = json.loads((self.slices/'slice_manifest.json').read_text(encoding='utf-8'))
        manifest['outputs'][path.name].update(descriptor(path),row_count=len(rows))
        write_json(self.slices/'slice_manifest.json',manifest)

    def test_saved_fixture_and_example_do_not_embed_machine_paths(self):
        forbidden = (
            ("C:" + "\\Projects\\").encode(),
            ("C:" + "\\Users\\").encode(),
            b"/" + b"home" + b"/",
            b"/" + b"Users" + b"/",
        )
        paths = [REPORT_DIR/'examples/README.md']
        paths.extend(path for path in FIXTURE.rglob('*') if path.is_file())
        for path in paths:
            content = path.read_bytes()
            for marker in forbidden:
                with self.subTest(path=path.relative_to(REPORT_DIR), marker=marker):
                    self.assertNotIn(marker, content)

    def test_all_current_slices_and_scalar_comparability(self):
        self.assertEqual(len(self.data.slices),26)
        self.assertTrue(self.data.slices['problem_history'])
        self.assertEqual({r['first_reference_comparability'] for r in self.data.slices['problem_history']}, {'not_comparable','exact_keys_only_uncontrolled'})
        model,_ = self.model(['problem_history','problem_views','db_chatty','apdex_changes','apdex'])
        self.assertTrue(all(s.tables for s in model.sections))

    def test_apdex_not_microseconds_and_problem_native_units(self):
        model,config = self.model(['apdex_overall','problem_history'])
        composition = next(t for t in model.sections[1].tables if t.name == 'apdex_composition' and t.rows)
        score = next(c for c in composition.rows[0].cells if c.field == 'operation_user_measurement_apdex')
        self.assertEqual(score.unit,'')
        self.assertEqual(Decimal(format_cell(score,config).replace(',','.')),score.value)
        problem = next(t for t in model.sections[2].tables if t.name == 'problem_history')
        duration = next(r for r in problem.rows if values(r)['metric'] == 'operation.avg_us')
        threshold = next(c for c in duration.cells if c.field == 'threshold')
        self.assertEqual(format_cell(threshold,config),'5 с')
        deficit = next(r for r in problem.rows if values(r)['metric'] == 'apdex.deficit')
        self.assertEqual(next(c.unit for c in deficit.cells if c.field == 'source_metric_value'),'APDEX')
        self.assertEqual(next(c.unit for c in deficit.cells if c.field == 'value'),'1 − APDEX')

    def test_overall_keeps_complete_composition_and_matching_coverage(self):
        model,_ = self.model(['apdex_overall'],display_measurement_ids=[self.mids[0]],tables={'apdex_overall':{'top_n':1}})
        tables = model.sections[1].tables
        parent = values(tables[0].rows[0])
        self.assertEqual(parent['measurement_ids'],[self.mids[0]])
        self.assertEqual(len(tables[1].rows),parent['composition_row_count'])
        for row in tables[1].rows:
            member = values(row)
            self.assertEqual(member['overall_id'],parent['overall_id'])
            self.assertEqual(member['overall_apdex_denominator'],parent['apdex_denominator'])
        coverage = values(tables[2].rows[0])
        self.assertEqual(coverage['measurement_ids'],parent['measurement_ids'])
        self.assertEqual(coverage['population_scope'],parent['population_scope'])
        self.assertEqual(coverage['call_share_denominator'],parent['call_share_denominator'])

    def test_dependent_tables_cannot_have_independent_top_n(self):
        for name in ('comparability','apdex_composition','apdex_coverage','problem_rule_coverage'):
            with self.subTest(table=name), self.assertRaisesRegex(ReportError,'dependent context'):
                config_fixture(self.root,tables={name:{'top_n':1}})

    def test_comparison_context_and_external_base_retained(self):
        model,_ = self.model(['comparisons'],report_kind='comparison',display_measurement_ids=[self.mids[-1]],tables={'measurement_comparisons':{'top_n':1}})
        tables = model.sections[1].tables
        comparison,context = values(tables[0].rows[0]),values(tables[1].rows[0])
        original = next(r for r in self.data.slices['measurement_comparisons'] if r['comparison_id'] == comparison['comparison_id'])
        self.assertEqual(comparison,original)
        self.assertEqual(comparison['comparison_id'],context['comparison_id'])
        self.assertNotEqual(comparison['reference_measurement_id'],comparison['current_measurement_id'])
        self.assertEqual(context['unknown_parameters'],next(r['unknown_parameters'] for r in self.data.slices['comparability'] if r['comparison_id'] == comparison['comparison_id']))

    def test_top_n_history_selects_whole_trajectory_in_saved_order(self):
        model,_ = self.model(['operations','problem_history'],report_kind='history',tables={'operation_history':{'sort':[{'field':'avg_us','direction':'desc'}],'top_n':1},'problem_history':{'top_n':1}})
        for section,key,name in [(model.sections[1],'cohort_id','operation_history'),(model.sections[2],'problem_id','problem_history')]:
            table = next(t for t in section.tables if t.name == name)
            identity = values(table.rows[0])[key]
            expected = [r['measurement_id'] for r in self.data.slices[name] if r[key] == identity]
            self.assertEqual([values(r)['measurement_id'] for r in table.rows],expected)
            self.assertEqual(len(table.rows),3)

    def test_latest_problem_snapshot_not_rebased_to_display_window(self):
        model,_ = self.model(['problems'],report_kind='history',display_measurement_ids=[self.mids[0]])
        table = model.sections[1].tables[0]
        self.assertEqual(len(table.rows),len(self.data.slices['problem_registry']))
        self.assertEqual({values(r)['measurement_id'] for r in table.rows},{self.mids[-1]})
        self.assertIn('последнего замера полного комплекта',table.note)

    def test_sources_selected_through_dataset_membership(self):
        model,_ = self.model(['sources'],focus_measurement_id=self.mids[0])
        self.assertTrue(all(t.rows for t in model.sections[1].tables))
        self.assertIn('capture',{values(r)['dataset_id'] for r in model.sections[1].tables[1].rows})

    def test_explicit_zero_null_absence_missing_slice_and_partial(self):
        model,config = self.model(['problem_history','operations'])
        rows = model.sections[1].tables[0].rows
        absent = next(r for r in rows if values(r)['threshold_status'] == 'не наблюдалось')
        self.assertEqual(absent.state,DisplayState.NO_OBSERVATIONS)
        self.assertEqual(values(absent)['count'],0)
        cell = next(c for c in absent.cells if c.field == 'value')
        self.assertIsNone(cell.value)
        self.assertIn('нет наблюдений',format_cell(cell,config))
        self.data.slices.pop('comparability')
        missing,_ = self.model(['comparisons'])
        self.assertEqual(missing.sections[1].state,DisplayState.NOT_CALCULATED)
        self.data.manifest['analysis_complete'] = False
        partial,_ = self.model(['operations'])
        self.assertEqual(partial.sections[1].tables[0].state,DisplayState.PARTIAL)

    def test_saved_errors_and_versions_have_json_provenance(self):
        model,_ = self.model([])
        cells = {c.field:c for c in model.sections[0].tables[0].rows[0].cells}
        self.assertEqual(cells['/error_summary/event_count'].value,self.data.manifest['error_summary']['event_count'])
        self.assertEqual(cells['/error_summary/event_count'].source_file,'analysis_metrics.json')
        self.assertIn('/absolute_timestamps_complete',cells)

    def test_csv_json_disagreement_rejected(self):
        path = self.analysis/'operations.csv'
        with path.open(encoding='utf-8-sig',newline='') as f:
            reader = csv.DictReader(f)
            columns,rows = reader.fieldnames,list(reader)
        rows[0]['avg_us'] = '42'
        write_csv(path,columns,rows)
        with self.assertRaisesRegex(ReportError,'CSV/JSON mirror mismatch'):
            load_input(self.analysis,self.slices)

    def test_invalid_counts_statuses_and_required_fields_rejected(self):
        for field,value in [('count','1.5'),('count','-1'),('count',''),('threshold_status','count')]:
            with self.subTest(field=field,value=value), self.assertRaises(ReportError):
                parse_value('problem_history',field,value)
        with self.assertRaises(ReportError):
            parse_value('apdex','apdex','1.1')

    def test_history_sort_without_limit_preserves_chronology(self):
        model,_ = self.model(['operations'],report_kind='history',tables={'operation_history':{'sort':[{'field':'avg_us','direction':'desc'}]}})
        groups = {}
        for row in model.sections[1].tables[0].rows:
            v = values(row)
            groups.setdefault(v['cohort_id'],[]).append(v['measurement_order'])
        self.assertTrue(all(order == sorted(order) for order in groups.values()))

    def test_missing_overall_coverage_is_not_empty_population(self):
        self.data.slices.pop('apdex_coverage')
        model,_ = self.model(['apdex_overall'],tables={'apdex_overall':{'top_n':1}})
        section = model.sections[1]
        self.assertEqual(section.state,DisplayState.NOT_CALCULATED)
        self.assertTrue(section.tables[0].rows)
        self.assertEqual(section.tables[2].state,DisplayState.NOT_CALCULATED)

    def test_invalid_effective_targets_rejected_after_hash_update(self):
        path = self.slices/'slice_manifest.json'
        manifest = json.loads(path.read_text(encoding='utf-8'))
        config = manifest['configuration']
        config['apdex']['targets'].append(config['apdex']['targets'][0].copy())
        manifest['configuration_effective_sha256'] = digest(canonical(config).encode())
        write_json(path,manifest)
        with self.assertRaisesRegex(ReportError,'duplicate APDEX identity'):
            load_input(self.analysis,self.slices)

    def test_corrupt_comparison_context_rejected_even_with_updated_hash(self):
        self.mutate_slice('comparability',lambda rows: rows[0].update(current_count='999'))
        with self.assertRaisesRegex(ReportError,'Conflicting comparison current_count'):
            load_input(self.analysis,self.slices)

    def test_corrupt_composition_rejected_even_with_updated_hash(self):
        self.mutate_slice('apdex_composition',lambda rows: rows[0].update(overall_apdex_denominator='999'))
        with self.assertRaisesRegex(ReportError,'composition denominator mismatch'):
            load_input(self.analysis,self.slices)

    def test_corrupt_problem_source_value_rejected(self):
        self.mutate_slice('problem_history',lambda rows: rows[0].update(source_metric_value='999'))
        with self.assertRaisesRegex(ReportError,'source metric value mismatch'):
            load_input(self.analysis,self.slices)

    def test_unknown_time_measurement_from_saved_dataset(self):
        root = fixture(self.root/'unknown')
        manifest = json.loads((root/'analysis_metrics.json').read_text(encoding='utf-8'))
        manifest['datasets'][0]['actual_measurement_ids'] = []
        manifest['datasets'][0]['events_without_absolute_timestamp'] = 1
        for table in ('datasets','operations','call_observations'):
            path = root/(table+'.csv')
            text = path.read_text(encoding='utf-8-sig').replace('arbitrary-id','capture-any@unknown-date')
            if table == 'datasets':
                with path.open(encoding='utf-8-sig',newline='') as f:
                    reader = csv.DictReader(f)
                    columns,rows = reader.fieldnames,list(reader)
                rows[0].update(actual_measurement_ids='',events_without_absolute_timestamp=1)
                write_csv(path,columns,rows)
            else:
                path.write_text(text,encoding='utf-8-sig')
        manifest['operations'][0]['measurement_id'] = 'capture-any@unknown-date'
        write_json(root/'analysis_metrics.json',manifest)
        data = load_input(root)
        self.assertEqual(data.measurement_ids,{'capture-any@unknown-date'})

    def test_hidden_source_paths_not_leaked_by_row_keys(self):
        from pypdf import PdfReader
        model,config = self.model(['sources'])
        output = self.root/'paths.pdf'
        render_pdf(model,config,self.data,output)
        text = '\n'.join(p.extract_text() for p in PdfReader(output).pages)
        for row in self.data.tables['files']:
            self.assertNotIn(row['source'],text)
        self.assertIn('Путь происхождения скрыт',text)

    def test_cli_invalid_input_keeps_existing_pdf(self):
        _,config = self.model(['operations'])
        out = self.root/'existing.pdf'
        out.write_bytes(b'existing PDF must survive')
        self.mutate_slice('problem_history',lambda rows: rows[0].update(threshold_status='unsupported'))
        result = subprocess.run([sys.executable,'-B',str(REPORT_DIR/'build_report.py'),'--analysis-dir',str(self.analysis),'--slices-dir',str(self.slices),'--report-config',str(config.path),'--output',str(out),'--overwrite'],capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'unsupported',result.stderr)
        self.assertEqual(out.read_bytes(),b'existing PDF must survive')

    def test_saved_bundle_only_no_calculator_imports(self):
        original = __import__
        def guarded(name,*args,**kwargs):
            if name.startswith(('derive_slices','analyze_1c_tj','slice_')):
                raise AssertionError('PDF attempted analytical import: '+name)
            return original(name,*args,**kwargs)
        with patch('builtins.__import__',side_effect=guarded),patch('socket.socket',side_effect=AssertionError('network')):
            data = load_input(self.analysis,self.slices)
            config = config_fixture(self.root,sections=['provenance','apdex_overall','problem_history'])
            build_model(data,config)

    def test_three_examples_are_generic_and_build_distinct_main_structures(self):
        expected_files = {
            'overview.example.json':'overview',
            'comparison.example.json':'comparison',
            'history.example.json':'history',
        }
        paths = {path.name:path for path in (REPORT_DIR/'configs').glob('*.example.json')}
        self.assertEqual(set(paths),set(expected_files))
        required = {
            'overview':['scope','overview-db-chatty','overview-apdex-overall'],
            'comparison':['scope','measurement_comparisons','db_chatty_changes','apdex_changes'],
            'history':['scope','history-operations','history-all-users','history-problems'],
        }
        signatures = {}
        for filename,kind in expected_files.items():
            path = paths[filename]
            with self.subTest(path=path.name):
                raw=json.loads(path.read_text(encoding='utf-8'))
                self.assertEqual(raw['report_kind'],kind)
                self.assertNotIn('display_measurement_ids',raw)
                self.assertNotIn('focus_measurement_id',raw)
                self.assertNotIn('labels',raw)
                config=load_config(path)
                model=build_model(self.data,config)
                ids=[section.id.split('-[',1)[0] for section in model.main_sections]
                for prefix in required[kind]:
                    self.assertTrue(any(value == prefix or value.startswith(prefix) for value in ids),prefix)
                if kind == 'overview':
                    self.assertTrue(any(section.id == 'overview-'+mid for section in model.main_sections for mid in self.mids))
                signatures[kind]=tuple(ids)
        self.assertEqual(len({signatures[kind] for kind in signatures}),3)

    def test_main_saved_cells_keep_exact_source_row_and_field(self):
        for kind,sections in [('overview',['quality','operations','sql']),('comparison',['comparisons']),('history',['operations','problem_history'])]:
            model,_=self.model(sections,report_kind=kind,tables={'measurement_comparisons':{'top_n':1}} if kind == 'comparison' else {})
            technical={(cell.source_file,cell.row_key,cell.field):cell.value
                for section in model.sections for table in section.tables for row in table.rows for cell in row.cells}
            for section in model.main_sections:
                for table in section.tables:
                    for row in table.rows:
                        for cell in row.cells:
                            if cell.source_file in {'presentation_dictionary','structural_validation','presentation_configuration'}:
                                continue
                            identity=(cell.source_file,cell.row_key,cell.field)
                            if cell.source_file.endswith('.csv'):
                                name=cell.source_file.removesuffix('.csv')
                                source=self.data.slices.get(name,self.data.tables.get(name))
                                self.assertIsNotNone(source,cell.source_file)
                                original=next(r for r in source if stable_key(name,r) == cell.row_key)
                                self.assertEqual(cell.value,original[cell.field])
                            else:
                                self.assertIn(identity,technical)
                                self.assertEqual(cell.value,technical[identity])
            scope=next(table for section in model.main_sections for table in section.tables if table.name == 'report-scope')
            for row in scope.rows:
                order=next(cell for cell in row.cells if cell.field == 'measurement_order')
                measurement=next(cell for cell in row.cells if cell.field != 'measurement_order')
                if order.value is not None:
                    self.assertIn(order.source_file,{'data_quality.csv','operation_history.csv','problem_history.csv'})
                    self.assertFalse(order.reason)
                self.assertEqual(measurement.value,row.key)
                self.assertTrue(measurement.source_file.endswith(('.csv','.json')))

    def test_comparison_projects_saved_inconsistent_delta_without_recalculation(self):
        row=self.data.slices['measurement_comparisons'][0]
        row['p95_us_delta_absolute']=Decimal('1234567.89')
        model,_=self.model(['comparisons'],report_kind='comparison',tables={'measurement_comparisons':{'top_n':1}})
        table=next(t for s in model.main_sections for t in s.tables if t.name == 'measurement_comparisons-values')
        cell=next(c for r in table.rows for c in r.cells if c.field == 'p95_us_delta_absolute')
        self.assertEqual(cell.value,Decimal('1234567.89'))

    def test_history_projects_saved_status_and_top_n_unique_trajectories(self):
        row=self.data.slices['problem_history'][0]
        row['previous_comparable_change_status']='показатель вырос'
        model,_=self.model(['operations','problem_history'],report_kind='history',tables={'operation_history':{'sort':[{'field':'p95_us','direction':'desc'}],'top_n':2},'problem_history':{'top_n':2}})
        operation_sections=[s for s in model.main_sections if s.id.startswith('history-operations-')]
        self.assertEqual(len(operation_sections),2)
        identities=set()
        for section in operation_sections:
            identity=next(t for t in section.tables if t.name == 'operation_history-identity')
            cohort=next(c.value for c in identity.rows[0].cells if c.field == 'cohort_id')
            identities.add(cohort)
            operations=next(t for t in section.tables if t.name == 'operation_history')
            order=[next(c.value for c in r.cells if c.field == 'measurement_order') for r in operations.rows]
            self.assertEqual(order,sorted(order))
            for presented in operations.rows:
                original=next(item for item in self.data.slices['operation_history'] if stable_key('operation_history',item) == presented.key)
                self.assertEqual(original['cohort_id'],cohort)
        self.assertEqual(len(identities),2)
        problem_sections=[s for s in model.main_sections if s.id.startswith('history-problems-')]
        self.assertEqual(len(problem_sections),2)
        selected=next(s for s in problem_sections if s.id == 'history-problems-'+row['problem_id'])
        problems=next(t for t in selected.tables if t.name == 'problem_history-status')
        saved=next(c for r in problems.rows for c in r.cells if c.row_key == stable_key('problem_history',row) and c.field == 'previous_comparable_change_status')
        self.assertEqual(saved.value,'показатель вырос')
        fields={c.field for table in selected.tables for presented in table.rows for c in presented.cells}
        self.assertTrue({'previous_reference_comparability','previous_comparable_known_differences','unknown_parameters','known_limitations'} <= fields)
        self.assertTrue(any(table.name == 'problem_rule_coverage' for table in selected.tables))

    def test_overall_apdex_main_keeps_parent_full_composition_and_coverage_together(self):
        model,_=self.model(['apdex_overall'],tables={'apdex_overall':{'top_n':1}})
        section=next(s for s in model.main_sections if s.id.startswith('overview-apdex-overall-'))
        tables={table.name:table for table in section.tables}
        self.assertEqual(set(tables),{'apdex_overall','apdex_composition','apdex_coverage'})
        parent=values(tables['apdex_overall'].rows[0])
        self.assertEqual(len(tables['apdex_composition'].rows),next(
            r['composition_row_count'] for r in self.data.slices['apdex_overall'] if r['overall_id'] == parent['overall_id']))
        self.assertTrue(all(values(row)['overall_id'] == parent['overall_id'] for row in tables['apdex_composition'].rows))
        self.assertTrue(tables['apdex_coverage'].rows)
        coverage=values(tables['apdex_coverage'].rows[0])
        self.assertEqual(coverage['measurement_ids'],parent['measurement_ids'])
        self.assertEqual(coverage['population_scope'],parent['population_scope'])

    def test_operation_apdex_keeps_coverage_not_used_by_limited_overall(self):
        model,_=self.model(['apdex','apdex_overall'],tables={'apdex_overall':{'top_n':1}})
        available={row.key for section in model.sections for table in section.tables if table.name == 'apdex_coverage' for row in table.rows}
        visible={row.key for section in model.main_sections for table in section.tables if table.name == 'apdex_coverage' for row in table.rows}
        self.assertGreater(len(available),1)
        self.assertTrue(any(table.name == 'apdex' and table.rows for section in model.main_sections for table in section.tables))
        self.assertEqual(visible,available)

    def test_missing_apdex_composition_is_not_calculated_in_main(self):
        self.data.slices.pop('apdex_composition')
        model,_=self.model(['apdex_overall'],tables={'apdex_overall':{'top_n':1}})
        section=next(s for s in model.main_sections if s.id.startswith('overview-apdex-overall-'))
        composition=next(t for t in section.tables if t.name == 'apdex_composition')
        self.assertEqual(composition.state,DisplayState.NOT_CALCULATED)
        self.assertFalse(composition.rows)

    def test_comparison_main_keeps_db_and_apdex_context(self):
        model,_=self.model(['db_chatty_comparison','apdex_changes'],report_kind='comparison',tables={
            'db_chatty_changes':{'top_n':1},'apdex_changes':{'top_n':1}})
        required={
            'db_chatty_changes':{
                'reference_measurement_id','current_measurement_id','comparison_basis','reference_relation',
                'threshold_db_events','threshold_operator','reference_call_share_denominator','current_call_share_denominator',
                'reference_measurement_db_linked_count_percent','current_measurement_db_linked_count_percent',
                'known_differences','unknown_parameters','known_limitations'},
            'apdex_changes':{
                'reference_measurement_id','current_measurement_id','comparison_basis','reference_relation',
                'reference_target_id','current_target_id','reference_target_status','current_target_status',
                'reference_target_source','current_target_source','reference_t_us','current_t_us','target_match','reference_apdex_denominator','current_apdex_denominator',
                'failure_policy','assessment_scope','known_differences','unknown_parameters','known_limitations'},
        }
        for name,fields in required.items():
            with self.subTest(name=name):
                section=next(s for s in model.main_sections if s.id.startswith(name+'-'))
                actual={cell.field for table in section.tables for row in table.rows for cell in row.cells}
                self.assertTrue(fields <= actual,fields-actual)

    def test_quality_and_manifest_limitations_are_visible_in_main(self):
        model,_=self.model(['quality'])
        scope=next(s for s in model.main_sections if s.id == 'scope')
        completeness=next(t for t in scope.tables if t.name == 'analysis-completeness')
        self.assertEqual(values(completeness.rows[0])['/analysis_complete'],self.data.manifest['analysis_complete'])
        context=next(t for t in scope.tables if t.name == 'data-quality-context')
        fields={cell.field for row in context.rows for cell in row.cells}
        self.assertTrue({'source_completeness','db_linkage_status','known_limitations'} <= fields)
        for row in context.rows:
            original=next(item for item in self.data.slices['data_quality'] if stable_key('data_quality',item) == row.key)
            self.assertEqual(values(row)['source_completeness'],original['source_completeness'])

    def test_manifest_quality_remains_when_quality_slice_is_absent(self):
        self.data.slices.pop('data_quality')
        model,_=self.model(['quality'])
        scope=next(s for s in model.main_sections if s.id == 'scope')
        self.assertTrue(next(t for t in scope.tables if t.name == 'analysis-completeness').rows)
        self.assertEqual(next(t for t in scope.tables if t.name == 'data_quality').state,DisplayState.NOT_CALCULATED)

    def test_bundle_error_summary_is_visible_without_recalculation(self):
        model,_=self.model(['errors'])
        summary=next(t for s in model.main_sections for t in s.tables if t.name == 'error-summary')
        row=values(summary.rows[0])
        self.assertEqual(row['/error_summary/event_count'],self.data.manifest['error_summary']['event_count'])
        self.assertEqual(row['/error_summary/affected_call_count'],self.data.manifest['error_summary']['affected_call_count'])

    def test_empty_comparison_is_no_observations_not_missing_slice(self):
        self.data.slices['measurement_comparisons']=[]
        model,_=self.model(['comparisons'],report_kind='comparison')
        section=next(s for s in model.main_sections if s.id == 'measurement_comparisons')
        self.assertEqual(section.state,DisplayState.NO_OBSERVATIONS)
        self.assertEqual(section.tables[0].state,DisplayState.NO_OBSERVATIONS)

    def test_overview_top_n_is_per_measurement(self):
        model,_=self.model(['operations'],report_kind='overview',tables={'operations':{'sort':[{'field':'p95_us','direction':'desc'}],'top_n':1}})
        sections=[s for s in model.main_sections if s.id.startswith('overview-')]
        expected={r['measurement_id'] for r in self.data.tables['operations']}
        self.assertEqual({s.id.removeprefix('overview-') for s in sections},expected)
        for section in sections:
            operations=next(t for t in section.tables if t.name == 'operations')
            self.assertEqual(len(operations.rows),1)

    def test_focus_is_rejected_outside_overview(self):
        for kind in ('comparison','history'):
            with self.subTest(kind=kind),self.assertRaisesRegex(ReportError,'only valid for overview'):
                config_fixture(self.root,report_kind=kind,focus_measurement_id=self.mids[0])

    def test_compact_pdf_has_russian_main_and_traceable_appendix(self):
        from pypdf import PdfReader
        model,config=self.model(['comparisons'],report_kind='comparison',tables={'measurement_comparisons':{'top_n':1}})
        output=self.root/'structured.pdf'
        render_pdf(model,config,self.data,output)
        text='\n'.join(page.extract_text() for page in PdfReader(output).pages)
        self.assertIn('Основная часть',text)
        self.assertIn('Опорный замер',text)
        self.assertIn('Готовые значения и дельты',text)
        self.assertIn('Сопоставимость и ограничения',text)
        self.assertIn('Приложение: полные технические данные и происхождение',text)
        self.assertIn('Индекс происхождения значений основной части',text)
        self.assertIn('V0001',text)
        self.assertIn('не доказывает исправление или регрессию кода',text)


if __name__ == '__main__':
    unittest.main()
