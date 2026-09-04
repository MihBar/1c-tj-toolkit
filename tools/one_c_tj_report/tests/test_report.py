"""Small saved-result fixtures: no journal parsing or analytical calculation."""
import copy
import csv
import importlib
import json
from pathlib import Path
import shutil
import sqlite3
from contextlib import closing
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPORT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPORT_DIR))
from report_schema import profile, canonical, digest, ReportError
from report_input import load_input, descriptor, DETAIL_FILES
from report_config import load_config
from report_model import build_model, DisplayState, format_cell, present_table, Cell
from report_layout import render_pdf
from decimal import Decimal


def write_json(path, value):
    path.write_text(canonical(value)+'\n',encoding='utf-8')


def write_csv(path, columns, rows):
    with path.open('w',encoding='utf-8-sig',newline='') as f:
        writer = csv.DictWriter(f,fieldnames=columns,lineterminator='\n')
        writer.writeheader()
        for row in rows:
            writer.writerow({k:canonical(v) if isinstance(v,(list,dict,bool)) else v for k,v in row.items()})


def fixture(root, *, partial=False, observed=True):
    root.mkdir(parents=True)
    p = profile()
    rows = {name:[] for name in p['analysis_tables']}
    if observed:
        def row(table, **values):
            return dict.fromkeys(p['analysis_tables'][table]) | values
        rows['datasets'] = [row('datasets',dataset_id='dataset-any',measurement_id='capture-any',actual_measurement_ids='arbitrary-id',users=['Пользователь'],events_without_absolute_timestamp=0)]
        rows['operations'] = [row('operations',measurement_id='arbitrary-id',dataset_id='dataset-any',user='Пользователь',signature='Произвольная операция <img src="https://invalid">',count=1,priority='P2',p95_us=2500000,avg_us=2500000,db_per_call=0)]
        rows['call_observations'] = [row('call_observations',call_id=1,measurement_id='arbitrary-id',dataset_id='dataset-any',user='Пользователь',signature=rows['operations'][0]['signature'],duration_us=2500000,source='Z:/MUST_NOT_OPEN/original.log')]
    from report_input import csv_scalar
    for name,cols in p['analysis_tables'].items():
        write_csv(root/(name+'.csv'),cols,[{k:csv_scalar(v) for k,v in r.items()} for r in rows[name]])
    with closing(sqlite3.connect(root/'analysis.sqlite')) as db:
        for name, cols in p['sqlite_columns'].items():
            db.execute('CREATE TABLE '+name+' ('+','.join('"'+c+'" TEXT' for c in cols)+')')
        for k,v in p['analysis_versions'].items():
            db.execute('INSERT INTO metadata (key,value) VALUES (?,?)',(k,canonical(v)))
        db.execute('INSERT INTO metadata (key,value) VALUES (?,?)',('publication_state',canonical('complete')))
        db.commit()
    write_json(root/'source_map.json',{'capture_id':'capture-any','sources':[]})
    artifacts = {n:descriptor(root/n)|{'row_count':len(rows.get(Path(n).stem,[]))} for n in DETAIL_FILES}
    counts = {'sources_discovered':0,'datasets':len(rows['datasets']),'operations':len(rows['operations']),'identical_operation_rows':0,'sql_patterns':0,'error_signatures':0,'lock_signatures':0,'linkage_rows':0,'call_observations':len(rows['call_observations'])}
    error_summary = dict.fromkeys(('event_count','linked_error_event_count','unlinked_error_event_count','affected_call_count','suspected_incident_count','ambiguous_linked_error_event_count','fallback_linked_error_event_count'),0)
    manifest = p['analysis_versions'] | {'publication_state':'complete','analysis_complete':not partial,'source_processing_complete':not partial,'collection_completeness':'unknown','source_content_hashes_complete':False,'absolute_timestamps_complete':False,'salvage_nul_prefix':False,'units':p['units'],'method':p['analysis_method'],'counts':counts,'error_summary':error_summary,'artifacts':artifacts,'warnings':[],'source_set_hash_sha256':'a'*64,'capture_id':'capture-any'}
    manifest.update({k:rows[k] for k in ('files','datasets','operations','identical_operations','heavy_sql','errors','locks','linkage','top_calls')})
    if observed:
        manifest['datasets'][0]['actual_measurement_ids'] = ['arbitrary-id']
    write_json(root/'analysis_metrics.json',manifest)
    return root


def slices_fixture(root, data, selected=('data_quality',)):
    root.mkdir()
    p = profile()
    config = copy.deepcopy(p['default_analytics'])
    config['slices'] = sorted(selected)
    outputs = {}
    for name in selected:
        write_csv(root/(name+'.csv'),p['slice_tables'][name],[])
        outputs[name+'.csv'] = descriptor(root/(name+'.csv')) | {'row_count':0,'columns':p['slice_tables'][name]}
    s = {'calculator':'1c_tj_saved_result_slices','calculator_version':'1.8.0','slice_schema_version':'1.8','config_version':'1.0','bundle_id':data.bundle_id,'input_files':data.input_files,'input_schema_version':'1.6','input_analyzer_version':'1.6.1','input_sql_normalization_version':'2.0','input_linkage_rules_version':data.manifest['linkage_rules_version'],'input_error_rules':{k:data.manifest[k] for k in ('error_signature_version','error_linkage_rules_version','incident_rules_version')},'recorded_source_set_hash_sha256':data.manifest['source_set_hash_sha256'],'source_analysis_complete':data.manifest['analysis_complete'],'input_files_unchanged':True,'configuration':config,'configuration_effective_sha256':digest(canonical(config).encode()),'configuration_file_sha256':'b'*64,'selected_slices':config['slices'],'outputs':outputs,'population':{'primary':'call_observations.csv','key':['bundle_id','call_id'],'count':len(data.tables['call_observations']),'json_and_top_calls_are_not_additional_observations':True},'method':p['slice_method'],'validation_checks':[]}
    write_json(root/'slice_manifest.json',s)
    return root


def config_fixture(root, **changes):
    c = {'report_config_version':'1.0','report_kind':'overview','title':'Проверка кириллицы: ёж и объём','locale':'ru-RU','report_date':'2026-09-03','sections':['provenance','operations','quality','comparisons']}
    c.update(changes)
    write_json(root/'report.json',c)
    return load_config(root/'report.json')


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.analysis = fixture(self.root/'analysis')

    def test_one_measurement_null_and_zero(self):
        data = load_input(self.analysis)
        c = config_fixture(self.root)
        model = build_model(data,c)
        self.assertEqual(data.measurement_ids,{'arbitrary-id'})
        cells = {x.field:x for x in model.sections[1].tables[0].rows[0].cells}
        self.assertEqual(cells['db_per_call'].value,0)
        self.assertIsNone(cells['cpu_us'].value)
        self.assertIn('недоступен',format_cell(cells['cpu_us'],c))
        self.assertEqual(model.sections[3].state,DisplayState.NOT_CALCULATED)

    def test_missing_required_file_and_version(self):
        (self.analysis/'errors.csv').unlink()
        with self.assertRaises(ReportError): load_input(self.analysis)
        other = fixture(self.root/'other')
        m = json.loads((other/'analysis_metrics.json').read_text(encoding='utf-8'))
        m['schema_version'] = '1.2'
        write_json(other/'analysis_metrics.json',m)
        with self.assertRaisesRegex(ReportError,'schema_version'): load_input(other)

    def test_invalid_numeric_does_not_become_empty(self):
        f = self.analysis/'operations.csv'
        text = f.read_text(encoding='utf-8-sig').replace('2500000','not-a-number')
        f.write_text(text,encoding='utf-8-sig')
        with self.assertRaisesRegex(ReportError,'invalid number'): load_input(self.analysis)

    def test_empty_and_partial(self):
        empty = load_input(fixture(self.root/'empty',observed=False))
        c = config_fixture(self.root)
        self.assertEqual(build_model(empty,c).sections[1].tables[0].state,DisplayState.NO_OBSERVATIONS)
        partial = load_input(fixture(self.root/'partial',partial=True))
        self.assertTrue(build_model(partial,c).partial)

    def test_slice_identity_hashes_and_corruption(self):
        data = load_input(self.analysis)
        sroot = slices_fixture(self.root/'slices',data)
        self.assertIn('data_quality',load_input(self.analysis,sroot).slices)
        (sroot/'data_quality.csv').write_text('corrupt',encoding='utf-8')
        with self.assertRaisesRegex(ReportError,'descriptor mismatch'): load_input(self.analysis,sroot)

    def test_wrong_bundle_never_falls_back(self):
        sroot = slices_fixture(self.root/'slices',load_input(self.analysis))
        s = json.loads((sroot/'slice_manifest.json').read_text(encoding='utf-8'))
        s['bundle_id'] = 'c'*64
        write_json(sroot/'slice_manifest.json',s)
        with self.assertRaisesRegex(ReportError,'bundle_id'): load_input(self.analysis,sroot)

    def test_missing_declared_slice_and_effective_configuration(self):
        sroot = slices_fixture(self.root/'slices',load_input(self.analysis))
        s = json.loads((sroot/'slice_manifest.json').read_text(encoding='utf-8'))
        s['configuration']['db_chatty']['thresholds'] = [999]
        write_json(sroot/'slice_manifest.json',s)
        with self.assertRaisesRegex(ReportError,'configuration hash'): load_input(self.analysis,sroot)

    def test_no_analytics_network_or_source_access(self):
        original = Path.open
        def guarded(path,*args,**kwargs):
            self.assertNotIn('MUST_NOT_OPEN',str(path))
            return original(path,*args,**kwargs)
        with patch.object(Path,'open',guarded), patch('socket.socket',side_effect=AssertionError('network')):
            load_input(self.analysis)
        self.assertNotIn('derive_slices',sys.modules)
        self.assertNotIn('slice_input',sys.modules)

    def test_sort_top_n_null_last_preserves_values(self):
        c = config_fixture(self.root,tables={'operations':{'sort':[{'field':'p95_us','direction':'desc'}],'top_n':2}})
        data = load_input(self.analysis)
        row = data.tables['operations'][0]
        rows = [row|{'signature':'a','p95_us':None},row|{'signature':'b','p95_us':Decimal('1.0001')},row|{'signature':'c','p95_us':Decimal('1.0002')}]
        table = present_table('operations',rows,c,False)
        self.assertEqual(table.available_rows,3)
        self.assertEqual([next(x.value for x in r.cells if x.field=='signature') for r in table.rows],['c','b'])
        self.assertEqual(rows[1]['p95_us'],Decimal('1.0001'))

    def test_config_rejects_analytics_and_unknown_ids(self):
        with self.assertRaises(ReportError): config_fixture(self.root,thresholds=[100])
        with self.assertRaises(ReportError): config_fixture(self.root,document_notice='   ')
        c = config_fixture(self.root,focus_measurement_id='missing')
        with self.assertRaisesRegex(ReportError,'Unknown'): build_model(load_input(self.analysis),c)

    def test_import_and_help_do_not_register_fonts(self):
        code = 'import sys; sys.path.insert(0,sys.argv[1]); import build_report,build_trend_report,build_iteration_history_report; assert "reportlab" not in sys.modules'
        subprocess.run([sys.executable,'-B','-c',code,str(REPORT_DIR)],check=True,capture_output=True)
        result = subprocess.run([sys.executable,'-B',str(REPORT_DIR/'build_report.py'),'--help'],capture_output=True)
        self.assertEqual(result.returncode,0)

    def test_populated_slice_preserves_ready_values_and_rejects_missing_key(self):
        data = load_input(self.analysis)
        root = slices_fixture(self.root/'slices',data)
        columns = profile()['slice_tables']['data_quality']
        row = dict.fromkeys(columns) | {'measurement_id':'arbitrary-id','call_count':1,'configured_min_call_count':1,'configured_db_linkage_warning_percent':95}
        def save():
            write_csv(root/'data_quality.csv',columns,[row])
            manifest = json.loads((root/'slice_manifest.json').read_text(encoding='utf-8'))
            manifest['outputs']['data_quality.csv'] = descriptor(root/'data_quality.csv') | {'columns':columns,'row_count':1}
            write_json(root/'slice_manifest.json',manifest)
        save()
        loaded = load_input(self.analysis,root)
        self.assertEqual(loaded.slices['data_quality'][0]['call_count'],Decimal(1))
        row['measurement_id'] = None
        save()
        with self.assertRaisesRegex(ReportError,'missing row identifier'):
            load_input(self.analysis,root)

    def test_duplicate_json_and_nonfinite_are_errors(self):
        from report_schema import strict_json
        for text in ('{"x":1,"x":2}','{"x":NaN}','{"x":1e999}'):
            with self.assertRaises(ReportError): strict_json(text,'fixture')

    def test_other_modes_accept_single_measurement_without_recalculation(self):
        data = load_input(self.analysis)
        for kind in ('comparison','history'):
            config = config_fixture(self.root,report_kind=kind)
            model = build_model(data,config)
            self.assertEqual(model.sections[-1].state,DisplayState.NOT_CALCULATED)
            render_pdf(model,config,data,self.root/(kind+'.pdf'))

    def test_pdf_atomic_and_cyrillic(self):
        from pypdf import PdfReader
        data = load_input(self.analysis)
        notice = 'ТЕСТОВЫЙ ОТЧЕТ: только синтетические данные'
        c = config_fixture(self.root,sections=['provenance','operations'],document_notice=notice)
        model = build_model(data,c)
        out = self.root/'result.pdf'
        render_pdf(model,c,data,out)
        pages = PdfReader(out).pages
        page_texts = [page.extract_text() for page in pages]
        text = '\n'.join(page_texts)
        self.assertIn('Проверка кириллицы',text)
        self.assertIn('показатель недоступен',text)
        self.assertIn(notice,text)
        self.assertEqual(text.count('ТЕХНИЧЕСКОЕ ПРИЛОЖЕНИЕ'),1)
        appendix = next(index for index,value in enumerate(page_texts) if 'ТЕХНИЧЕСКОЕ ПРИЛОЖЕНИЕ' in value)
        for number,value in enumerate(page_texts,1):
            self.assertIn(f'Страница {number} из {len(page_texts)}',value)
            self.assertIn('Техническое приложение |' if number > appendix else 'Основной отчет |',value)
        before = out.read_bytes()
        with self.assertRaises(ReportError): render_pdf(model,c,data,out)
        self.assertEqual(before,out.read_bytes())
        (self.analysis/'files.csv').write_text('changed',encoding='utf-8')
        with self.assertRaises(ReportError): render_pdf(model,c,data,out,overwrite=True)
        self.assertEqual(before,out.read_bytes())


if __name__ == '__main__':
    unittest.main()
