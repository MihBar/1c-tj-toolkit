"""Structural saved-result reader. No parser, analytical builder or verifier imports."""
from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
import sqlite3
from contextlib import closing

try:
    from .report_schema import ReportError, require, strict_json, canonical, digest, profile, field_spec, DETAIL_FILES
except ImportError:
    from report_schema import ReportError, require, strict_json, canonical, digest, profile, field_spec, DETAIL_FILES


def safe_file(root, name):
    require(Path(name).name == name and name not in {'.', '..'}, f'Invalid artifact name: {name}')
    path = root / name
    resolved = path.resolve(strict=True)
    require(resolved.parent == root and resolved.is_file(), f'Artifact escapes directory: {name}')
    return resolved


def descriptor(path):
    import hashlib
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return {'sha256': h.hexdigest(), 'size_bytes': path.stat().st_size}


def read_json(path):
    return strict_json(path.read_text(encoding='utf-8-sig'), path.name)


def parse_value(table, field, value, is_slice=False, vocabulary=None):
    spec = field_spec(table,field)
    if value == '':
        require(spec['nullable'], f'{table}.{field}: required value is missing')
        return None
    kind = spec['type']
    if kind in {'number','integer'}:
        try:
            n = Decimal(value)
            require(n.is_finite(), f'{table}.{field}: non-finite value')
            if kind == 'integer':
                require(n == n.to_integral_value(), f'{table}.{field}: expected integer')
            require(spec.get('minimum') is None or n >= spec['minimum'], f'{table}.{field}: value below minimum')
            require(spec.get('maximum') is None or n <= spec['maximum'], f'{table}.{field}: value above maximum')
            return n
        except InvalidOperation as exc:
            raise ReportError(f'{table}.{field}: invalid number {value!r}') from exc
    if kind == 'bool':
        require(value.lower() in {'true', 'false', '0', '1'}, f'{table}.{field}: invalid boolean')
        return value.lower() in {'true', '1'}
    if kind in {'object','array'}:
        result = strict_json(value, f'{table}.{field}')
        require(isinstance(result, dict if kind == 'object' else list), f'{table}.{field}: expected {kind}')
        validate_nested(result,f'{table}.{field}')
        return result
    if kind == 'timestamp':
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ReportError(f'{table}.{field}: invalid timestamp {value!r}') from exc
        require(parsed.tzinfo is None, f'{table}.{field}: unexpected timezone')
    if 'enum' in spec:
        require(value in spec['enum'], f'{table}.{field}: unsupported value {value!r}')
    return value


def validate_nested(value, label):
    """Validate saved counter shapes and types without recomputing their values."""
    if isinstance(value,list):
        for child in value:
            validate_nested(child,label)
    elif isinstance(value,dict):
        if 'eligible_count' in value:
            fields = {'eligible_count','available_count','empty_count','invalid_count','missing_count','out_of_range_count','zero_count','mean_denominator','sum_known','sum_complete','mean','max_known','coverage_percent'}
            require(set(value) == fields, f'{label}: invalid counter summary fields')
            for key,item in value.items():
                if key.endswith('_count') or key == 'mean_denominator':
                    require(type(item) is int and item >= 0, f'{label}.{key}: expected nonnegative integer')
                else:
                    require(item is None or type(item) in (int,float), f'{label}.{key}: invalid counter value')
        if 'raw_value' in value and 'state' in value:
            require(set(value) == {'raw_value','state','value','unit','reason'}, f'{label}: invalid observation counter fields')
            require(value['state'] in {'valid','missing','empty','invalid','out_of_range'}, f'{label}: invalid counter state')
            require(value['value'] is None or type(value['value']) is int, f'{label}: invalid counter value')
        for child in value.values():
            validate_nested(child,label)


def read_csv(path, columns, is_slice=False, vocabulary=None, retain_fields=None, mirrors=None):
    previous = csv.field_size_limit()
    csv.field_size_limit(16 * 1024 * 1024)
    try:
        with path.open(encoding='utf-8-sig', newline='') as stream:
            reader = csv.DictReader(stream, strict=True)
            require(reader.fieldnames == columns, f'{path.name}: incompatible columns')
            rows = []
            for index, row in enumerate(reader, 2):
                require(None not in row and None not in row.values(), f'{path.name}:{index}: malformed CSV')
                parsed = {k: parse_value(path.stem, k, v, is_slice, vocabulary) for k,v in row.items()}
                if mirrors is not None:
                    validate_mirror(path.stem,parsed,mirrors)
                rows.append(parsed if retain_fields is None else {k:v for k,v in parsed.items() if k in retain_fields})
            return rows
    finally:
        csv.field_size_limit(previous)


@dataclass
class SavedInput:
    analysis_dir: Path
    slices_dir: Path | None
    manifest: dict
    slice_manifest: dict | None
    tables: dict
    slices: dict
    input_files: dict
    slice_files: dict
    bundle_id: str
    measurement_ids: set
    measurement_datasets: dict

    def assert_unchanged(self):
        for root, files in ((self.analysis_dir, self.input_files), (self.slices_dir, self.slice_files)):
            if root:
                for name, expected in files.items():
                    require(descriptor(safe_file(root, name)) == expected, f'Input changed: {name}')


KEYS = {
    'files': ('source',), 'datasets': ('dataset_id',),
    'operations': ('measurement_id','dataset_id','user','signature'),
    'identical_operations': ('measurement_id','user','signature'),
    'heavy_sql': ('measurement_id','sql_fingerprint_sha256'),
    'errors': ('measurement_id','event','signature_id'),
    'locks': ('measurement_id','event','context'),
    'linkage': ('measurement_id','dataset_id'),
    'call_observations': ('call_id',), 'top_calls': ('call_id',),
    'db_observations': ('event_id',), 'event_links': ('event_id',),
    'link_candidates': ('event_id','call_event_id'),
    'error_observations': ('event_id',), 'error_event_links': ('event_id',),
    'error_link_candidates': ('event_id','call_event_id'),
    'error_incidents': ('incident_id',), 'error_incident_members': ('event_id',),
}
SLICE_KEYS = {
    'data_quality': ('measurement_id',), 'operation_history': ('history_id',),
    'operation_history_all_users': ('history_id',), 'measurement_comparisons': ('comparison_id',),
    'comparability': ('comparison_id',), 'db_chatty': ('group_id',),
    'db_chatty_calls': ('observation_id',), 'db_chatty_fast_calls': ('observation_id',),
    'db_chatty_duration': ('distribution_id',), 'db_chatty_coverage': ('coverage_id',),
    'db_chatty_changes': ('comparison_id',), 'apdex': ('apdex_row_id',),
    'apdex_uncovered': ('apdex_row_id',), 'apdex_calls': ('observation_id',),
    'apdex_coverage': ('coverage_id',), 'apdex_overall': ('overall_id',),
    'apdex_composition': ('composition_id',), 'apdex_changes': ('comparison_id',),
    'problem_registry': ('problem_id',), 'problem_history': ('history_row_id',),
    'problem_improved': ('transition_id',), 'problem_worsened': ('transition_id',),
    'problem_persisting': ('problem_id',), 'problem_unchecked': ('problem_id',),
    'problem_new': ('history_row_id',), 'problem_rule_coverage': ('rule_id','measurement_id'),
}


def unique(rows, keys, label):
    seen = set()
    for row in rows:
        key = tuple(row[k] for k in keys)
        require(all(row[k] is not None for k in keys if k not in {'user','context','signature'}), f'{label}: missing row identifier')
        require(key not in seen, f'{label}: duplicate key {key}')
        seen.add(key)


def csv_scalar(value):
    """Published JSON-to-CSV representation, used only to compare saved mirrors."""
    if value is None:
        return ''
    if isinstance(value,list):
        return canonical(value) if any(isinstance(x,(dict,list)) for x in value) else ' | '.join(str(x) for x in sorted(value))
    if isinstance(value,dict):
        return canonical(value)
    return str(value)


def mirror_index(table, rows):
    result = {}
    for row in rows:
        require(isinstance(row,dict), f'{table}: invalid JSON row')
        require(set(profile()['analysis_tables'][table]) <= set(row), f'{table}: missing JSON mirror fields')
        key = tuple(parse_value(table,k,csv_scalar(row.get(k))) for k in KEYS[table])
        require(key not in result, f'{table}: duplicate JSON key')
        result[key] = row
    return result


def validate_mirror(table, parsed, index):
    key = tuple(parsed[k] for k in KEYS[table])
    require(key in index, f'{table}: CSV key absent from JSON')
    row = index[key]
    for k,v in parsed.items():
        expected = parse_value(table,k,csv_scalar(row.get(k)))
        require(v == expected, f'{table}.{k}: CSV/JSON mirror mismatch at {key}')


def validate_analytics(c, known_slices, bundle_id):
    """Check saved configuration shape, never normalize time/thresholds or score."""
    required = {'config_version','slices','measurement_ids','expected_bundle_id','data_quality','operations','db_chatty','apdex','problems'}
    require(isinstance(c, dict) and set(c) == required and c['config_version'] == '1.0', 'Invalid effective analytics configuration')
    require(c['expected_bundle_id'] in (None, bundle_id), 'expected_bundle_id mismatch')
    names = c['slices']
    require(isinstance(names, list) and names and all(isinstance(n, str) and n in known_slices for n in names) and names == sorted(set(names)), 'Invalid selected slices')
    shapes = {
        'data_quality': {'min_call_count', 'db_linkage_warning_percent'},
        'operations': {'series_baseline_measurement_id','measurement_order','min_comparison_count'},
        'db_chatty': {'thresholds','duration_bounds_seconds','fast_call_max_seconds'},
        'apdex': {'min_call_count','failure_policy','targets','classes','confirmed_failures'},
        'problems': {'series_id','rules'},
    }
    for key, fields in shapes.items():
        require(isinstance(c[key], dict) and set(c[key]) == fields, f'Invalid analytics {key}')
    for group, field in [('data_quality','min_call_count'),('operations','min_comparison_count'),('apdex','min_call_count')]:
        require(type(c[group][field]) is int and c[group][field] > 0, f'Invalid analytics {group}.{field}')
    percent = c['data_quality']['db_linkage_warning_percent']
    require(type(percent) in (int,float) and 0 <= percent <= 100, 'Invalid saved linkage threshold')
    chatty = c['db_chatty']
    for key in ('thresholds','duration_bounds_seconds'):
        values = chatty[key]
        require(isinstance(values,list) and values and all(type(v) in (int,float) and v > 0 for v in values) and values == sorted(set(values)), f'Invalid saved {key}')
    require(all(type(v) is int for v in chatty['thresholds']), 'DB thresholds must be integers')
    require(type(chatty['fast_call_max_seconds']) in (int,float) and chatty['fast_call_max_seconds'] >= 0, 'Invalid fast CALL boundary')
    def seconds(value):
        require(type(value) in (int,float) and 0 <= value <= 9_007_199_254, 'Invalid saved seconds')
        converted = Decimal(str(value)).scaleb(6)
        require(converted == converted.to_integral_value(), 'Saved seconds must represent whole microseconds')
    for value in [chatty['fast_call_max_seconds'],*chatty['duration_bounds_seconds']]:
        seconds(value)
    require(c['apdex']['failure_policy'] in {'latency_only','confirmed_failures_frustrated'}, 'Invalid APDEX policy')
    class_members = set()
    for key in ('targets','classes'):
        require(isinstance(c['apdex'][key], list), 'Invalid APDEX entries')
        seen = set()
        for entry in c['apdex'][key]:
            fields = {'signature','t_seconds','status','source'} if key == 'targets' else {'class_id','signatures','t_seconds','status','source'}
            require(isinstance(entry, dict) and set(entry) == fields, 'Invalid APDEX target')
            require(entry['status'] in {'engineering_proposal','business_approved'} and type(entry['t_seconds']) in (int,float) and entry['t_seconds'] > 0, 'Invalid APDEX target value/status')
            seconds(entry['t_seconds'])
            identity = entry['signature' if key == 'targets' else 'class_id']
            require(isinstance(identity,str) and identity.strip() and identity not in seen, 'Invalid/duplicate APDEX identity')
            require(isinstance(entry['source'],str) and entry['source'].strip(), 'Missing APDEX target source')
            seen.add(identity)
            if key == 'classes':
                members = entry['signatures']
                require(isinstance(members,list) and members and all(isinstance(x,str) and x.strip() for x in members) and len(members) == len(set(members)), 'Invalid APDEX class members')
                require(not class_members.intersection(members), 'Ambiguous APDEX class membership')
                class_members.update(members)
    failures = c['apdex']['confirmed_failures']
    require(isinstance(failures, dict) and set(failures) == {'bundle_id','calls'} and isinstance(failures['calls'], list), 'Invalid confirmed failures')
    require(failures['bundle_id'] in (None, bundle_id), 'Failure evidence belongs to another bundle')
    seen = set()
    for entry in failures['calls']:
        require(isinstance(entry,dict) and set(entry) == {'call_id','evidence'}, 'Invalid confirmed failure entry')
        require(type(entry['call_id']) is int and entry['call_id'] > 0 and entry['call_id'] not in seen, 'Invalid/duplicate confirmed CALL')
        require(isinstance(entry['evidence'],str) and entry['evidence'].strip(), 'Missing confirmed failure evidence')
        seen.add(entry['call_id'])
    require(not seen or failures['bundle_id'] == bundle_id and c['apdex']['failure_policy'] == 'confirmed_failures_frustrated', 'Confirmed failures require pinned policy and bundle')
    require(isinstance(c['problems']['rules'], list), 'Invalid problem rules')
    series_id = c['problems']['series_id']
    require(series_id is None or isinstance(series_id,str) and series_id.strip(), 'Invalid problem series_id')
    require(not c['problems']['rules'] or series_id is not None, 'Problem rules require series_id')
    seen = set()
    for rule in c['problems']['rules']:
        fields = {'rule_id','metric','operator','threshold','min_call_count','source','scope','signatures','users','db_events_threshold','min_db_linked_count_percent','min_db_linked_duration_percent','require_clean_sources'}
        require(isinstance(rule, dict) and set(rule) == fields, 'Invalid effective problem rule')
        require(isinstance(rule['rule_id'],str) and rule['rule_id'].strip() and rule['rule_id'] not in seen, 'Invalid/duplicate problem rule_id')
        seen.add(rule['rule_id'])
        require(rule['metric'] in profile()['problem_metrics'], 'Unknown problem metric')
        require(isinstance(rule['source'],str) and rule['source'].strip(), 'Missing problem rule source')
        require(rule['operator'] in {'>', '>='} and rule['scope'] == 'same_user', 'Invalid problem rule operator/scope')
        require(type(rule['threshold']) in (int,float) and type(rule['min_call_count']) is int and rule['min_call_count'] > 0, 'Invalid problem rule numeric settings')
        require(0 <= rule['threshold'] <= (1 if rule['metric'] == 'apdex.deficit' else 10**30), 'Invalid problem threshold range')
        require(type(rule['require_clean_sources']) is bool, 'Invalid clean-source gate')
        for field in ('signatures','users'):
            values = rule[field]
            require(values is None or isinstance(values,list) and values and all(isinstance(x,str) and x for x in values) and len(values) == len(set(values)), f'Invalid problem {field}')
        for field in ('min_db_linked_count_percent','min_db_linked_duration_percent'):
            value = rule[field]
            require(value is None or type(value) in (int,float) and 0 <= value <= 100, 'Invalid problem coverage gate')
            require(value is None or rule['metric'].startswith(('operation.db_','db_chatty.')), 'DB gate on non-DB metric')
        value = rule['db_events_threshold']
        require((type(value) is int and value > 0) if rule['metric'].startswith('db_chatty.') else value is None, 'Invalid DB rule threshold')


def validate_verification_metadata(manifest):
    if 'verification' not in manifest:
        return
    v = manifest['verification']
    require(isinstance(v, dict) and v.get('policy_version') == '1' and v.get('mode') in ('full', 'basic'), 'Invalid verification policy')
    require(v.get('scope') == 'saved_analysis_bundle' and
            v.get('full_verification') == ('passed' if v['mode'] == 'full' else 'skipped'), 'Invalid verification status')
    require(v.get('input_schema_version') == manifest.get('schema_version', manifest.get('input_schema_version')), 'Verification schema mismatch')
    require(all(isinstance(v.get(k), list) and all(isinstance(item, str) for item in v[k])
                for k in ('completed_groups', 'skipped_groups')), 'Invalid verification groups')


def load_input(analysis_dir, slices_dir=None):
    try:
        return _load_input(analysis_dir, slices_dir)
    except (OSError, UnicodeError, csv.Error, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
        raise ReportError(f'Invalid saved input: {exc}') from exc


def _load_input(analysis_dir, slices_dir):
    p = profile()
    root = Path(analysis_dir).resolve(strict=True)
    require(root.is_dir(), 'analysis_dir is not a directory')
    names = {'analysis_metrics.json','source_map.json','analysis.sqlite'} | {n+'.csv' for n in p['analysis_tables']}
    require(len(names) == 21, 'Internal schema profile must contain 21 analysis files')
    hashes = {n: descriptor(safe_file(root,n)) for n in sorted(names)}
    m = read_json(safe_file(root,'analysis_metrics.json'))
    require(isinstance(m, dict), 'Analysis manifest must be an object')
    validate_verification_metadata(m)
    for key, value in p['analysis_versions'].items():
        require(m.get(key) == value, f'Unsupported/missing {key}: expected {value}')
    require(m.get('publication_state') == 'complete', 'Analysis publication is incomplete')
    for key in ('analysis_complete','source_processing_complete','source_content_hashes_complete','absolute_timestamps_complete','salvage_nul_prefix'):
        require(type(m.get(key)) is bool, f'Missing/invalid {key}')
    require(m['source_processing_complete'] == m['analysis_complete'], 'Conflicting completeness flags')
    require(m.get('collection_completeness') == 'unknown', 'Unsupported collection_completeness')
    for key in ('units','method','counts','error_summary','artifacts'):
        require(isinstance(m.get(key), dict), f'Missing {key}')
    require(m['method'] == p['analysis_method'] and m['units'] == p['units'], 'Unsupported analysis method/units')
    for key in ('warnings','datasets','files','operations','identical_operations','heavy_sql','errors','locks','linkage','top_calls'):
        require(isinstance(m.get(key), list), f'Missing {key}')
    require(all(isinstance(w,dict) and isinstance(w.get('type'),str) for w in m['warnings']), 'Invalid saved warnings')
    for key in ('event_count','linked_error_event_count','unlinked_error_event_count','affected_call_count','suspected_incident_count','ambiguous_linked_error_event_count','fallback_linked_error_event_count'):
        require(type(m['error_summary'].get(key)) is int and m['error_summary'][key] >= 0, f'Invalid error_summary.{key}')
    require(isinstance(m.get('capture_id'),str) and m['capture_id'], 'Missing capture_id')
    require(isinstance(m.get('source_set_hash_sha256'), str) and len(m['source_set_hash_sha256']) == 64 and all(c in '0123456789abcdef' for c in m['source_set_hash_sha256']), 'Invalid source-set hash')
    require(set(m['artifacts']) == set(DETAIL_FILES), 'Invalid artifact descriptors')
    for n in DETAIL_FILES:
        d = m['artifacts'][n]
        require(isinstance(d,dict) and all(d.get(k) == v for k,v in hashes[n].items()) and type(d.get('row_count')) is int and d['row_count'] >= 0, f'Artifact mismatch: {n}')
    tables = {}
    for n, columns in p['analysis_tables'].items():
        # Validate every cell, retaining only identity/reference fields for detail
        # tables that cannot be displayed. Large SQL/context payloads stay on disk.
        retained = None
        if n+'.csv' in DETAIL_FILES:
            retained = set(KEYS[n]) | {k for k in columns if k.endswith('_id')}
        mirrors = mirror_index(n,m[n]) if n in m and isinstance(m[n],list) else None
        tables[n] = read_csv(safe_file(root,n+'.csv'), columns, retain_fields=retained, mirrors=mirrors)
        require(mirrors is None or len(mirrors) == len(tables[n]), f'{n}: JSON/CSV row count mismatch')
    for n, rows in tables.items():
        unique(rows, KEYS[n], n)
        if n+'.csv' in m['artifacts']:
            require(len(rows) == m['artifacts'][n+'.csv']['row_count'], f'{n}: row_count mismatch')
    counts = {'files':'sources_discovered','datasets':'datasets','operations':'operations','identical_operations':'identical_operation_rows','heavy_sql':'sql_patterns','errors':'error_signatures','locks':'lock_signatures','linkage':'linkage_rows','call_observations':'call_observations'}
    for table, key in counts.items():
        require(type(m['counts'].get(key)) is int and m['counts'][key] == len(tables[table]), f'{key}: count mismatch')
    sm = read_json(safe_file(root,'source_map.json'))
    require(isinstance(sm,dict) and sm.get('capture_id') == m.get('capture_id') and isinstance(sm.get('sources'),list) and len(sm['sources']) == m['artifacts']['source_map.json']['row_count'], 'Invalid source map')
    with closing(sqlite3.connect(safe_file(root,'analysis.sqlite').as_uri()+'?mode=ro&immutable=1', uri=True)) as db:
        require(db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'Corrupt SQLite')
        for table, columns in p['sqlite_columns'].items():
            require([r[1] for r in db.execute('PRAGMA table_info('+table+')')] == columns, f'SQLite schema mismatch: {table}')
        metadata = {k: strict_json(v, 'SQLite metadata') for k,v in db.execute('SELECT key,value FROM metadata')}
        require(all(metadata.get(k) == v for k,v in p['analysis_versions'].items() if k not in {'schema_version','analyzer_version','sql_fingerprint_algorithm'}), 'SQLite version mismatch')
        require(metadata.get('publication_state') == 'complete', 'SQLite publication incomplete')
    memberships = {}
    datasets = {r['dataset_id']:r for r in m['datasets']}
    for ds in m['datasets']:
        require(isinstance(ds.get('actual_measurement_ids'),list), 'Invalid dataset measurements')
        require(len(set(ds['actual_measurement_ids'])) == len(ds['actual_measurement_ids']), 'Duplicate dataset measurement')
        for mid in ds['actual_measurement_ids']:
            memberships.setdefault(mid,set()).add(ds['dataset_id'])
        require(type(ds.get('events_without_absolute_timestamp')) is int and ds['events_without_absolute_timestamp'] >= 0, 'Invalid dataset timestamp coverage')
        if ds['events_without_absolute_timestamp']:
            memberships.setdefault(ds['measurement_id']+'@unknown-date',set()).add(ds['dataset_id'])
    # Unknown-time identifiers must already be present in saved observations.
    # The schema's identifier rule validates ownership; no date/order is inferred.
    for table in ('call_observations','linkage'):
        for row in tables[table]:
            did,mid = row['dataset_id'],row['measurement_id']
            require(did in datasets, f'{table}: unknown dataset')
            ds = datasets[did]
            if mid not in ds['actual_measurement_ids']:
                require(ds['events_without_absolute_timestamp'] > 0 and mid == ds['measurement_id']+'@unknown-date', f'{table}: measurement inconsistent with dataset')
                if table == 'call_observations':
                    require(row['end_timestamp'] is None, 'Unknown-date CALL has absolute time')
            memberships.setdefault(mid,set()).add(did)
    mids = set(memberships)
    require(all(isinstance(x,str) and x for x in mids), 'Invalid measurement identifiers')
    for table in ('operations','heavy_sql','errors','locks','linkage','call_observations'):
        require(all(row['measurement_id'] in mids for row in tables[table]), f'{table}: measurement absent from dataset manifest')
    call_ids = {r['call_id'] for r in tables['call_observations']}
    require(all(r['call_id'] in call_ids for r in tables['top_calls']), 'Unknown top CALL')
    calls = {r['call_id']:r for r in tables['call_observations']}
    for row in tables['top_calls']:
        require(row == calls[row['call_id']], 'Top CALL differs from saved observation')
    ds_ids = {r['dataset_id'] for r in tables['datasets']}
    for table in ('operations','linkage','call_observations'):
        require(all(r['dataset_id'] in ds_ids for r in tables[table]), f'{table}: unknown dataset')
    bundle_id = digest(canonical(hashes).encode())
    result = SavedInput(root, None, m, None, tables, {}, hashes, {}, bundle_id, mids, memberships)
    if slices_dir is not None:
        sroot = Path(slices_dir).resolve(strict=True)
        require(sroot.is_dir(), 'slices_dir is not a directory')
        sh = {'slice_manifest.json': descriptor(safe_file(sroot,'slice_manifest.json'))}
        s = read_json(safe_file(sroot,'slice_manifest.json'))
        require(isinstance(s,dict), 'Invalid slice manifest')
        validate_verification_metadata(s)
        expected = {'calculator':'1c_tj_saved_result_slices','calculator_version':'1.8.0','slice_schema_version':'1.8','config_version':'1.0','bundle_id':bundle_id,'input_files':hashes,'input_schema_version':'1.6','input_analyzer_version':'1.6.1','input_sql_normalization_version':'2.0','input_linkage_rules_version':m['linkage_rules_version'],'input_error_rules':{k:m[k] for k in ('error_signature_version','error_linkage_rules_version','incident_rules_version')},'recorded_source_set_hash_sha256':m['source_set_hash_sha256'],'source_analysis_complete':m['analysis_complete'],'input_files_unchanged':True}
        for k,v in expected.items():
            require(s.get(k) == v, f'Slice manifest mismatch: {k}')
        c = s.get('configuration')
        validate_analytics(c,p['slice_tables'],bundle_id)
        require(all(r['call_id'] in call_ids for r in c['apdex']['confirmed_failures']['calls']), 'Confirmed failure references unknown CALL')
        signatures = {r['signature'] for r in tables['call_observations']}
        require(all(r['signature'] in signatures for r in c['apdex']['targets']) and all(sig in signatures for cls in c['apdex']['classes'] for sig in cls['signatures']), 'Unknown APDEX target signature')
        require(s.get('configuration_effective_sha256') == digest(canonical(c).encode()), 'Effective configuration hash mismatch')
        require(isinstance(s.get('configuration_file_sha256'),str) and len(s['configuration_file_sha256']) == 64 and all(x in '0123456789abcdef' for x in s['configuration_file_sha256']), 'Invalid original configuration hash')
        require(s.get('selected_slices') == c['slices'], 'Slice selection mismatch')
        require(isinstance(s.get('outputs'),dict) and set(s['outputs']) == {n+'.csv' for n in c['slices']}, 'Slice outputs mismatch')
        require('apdex_overall' not in c['slices'] or 'apdex_composition' in c['slices'], 'APDEX composition missing')
        require(s.get('population') == {'primary':'call_observations.csv','key':['bundle_id','call_id'],'count':len(call_ids),'json_and_top_calls_are_not_additional_observations':True}, 'Population contract mismatch')
        require(s.get('method') == p['slice_method'] and isinstance(s.get('validation_checks'),list), 'Missing/incompatible method/validation metadata')
        for selection in (c['measurement_ids'], c['operations']['measurement_order']):
            require(selection is None or isinstance(selection,list) and all(isinstance(x,str) and x in mids for x in selection) and len(selection) == len(set(selection)), 'Unknown/duplicate analytics measurement')
        order = c['operations']['measurement_order']
        require(order is None or set(order) == mids, 'Explicit order must cover the bundle')
        require(c['operations']['series_baseline_measurement_id'] is None or c['operations']['series_baseline_measurement_id'] in mids, 'Unknown baseline')
        slices = {}
        for name in c['slices']:
            file = name+'.csv'
            path = safe_file(sroot,file)
            sh[file] = descriptor(path)
            d = s['outputs'][file]
            require(isinstance(d,dict) and all(d.get(k) == v for k,v in sh[file].items()) and d.get('columns') == p['slice_tables'][name], f'Slice descriptor mismatch: {file}')
            rows = read_csv(path,p['slice_tables'][name],True)
            require(type(d.get('row_count')) is int and len(rows) == d['row_count'], f'{file}: row_count mismatch')
            unique(rows,SLICE_KEYS[name],name)
            for row in rows:
                for k,v in row.items():
                    if k == 'measurement_id' or k.endswith('_measurement_id'):
                        require(v is None or v in mids, f'{name}: unknown measurement in {k}')
                if 'call_id' in row:
                    require(row['call_id'] in call_ids, f'{name}: unknown CALL')
            slices[name] = rows
        result.slices_dir, result.slice_manifest, result.slices, result.slice_files = sroot,s,slices,sh
        validate_slice_links(result)
    result.assert_unchanged()
    return result


def validate_slice_links(data):
    """Join only existing rows. Filtered-out historical bases are allowed."""
    slices = data.slices
    operations = {}
    signatures = {r['signature'] for r in data.tables['call_observations']}
    for name,rows in slices.items():
        for row in rows:
            if 'operation_id' in row:
                oid,signature = row['operation_id'],row['signature']
                require(signature in signatures, f'{name}: unknown operation signature')
                require(oid not in operations or operations[oid] == signature, f'{name}: conflicting operation identity')
                operations[oid] = signature
    if 'comparability' in slices and 'measurement_comparisons' in slices:
        comparisons = {r['comparison_id']:r for r in slices['measurement_comparisons']}
        require(set(comparisons) == {r['comparison_id'] for r in slices['comparability']}, 'Comparability keys mismatch')
        for row in slices['comparability']:
            other = comparisons[row['comparison_id']]
            for key in row.keys() & other.keys():
                require(row[key] == other[key], f'Conflicting comparison {key}')
    positions = {}
    for name,rows in slices.items():
        for row in rows:
            if 'measurement_order' not in row or name == 'data_quality':
                continue
            mid, order = row['measurement_id'], row['measurement_order']
            require(order is not None and 1 <= order <= len(data.measurement_ids), f'{name}: invalid measurement order')
            require(mid not in positions or positions[mid] == order, 'Conflicting measurement order')
            positions[mid] = order
    require(len(set(positions.values())) == len(positions), 'Duplicate measurement order')
    order = data.slice_manifest['configuration']['operations']['measurement_order']
    if order is not None:
        require(all(order[int(position)-1] == mid for mid,position in positions.items() if position is not None), 'Order differs from saved configuration')
    selected = data.slice_manifest['configuration']['measurement_ids']
    selected = set(data.measurement_ids if selected is None else selected)
    history = {r['history_id']:r for r in slices.get('operation_history',[])}
    for name in ('measurement_comparisons','comparability','apdex_changes','db_chatty_changes'):
        for row in slices.get(name,[]):
            for side in ('reference','current'):
                key = row.get(side+'_history_id')
                mid = row.get(side+'_measurement_id')
                if key is None or 'operation_history' not in slices:
                    continue
                require(key in history or mid not in selected, f'{name}: missing {side} history row')
                if key in history:
                    other = history[key]
                    require(other['measurement_id'] == mid, f'{name}: history measurement mismatch')
                    require(all(other[k] == row[k] for k in ('operation_id','cohort_id','signature','user')), f'{name}: history identity mismatch')
                    require(other['count'] == row[side+'_count'], f'{name}: history population mismatch')
                    if name == 'measurement_comparisons':
                        for field in other:
                            mirrored = field+'_'+side
                            if mirrored in row:
                                require(row[mirrored] == other[field], f'{name}: saved {mirrored} differs from history')
    for name,rows in slices.items():
        for row in rows:
            for field in ('measurement_ids','scope_measurement_ids','output_measurement_ids'):
                if field not in row:
                    continue
                mids = row[field]
                require(isinstance(mids,list) and all(isinstance(x,str) for x in mids) and len(mids) == len(set(mids)) and set(mids) <= data.measurement_ids, f'{name}: invalid population {field}')
                if row.get('population_scope') == 'measurement_all_users':
                    require(mids == [row['measurement_id']], f'{name}: conflicting measurement scope')
    if 'apdex_overall' in slices:
        parents = {r['overall_id']:r for r in slices['apdex_overall']}
        groups = {r['apdex_row_id']:r for r in slices.get('apdex',[])}
        members = {key:[] for key in parents}
        for row in slices['apdex_composition']:
            require(row['overall_id'] in parents, 'Unknown APDEX overall_id')
            other = parents[row['overall_id']]
            members[row['overall_id']].append(row)
            require(row['scope_measurement_ids'] == other['measurement_ids'] and row['measurement_id'] in other['measurement_ids'], 'APDEX composition scope mismatch')
            for key in ('population_scope','target_status','assessment_scope','failure_policy'):
                require(row[key] == other[key], f'APDEX composition {key} mismatch')
            require(row['overall_apdex_denominator'] == other['apdex_denominator'], 'APDEX composition denominator mismatch')
            if 'apdex' in slices:
                require(row['apdex_row_id'] in groups, 'Unknown APDEX group')
                group = groups[row['apdex_row_id']]
                for key in row.keys() & group.keys():
                    require(row[key] == group[key], f'APDEX group {key} mismatch')
                require(row['operation_user_measurement_apdex'] == group['apdex'] and row['call_count'] == group['count'], 'APDEX composition value mismatch')
        for key,parent in parents.items():
            require(parent['composition_file'] == 'apdex_composition.csv' and len(members[key]) == parent['composition_row_count'], 'APDEX composition row count mismatch')
            require(len({r['apdex_row_id'] for r in members[key]}) == len(members[key]), 'Duplicate APDEX composition member')
    if 'apdex_coverage' in slices:
        coverage = {scope_key(r):r for r in slices['apdex_coverage']}
        require(len(coverage) == len(slices['apdex_coverage']), 'Duplicate APDEX coverage scope')
        for row in slices.get('apdex_overall',[]):
            require(scope_key(row) in coverage, 'Missing APDEX coverage scope')
            other = coverage[scope_key(row)]
            require(row['call_share_denominator'] == other['call_share_denominator'] and row['total_calls_in_scope'] == other['total_call_count'], 'APDEX coverage population mismatch')
    rules = {r['rule_id']:r for r in data.slice_manifest['configuration']['problems']['rules']}
    metric_indexes = {name:{r[SLICE_KEYS[name][0]]:r for r in slices[name]} for name in ('operation_history','db_chatty','apdex') if name in slices}
    for name,rows in slices.items():
        if not name.startswith('problem_'):
            continue
        for row in rows:
            require(row['rule_id'] in rules, f'{name}: unknown rule')
            rule = rules[row['rule_id']]
            for key in ('metric','operator','threshold','min_call_count','scope'):
                if key in row:
                    expected = Decimal(str(rule[key])) if isinstance(row[key],Decimal) else rule[key]
                    require(row[key] == expected, f'{name}: rule {key} mismatch')
            metric = profile()['problem_metrics'][rule['metric']]
            if 'metric_unit' in row:
                require(row['metric_unit'] == metric['unit'] and row['metric_source_slice'] == metric['source'], f'{name}: problem metric source/unit mismatch')
            source = metric['source']
            if source in slices and row.get('metric_source_row_id') is not None:
                index = metric_indexes[source]
                key = row['metric_source_row_id']
                require(key in index or row['measurement_id'] not in selected, f'{name}: missing metric source row')
                if key in index:
                    other = index[key]
                    require(all(row[k] == other[k] for k in ('signature','user','measurement_id')), f'{name}: metric identity mismatch')
                    require(row['source_metric_value'] == other[metric['field']], f'{name}: source metric value mismatch')


def scope_key(row):
    return (row['population_scope'],tuple(row['measurement_ids']),row['failure_policy'],row['assessment_scope'])
