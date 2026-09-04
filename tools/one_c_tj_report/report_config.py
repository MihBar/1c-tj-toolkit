"""Presentation settings only. No thresholds, scoring or comparison selection."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path

try:
    from .report_schema import require, strict_json, digest, profile
except ImportError:
    from report_schema import require, strict_json, digest, profile

SECTIONS = {
    'provenance': ('Происхождение', ()),
    'sources': ('Источники', ('files', 'datasets')),
    'quality': ('Качество данных', ('data_quality',)),
    'operations': ('Операции', ('operations',)),
    'operations_all_users': ('Операции: все пользователи', ('operation_history_all_users',)),
    'comparisons': ('Сравнения', ('measurement_comparisons', 'comparability')),
    'db_chatty': ('DB-chatty', ('db_chatty', 'db_chatty_calls', 'db_chatty_fast_calls', 'db_chatty_duration', 'db_chatty_coverage', 'db_chatty_changes')),
    'db_chatty_summary': ('DB-chatty: сводка', ('db_chatty', 'db_chatty_coverage')),
    'db_chatty_comparison': ('DB-chatty: сравнения', ('db_chatty_changes',)),
    'apdex': ('APDEX', ('apdex', 'apdex_coverage', 'apdex_uncovered')),
    'apdex_overall': ('APDEX: итог и состав', ('apdex_overall', 'apdex_composition', 'apdex_coverage')),
    'apdex_changes': ('APDEX: изменения', ('apdex_changes',)),
    'problems': ('Числовые правила', ('problem_registry', 'problem_rule_coverage')),
    'problem_history': ('История правил', ('problem_history', 'problem_rule_coverage')),
    'problem_views': ('Представления правил', ('problem_improved', 'problem_persisting', 'problem_worsened', 'problem_new', 'problem_unchecked')),
    'sql': ('SQL', ('heavy_sql',)), 'errors': ('Ошибки', ('errors',)),
    'locks': ('Блокировки', ('locks',)),
}

DEFAULT_SECTIONS_BY_KIND = {
    'overview': ['provenance','sources','quality','operations','sql','errors','locks'],
    'comparison': ['provenance','quality','comparisons'],
    'history': ['provenance','quality','operations','problem_history'],
}


@dataclass(frozen=True)
class ReportConfig:
    path: Path
    sha256: str
    settings: dict

    def assert_unchanged(self):
        require(digest(self.path.read_bytes()) == self.sha256, 'Presentation configuration changed')


def load_config(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    c = strict_json(raw.decode('utf-8-sig'), 'report configuration')
    allowed = {'report_config_version', 'report_kind', 'title', 'document_notice', 'locale', 'report_date', 'labels', 'sections', 'tables', 'display_measurement_ids', 'focus_measurement_id', 'format', 'fonts'}
    require(isinstance(c, dict) and set(c) <= allowed, 'Unknown presentation configuration fields')
    require(c.get('report_config_version') == '1.0', 'report_config_version must be 1.0')
    require(c.get('report_kind') in {'overview', 'comparison', 'history'}, 'Invalid report_kind')
    require(c.get('locale') == 'ru-RU', 'Only locale ru-RU is supported')
    require(isinstance(c.get('title'), str) and c['title'].strip(), 'title is required')
    require(c.get('document_notice') is None or isinstance(c['document_notice'],str) and c['document_notice'].strip(), 'document_notice must be a non-empty string')
    require(isinstance(c.get('report_date'), str), 'Explicit report_date is required')
    date.fromisoformat(c['report_date'])
    sections = c.get('sections', DEFAULT_SECTIONS_BY_KIND[c['report_kind']])
    require(isinstance(sections, list) and all(isinstance(x, str) and x in SECTIONS for x in sections) and len(set(sections)) == len(sections), 'Invalid sections')
    require('provenance' in sections, 'provenance is required')
    c['sections'] = sections
    labels = c.setdefault('labels', {})
    require(isinstance(labels, dict) and set(labels) <= {'measurements', 'users', 'operations'}, 'Invalid labels')
    for mapping in labels.values():
        require(isinstance(mapping, dict) and all(isinstance(k, str) and isinstance(v, str) and v.strip() for k,v in mapping.items()), 'Invalid label mapping')
    ids = c.get('display_measurement_ids')
    require(ids is None or isinstance(ids, list) and all(isinstance(x, str) and x for x in ids) and len(set(ids)) == len(ids), 'Invalid display_measurement_ids')
    require(c.get('focus_measurement_id') is None or isinstance(c['focus_measurement_id'], str) and c['focus_measurement_id'], 'Invalid focus_measurement_id')
    require(c.get('focus_measurement_id') is None or c['report_kind'] == 'overview', 'focus_measurement_id is only valid for overview')
    p = profile()
    schemas = p['analysis_tables'] | p['slice_tables']
    tables = c.setdefault('tables', {})
    require(isinstance(tables, dict), 'tables must be an object')
    for name, opts in tables.items():
        require(name in schemas and isinstance(opts, dict) and set(opts) <= {'sort', 'top_n'}, f'Unknown table/settings: {name}')
        n = opts.get('top_n')
        require(n is None or type(n) is int and n > 0, f'{name}: top_n must be positive or null')
        require(n is None or name not in {'comparability','apdex_composition','apdex_coverage','problem_rule_coverage'}, f'{name}: dependent context cannot be limited by top_n')
        sort = opts.get('sort', [])
        require(isinstance(sort, list), 'sort must be a list')
        for item in sort:
            require(isinstance(item, dict) and set(item) == {'field', 'direction'} and item['field'] in schemas[name] and item['direction'] in {'asc', 'desc'}, f'{name}: invalid sort')
    fmt = c.setdefault('format', {})
    require(isinstance(fmt, dict) and set(fmt) <= {'digits', 'duration', 'volume', 'show_paths', 'show_sql'}, 'Invalid format')
    fmt.setdefault('digits', 3)
    fmt.setdefault('duration', 's')
    fmt.setdefault('volume', 'MiB')
    fmt.setdefault('show_paths', False)
    fmt.setdefault('show_sql', True)
    require(type(fmt['digits']) is int and 0 <= fmt['digits'] <= 9 and fmt['duration'] in {'us', 'ms', 's'} and fmt['volume'] in {'bytes', 'MiB'}, 'Invalid units/precision')
    require(type(fmt['show_paths']) is bool and type(fmt['show_sql']) is bool, 'Invalid visibility settings')
    fonts = c.setdefault('fonts', {'profile': 'liberation-sans'})
    require(isinstance(fonts, dict), 'Invalid fonts')
    if 'profile' in fonts:
        require(fonts == {'profile': 'liberation-sans'}, 'Unknown font profile')
    else:
        require(set(fonts) == {'regular', 'bold'} and all(isinstance(v, str) and v for v in fonts.values()), 'fonts requires regular and bold paths')
        c['fonts'] = {k: str((path.parent/v).resolve(strict=True)) for k,v in fonts.items()}
    return ReportConfig(path, digest(raw), c)
