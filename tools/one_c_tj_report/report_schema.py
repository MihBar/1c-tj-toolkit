"""Pinned, data-only schema profile. Never imports analyzer/calculator code."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from functools import lru_cache


class ReportError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ReportError(message)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data, label):
    def pairs(items):
        obj = {}
        for key, value in items:
            require(key not in obj, f"{label}: duplicate key {key}")
            obj[key] = value
        return obj

    def invalid(value):
        raise ReportError(f"{label}: non-finite number {value}")

    try:
        result = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
        canonical(result)  # also rejects overflow such as 1e999
        return result
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ReportError(f"{label}: {exc}") from exc


@lru_cache(maxsize=1)
def profile():
    return strict_json(Path(__file__).with_name('schema_profile.json').read_text(encoding='utf-8'), 'schema profile')


DETAIL_FILES = ('analysis.sqlite', 'source_map.json', 'db_observations.csv',
                'event_links.csv', 'link_candidates.csv', 'error_observations.csv',
                'error_event_links.csv', 'error_link_candidates.csv',
                'error_incidents.csv', 'error_incident_members.csv')

def field_spec(table, field):
    """Exact pinned field metadata; names never determine units at runtime."""
    spec = profile()['fields'].get(table, {}).get(field)
    require(spec is not None, f'Unknown schema field: {table}.{field}')
    return spec


def field_type(table, field, is_slice=False):
    return field_spec(table, field)['type']


def unit(table, field, row=None):
    spec = field_spec(table, field)
    if table.startswith('problem_') and row is not None:
        dynamic = {'threshold', 'value', 'source_metric_value', 'first_problem_value', 'reference_value', 'delta_absolute'}
        if field in dynamic or field.endswith(('_reference_value', '_delta_absolute')):
            metric = row.get('metric')
            catalog = profile()['problem_metrics'].get(metric)
            require(catalog is not None, f'Unknown problem metric: {metric}')
            if field == 'source_metric_value' and metric == 'apdex.deficit':
                return 'APDEX'
            value = {'microseconds':'us', 'bytes':'bytes', 'percent':'%',
                     'seconds_per_CALL':'s', 'DB_events_per_CALL':'DB/CALL',
                     '1_minus_APDEX':'1 − APDEX', 'CALL_count':'CALL', 'count':''}[catalog['unit']]
            return 'pp' if value == '%' and field.endswith('delta_absolute') else value
    return spec['unit']
