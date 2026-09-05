"""Presentation of retained rows; no population statistics or analytic statuses."""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
import json

try:
    from .report_schema import require, canonical, unit, profile
    from .report_config import SECTIONS
    from .report_input import KEYS, SLICE_KEYS, scope_key
except ImportError:
    from report_schema import require, canonical, unit, profile
    from report_config import SECTIONS
    from report_input import KEYS, SLICE_KEYS, scope_key


class DisplayState(str, Enum):
    READY = 'готовые данные'
    NOT_CALCULATED = 'не рассчитано'
    NO_OBSERVATIONS = 'нет наблюдений'
    UNAVAILABLE = 'показатель недоступен'
    PARTIAL = 'частичные данные'


@dataclass(frozen=True)
class Cell:
    value: object
    source_file: str
    row_key: str
    field: str
    unit: str = ''
    state: DisplayState = DisplayState.READY
    reason: str = ''
    sensitive: bool = False


@dataclass(frozen=True)
class PresentedRow:
    key: str
    cells: tuple[Cell, ...]
    state: DisplayState


@dataclass
class TableView:
    name: str
    rows: list[PresentedRow]
    available_rows: int
    state: DisplayState
    note: str = ''


@dataclass
class Section:
    id: str
    title: str
    tables: list[TableView] = field(default_factory=list)
    state: DisplayState = DisplayState.READY
    note: str = ''


@dataclass(frozen=True)
class CompactRow:
    key: str
    cells: tuple[Cell, ...]
    state: DisplayState


@dataclass
class CompactTable:
    name: str
    title: str
    headers: tuple[str, ...]
    rows: list[CompactRow]
    state: DisplayState = DisplayState.READY
    note: str = ''


@dataclass
class MainSection:
    id: str
    title: str
    tables: list[CompactTable] = field(default_factory=list)
    state: DisplayState = DisplayState.READY
    note: str = ''


@dataclass
class ReportModel:
    title: str
    report_date: str
    kind: str
    bundle_id: str
    partial: bool
    sections: list[Section]
    main_sections: list[MainSection] = field(default_factory=list)
    verification_notice: str = ''


def stable_key(name, row):
    keys = (SLICE_KEYS | KEYS)[name]
    return json.dumps([str(row[k]) if isinstance(row[k], Decimal) else row[k] for k in keys], ensure_ascii=False)


def join_rows(left, right, key):
    """Exact one-to-one join, retaining fields and their table-qualified names."""
    index = {row[key]: row for row in right}
    require(len(index) == len(right), f'Duplicate join key: {key}')
    result = []
    for row in left:
        require(row[key] in index, f'Missing join key: {key}')
        result.append((row, index[row[key]]))
    return result


def select_rows(name, source, config, data=None):
    c = config.settings
    rows = list(source)
    selected = c.get('display_measurement_ids')
    focus = c.get('focus_measurement_id') if c['report_kind'] == 'overview' else None
    if selected is not None or focus:
        visible = set(selected) if selected is not None else None
        if focus:
            visible = {focus} if visible is None else visible.intersection({focus})
        if name in {'problem_registry','problem_persisting','problem_unchecked'}:
            pass  # Ready latest snapshots retain their full-bundle meaning.
        elif name in {'files','datasets'} and data is not None:
            datasets = {did for mid in visible for did in data.measurement_datasets[mid]}
            captures = {r['measurement_id'] for r in data.tables['datasets'] if r['dataset_id'] in datasets}
            rows = [r for r in rows if r['dataset_id'] in datasets or name == 'files' and r['measurement_id'] in captures]
        else:
            def in_scope(row):
                mid = row.get('current_measurement_id',row.get('measurement_id'))
                if mid is not None:
                    return mid in visible
                scope = row.get('measurement_ids',row.get('scope_measurement_ids'))
                return isinstance(scope,list) and bool(scope) and set(scope) <= visible
            rows = [r for r in rows if in_scope(r)]
    opts = c.get('tables',{}).get(name,{})
    sorts = opts.get('sort',[])
    if sorts:
        rows.sort(key=lambda r: stable_key(name,r))
        for item in reversed(sorts):
            k = item['field']
            available = [r for r in rows if r[k] is not None]
            missing = [r for r in rows if r[k] is None]
            def sort_key(r):
                v = r[k]
                return canonical(v) if isinstance(v,(dict,list)) else v
            rows = sorted(available,key=sort_key,reverse=item['direction']=='desc') + missing
    count = len(rows)
    n = opts.get('top_n')
    if name in {'operation_history','operation_history_all_users','problem_history'}:
        key = 'problem_id' if name == 'problem_history' else 'cohort_id'
        selected_keys = []
        selected_set = set()
        for row in rows:
            if row[key] not in selected_set:
                selected_keys.append(row[key])
                selected_set.add(row[key])
                if n is not None and len(selected_keys) == n:
                    break
        groups = {identity:[] for identity in selected_keys}
        for row in rows:
            if row[key] in groups:
                groups[row[key]].append(row)
        rows = [r for identity in selected_keys for r in sorted(groups[identity],key=lambda r:(r['measurement_order'] is None,r['measurement_order']))]
    elif n is not None and c['report_kind'] == 'overview' and data is not None and len({r.get('measurement_id') for r in rows if r.get('measurement_id') is not None}) > 1:
        grouped = {}
        for row in rows:
            grouped.setdefault(row.get('measurement_id'),[]).append(row)
        order = {}
        for table in (data.slices.get('data_quality',[]),data.slices.get('operation_history',[])):
            for row in table:
                if row.get('measurement_order') is not None:
                    order.setdefault(row['measurement_id'],row['measurement_order'])
        mids = sorted(grouped,key=lambda mid:(order.get(mid,10**18),str(mid)))
        rows = [row for mid in mids for row in grouped[mid][:n]]
    elif n is not None:
        rows = rows[:n]
    return rows,count


def missing_reason(row, field):
    if row.get('observation_status') == 'not_observed' or row.get('threshold_status') == 'не наблюдалось':
        return 'нет наблюдений'
    if row.get('target_coverage_status') == 'uncovered_no_target' or 'APDEX_T_not_defined' in (row.get('insufficient_reasons') or []):
        return 'цель APDEX не задана'
    if field.endswith('change_status'):
        direction = field[:-len('change_status')]+'change_direction'
        if row.get(direction) == 'unchanged':
            return 'направление: unchanged; числовой статус не задан расчётчиком'
    if 'percent' in field:
        prefix = field[:-len('delta_percent')] if field.endswith('delta_percent') else ''
        if row.get(prefix+'percent_status') == 'undefined_zero_reference' or row.get('sample_count_percent_status') == 'undefined_zero_reference' and field.startswith('sample_count'):
            return 'процент не определён: нулевая база'
        metrics = row.get('percent_undefined_zero_reference_metrics') or []
        if field.removesuffix('_delta_percent') in metrics:
            return 'процент не определён: нулевая база'
    if row.get('reference_relation') == 'no_reference' and ('reference' in field or 'delta' in field):
        return 'база сравнения отсутствует'
    return 'показатель недоступен'


def row_cells(name, row, key):
    cells = []
    counter_units = {'cpu_us':'us','memory':'bytes','memory_peak':'bytes','in_bytes':'bytes','out_bytes':'bytes','rows_affected':'','db_rows':''}
    quality_values = {'sum_known','sum_complete','mean','max_known','value'}
    def append(value, field, units='', sensitive=False):
        if isinstance(value,dict):
            for child, item in value.items():
                child_unit = ''
                if child in quality_values:
                    child_unit = next((counter_units[token] for token in field.split('.') if token in counter_units),'')
                elif child == 'coverage_percent':
                    child_unit = '%'
                elif child in profile()['fields'].get('data_quality',{}):
                    child_unit = unit('data_quality',child)
                elif child in {'duration_us','max_us','min_us','avg_us'}:
                    child_unit = 'us'
                append(item,field+'.'+child,child_unit,sensitive)
            if value:
                return
        cells.append(Cell(value,name+'.csv',key,field,units,DisplayState.UNAVAILABLE if value is None else DisplayState.READY,missing_reason(row,field) if value is None else '',sensitive))
    for field,value in row.items():
        append(value,field,unit(name,field,row),field in {'source','resolved_source','input_root','member'})
    return tuple(cells)


def present_table(name, source, config, partial, data=None, *, selected=None, note=''):
    rows,count = select_rows(name,source,config,data) if selected is None else (selected,len(selected))
    presented = []
    for r in rows:
        key = stable_key(name,r)
        state = DisplayState.PARTIAL if partial else DisplayState.READY
        if r.get('observation_status') == 'not_observed' or r.get('threshold_status') == 'не наблюдалось':
            state = DisplayState.NO_OBSERVATIONS
        elif r.get('source_status', r.get('status')) in {'partial_read_error','partial_nul_salvaged'} or r.get('measurement_source_health') == 'known_related_capture_gaps':
            state = DisplayState.PARTIAL
        presented.append(PresentedRow(key,row_cells(name,r,key),state))
    state = DisplayState.NO_OBSERVATIONS if not rows else (DisplayState.PARTIAL if partial else DisplayState.READY)
    note += (' В сохранённой таблице нет строк.' if not source else (' Нет строк в выбранном отображении.' if not rows else ''))
    if name in {'operation_history','operation_history_all_users','problem_history'}:
        note += ' Сортировка и top-N выбирают траектории по начальным строкам; внутри каждой показаны все сохранённые точки окна в порядке measurement_order.'
    if name in {'problem_registry','problem_persisting','problem_unchecked'}:
        note += ' Снимок последнего замера полного комплекта; выбор исторического окна его не заменяет.'
    return TableView(name,presented,count,state,note)


def _comparability_by_id(rows):
    # The loader enforces unique IDs. Keep all matches in source order here
    # to preserve the model's existing behavior for already assembled inputs.
    index = {}
    for row in rows:
        index.setdefault(row['comparison_id'], []).append(row)
    return index


def build_model(data, config):
    c = config.settings
    for selected in (c.get('display_measurement_ids'), [c['focus_measurement_id']] if c.get('focus_measurement_id') else None):
        require(selected is None or set(selected) <= data.measurement_ids, 'Unknown presentation measurement')
    keys = {'measurements':data.measurement_ids,
            'users':{r['user'] for r in data.tables['call_observations']},
            'operations':{r['signature'] for r in data.tables['operations']} | {r['operation_id'] for rows in data.slices.values() for r in rows if 'operation_id' in r}}
    for kind, mapping in c['labels'].items():
        require(set(mapping) <= keys[kind], f'Unknown label identifiers: {kind}')
    partial = data.manifest['analysis_complete'] is False
    sections = []
    for section_id in c['sections']:
        title, names = SECTIONS[section_id]
        section = Section(section_id,title)
        if section_id == 'provenance':
            cells = []
            def add(value,source,path,units=''):
                if isinstance(value,dict) and value:
                    for key,item in value.items():
                        child_unit = unit('problem_history','threshold',value) if key == 'threshold' and 'metric' in value else 's' if key == 't_seconds' else ''
                        add(item,source,path+'/'+key,child_unit)
                elif isinstance(value,list) and value and isinstance(value[0],dict):
                    for i,item in enumerate(value):
                        add(item,source,path+'/'+str(i))
                else:
                    cells.append(Cell(value,source,'manifest',path,units,state=DisplayState.UNAVAILABLE if value is None else DisplayState.READY,sensitive=path.rsplit('/',1)[-1] in {'path','input_root','resolved_source','member'}))
            for key in (*profile()['analysis_versions'], 'publication_state','analysis_complete','source_processing_complete','source_content_hashes_complete','absolute_timestamps_complete','collection_completeness','source_set_hash_sha256','counts','error_summary','units','warnings'):
                add(data.manifest[key],'analysis_metrics.json','/'+key)
            add(data.bundle_id,'structural_validation','/bundle_id')
            add(config.sha256,'presentation_configuration','/configuration_sha256')
            for key in ('display_measurement_ids','focus_measurement_id'):
                if key in c:
                    add(c[key],'presentation_configuration','/'+key)
            if data.slice_manifest:
                for key in ('calculator_version','slice_schema_version','configuration','configuration_effective_sha256','selected_slices'):
                    add(data.slice_manifest[key],'slice_manifest.json','/'+key)
            section.tables = [TableView('provenance',[PresentedRow('manifest',cells,DisplayState.PARTIAL if partial else DisplayState.READY)],1,DisplayState.PARTIAL if partial else DisplayState.READY)]
            section.note = 'Проверены структура и хеши сохранённых файлов. Аналитика не пересчитывалась. Полнота ТЖ не установлена. Совпадение сигнатур не подтверждает одинаковый сценарий.'
        else:
            if section_id == 'operations' and c['report_kind'] == 'history':
                names = ('operation_history',)
            def append_table(name, selected=None, note=''):
                source = data.slices.get(name,data.tables.get(name))
                if source is None:
                    section.tables.append(TableView(name,[],0,DisplayState.NOT_CALCULATED,'Срез не предоставлен. '+note))
                    section.state = DisplayState.NOT_CALCULATED
                else:
                    section.tables.append(present_table(name,source,config,partial,data,selected=selected,note=note))
            if section_id == 'comparisons':
                rows,available = select_rows('measurement_comparisons',data.slices.get('measurement_comparisons',[]),config,data)
                contexts = _comparability_by_id(data.slices.get('comparability',[])) if rows else {}
                if not rows:
                    append_table('measurement_comparisons')
                    append_table('comparability',selected=[])
                for row in rows:
                    append_table('measurement_comparisons',selected=[row])
                    context = contexts.get(row['comparison_id'], [])
                    append_table('comparability',selected=context,note='Ограничения относятся к comparison_id выше; сохранённая база не меняется фильтром.')
                section.note = f'Выбрано {len(rows)} из {available} сохранённых сравнений в окне отображения. Показаны сохранённые базы сравнения и статусы. Числовое изменение не доказывает исправление или регрессию кода.'
            elif section_id == 'apdex_overall':
                rows,available = select_rows('apdex_overall',data.slices.get('apdex_overall',[]),config,data)
                if not rows:
                    for name in names:
                        append_table(name,selected=[])
                for row in rows:
                    append_table('apdex_overall',selected=[row])
                    append_table('apdex_composition',selected=[r for r in data.slices.get('apdex_composition',[]) if r['overall_id'] == row['overall_id']],note='Полный сохранённый состав этого overall_id; top-N к составу не применяется.')
                    append_table('apdex_coverage',selected=[r for r in data.slices.get('apdex_coverage',[]) if scope_key(r) == scope_key(row)],note='Покрытие всей указанной области, включая обе категории целей; не только показанной категории target_status.')
                section.note = f'Выбрано {len(rows)} из {available} сохранённых итогов в окне отображения. Общий APDEX показан только для сохранённой области целиком. Фильтр исключает итог с замерами вне окна; состав и покрытие следуют за итогом. Области могут пересекаться.'
            else:
                for name in names:
                    if name == 'problem_rule_coverage':
                        continue
                    append_table(name)
                    if name.startswith('problem_'):
                        rows,_ = select_rows(name,data.slices.get(name,[]),config,data)
                        wanted = {(r['rule_id'],r['measurement_id']) for r in rows}
                        coverage = [r for r in data.slices.get('problem_rule_coverage',[]) if (r['rule_id'],r['measurement_id']) in wanted]
                        append_table('problem_rule_coverage',selected=coverage,note='Покрытие правил для показанных строк. Сохранённые статусы порога и изменения независимы.')
                        if wanted - {(r['rule_id'],r['measurement_id']) for r in coverage}:
                            section.note += ' Покрытие некоторых правил/замеров не предоставлено; в частности, снимок последнего замера может быть вне окна сохранённых срезов.'
                if section_id == 'quality' and 'data_quality' not in data.slices:
                    section.note = 'Готовые флаги анализа показаны в разделе происхождения; сводка качества не рассчитана.'
                if section_id == 'sources':
                    section.note = 'Источники выбраны через принадлежность замеров наборам данных. Показатели файлов и наборов сохраняют исходную область capture, которая может охватывать несколько дней.'
        sections.append(section)
    model = ReportModel(c['title'],c['report_date'],c['report_kind'],data.bundle_id,partial,sections)
    policies = [m.get('verification') for m in (data.manifest, data.slice_manifest or {})]
    if any(v and v.get('mode') == 'basic' for v in policies):
        model.verification_notice = 'При подготовке данных использован режим basic. Полная верификация не выполнялась на одном или нескольких этапах. Построение PDF не заменяет полную верификацию.'
    elif any(policies):
        model.verification_notice = 'Сохранённый комплект анализа проверен в режиме full. Статус отдельной проверки воспроизводимости срезов в комплекте не записан.'
    try:
        from .report_presentations import build_main_sections
    except ImportError:
        from report_presentations import build_main_sections
    model.main_sections = build_main_sections(model,data,config)
    return model


def format_cell(cell, config):
    if cell.value is None:
        return '- ('+(cell.reason or 'показатель недоступен')+')'
    v = cell.value
    fmt = config.settings['format']
    if isinstance(v, bool):
        return 'да' if v else 'нет'
    if isinstance(v,(Decimal,int,float)):
        n, units = Decimal(str(v)), cell.unit
        if units == 'us':
            target = fmt['duration']
            n = n / {'us':1,'ms':1000,'s':1000000}[target]
            units = {'us':'мкс','ms':'мс','s':'с'}[target]
        elif units == 'bytes' and fmt['volume'] == 'MiB':
            n = n / (1024*1024)
            units = 'MiB'
        elif units == 's':
            units = 'с'
        elif units == 'pp':
            units = 'п.п.'
        text = str(n) if n == n.to_integral() else f'{n:.{fmt["digits"]}f}'
        return text.replace('.',',') + (' '+units if units else '')
    if isinstance(v,(dict,list)):
        return json.dumps(v,ensure_ascii=False,indent=2)
    label_group = 'measurements' if cell.field == 'measurement_id' or cell.field.endswith('_measurement_id') else 'users' if cell.field == 'user' else 'operations' if cell.field in {'signature','operation_id'} else None
    label = config.settings['labels'].get(label_group,{}).get(v) if label_group else None
    return f'{label} [{v}]' if label and label != v else str(v)
