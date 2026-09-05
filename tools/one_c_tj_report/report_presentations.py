"""Mode-specific compact views over saved cells; no analytical calculations."""
from __future__ import annotations

import re

try:
    from .report_schema import require
    from .report_input import scope_key
    from .report_model import (Cell, CompactRow, CompactTable, MainSection,
                               DisplayState, select_rows, row_cells, stable_key)
except ImportError:
    from report_schema import require
    from report_input import scope_key
    from report_model import (Cell, CompactRow, CompactTable, MainSection,
                              DisplayState, select_rows, row_cells, stable_key)


# These are presentation choices only. Every selected value remains the original
# Cell with its source file, saved row key, field, unit and missing-value reason.
STANDARD = {
    'files': ('Файлы источников', (
        ('Источник','source_id'),('Набор','dataset_id'),('Область capture','measurement_id'),
        ('Состояние','status'),('Записей','records'),('Ошибок разбора','parse_errors'))),
    'datasets': ('Наборы данных', (
        ('Набор','dataset_id'),('Область capture','measurement_id'),('Замеры','actual_measurement_ids'),
        ('Записей','records'),('Ошибок разбора','parse_errors'),('Без абсолютного времени','events_without_absolute_timestamp'))),
    'data_quality': ('Качество данных по замерам', (
        ('Порядок','measurement_order'),('Замер','measurement_id'),('CALL','call_count'),
        ('Пользователи','user_count'),('Операции','operation_signature_count'),
        ('CALL без времени','calls_without_time'),('CALL из частичных источников','calls_from_partial_sources'),
        ('Покрытие DB по количеству','db_linked_count_percent'),('Покрытие DB по времени','db_linked_duration_percent'),
        ('Состояние выборки','sample_size_status'),('Состояние источников','recorded_source_health'))),
    'operations': ('Операции по сохранённым показателям', (
        ('Замер','measurement_id'),('Операция','signature'),('Пользователь','user'),('Приоритет','priority'),
        ('CALL','count'),('Среднее','avg_us'),('P95','p95_us'),('Максимум','max_us'),
        ('DB/CALL','db_per_call'),('DB время/CALL','db_seconds_per_call'),
        ('Ошибки','error_count'),('Блокировки','lock_count'))),
    'heavy_sql': ('SQL по сохранённым показателям', (
        ('Замер','measurement_id'),('Отпечаток SQL','sql_fingerprint_sha256'),('События','count'),
        ('Суммарное время','duration_us'),('Среднее','avg_us'),('P95','p95_us'),('Максимум','max_us'),
        ('Таблицы','tables'),('Нормализация','sql_normalization_status'),('Пример SQL','sample_sql'))),
    'errors': ('Ошибки', (
        ('Замер','measurement_id'),('Категория','category'),('Сигнатура','signature'),
        ('События','event_count'),('Связанные события','linked_error_event_count'),
        ('Затронутые CALL','affected_call_count'),('Предполагаемые инциденты','suspected_incident_count'))),
    'locks': ('Блокировки', (
        ('Замер','measurement_id'),('Событие','event'),('Контекст','context'),('Количество','count'),
        ('Суммарное время','duration_us'),('P95','p95_us'),('Связанные CALL','linked_call_count'))),
    'operation_history': ('Показатели операций по замерам', (
        ('Операция','signature'),('Пользователь','user'),('Порядок','measurement_order'),('Замер','measurement_id'),
        ('Наблюдение','observation_status'),('CALL','count'),('Среднее','avg_us'),('P95','p95_us'),
        ('DB/CALL','db_per_call'),('DB время/CALL','db_seconds_per_call'),('CPU/стена','cpu_percent_of_wall'))),
    'operation_history_all_users': ('Операции по замерам: все идентификаторы пользователей', (
        ('Операция','signature'),('Порядок','measurement_order'),('Замер','measurement_id'),
        ('Наблюдение','observation_status'),('CALL','count'),('Среднее','avg_us'),('P95','p95_us'),
        ('DB/CALL','db_per_call'),('Пользователи','users'))),
    'db_chatty': ('Готовый срез DB-chatty', (
        ('Операция','signature'),('Пользователь','user'),('Порядок','measurement_order'),('Замер','measurement_id'),
        ('CALL','count'),('Порог DB','threshold_db_events'),('Среднее DB/CALL','db_per_call_avg'),
        ('P95 DB/CALL','db_per_call_p95'),('CALL выше порога','calls_above_threshold_count'),
        ('Доля выше порога','calls_above_threshold_percent'),('Состояние выборки','sample_size_status'))),
    'db_chatty_coverage': ('Покрытие среза DB-chatty', (
        ('Область','population_scope'),('Замер','measurement_id'),('Замеры','measurement_ids'),
        ('Порог DB','threshold_db_events'),('CALL','total_call_count'),('CALL выше порога','chatty_call_count'),
        ('Доля выше порога','chatty_call_percent'),('Затронутые операции','affected_operation_count'),
        ('Покрытие по замерам','measurement_db_coverage'),('Ограничения','known_limitations'))),
    'apdex': ('APDEX операций', (
        ('Операция','signature'),('Пользователь','user'),('Порядок','measurement_order'),('Замер','measurement_id'),
        ('Цель T','t_seconds'),('Статус цели','target_status'),('CALL в знаменателе','apdex_denominator'),
        ('APDEX','apdex'),('Удовлетворительно','satisfied_count'),('Допустимо','tolerating_count'),
        ('Неудовлетворительно','frustrated_count'),('Состояние выборки','sample_size_status'))),
    'apdex_uncovered': ('Операции без цели APDEX', (
        ('Операция','signature'),('Пользователь','user'),('Порядок','measurement_order'),('Замер','measurement_id'),
        ('CALL','count'),('Покрытие цели','target_coverage_status'),('Причины и ограничения','known_limitations'))),
    'apdex_coverage': ('Покрытие APDEX', (
        ('Область','population_scope'),('Замер','measurement_id'),('Замеры','measurement_ids'),
        ('CALL всего','total_call_count'),('CALL с целью','covered_call_count'),('CALL без цели','uncovered_call_count'),
        ('Покрытие CALL','covered_call_percent'),('Операции с целью','covered_operation_count'),
        ('Покрытие операций','covered_operation_percent'),('Политика','failure_policy'))),
    'apdex_overall': ('Общий APDEX', (
        ('Итог','overall_id'),('Область','population_scope'),('Замер','measurement_id'),('Замеры','measurement_ids'),
        ('Статус цели','target_status'),('CALL в области','total_calls_in_scope'),('CALL без цели','calls_without_target'),
        ('CALL в знаменателе','apdex_denominator'),('Доля оценённых CALL','scored_call_percent'),
        ('APDEX','apdex'),('Состояние выборки','sample_size_status'),('Политика','failure_policy'))),
    'apdex_composition': ('Состав общего APDEX', (
        ('Итог','overall_id'),('Операция','signature'),('Пользователь','user'),('Замер','measurement_id'),
        ('Цель T','t_seconds'),('Статус цели','target_status'),('CALL','call_count'),
        ('Удовлетворительно','satisfied_count'),('Допустимо','tolerating_count'),
        ('Неудовлетворительно','frustrated_count'),('Вес CALL','call_weight_percent'),
        ('Вклад в общий APDEX','contribution_to_overall_apdex'))),
    'problem_registry': ('Снимок числовых проблем', (
        ('Правило','rule_id'),('Операция','signature'),('Пользователь','user'),('Показатель','metric'),
        ('Замер','measurement_id'),('Значение','value'),('Порог','threshold'),('Статус порога','threshold_status'),
        ('Статус изменения','previous_comparable_change_status'),('Причины','insufficient_reasons'))),
    'problem_improved': ('Сохранённые снижения показателей', (
        ('Правило','rule_id'),('Операция','signature'),('Пользователь','user'),('Замер','measurement_id'),
        ('Показатель','metric'),('Значение','value'),('База','reference_measurement_id'),
        ('Δ','delta_absolute'),('Δ %','delta_percent'),('Статус изменения','change_status'))),
    'problem_worsened': ('Сохранённые увеличения показателей', (
        ('Правило','rule_id'),('Операция','signature'),('Пользователь','user'),('Замер','measurement_id'),
        ('Показатель','metric'),('Значение','value'),('База','reference_measurement_id'),
        ('Δ','delta_absolute'),('Δ %','delta_percent'),('Статус изменения','change_status'))),
    'problem_new': ('Первые сохранённые превышения', (
        ('Правило','rule_id'),('Операция','signature'),('Пользователь','user'),('Замер','measurement_id'),
        ('Показатель','metric'),('Значение','value'),('Порог','threshold'),('Статус порога','threshold_status'))),
    'problem_persisting': ('Последний снимок: порог превышен', (
        ('Правило','rule_id'),('Операция','signature'),('Пользователь','user'),('Замер','measurement_id'),
        ('Показатель','metric'),('Значение','value'),('Порог','threshold'),('Статус порога','threshold_status'))),
    'problem_unchecked': ('Последний снимок: нет проверки', (
        ('Правило','rule_id'),('Операция','signature'),('Пользователь','user'),('Замер','measurement_id'),
        ('Показатель','metric'),('Значение','value'),('Статус порога','threshold_status'),('Причины','insufficient_reasons'))),
    'problem_rule_coverage': ('Покрытие числовых правил', (
        ('Правило','rule_id'),('Порядок','measurement_order'),('Замер','measurement_id'),
        ('Выбранные группы','selected_operation_user_cohort_count'),('Наблюдаемые группы','observed_cohort_count'),
        ('Оцениваемые группы','evaluable_cohort_count'),('Недостаточно данных','insufficient_cohort_count'),
        ('Отсутствующие группы','absent_cohort_count'),('Наблюдаемые CALL','observed_call_count'),
        ('Ограничения','known_limitations'))),
}


COMPARISON_METRICS = {
    'measurement_comparisons': (
        ('Число CALL','reference_count','current_count','sample_count_delta_absolute','sample_count_delta_percent'),
        ('Суммарное время','duration_us_sum_reference','duration_us_sum_current','duration_us_sum_delta_absolute','duration_us_sum_delta_percent'),
        ('Среднее время','avg_us_reference','avg_us_current','avg_us_delta_absolute','avg_us_delta_percent'),
        ('P95','p95_us_reference','p95_us_current','p95_us_delta_absolute','p95_us_delta_percent'),
        ('Максимум','max_us_reference','max_us_current','max_us_delta_absolute','max_us_delta_percent'),
        ('DB/CALL','db_per_call_reference','db_per_call_current','db_per_call_delta_absolute','db_per_call_delta_percent'),
        ('DB время/CALL','db_seconds_per_call_reference','db_seconds_per_call_current','db_seconds_per_call_delta_absolute','db_seconds_per_call_delta_percent'),
        ('CPU/стена','cpu_percent_of_wall_reference','cpu_percent_of_wall_current','cpu_percent_of_wall_delta_absolute','cpu_percent_of_wall_delta_percent')),
    'db_chatty_changes': (
        ('Число CALL','reference_count','current_count','sample_count_delta_absolute','sample_count_delta_percent'),
        ('Среднее DB/CALL','db_per_call_avg_reference','db_per_call_avg_current','db_per_call_avg_delta_absolute','db_per_call_avg_delta_percent'),
        ('P95 DB/CALL','db_per_call_p95_reference','db_per_call_p95_current','db_per_call_p95_delta_absolute','db_per_call_p95_delta_percent'),
        ('Доля CALL выше порога','calls_above_threshold_percent_reference','calls_above_threshold_percent_current','calls_above_threshold_percent_delta_absolute','calls_above_threshold_percent_delta_percent'),
        ('Доля быстрых CALL выше порога','fast_calls_above_threshold_percent_reference','fast_calls_above_threshold_percent_current','fast_calls_above_threshold_percent_delta_absolute','fast_calls_above_threshold_percent_delta_percent'),
        ('Связанное DB-время/CALL','linked_db_seconds_per_call_reference','linked_db_seconds_per_call_current','linked_db_seconds_per_call_delta_absolute','linked_db_seconds_per_call_delta_percent')),
    'apdex_changes': (
        ('Число CALL','reference_count','current_count','sample_count_delta_absolute','sample_count_delta_percent'),
        ('APDEX','apdex_reference','apdex_current','apdex_delta_absolute','apdex_delta_percent'),
        ('Удовлетворительно','satisfied_count_reference','satisfied_count_current','satisfied_count_delta_absolute','satisfied_count_delta_percent'),
        ('Допустимо','tolerating_count_reference','tolerating_count_current','tolerating_count_delta_absolute','tolerating_count_delta_percent'),
        ('Неудовлетворительно','frustrated_count_reference','frustrated_count_current','frustrated_count_delta_absolute','frustrated_count_delta_percent'),
        ('Подтверждённые отказы','confirmed_failure_count_reference','confirmed_failure_count_current','confirmed_failure_count_delta_absolute','confirmed_failure_count_delta_percent')),
}


def table_views(model, name):
    return [table for section in model.sections for table in section.tables if table.name == name]


def cell_index(row):
    return {cell.field:cell for cell in row.cells}


def state_for(rows, fallback=DisplayState.NO_OBSERVATIONS):
    if not rows:
        return fallback
    if any(row.state == DisplayState.PARTIAL for row in rows):
        return DisplayState.PARTIAL
    if all(row.state == DisplayState.NO_OBSERVATIONS for row in rows):
        return DisplayState.NO_OBSERVATIONS
    return DisplayState.READY


def standard_table(model, name):
    title, fields = STANDARD[name]
    views = table_views(model,name)
    rows = []
    seen = set()
    for view in views:
        for row in view.rows:
            if row.key in seen:
                continue
            seen.add(row.key)
            index = cell_index(row)
            require(all(field in index for _,field in fields), f'{name}: compact field absent')
            rows.append(CompactRow(row.key,tuple(index[field] for _,field in fields),row.state))
    fallback = DisplayState.NOT_CALCULATED if views and any(v.state == DisplayState.NOT_CALCULATED for v in views) else DisplayState.NO_OBSERVATIONS
    sentences = []
    seen_notes = set()
    for view in views:
        for sentence in re.split(r'(?<=[.!?])\s+',view.note.strip()):
            if sentence and sentence not in seen_notes:
                seen_notes.add(sentence)
                sentences.append(sentence)
    notes = ' '.join(sentences)
    return CompactTable(name,title,tuple(label for label,_ in fields),rows,state_for(rows,fallback),notes)


def unique_rows(model, name):
    rows = []
    seen = set()
    for view in table_views(model,name):
        for row in view.rows:
            if row.key not in seen:
                seen.add(row.key)
                rows.append(row)
    return rows


def project_rows(name, rows, table_name, title, fields, fallback=DisplayState.NO_OBSERVATIONS, note=''):
    """Project ready cells without changing their values or provenance."""
    projected = []
    for row in rows:
        index = cell_index(row)
        require(all(field in index for _,field in fields), f'{name}: compact field absent')
        projected.append(CompactRow(row.key,tuple(index[field] for _,field in fields),row.state))
    return CompactTable(table_name,title,tuple(label for label,_ in fields),projected,state_for(projected,fallback),note)


def projected_table(model, name, table_name, title, fields):
    views = table_views(model,name)
    rows = []
    seen = set()
    for view in views:
        for row in view.rows:
            if row.key in seen:
                continue
            seen.add(row.key)
            rows.append(row)
    fallback = DisplayState.NOT_CALCULATED if views and any(v.state == DisplayState.NOT_CALCULATED for v in views) else DisplayState.NO_OBSERVATIONS
    notes = ' '.join(v.note.strip() for v in views if v.note.strip())
    return project_rows(name,rows,table_name,title,fields,fallback,notes)


def manifest_table(model, table_name, title, fields):
    rows = unique_rows(model,'provenance')
    require(rows, 'provenance row absent')
    source = rows[0]
    index = cell_index(source)
    cells = tuple(index.get(field,Cell(None,'analysis_metrics.json','manifest',field,state=DisplayState.UNAVAILABLE,
        reason='поле не предоставлено сохранённым анализом')) for _,field in fields)
    state = DisplayState.PARTIAL if any(cell.state == DisplayState.UNAVAILABLE for cell in cells) else source.state
    return CompactTable(table_name,title,tuple(label for label,_ in fields),[CompactRow(source.key,cells,state)],state)


def literal(label, key, field):
    return Cell(label,'presentation_dictionary',key,field)


def _comparability_cells_by_id(model):
    index = {}
    for view in table_views(model, 'comparability'):
        for row in view.rows:
            cells = cell_index(row)
            # Multiple views can expose the same ID. As before, the first
            # match supplies both the original cells and the display state.
            index.setdefault(cells['comparison_id'].value, (row, cells))
    return index


def comparison_tables(model, name, context=False):
    result = []
    views = table_views(model, name)
    contexts = _comparability_cells_by_id(model) if context and any(v.rows for v in views) else {}
    title = 'Сравнение сохранённых показателей' if name == 'measurement_comparisons' else ('Сравнение DB-chatty' if name == 'db_chatty_changes' else 'Сравнение APDEX')
    for view in views:
        for row in view.rows:
            index = cell_index(row)
            side_fields = (
                ('Операция','signature'),('Пользователь','user'),
                ('Опорный замер','reference_measurement_id'),('N опоры','reference_count'),
                ('Наблюдение опоры','reference_observation_status'),
                ('Текущий замер','current_measurement_id'),('N текущего','current_count'),
                ('Наблюдение текущего','current_observation_status'))
            basis_fields = (
                ('Тип базы','comparison_basis'),('Отношение к базе','reference_relation'),
                ('Состояние сравнения','comparison_state'),('Состояние выборки','sample_size_status'))
            require(all(field in index for _,field in (*side_fields,*basis_fields)), f'{name}: comparison identity absent')
            sides = CompactTable(name+'-sides','Текущий и опорный замеры',tuple(x[0] for x in side_fields),
                [CompactRow(row.key,tuple(index[x[1]] for x in side_fields),row.state)],row.state)
            basis = CompactTable(name+'-basis','База сравнения',tuple(x[0] for x in basis_fields),
                [CompactRow(row.key,tuple(index[x[1]] for x in basis_fields),row.state)],row.state)
            metrics = []
            for label,*fields in COMPARISON_METRICS[name]:
                require(all(field in index for field in fields), f'{name}: comparison metric absent')
                metrics.append(CompactRow(row.key,tuple([literal(label,row.key,fields[0]),*(index[field] for field in fields)]),row.state))
            values = CompactTable(name+'-values','Готовые значения и дельты',('Показатель','Опорный','Текущий','Δ','Δ %'),metrics,row.state,
                'Дельты и процентные статусы прочитаны из сохранённой строки; PDF их не рассчитывает.')
            tables = [sides,basis,values]
            if context:
                match = contexts.get(index['comparison_id'].value)
                if match is not None:
                    related, other = match
                    fields = (('Сопоставимость','comparability_status'),('Совпала техническая сигнатура','signature_match'),
                              ('Совпал идентификатор пользователя','user_match'),('Отношение к базе','reference_relation'),
                              ('Известные различия','known_differences'),('Неизвестные условия','unknown_parameters'),
                              ('Ограничения','known_limitations'))
                    tables.append(CompactTable('comparability-context','Сопоставимость и ограничения',tuple(x[0] for x in fields),
                        [CompactRow(row.key,tuple(other[x[1]] for x in fields),related.state)],related.state,
                        'Совпадение сигнатуры и идентификатора пользователя не подтверждает одинаковый пользовательский сценарий.'))
                    coverage_fields = (
                        ('CALL из частичных источников: опора','reference_calls_from_partial_sources'),
                        ('CALL из частичных источников: текущий','current_calls_from_partial_sources'),
                        ('DB по количеству: опора','reference_measurement_db_linked_count_percent'),
                        ('DB по количеству: текущий','current_measurement_db_linked_count_percent'),
                        ('DB по времени: опора','reference_measurement_db_linked_duration_percent'),
                        ('DB по времени: текущий','current_measurement_db_linked_duration_percent'))
                    tables.append(CompactTable('comparability-coverage','Покрытие сравниваемых выборок',tuple(x[0] for x in coverage_fields),
                        [CompactRow(row.key,tuple(other[x[1]] for x in coverage_fields),related.state)],related.state))
                else:
                    tables.append(CompactTable('comparability-context','Сопоставимость и ограничения',('Состояние',),[],DisplayState.NOT_CALCULATED,'Срез comparability не предоставлен для этой строки.'))
            else:
                fields = (('Совпала техническая сигнатура','signature_match'),('Совпал идентификатор пользователя','user_match'),
                          ('Известные различия','known_differences'),('Неизвестные условия','unknown_parameters'),('Ограничения','known_limitations'))
                if all(field in index for _,field in fields):
                    tables.append(CompactTable(name+'-context','Ограничения',tuple(x[0] for x in fields),
                        [CompactRow(row.key,tuple(index[x[1]] for x in fields),row.state)],row.state))
                if name == 'db_chatty_changes':
                    threshold_fields = (
                        ('Порог DB','threshold_db_events'),('Оператор','threshold_operator'),
                        ('Знаменатель CALL: опора','reference_call_share_denominator'),
                        ('Знаменатель CALL: текущий','current_call_share_denominator'),
                        ('DB по количеству: опора','reference_measurement_db_linked_count_percent'),
                        ('DB по количеству: текущий','current_measurement_db_linked_count_percent'),
                        ('DB по времени: опора','reference_measurement_db_linked_duration_percent'),
                        ('DB по времени: текущий','current_measurement_db_linked_duration_percent'))
                    tables.append(CompactTable(name+'-parameters','Порог, знаменатели и покрытие DB',tuple(x[0] for x in threshold_fields),
                        [CompactRow(row.key,tuple(index[x[1]] for x in threshold_fields),row.state)],row.state))
                elif name == 'apdex_changes':
                    policy_fields = (
                        ('Область оценки','assessment_scope'),('Политика отказов','failure_policy'),('Цели совпали','target_match'))
                    target_fields = (
                        ('Цель опоры','reference_target_id'),('Статус цели опоры','reference_target_status'),
                        ('Источник цели опоры','reference_target_source'),('T опоры','reference_t_us'),
                        ('Текущая цель','current_target_id'),('Статус текущей цели','current_target_status'),
                        ('Источник текущей цели','current_target_source'),('T текущего','current_t_us'))
                    denominator_fields = (
                        ('Знаменатель APDEX опоры','reference_apdex_denominator'),
                        ('Знаменатель APDEX текущего','current_apdex_denominator'),
                        ('Минимум CALL','min_call_count'),('Предупреждение выборки','small_sample_warning'))
                    tables.append(CompactTable(name+'-policy','Область и правила APDEX',tuple(x[0] for x in policy_fields),
                        [CompactRow(row.key,tuple(index[x[1]] for x in policy_fields),row.state)],row.state))
                    tables.append(CompactTable(name+'-targets','Цели APDEX обеих сторон',tuple(x[0] for x in target_fields),
                        [CompactRow(row.key,tuple(index[x[1]] for x in target_fields),row.state)],row.state))
                    tables.append(CompactTable(name+'-denominators','Знаменатели APDEX',tuple(x[0] for x in denominator_fields),
                        [CompactRow(row.key,tuple(index[x[1]] for x in denominator_fields),row.state)],row.state))
            result.append(MainSection(name+'-'+row.key,title,tables,note='Числовое изменение само по себе не доказывает исправление или регрессию кода.'))
    if not result:
        views = table_views(model,name)
        empty_state = DisplayState.NOT_CALCULATED if not views or any(view.state == DisplayState.NOT_CALCULATED for view in views) else DisplayState.NO_OBSERVATIONS
        note = 'Подходящий готовый срез не предоставлен.' if empty_state == DisplayState.NOT_CALCULATED else 'Готовый срез предоставлен, но в выбранном отображении строк нет.'
        result.append(MainSection(name,title,[
            CompactTable(name,'Сохранённые сравнения',('Состояние',),[],empty_state,note)
        ],empty_state))
    return result


def scope_table(model,data,config):
    selected = config.settings.get('display_measurement_ids')
    focus = config.settings.get('focus_measurement_id') if config.settings['report_kind'] == 'overview' else None
    visible = set(selected) if selected is not None else set(data.measurement_ids)
    if focus:
        visible &= {focus}
    order_cells = {}
    measurement_cells = {}
    sources = ('data_quality','operation_history') if config.settings['report_kind'] == 'overview' else ('operation_history','problem_history')
    for name in sources:
        for row in data.slices.get(name,[]):
            mid = row['measurement_id']
            if mid in visible and row.get('measurement_order') is not None and mid not in order_cells:
                index = {cell.field:cell for cell in row_cells(name,row,stable_key(name,row))}
                order_cells[mid] = index['measurement_order']
                measurement_cells.setdefault(mid,index['measurement_id'])
    candidate_names = [name for name in (
        'data_quality','operation_history','problem_history','measurement_comparisons','comparability',
        'db_chatty','apdex','problem_registry','operations','heavy_sql','errors','locks','linkage','top_calls','datasets'
    ) if name in data.slices or name in data.tables]
    for name in candidate_names:
        if set(measurement_cells) >= visible:
            break
        rows = data.slices.get(name,data.tables.get(name,[]))
        for row in rows:
            for field in ('measurement_id','current_measurement_id','reference_measurement_id'):
                mid = row.get(field)
                if mid in visible and mid not in measurement_cells:
                    index = {cell.field:cell for cell in row_cells(name,row,stable_key(name,row))}
                    measurement_cells[mid] = index[field]
    if focus and focus not in measurement_cells:
        for row in unique_rows(model,'provenance'):
            candidate = cell_index(row).get('/focus_measurement_id')
            if candidate is not None and candidate.value == focus:
                measurement_cells[focus] = candidate
                break
    for row in data.tables.get('datasets',[]):
        for position,mid in enumerate(row.get('actual_measurement_ids') or []):
            if mid in visible and mid not in measurement_cells:
                measurement_cells[mid] = Cell(mid,'datasets.csv',stable_key('datasets',row),f'actual_measurement_ids/{position}')
    mids = sorted(visible,key=lambda mid:(order_cells[mid].value if mid in order_cells else 10**18,mid))
    rows = []
    for mid in mids:
        order_cell = order_cells.get(mid,Cell(None,'validated_input',mid,'measurement_order',state=DisplayState.UNAVAILABLE,reason='порядок в предоставленных срезах недоступен'))
        measurement_cell = measurement_cells.get(mid,Cell(None,'validated_input',mid,'measurement_id',state=DisplayState.UNAVAILABLE,reason='точный скалярный источник идентификатора не предоставлен'))
        rows.append(CompactRow(mid,(order_cell,measurement_cell),DisplayState.READY))
    note = ('В overview порядок из data_quality используется только для показа и не выбирает аналитическую базу. '
            if config.settings['report_kind'] == 'overview' else
            'Порядок берётся только из готового хронологического среза операций или проблем. ')
    return CompactTable('report-scope','Замеры в области отчёта',('Порядок','Замер'),rows,state_for(rows),
        note+'При его отсутствии идентификаторы только упорядочиваются для отображения и такой порядок не считается хронологией.')


def problem_history_tables(model, selected_rows=None):
    value_fields = (
        ('Проблема','problem_id'),('Правило','rule_id'),('Операция','signature'),('Пользователь','user'),('Показатель','metric'),
        ('Порядок','measurement_order'),('Замер','measurement_id'),('CALL','count'),('Значение','value'),
        ('Порог','threshold'),('Статус порога','threshold_status'))
    status_fields = (
        ('Правило','rule_id'),('Порядок','measurement_order'),('Замер','measurement_id'),
        ('Опорный замер','previous_comparable_reference_measurement_id'),
        ('Δ','previous_comparable_delta_absolute'),('Δ %','previous_comparable_delta_percent'),
        ('Статус изменения','previous_comparable_change_status'),
        ('Сопоставимость базы','previous_reference_comparability'),('Причины статуса','insufficient_reasons'))
    limit_fields = (
        ('Правило','rule_id'),('Порядок','measurement_order'),('Замер','measurement_id'),
        ('Известные различия','previous_comparable_known_differences'),
        ('Неизвестные условия','unknown_parameters'),('Ограничения','known_limitations'))
    if selected_rows is None:
        selected_rows = unique_rows(model,'problem_history')
    fallback = DisplayState.NOT_CALCULATED if any(view.state == DisplayState.NOT_CALCULATED for view in table_views(model,'problem_history')) else DisplayState.NO_OBSERVATIONS
    return [
        project_rows('problem_history',selected_rows,'problem_history','Числовые проблемы по замерам',value_fields,fallback),
        project_rows('problem_history',selected_rows,'problem_history-status','Сохранённые статусы и их основания',status_fields,fallback),
        project_rows('problem_history',selected_rows,'problem_history-limits','Ограничения интерпретации статусов',limit_fields,fallback),
    ]


def present_names(model):
    return {table.name for section in model.sections for table in section.tables}


def additional_sections(model, consumed, consumed_row_keys=None):
    consumed_row_keys = consumed_row_keys or {}
    tables=[]
    for name in STANDARD:
        if name in consumed or not table_views(model,name):
            continue
        table = standard_table(model,name)
        excluded = consumed_row_keys.get(name,set())
        if excluded:
            table.rows = [row for row in table.rows if row.key not in excluded]
            if not table.rows:
                continue
            table.state = state_for(table.rows,table.state)
            table.note = (table.note+' ' if table.note else '')+'Строки, уже показанные рядом со связанным итогом, здесь не повторяются.'
        tables.append(table)
    if not tables:
        return []
    return [MainSection('additional','Дополнительные готовые срезы',tables,note='Показаны только предоставленные и выбранные конфигурацией срезы; приложение содержит их полные строки.')]


def rows_for_measurement(table, mid):
    selected=[]
    for row in table.rows:
        value=next((cell.value for cell in row.cells if cell.field == 'measurement_id'),None)
        if value == mid:
            selected.append(row)
    state = table.state if not selected and table.state == DisplayState.NOT_CALCULATED else state_for(selected)
    note = table.note
    if not selected and state == DisplayState.NO_OBSERVATIONS:
        note = (note+' ' if note else '')+'Для этого замера строк нет.'
    return CompactTable(table.name,table.title,table.headers,selected,state,note)


def saved_row(row):
    return {cell.field:cell.value for cell in row.cells}


def slice_fallback(model, name):
    views = table_views(model,name)
    return DisplayState.NOT_CALCULATED if not views or any(view.state == DisplayState.NOT_CALCULATED for view in views) else DisplayState.NO_OBSERVATIONS


def apdex_overall_sections(model):
    overalls = unique_rows(model,'apdex_overall')
    overall_fields = STANDARD['apdex_overall'][1]
    composition_fields = STANDARD['apdex_composition'][1]
    coverage_fields = STANDARD['apdex_coverage'][1]
    if not overalls:
        return [MainSection('overview-apdex-overall','Общий APDEX: итог, состав и покрытие',[
            project_rows('apdex_overall',[],'apdex_overall',STANDARD['apdex_overall'][0],overall_fields,slice_fallback(model,'apdex_overall')),
            project_rows('apdex_composition',[],'apdex_composition',STANDARD['apdex_composition'][0],composition_fields,slice_fallback(model,'apdex_composition')),
            project_rows('apdex_coverage',[],'apdex_coverage',STANDARD['apdex_coverage'][0],coverage_fields,slice_fallback(model,'apdex_coverage')),
        ],slice_fallback(model,'apdex_overall'))],set()
    compositions = unique_rows(model,'apdex_composition')
    coverages = unique_rows(model,'apdex_coverage')
    result = []
    used_coverage_keys = set()
    for position,overall in enumerate(overalls,1):
        values = saved_row(overall)
        overall_id = values['overall_id']
        matching_composition = [row for row in compositions if saved_row(row)['overall_id'] == overall_id]
        overall_scope = scope_key(values)
        matching_coverage = [row for row in coverages if scope_key(saved_row(row)) == overall_scope]
        used_coverage_keys.update(row.key for row in matching_coverage)
        tables = [
            project_rows('apdex_overall',[overall],'apdex_overall',STANDARD['apdex_overall'][0],overall_fields),
            project_rows('apdex_composition',matching_composition,'apdex_composition',STANDARD['apdex_composition'][0],composition_fields,slice_fallback(model,'apdex_composition'),
                'Полный сохранённый состав этого overall_id; top-N к составу не применяется.'),
            project_rows('apdex_coverage',matching_coverage,'apdex_coverage',STANDARD['apdex_coverage'][0],coverage_fields,slice_fallback(model,'apdex_coverage'),
                'Покрытие относится ко всей области итога и может включать обе категории целей.'),
        ]
        state = DisplayState.PARTIAL if any(table.state == DisplayState.PARTIAL for table in tables) else DisplayState.READY
        result.append(MainSection('overview-apdex-overall-'+str(overall_id),'Общий APDEX '+str(position),tables,state,
            'Итог, знаменатель, полный состав и покрытие связаны готовыми ключами; PDF их не пересчитывает.'))
    return result,used_coverage_keys


def operation_history_sections(model, name, prefix, heading, overlap_note=''):
    rows = unique_rows(model,name)
    if not rows:
        fallback = slice_fallback(model,name)
        return [MainSection(prefix,heading,[CompactTable(name,heading,('Состояние',),[],fallback,
            'Хронологический срез не предоставлен.' if fallback == DisplayState.NOT_CALCULATED else 'Готовый срез не содержит строк.')],fallback)]
    groups = {}
    for row in rows:
        groups.setdefault(saved_row(row)['cohort_id'],[]).append(row)
    result = []
    for position,(cohort_id, points) in enumerate(groups.items(),1):
        identity_fields = [('Траектория','cohort_id'),('Область','population_scope'),('Операция','signature')]
        if name == 'operation_history_all_users':
            identity_fields += [('Пользователи','users')]
        else:
            identity_fields += [('Пользователь','user')]
        identity_fields += [('Основа порядка','order_basis'),('Надёжность порядка','series_order_reliable')]
        metric_fields = (
            ('Порядок','measurement_order'),('Замер','measurement_id'),('Наблюдение','observation_status'),('CALL','count'),
            ('Среднее','avg_us'),('Медиана','median_us'),('P95','p95_us'),('Максимум','max_us'),
            ('DB/CALL','db_per_call'),('DB время/CALL','db_seconds_per_call'),('CPU/стена','cpu_percent_of_wall'))
        quality_fields = (
            ('Порядок','measurement_order'),('Замер','measurement_id'),('CALL из частичных источников','calls_from_partial_sources'),
            ('Состояние источников','measurement_source_health'),('DB по количеству','measurement_db_linked_count_percent'),
            ('DB по времени','measurement_db_linked_duration_percent'),('Ограничения','known_limitations'))
        tables = [
            project_rows(name,points[:1],name+'-identity','Идентификатор и область траектории',tuple(identity_fields)),
            project_rows(name,points,name,'Показатели по замерам',metric_fields),
            project_rows(name,points,name+'-quality','Качество точек траектории',quality_fields),
        ]
        result.append(MainSection(prefix+'-'+str(cohort_id),heading+' '+str(position),tables,note=(
            'Точки показаны по готовому measurement_order. Совпадение технической сигнатуры не подтверждает одинаковый пользовательский сценарий. '+overlap_note).strip()))
    return result


def problem_history_sections(model):
    rows = unique_rows(model,'problem_history')
    if not rows:
        fallback = slice_fallback(model,'problem_history')
        tables = problem_history_tables(model,[])
        tables.append(project_rows('problem_rule_coverage',[],'problem_rule_coverage',STANDARD['problem_rule_coverage'][0],STANDARD['problem_rule_coverage'][1],slice_fallback(model,'problem_rule_coverage')))
        return [MainSection('history-problems','История числовых проблем',tables,fallback)]
    groups = {}
    for row in rows:
        groups.setdefault(saved_row(row)['problem_id'],[]).append(row)
    coverage_rows = unique_rows(model,'problem_rule_coverage')
    result = []
    for position,(problem_id, points) in enumerate(groups.items(),1):
        wanted = {(saved_row(row)['rule_id'],saved_row(row)['measurement_id']) for row in points}
        coverage = [row for row in coverage_rows if (saved_row(row)['rule_id'],saved_row(row)['measurement_id']) in wanted]
        tables = problem_history_tables(model,points)
        tables.append(project_rows('problem_rule_coverage',coverage,'problem_rule_coverage',STANDARD['problem_rule_coverage'][0],STANDARD['problem_rule_coverage'][1],slice_fallback(model,'problem_rule_coverage'),
            'Покрытие показано для готовых rule_id и measurement_id этой траектории.'))
        result.append(MainSection('history-problems-'+str(problem_id),'Числовая проблема '+str(position),tables,note=(
            'Точки сгруппированы только по готовому problem_id. Статус порога, статус изменения и его сохранённые основания показаны раздельно; снижение показателя не называется доказанным исправлением.')))
    return result


def build_main_sections(model,data,config):
    kind=config.settings['report_kind']
    names=present_names(model)
    scope=MainSection('scope','Область отчёта и качество данных',[
        scope_table(model,data,config),
        manifest_table(model,'analysis-completeness','Полнота сохранённого анализа',(
            ('Анализ завершён','/analysis_complete'),('Обработка источников завершена','/source_processing_complete'),
            ('Хеши содержимого полны','/source_content_hashes_complete'),('Абсолютное время полно','/absolute_timestamps_complete'),
            ('Полнота сбора','/collection_completeness'))),
    ])
    consumed=set()
    if 'data_quality' in names:
        scope.tables.append(standard_table(model,'data_quality'))
        scope.tables.append(projected_table(model,'data_quality','data-quality-context','Период наблюдений и ограничения',(
            ('Замер','measurement_id'),('Начало наблюдений','observed_call_start'),('Конец наблюдений','observed_call_end'),
            ('Полнота источников','source_completeness'),('Состояние DB-связей','db_linkage_status'),
            ('Недоступные измерения','unavailable_dimensions'),('Ограничения','known_limitations'))))
        consumed.add('data_quality')
    if kind == 'overview':
        result=[scope]
        core={name:standard_table(model,name) for name in ('operations','heavy_sql','errors','locks') if name in names}
        consumed.update(core)
        for scope_row in scope.tables[0].rows:
            mid=scope_row.cells[1].value
            tables=[rows_for_measurement(table,mid) for table in core.values()]
            if tables:
                result.append(MainSection('overview-'+str(mid),'Показатели замера '+str(mid),tables,
                    note='Операции, SQL, ошибки и блокировки остаются раздельными популяциями. Порядок и top-N задаются представлением; PDF не вводит порог медленной операции.'))
        if 'errors' in names:
            result.append(MainSection('overview-error-summary','Сохранённая сводка ошибок комплекта',[
                manifest_table(model,'error-summary','Количество событий и затронутых CALL',(
                    ('События','/error_summary/event_count'),('Связанные события','/error_summary/linked_error_event_count'),
                    ('Несвязанные события','/error_summary/unlinked_error_event_count'),('Неоднозначные связи','/error_summary/ambiguous_linked_error_event_count'),
                    ('Резервные связи','/error_summary/fallback_linked_error_event_count'),('Затронутые CALL','/error_summary/affected_call_count'),
                    ('Предполагаемые инциденты','/error_summary/suspected_incident_count'))),
                manifest_table(model,'error-semantics','Сохранённые определения',(
                    ('Смысл затронутых CALL','/error_summary/affected_call_semantics'),
                    ('Смысл предполагаемых инцидентов','/error_summary/incident_semantics'),
                    ('Версия правил инцидентов','/error_summary/incident_rules_version'))),
            ]))
        if 'db_chatty' in names or 'db_chatty_coverage' in names:
            ready = [standard_table(model,name) for name in ('db_chatty','db_chatty_coverage') if name in names]
            result.append(MainSection('overview-db-chatty','DB-chatty: готовая сводка и покрытие',ready))
            consumed.update({'db_chatty','db_chatty_coverage'})
        if 'apdex_overall' in names:
            overall_sections,used_coverage_keys = apdex_overall_sections(model)
            result += overall_sections
            consumed.update({'apdex_overall','apdex_composition'})
        else:
            used_coverage_keys = set()
        return result+additional_sections(model,consumed,{'apdex_coverage':used_coverage_keys})
    if kind == 'comparison':
        result=[scope]
        if 'measurement_comparisons' in names:
            result += comparison_tables(model,'measurement_comparisons',True)
            consumed.update({'measurement_comparisons','comparability'})
        for name in ('db_chatty_changes','apdex_changes'):
            if name in names:
                result += comparison_tables(model,name)
                consumed.add(name)
        return result+additional_sections(model,consumed)
    result=[scope]
    if 'operation_history' in names:
        result += operation_history_sections(model,'operation_history','history-operations','Траектория операции')
        consumed.add('operation_history')
    if 'operation_history_all_users' in names:
        result += operation_history_sections(model,'operation_history_all_users','history-all-users','Траектория операции: все идентификаторы пользователей',
            'Срез всех пользователей перекрывается со строками same-user и не суммируется с ними.')
        consumed.add('operation_history_all_users')
    if 'problem_history' in names:
        result += problem_history_sections(model)
        consumed.add('problem_history')
        consumed.add('problem_rule_coverage')
    return result+additional_sections(model,consumed)
