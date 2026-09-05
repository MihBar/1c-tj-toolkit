"""Escaped PDF presentation and atomic publication. No external resources."""
from __future__ import annotations

import html
import json
import math
import os
from pathlib import Path
import tempfile

try:
    from .report_schema import require
    from .report_fonts import register_fonts
    from .report_model import format_cell, DisplayState
except ImportError:
    from report_schema import require
    from report_fonts import register_fonts
    from report_model import format_cell, DisplayState


def render_pdf(model, config, data, output, overwrite=False):
    # ReportLab and fonts are deliberately absent from the import path of loaders/CLI help.
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas
    from reportlab.platypus import (CondPageBreak, Flowable, HRFlowable, LongTable,
                                    PageBreak, Paragraph, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)

    output = Path(output).resolve()
    for root in (data.analysis_dir,data.slices_dir):
        require(root is None or (output != root and root not in output.parents), 'PDF output must be outside input directories')
    require(output != config.path, 'Cannot overwrite configuration')
    protected_fonts = [Path(v).resolve() for k,v in config.settings['fonts'].items() if k != 'profile']
    require(output not in protected_fonts and output.suffix.lower() == '.pdf', 'Output must be a PDF distinct from font resources')
    require(not output.exists() or overwrite, 'PDF exists; explicit --overwrite required')

    regular,bold = register_fonts(config)
    navy = colors.HexColor('#173A57')
    blue = colors.HexColor('#2D6F93')
    pale_blue = colors.HexColor('#EAF2F7')
    pale_row = colors.HexColor('#F5F8FA')
    pale_gray = colors.HexColor('#F2F4F6')
    line = colors.HexColor('#B9C7D2')
    dark = colors.HexColor('#172B3A')
    muted = colors.HexColor('#526674')
    notice_fill = colors.HexColor('#FFF4D6')
    notice_line = colors.HexColor('#D49B25')

    styles = {
        'body':ParagraphStyle('body',fontName=regular,fontSize=9.2,leading=13.2,textColor=dark,splitLongWords=True),
        'title':ParagraphStyle('title',fontName=bold,fontSize=22,leading=27,textColor=navy,spaceAfter=12),
        'cover_label':ParagraphStyle('cover_label',fontName=bold,fontSize=9,leading=12,textColor=blue,spaceAfter=7),
        'section':ParagraphStyle('section',fontName=bold,fontSize=13.5,leading=18,textColor=navy,spaceBefore=8,spaceAfter=6,keepWithNext=True),
        'section_plain':ParagraphStyle('section_plain',fontName=bold,fontSize=13.5,leading=18,textColor=navy,spaceBefore=8,spaceAfter=6),
        'table_title':ParagraphStyle('table_title',fontName=bold,fontSize=9.4,leading=12.2,textColor=dark,spaceBefore=4,spaceAfter=3,keepWithNext=True),
        'table_title_plain':ParagraphStyle('table_title_plain',fontName=bold,fontSize=9.4,leading=12.2,textColor=dark,spaceBefore=4,spaceAfter=3),
        'small':ParagraphStyle('small',fontName=regular,fontSize=7.5,leading=10.3,textColor=muted,splitLongWords=True),
        'small_keep':ParagraphStyle('small_keep',fontName=regular,fontSize=7.5,leading=10.3,textColor=muted,splitLongWords=True,keepWithNext=True),
        'compact':ParagraphStyle('compact',fontName=regular,fontSize=7.7,leading=9.8,textColor=dark,splitLongWords=True),
        'compact_head':ParagraphStyle('compact_head',fontName=bold,fontSize=7.7,leading=9.8,textColor=colors.white,splitLongWords=True),
        'caption':ParagraphStyle('caption',fontName=bold,fontSize=8.2,leading=10.3,textColor=colors.white,splitLongWords=True),
        'appendix_head':ParagraphStyle('appendix_head',fontName=bold,fontSize=7.7,leading=9.8,textColor=navy,splitLongWords=True),
        'notice':ParagraphStyle('notice',fontName=regular,fontSize=9,leading=13,textColor=dark,splitLongWords=True),
        'empty':ParagraphStyle('empty',fontName=regular,fontSize=8.5,leading=12,textColor=muted,splitLongWords=True),
    }

    def p(text,style='body'):
        return Paragraph(html.escape(str(text),quote=True).replace('\n','<br/>'),styles[style])

    page_size = landscape(A4)
    horizontal_margin = 15*mm
    # SimpleDocTemplate's frame reserves 6 pt on both sides inside the margins.
    content_width = page_size[0]-2*horizontal_margin-12
    kind_labels={'overview':'обзор','comparison':'сравнение','history':'история'}
    kind_label=kind_labels.get(model.kind,model.kind)

    class PartMarker(Flowable):
        def __init__(self, label):
            super().__init__()
            self.label = label
            self.width = self.height = 0

        def draw(self):
            self.canv._report_part = self.label

    class NumberedCanvas(canvas.Canvas):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs)
            self._saved_page_states=[]

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total=len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self.saveState()
                self.setStrokeColor(line)
                self.setLineWidth(0.35)
                self.line(horizontal_margin,13*mm,page_size[0]-horizontal_margin,13*mm)
                self.setFillColor(muted)
                self.setFont(regular,7.5)
                part=getattr(self,'_report_part','Отчет')
                self.drawString(horizontal_margin,8.5*mm,part+' | '+model.bundle_id[:16])
                self.drawRightString(page_size[0]-horizontal_margin,8.5*mm,f'Страница {self._pageNumber} из {total}')
                self.restoreState()
                canvas.Canvas.showPage(self)
            canvas.Canvas.save(self)

    status_labels = {
        'observed':'наблюдалось','not_observed':'не наблюдалось','no_reference':'нет базы',
        'series_baseline':'база серии','first_observation':'первое наблюдение',
        'previous_observation':'предыдущее наблюдение','previous_measurement':'предыдущий замер',
        'numerical_comparison':'числовое сравнение','same_measurement':'тот же замер',
        'same_signature_same_user_uncontrolled':'совпадают техническая сигнатура и идентификатор пользователя; условия не контролировались',
        'user_identity_unknown':'идентификатор пользователя неизвестен',
        'insufficient_observations_for_comparison':'недостаточно наблюдений для сравнения',
        'below_configured_minimum':'ниже настроенного минимума','meets_count_threshold_only':'достигнут только порог численности',
        'no_calls':'нет CALL','no_scored_calls':'нет оцененных CALL','missing_observations':'нет наблюдений',
        'target_defined':'цель задана','uncovered_no_target':'цель не задана',
        'business_approved':'цель объявлена согласованной','engineering_proposal':'инженерное предложение',
        'latency_only':'только задержка','confirmed_failures_frustrated':'подтвержденные отказы считаются неудовлетворительными',
        'not_established_from_saved_results':'не установлена по сохраненным результатам',
        'all_recorded_db_events_linked_not_source_completeness':'все записанные DB-события связаны; полнота источников не подтверждена',
        'no_recorded_related_capture_problem':'проблемы сохраненных связанных источников не зафиксированы',
        'known_related_capture_gaps':'есть зафиксированные пропуски связанных источников',
        'saved_call_start_time':'сохраненное время начала CALL','exact_keys_only_uncontrolled':'точные ключи; условия не контролировались',
        'not_comparable':'не сопоставимо','earlier':'раньше','unknown':'неизвестно','same_user':'тот же идентификатор пользователя',
        'all_users':'все идентификаторы пользователей','measurement_all_users':'замер, все идентификаторы пользователей',
        'selected_measurements_all_users':'выбранные замеры, все идентификаторы пользователей','valid':'валиден',
    }

    def display(cell, compact=False):
        if not config.settings['format']['show_paths'] and cell.sensitive:
            return 'Путь происхождения скрыт настройкой представления'
        if not config.settings['format']['show_sql'] and cell.field in {'sample_sql','normalized_sql','raw_sql'}:
            return 'SQL скрыт настройкой представления'
        value = format_cell(cell,config)
        if compact and isinstance(cell.value,str):
            if cell.field in {'sample_sql','normalized_sql','raw_sql'} and len(value)>420:
                return value[:420]+'... (полный текст по ссылке V)'
            return status_labels.get(cell.value,value)
        if compact and isinstance(cell.value,list):
            if not cell.value:
                return 'нет элементов'
            if cell.field == 'measurement_db_coverage':
                shown=[]
                for item in cell.value[:3]:
                    if isinstance(item,dict):
                        health=item.get('source_health','?')
                        shown.append(f'{item.get("measurement_id", "?")}: количество {item.get("db_linked_count_percent", "?")}% | время {item.get("db_linked_duration_percent", "?")}% | {status_labels.get(health,health)}')
                    else:
                        shown.append(str(item))
                suffix=f'; ... еще {len(cell.value)-3}' if len(cell.value)>3 else ''
                return '; '.join(shown)+suffix
            compact_lists={'known_limitations','known_differences','unknown_parameters','unavailable_dimensions','insufficient_reasons'}
            limit=2 if cell.field in compact_lists else len(cell.value)
            suffix=f'; ... еще {len(cell.value)-limit}' if len(cell.value)>limit else ''
            return '; '.join(str(x) for x in cell.value[:limit])+suffix
        return value

    references = {}
    for section in model.main_sections:
        for table in section.tables:
            for row in table.rows:
                for cell in row.cells:
                    if cell.source_file == 'presentation_dictionary':
                        continue
                    identity=(cell.source_file,cell.row_key,cell.field)
                    references.setdefault(identity,cell)
    reference_ids={key:f'V{number:04d}' for number,key in enumerate(references,1)}

    identity_fields = {
        'measurement_id','measurement_order','signature','user','operation_id','rule_id','problem_id',
        'overall_id','population_scope','comparison_id','metric','source_id','dataset_id','cohort_id',
        'reference_measurement_id','current_measurement_id'
    }
    long_tokens = ('signature','sql','limitation','reason','difference','parameter','context','table','users','coverage','status','source')
    numeric_tokens = ('count','percent','duration','avg','median','p95','p99','max','value','threshold','apdex','seconds','order')

    def column_bands(table):
        total=len(table.headers)
        if total <= 8:
            return [list(range(total))]
        fields=[cell.field for cell in table.rows[0].cells]
        keys=[index for index,field in enumerate(fields) if field in identity_fields][:3]
        if 0 not in keys:
            keys.insert(0,0)
        keys=keys[:3]
        remaining=[index for index in range(total) if index not in keys]
        capacity=max(1,8-len(keys))
        band_count=math.ceil(len(remaining)/capacity)
        chunk_size=math.ceil(len(remaining)/band_count)
        return [keys+remaining[start:start+chunk_size] for start in range(0,len(remaining),chunk_size)]

    def semantic_widths(table,indices):
        first=table.rows[0]
        weights=[]
        for index in indices:
            field=first.cells[index].field.lower()
            header=table.headers[index].lower()
            token=field+' '+header
            if field.endswith('_status'):
                weight=2.15
            elif field == 'value':
                weight=1.2
            elif field.endswith('_us') or any(item in token for item in numeric_tokens):
                weight=0.9
            elif any(item in token for item in long_tokens):
                weight=2.15
            elif field in identity_fields or field.endswith('_id'):
                weight=1.55
            else:
                weight=1.2
            weights.append(weight)
        total=sum(weights)
        return [content_width*weight/total for weight in weights]

    main_table_style = [
        ('SPAN',(0,0),(-1,0)),('BACKGROUND',(0,0),(-1,0),blue),
        ('BACKGROUND',(0,1),(-1,1),navy),('VALIGN',(0,0),(-1,-1),'TOP'),
        ('GRID',(0,0),(-1,-1),0.35,line),('ROWBACKGROUNDS',(0,2),(-1,-1),[colors.white,pale_row]),
        ('LEFTPADDING',(0,0),(-1,-1),4),('RIGHTPADDING',(0,0),(-1,-1),4),
        ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('NOSPLIT',(0,-2),(-1,-1)),
    ]

    def empty_box(text):
        box=Table([[p(text,'empty')]],colWidths=[content_width],hAlign='LEFT')
        box.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),pale_gray),('BOX',(0,0),(-1,-1),0.5,line),
                                 ('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),
                                 ('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6)]))
        return box

    story=[PartMarker('Основной отчет'),Spacer(1,13*mm),p('ОТЧЕТ ПО СОХРАНЕННЫМ ДАННЫМ','cover_label'),p(model.title,'title')]
    notice=config.settings.get('document_notice')
    if notice:
        notice_box=Table([[p(notice,'notice')]],colWidths=[content_width],hAlign='LEFT')
        notice_box.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),notice_fill),('BOX',(0,0),(-1,-1),0.8,notice_line),
                                        ('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9),
                                        ('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8)]))
        story.extend([notice_box,Spacer(1,9*mm)])
    cover_rows=[
        [p('Тип отчета','appendix_head'),p(kind_label),p('Дата отчета','appendix_head'),p(model.report_date)],
        [p('Комплект','appendix_head'),p(model.bundle_id),p('Состояние','appendix_head'),p('частичные данные' if model.partial else 'готовые данные')],
    ]
    if model.verification_notice:
        story.append(p(model.verification_notice, 'small'))
    cover_values=content_width-54*mm
    cover=Table(cover_rows,colWidths=[27*mm,cover_values*0.47,27*mm,cover_values*0.53],hAlign='LEFT')
    cover.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('GRID',(0,0),(-1,-1),0.35,line),
                               ('BACKGROUND',(0,0),(0,-1),pale_blue),('BACKGROUND',(2,0),(2,-1),pale_blue),
                               ('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),
                               ('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6)]))
    story.extend([cover,Spacer(1,8*mm),p('Отчет отображает готовые показатели и статусы. Ссылки V раскрывают точные сохраненные значения и их происхождение в техническом приложении.','small'),
                  PageBreak(),PartMarker('Основной отчет'),p('Основная часть','title')])
    if model.partial:
        story.append(empty_box('Частичные данные: analysis_complete=false. Интерпретируйте показатели вместе с указанными состояниями источников и покрытия.'))

    for section in model.main_sections:
        story.extend([CondPageBreak(42*mm),HRFlowable(width='100%',thickness=0.7,color=blue,spaceBefore=4,spaceAfter=2),p(section.title,'section')])
        if section.state != DisplayState.READY:
            story.append(p('Состояние раздела: '+section.state.value,'small_keep'))
        if section.note:
            story.append(p(section.note,'small_keep'))
        first_table_flow=True
        for table in section.tables:
            if not first_table_flow:
                story.append(CondPageBreak(42*mm))
            if not table.rows:
                story.extend([p(table.title,'table_title'),p(table.note,'small_keep') if table.note else Spacer(1,1),empty_box(table.state.value)])
                first_table_flow=False
                continue
            bands=column_bands(table)
            for band_number,indices in enumerate(bands,1):
                if not first_table_flow:
                    story.append(CondPageBreak(42*mm))
                suffix=f' - часть {band_number} из {len(bands)}' if len(bands)>1 else ''
                if table.note and band_number == 1:
                    story.append(p(table.note,'small_keep'))
                caption=table.title+' - '+table.state.value+suffix
                grid=[[p(caption,'caption')]+[p('','caption') for _ in indices[1:]],
                      [p(table.headers[index],'compact_head') for index in indices]]
                for row in table.rows:
                    values=[]
                    for index in indices:
                        cell=row.cells[index]
                        identity=(cell.source_file,cell.row_key,cell.field)
                        marker='' if cell.source_file == 'presentation_dictionary' else f' [{reference_ids[identity]}]'
                        values.append(p(display(cell,True)+marker,'compact'))
                    grid.append(values)
                table_class=Table if len(table.rows)<=3 else LongTable
                compact=table_class(grid,colWidths=semantic_widths(table,indices),repeatRows=2,
                                    splitByRow=0 if len(table.rows)<=3 else 1,hAlign='LEFT')
                compact.setStyle(TableStyle(main_table_style))
                story.append(compact)
                first_table_flow=False

    story.extend([PageBreak(),PartMarker('Техническое приложение'),p('ТЕХНИЧЕСКОЕ ПРИЛОЖЕНИЕ','cover_label'),
                  p('Приложение: полные технические данные и происхождение','title'),
                  p('Основная часть не заменяет сохраненные строки. Ниже приведены точные источники ее значений, затем полные технические поля выбранных разделов.')])

    def raw_value(cell):
        if not config.settings['format']['show_paths'] and cell.sensitive:
            return 'Путь происхождения скрыт настройкой представления'
        if not config.settings['format']['show_sql'] and cell.field in {'sample_sql','normalized_sql','raw_sql'}:
            return 'SQL скрыт настройкой представления'
        if cell.value is None:
            return 'null'
        if isinstance(cell.value,(dict,list)):
            return json.dumps(cell.value,ensure_ascii=False,separators=(',',':'))
        return str(cell.value)

    def chunks(value,limit):
        if not value:
            return ['']
        result=[]
        for line_value in value.splitlines() or ['']:
            if not line_value:
                result.append('')
                continue
            part_count=math.ceil(len(line_value)/limit)
            start=0
            for parts_left in range(part_count,0,-1):
                if parts_left == 1:
                    end=len(line_value)
                else:
                    remaining=len(line_value)-start
                    ideal=start+round(remaining/parts_left)
                    lower=max(start+1,len(line_value)-(parts_left-1)*limit)
                    upper=min(start+limit,len(line_value)-(parts_left-1))
                    radius=max(12,(ideal-start)//3)
                    candidates=[index+1 for index in range(max(lower,ideal-radius)-1,min(upper,ideal+radius))
                                if line_value[index].isspace()]
                    end=min(candidates,key=lambda value:abs(value-ideal)) if candidates else min(max(ideal,lower),upper)
                result.append(line_value[start:end])
                start=end
        return result or ['']

    appendix_header_style=[
        ('SPAN',(0,0),(-1,0)),('BACKGROUND',(0,0),(-1,0),blue),
        ('BACKGROUND',(0,1),(-1,1),pale_blue),('TEXTCOLOR',(0,1),(-1,1),navy),
        ('VALIGN',(0,0),(-1,-1),'TOP'),('GRID',(0,0),(-1,-1),0.3,line),
        ('ROWBACKGROUNDS',(0,2),(-1,-1),[colors.white,pale_row]),
        ('LEFTPADDING',(0,0),(-1,-1),4),('RIGHTPADDING',(0,0),(-1,-1),4),
        ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('NOSPLIT',(0,-2),(-1,-1)),
    ]

    story.extend([CondPageBreak(65*mm),p('Индекс происхождения значений основной части','section_plain')])
    origin_groups={}
    for identity,cell in references.items():
        origin_groups.setdefault((cell.source_file,cell.row_key),[]).append((identity,cell))
    first_origin=True
    for (source,key),items in origin_groups.items():
        display_key=key
        if source == 'files.csv' and not config.settings['format']['show_paths']:
            display_key=next((str(cell.value) for _,cell in items if cell.field == 'source_id'),'путь скрыт')
        caption=f'{source} | ключ {display_key}'
        entries=[]
        for identity,cell in items:
            state=cell.state.value+(('; '+cell.reason) if cell.reason else '')
            parts=chunks(raw_value(cell),220)
            for index,part in enumerate(parts):
                value=part
                if index == 0:
                    value+='\n'+(cell.unit or 'без единицы')+'; '+state
                entries.append((reference_ids[identity] if index == 0 else '',
                                cell.field if index == 0 else cell.field+' (продолжение '+str(index+1)+')',value))
        rows=[[p(caption,'caption')]+[p('','caption') for _ in range(5)],
              [p('Ссылка','appendix_head'),p('Поле','appendix_head'),p('Точное значение и состояние','appendix_head')]*2]
        for start in range(0,len(entries),2):
            values=[]
            for reference,field,value in entries[start:start+2]:
                values.extend([p(reference,'compact'),p(field,'appendix_head'),p(value,'compact')])
            while len(values)<6:
                values.extend([p('','compact'),p('','appendix_head'),p('','compact')])
            rows.append(values)
        if not first_origin:
            story.append(CondPageBreak(42*mm))
        origin_block=content_width/2
        origin=LongTable(rows,colWidths=[15*mm,32*mm,origin_block-47*mm]*2,repeatRows=2,splitByRow=1,hAlign='LEFT')
        origin.setStyle(TableStyle(appendix_header_style))
        story.append(origin)
        first_origin=False

    rendered=set()
    for section in model.sections:
        prepared=[]
        for table in section.tables:
            if not table.rows:
                prepared.append((table,[],0))
                continue
            effective=[]
            duplicates=0
            for row in table.rows:
                row_identity=(table.name,row.key)
                if row_identity in rendered:
                    duplicates+=1
                    continue
                rendered.add(row_identity)
                effective.append(row)
            if effective:
                prepared.append((table,effective,duplicates))
        if not prepared:
            continue
        story.extend([CondPageBreak(80*mm),HRFlowable(width='100%',thickness=0.7,color=blue,spaceBefore=5,spaceAfter=2),p(section.title,'section_plain')])
        if section.state != DisplayState.READY:
            story.append(p('Состояние раздела: '+section.state.value,'small'))
        if section.note:
            story.append(p(section.note,'small'))
        first_table_flow=True
        for table,effective_rows,duplicates in prepared:
            if not first_table_flow:
                story.append(CondPageBreak(70*mm))
            story.extend([p(f'{table.name} - {table.state.value}','table_title_plain'),
                          p(f'Показано {len(effective_rows)} из {table.available_rows} строк выбранного отображения.'+
                            (f' Ещё {duplicates} дублирующих технических строк уже приведено выше.' if duplicates else ''),'small')])
            if table.note:
                story.append(p(table.note,'small'))
            if not effective_rows:
                story.append(empty_box(table.state.value))
                first_table_flow=False
                continue
            first_row=True
            for row in effective_rows:
                key=row.key
                if table.name == 'files' and not config.settings['format']['show_paths']:
                    key=next((str(c.value) for c in row.cells if c.field == 'source_id'),'путь скрыт')
                origins=sorted({cell.source_file for cell in row.cells})
                entries=[]
                for cell in row.cells:
                    parts=chunks(raw_value(cell),180)
                    for index,part in enumerate(parts):
                        unit_label=f' [{cell.unit}]' if cell.unit else ''
                        label=cell.field+unit_label if index == 0 else cell.field+' (продолжение '+str(index+1)+')'
                        if len(origins)>1:
                            label=cell.source_file+'\n'+label
                        entries.append((label,part))
                caption=f'{table.name} | {row.state.value} | ключ {key} | источник: {", ".join(origins)}'
                detail_rows=[[p(caption,'caption')]+[p('','caption') for _ in range(5)],
                             [p('Поле','appendix_head'),p('Точное значение','appendix_head')]*3]
                for start in range(0,len(entries),3):
                    values=[]
                    for label,value in entries[start:start+3]:
                        values.extend([p(label,'appendix_head'),p(value,'compact')])
                    while len(values)<6:
                        values.extend([p('','appendix_head'),p('','compact')])
                    detail_rows.append(values)
                if not first_row:
                    story.append(CondPageBreak(42*mm))
                detail_block=content_width/3
                detail=LongTable(detail_rows,colWidths=[24*mm,detail_block-24*mm]*3,repeatRows=2,splitByRow=1,hAlign='LEFT')
                detail.setStyle(TableStyle(appendix_header_style))
                story.append(detail)
                first_row=False
                first_table_flow=False

    output.parent.mkdir(parents=True,exist_ok=True)
    fd,temp=tempfile.mkstemp(prefix='.report-',suffix='.pdf',dir=output.parent)
    os.close(fd)
    try:
        doc=SimpleDocTemplate(temp,pagesize=page_size,leftMargin=horizontal_margin,rightMargin=horizontal_margin,
                              topMargin=15*mm,bottomMargin=18*mm,title=model.title,
                              author='1c-tj-toolkit: визуализация сохраненных результатов')
        doc.build(story,canvasmaker=NumberedCanvas)
        data.assert_unchanged()
        config.assert_unchanged()
        if overwrite:
            os.replace(temp,output)
        else:
            # Atomic no-clobber publication; a concurrent creator is not overwritten.
            os.link(temp,output)
    finally:
        Path(temp).unlink(missing_ok=True)
    return output
