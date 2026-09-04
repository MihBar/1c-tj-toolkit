"""Build three visual PDF demos from an isolated synthetic saved-result bundle.

The frozen producer fixture is copied before presentation-only stress values are
inserted. No journal parser, analyzer, derive_slices module, LLM or network is
used. Existing analytical numbers and statuses are not recalculated.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import shutil
import sys

REPORT_DIR=Path(__file__).resolve().parents[1]
REPO_ROOT=REPORT_DIR.parents[1]
sys.path.insert(0,str(REPORT_DIR))

from report_config import load_config
from report_input import descriptor, load_input
from report_model import build_model
from report_layout import render_pdf
from report_schema import canonical, digest, profile, require


FIXTURE=REPORT_DIR/'tests/fixtures/current'
MARKER='.synthetic-pdf-demo.json'
MEASUREMENTS=['capture@2026-09-01','capture@2026-09-02','capture@2026-09-03']
LONG_SQL=(
    '/* СИНТЕТИЧЕСКИЙ SQL ДЛЯ ПРОВЕРКИ ПЕРЕНОСОВ, НЕ ПРОИЗВОДСТВЕННЫЙ ЗАПРОС */\n'
    'SELECT Заказы.Ссылка, Заказы.Номер, Клиенты.Наименование, Склады.Наименование КАК Склад, '
    'Остатки.Номенклатура, Остатки.КоличествоОстаток, Резервы.КоличествоОстаток КАК Резерв, '
    'ЕСТЬNULL(Цены.Цена, 0) КАК Цена\n'
    'FROM Документ.ЗаказКлиента КАК Заказы\n'
    'ЛЕВОЕ СОЕДИНЕНИЕ Справочник.Контрагенты КАК Клиенты ПО Клиенты.Ссылка = Заказы.Контрагент\n'
    'ЛЕВОЕ СОЕДИНЕНИЕ РегистрНакопления.ТоварыНаСкладах.Остатки(&Момент, Склад = &Склад) КАК Остатки '
    'ПО Остатки.Номенклатура = Заказы.Номенклатура\n'
    'ЛЕВОЕ СОЕДИНЕНИЕ РегистрНакопления.ТоварыВРезерве.Остатки(&Момент, ЗаказКлиента = &Заказ) КАК Резервы '
    'ПО Резервы.Номенклатура = Остатки.Номенклатура\n'
    'ЛЕВОЕ СОЕДИНЕНИЕ РегистрСведений.ЦеныНоменклатуры.СрезПоследних(&Момент, ВидЦены = &ВидЦены) КАК Цены '
    'ПО Цены.Номенклатура = Остатки.Номенклатура\n'
    'ГДЕ Заказы.Проведен = ИСТИНА И Заказы.Дата МЕЖДУ &НачалоПериода И &КонецПериода '
    'И (Остатки.КоличествоОстаток - ЕСТЬNULL(Резервы.КоличествоОстаток, 0)) < &МинимальныйСвободныйОстаток\n'
    'УПОРЯДОЧИТЬ ПО Клиенты.Наименование, Заказы.Дата, Остатки.Номенклатура'
)
OPERATION_LABELS={
    'A':'Формирование пакета документов по заказу клиента с проверкой взаиморасчетов, резервов и доступности товара на нескольких складах',
    'B':'Перепроведение реализации товаров и услуг с восстановлением движений по регистрам накопления и контролем фонового обмена',
    'Untargeted':'Регламентное задание сверки остатков и очереди обмена без настроенной цели APDEX',
}


def write_json(path,value):
    path.write_text(canonical(value)+'\n',encoding='utf-8')


def copy_fixture(destination):
    analysis=destination/'synthetic_data/analysis'
    slices=destination/'synthetic_data/slices'
    analysis.mkdir(parents=True,exist_ok=True)
    slices.mkdir(parents=True,exist_ok=True)
    for source in (FIXTURE/'analysis').iterdir():
        target=analysis/('analysis.sqlite' if source.name == 'analysis.sqlite.bin' else source.name)
        shutil.copyfile(source,target)
    for source in (FIXTURE/'slices').iterdir():
        shutil.copyfile(source,slices/source.name)
    return analysis,slices


def stress_synthetic_bundle(analysis,slices):
    sql_path=analysis/'heavy_sql.csv'
    with sql_path.open(encoding='utf-8-sig',newline='') as stream:
        reader=csv.DictReader(stream)
        fields,rows=reader.fieldnames,list(reader)
    for index,row in enumerate(rows,1):
        row['sample_sql']=LONG_SQL+f'\n/* СИНТЕТИЧЕСКИЙ ЗАМЕР {index}: <условие> &Параметр */'
        row['normalized_sql']='select <поля> from <синтетические_таблицы> where <условие> and параметр = <parameter>'
        row['tables']='Документ.ЗаказКлиента; РегистрНакопления.ТоварыНаСкладах; РегистрНакопления.ТоварыВРезерве; РегистрСведений.ЦеныНоменклатуры'
    with sql_path.open('w',encoding='utf-8-sig',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields,lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)

    manifest_path=analysis/'analysis_metrics.json'
    manifest=json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    by_key={(row['measurement_id'],row['sql_fingerprint_sha256']):row for row in rows}
    for item in manifest['heavy_sql']:
        source=by_key[(item['measurement_id'],item['sql_fingerprint_sha256'])]
        for field in ('sample_sql','normalized_sql','tables'):
            item[field]=source[field]
    manifest['analysis_complete']=False
    manifest['source_processing_complete']=False
    manifest['source_content_hashes_complete']=False
    manifest['absolute_timestamps_complete']=False
    manifest['warnings'].append({
        'type':'synthetic_pdf_demo_partial_data',
        'message':'Искусственный признак частичных данных для проверки визуального состояния отчета.'
    })
    write_json(manifest_path,manifest)

    p=profile()
    names={'analysis_metrics.json','source_map.json','analysis.sqlite'} | {name+'.csv' for name in p['analysis_tables']}
    hashes={name:descriptor(analysis/name) for name in sorted(names)}
    bundle_id=digest(canonical(hashes).encode())
    slice_manifest_path=slices/'slice_manifest.json'
    slice_manifest=json.loads(slice_manifest_path.read_text(encoding='utf-8-sig'))
    slice_manifest['bundle_id']=bundle_id
    slice_manifest['input_files']=hashes
    slice_manifest['source_analysis_complete']=False
    write_json(slice_manifest_path,slice_manifest)
    return bundle_id


def config_for(kind):
    common={
        'report_config_version':'1.0',
        'report_kind':kind,
        'title':{
            'overview':'Демонстрационный обзор результатов анализатора',
            'comparison':'Демонстрационное сравнение сохраненных замеров',
            'history':'Демонстрационная история операций и числовых проблем',
        }[kind],
        'document_notice':'ДЕМОНСТРАЦИОННЫЙ ОТЧЕТ. Все данные, имена, SQL и статусы синтетические. Это не SLA и не результат анализа пользовательских журналов.',
        'locale':'ru-RU',
        'report_date':'2026-09-03',
        'labels':{
            'measurements':{
                MEASUREMENTS[0]:'Замер 1 - исходная синтетическая нагрузка',
                MEASUREMENTS[1]:'Замер 2 - повтор после изменения условий',
                MEASUREMENTS[2]:'Замер 3 - частичная выборка с отсутствующими наблюдениями',
            },
            'users':{'User':'Синтетический пользователь Альфа','Other':'Синтетический пользователь Бета'},
            'operations':OPERATION_LABELS,
        },
        'format':{'digits':3,'duration':'s','volume':'MiB','show_paths':False,'show_sql':True},
        'fonts':{'profile':'liberation-sans'},
    }
    if kind == 'overview':
        common.update({
            'sections':['provenance','sources','quality','operations','sql','errors','locks','db_chatty_summary','apdex','apdex_overall','problem_views'],
            'tables':{
                'operations':{'sort':[{'field':'p95_us','direction':'desc'}],'top_n':2},
                'heavy_sql':{'sort':[{'field':'duration_us','direction':'desc'}],'top_n':1},
                'errors':{'top_n':2},'locks':{'top_n':2},'db_chatty':{'top_n':2},
                'apdex':{'top_n':3},'apdex_overall':{'top_n':1},
                'problem_improved':{'top_n':1},'problem_persisting':{'top_n':1},
                'problem_worsened':{'top_n':1},'problem_new':{'top_n':1},'problem_unchecked':{'top_n':1},
            }
        })
    elif kind == 'comparison':
        common.update({
            'sections':['provenance','quality','comparisons','db_chatty_comparison','apdex_changes','problem_views','sql'],
            'tables':{
                'measurement_comparisons':{'top_n':1},'db_chatty_changes':{'top_n':1},'apdex_changes':{'top_n':1},
                'heavy_sql':{'top_n':1},
                'problem_improved':{'top_n':1},'problem_persisting':{'top_n':1},
                'problem_worsened':{'top_n':1},'problem_new':{'top_n':1},'problem_unchecked':{'top_n':1},
            }
        })
    else:
        common.update({
            'sections':['provenance','quality','operations','operations_all_users','problem_history','problem_views','sql'],
            'tables':{
                'operation_history':{'top_n':2},'operation_history_all_users':{'top_n':1},'problem_history':{'top_n':1},
                'heavy_sql':{'top_n':1},
                'problem_improved':{'top_n':1},'problem_persisting':{'top_n':1},
                'problem_worsened':{'top_n':1},'problem_new':{'top_n':1},'problem_unchecked':{'top_n':1},
            }
        })
    return common


def build(destination,overwrite=False):
    destination=Path(destination).resolve()
    marker=destination/MARKER
    if destination.exists():
        require(marker.is_file(),f'Refusing non-demo destination: {destination}')
        require(overwrite,'Synthetic demo destination exists; pass --overwrite')
    else:
        destination.mkdir(parents=True)
    marker.write_text(json.dumps({'synthetic':True,'generator':'build_synthetic_demo.py'},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    analysis,slices=copy_fixture(destination)
    bundle_id=stress_synthetic_bundle(analysis,slices)
    data=load_input(analysis,slices)
    require(data.bundle_id == bundle_id,'Synthetic bundle identity mismatch')
    configs=destination/'configs'
    configs.mkdir(exist_ok=True)
    outputs=[]
    for kind in ('overview','comparison','history'):
        config_path=configs/(kind+'.synthetic.json')
        config_path.write_text(json.dumps(config_for(kind),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        config=load_config(config_path)
        output=destination/('synthetic_'+kind+'.pdf')
        render_pdf(build_model(data,config),config,data,output,overwrite=overwrite)
        outputs.append(output)
    (destination/'README.txt').write_text(
        'СИНТЕТИЧЕСКИЕ ДЕМОНСТРАЦИОННЫЕ ДАННЫЕ\n\n'
        'Комплект создан из замороженной искусственной producer-фикстуры только для визуальной проверки PDF.\n'
        'Длинные подписи и SQL добавлены как стресс-данные представления. Аналитические показатели и статусы не пересчитывались.\n'
        'Папки synthetic_data, configs и PDF не относятся к пользовательским данным.\n',encoding='utf-8')
    return outputs


def main():
    parser=argparse.ArgumentParser(description='Build isolated synthetic PDF demos')
    parser.add_argument('--output-dir',type=Path,default=REPO_ROOT/'output/pdf/synthetic_demo')
    parser.add_argument('--overwrite',action='store_true')
    args=parser.parse_args()
    for output in build(args.output_dir,args.overwrite):
        print(output)


if __name__ == '__main__':
    main()
