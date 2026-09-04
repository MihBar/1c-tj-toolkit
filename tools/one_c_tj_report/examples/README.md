# Синтетические примеры PDF

В каталоге есть два разных примера. `build_synthetic_demo.py` предназначен для
стрессовой проверки вёрстки по замороженной producer-фикстуре.
`prepare_pipeline_demo.py` готовит исходные синтетические `.log` и конфигурации
для полного прохода через настоящие CLI производителей. Он не создаёт
`analysis_metrics.json`, CSV анализа, срезы или PDF: эти файлы должны появиться
только после запуска анализатора, `derive_slices` и генераторов отчёта.

## Полный проход от исходных журналов

Команды ниже выполняются из корня клонированного репозитория. Каталог
`output\pdf\producer_pipeline_demo` изолирован от пользовательских данных.
Повторная подготовка удаляет только каталог с маркером этого синтетического
примера.

```powershell
$TjPython = 'python'
$Repo = (Get-Location).Path
$Analyzer = Join-Path $Repo 'tools\one_c_tj_analyzer'
$PdfTools = Join-Path $Repo 'tools\one_c_tj_report'
$Demo = Join-Path $Repo 'output\pdf\producer_pipeline_demo'
$SeriesAnalysis = Join-Path $Demo 'analysis\series'
$SeriesSlices = Join-Path $Demo 'slices\series'
$Reports = Join-Path $Demo 'reports'

& $TjPython -B "$PdfTools\examples\prepare_pipeline_demo.py" `
    --output-dir $Demo --overwrite
if ($LASTEXITCODE -ne 0) { throw 'Не удалось подготовить синтетические журналы' }

& $TjPython -B "$Analyzer\analyze_1c_tj.py" `
    (Join-Path $Demo 'raw\series') `
    --output-dir $SeriesAnalysis `
    --capture-id 'synthetic-producer-series-2026-09-03' `
    --archive-mode never --salvage-nul-prefix
if ($LASTEXITCODE -ne 0) { throw 'Анализатор завершился с ошибкой' }

& $TjPython -B "$Analyzer\verify_analysis.py" `
    --analysis-dir $SeriesAnalysis
if ($LASTEXITCODE -ne 0) { throw 'Проверка анализа не пройдена' }

& $TjPython -B "$Analyzer\derive_slices.py" `
    --analysis-dir $SeriesAnalysis `
    --config (Join-Path $Demo 'configs\analytics.series.json') `
    --output-dir $SeriesSlices
if ($LASTEXITCODE -ne 0) { throw 'Расчёт срезов завершился с ошибкой' }

& $TjPython -B "$Analyzer\verify_slices.py" `
    --analysis-dir $SeriesAnalysis --slices-dir $SeriesSlices
if ($LASTEXITCODE -ne 0) { throw 'Проверка срезов не пройдена' }

& $TjPython -B "$Analyzer\audit_stage1.py" `
    --analysis-dir $SeriesAnalysis --slices-dir $SeriesSlices
if ($LASTEXITCODE -ne 0) { throw 'Независимый аудит срезов не пройден' }

& $TjPython -B "$PdfTools\build_report.py" `
    --analysis-dir $SeriesAnalysis --slices-dir $SeriesSlices `
    --report-config (Join-Path $Demo 'configs\overview.series.json') `
    --output (Join-Path $Reports 'overview.pdf')
if ($LASTEXITCODE -ne 0) { throw 'Overview PDF не создан' }

& $TjPython -B "$PdfTools\build_trend_report.py" `
    --analysis-dir $SeriesAnalysis --slices-dir $SeriesSlices `
    --report-config (Join-Path $Demo 'configs\comparison.series.json') `
    --output (Join-Path $Reports 'comparison.pdf')
if ($LASTEXITCODE -ne 0) { throw 'Comparison PDF не создан' }

& $TjPython -B "$PdfTools\build_iteration_history_report.py" `
    --analysis-dir $SeriesAnalysis --slices-dir $SeriesSlices `
    --report-config (Join-Path $Demo 'configs\history.series.json') `
    --output (Join-Path $Reports 'history.pdf')
if ($LASTEXITCODE -ne 0) { throw 'History PDF не создан' }
```

Три результата полного прохода:

| Режим | Назначение | Путь |
|---|---|---|
| Overview | Область, качество, сохранённые показатели и дополнительные готовые срезы | `output\pdf\producer_pipeline_demo\reports\overview.pdf` |
| Comparison | Текущий и опорный замеры, готовые значения и дельты, база и ограничения сравнения | `output\pdf\producer_pipeline_demo\reports\comparison.pdf` |
| History | Порядок замеров, история операций и сохранённые статусы числовых проблем | `output\pdf\producer_pipeline_demo\reports\history.pdf` |

Тот же путь в изолированном временном каталоге, включая сверку ячеек PDF с
producer-CSV и атомарность при повреждённом входе, запускается одной адресной
проверкой:

```powershell
& $TjPython -B "$PdfTools\tests\test_producer_pipeline.py" -v
```

### Настройка аналитики

`configs\analytics.series.json` создаётся внутри демонстрационного каталога и
передаётся только `derive_slices`. В нём находятся выбранные срезы,
`measurement_order`, база серии, минимальные размеры выборки, пороги DB-chatty,
границы длительности, цели и политика APDEX, а также правила истории проблем.
Все значения демонстрационные: это не SLA и не рекомендуемые рабочие пороги.
Для реального запуска создайте отдельную конфигурацию аналитики и проверяйте её
вместе с контрактами расчётчика.

### Настройка представления

`overview.series.json`, `comparison.series.json` и `history.series.json`
передаются только генераторам PDF. Они управляют названием, пометкой документа,
подписями, составом разделов, сортировкой, top-N, округлением и единицами показа.
В них не задаются пороги, базы сравнений, APDEX или правила проблем. Фильтр и
top-N выбирают готовые строки для показа и не меняют аналитическую выборку.

### Один замер без срезов

Этот вариант подтверждает, что общий отчёт принимает настоящий результат
анализатора без `--slices-dir`. Сравнения, APDEX и история проблем при этом не
рассчитываются и не подменяются нулями.

```powershell
$SingleAnalysis = Join-Path $Demo 'analysis\single'
$Validation = Join-Path $Demo 'validation'

& $TjPython -B "$Analyzer\analyze_1c_tj.py" `
    (Join-Path $Demo 'raw\single') `
    --output-dir $SingleAnalysis `
    --capture-id 'synthetic-producer-single-2026-09-03' `
    --archive-mode never
if ($LASTEXITCODE -ne 0) { throw 'Однозамерный анализ завершился с ошибкой' }

& $TjPython -B "$Analyzer\verify_analysis.py" `
    --analysis-dir $SingleAnalysis
if ($LASTEXITCODE -ne 0) { throw 'Проверка однозамерного анализа не пройдена' }

& $TjPython -B "$PdfTools\build_report.py" `
    --analysis-dir $SingleAnalysis `
    --report-config (Join-Path $Demo 'configs\overview.single-no-slices.json') `
    --output (Join-Path $Validation 'single-no-slices.pdf')
if ($LASTEXITCODE -ne 0) { throw 'Однозамерный PDF без срезов не создан' }
```

Результат этого варианта:
`output\pdf\producer_pipeline_demo\validation\single-no-slices.pdf`.

### Один замер с готовыми срезами

Для рассчитанного однозамерного комплекта подготовлен отдельный
`analytics.single.json`. Он не имитирует один замер фильтром многозамерной серии:
расчётчик получает настоящий комплект с единственным `measurement_id`.

```powershell
$SingleSlices = Join-Path $Demo 'slices\single'

& $TjPython -B "$Analyzer\derive_slices.py" `
    --analysis-dir $SingleAnalysis `
    --config (Join-Path $Demo 'configs\analytics.single.json') `
    --output-dir $SingleSlices
if ($LASTEXITCODE -ne 0) { throw 'Однозамерные срезы не созданы' }

& $TjPython -B "$Analyzer\verify_slices.py" `
    --analysis-dir $SingleAnalysis --slices-dir $SingleSlices
if ($LASTEXITCODE -ne 0) { throw 'Однозамерные срезы не прошли проверку' }

& $TjPython -B "$Analyzer\audit_stage1.py" `
    --analysis-dir $SingleAnalysis --slices-dir $SingleSlices
if ($LASTEXITCODE -ne 0) { throw 'Однозамерный числовой аудит не пройден' }

& $TjPython -B "$PdfTools\build_trend_report.py" `
    --analysis-dir $SingleAnalysis --slices-dir $SingleSlices `
    --report-config (Join-Path $Demo 'configs\comparison.single-with-slices.json') `
    --output (Join-Path $Validation 'single-with-slices-comparison.pdf')

& $TjPython -B "$PdfTools\build_iteration_history_report.py" `
    --analysis-dir $SingleAnalysis --slices-dir $SingleSlices `
    --report-config (Join-Path $Demo 'configs\history.single-with-slices.json') `
    --output (Join-Path $Validation 'single-with-slices-history.pdf')
```

Здесь история содержит одну сохранённую точку; отсутствующие предыдущие замеры
и базы остаются отсутствующими, а не создаются визуализатором.

## Границы примера

- Синтетический smoke-проход подтверждает совместимость точек входа и контрактов
  на малом наборе. Он не измеряет производительность, память и устойчивость на
  полном объёме реальных журналов и не подтверждает готовность production-среды.
- В третьем замере намеренно записан NUL-хвост. Флаг
  `--salvage-nul-prefix` сохраняет завершённые записи и формирует у производителя
  состояние частичных данных; `PASS` верификатора не превращает его в полный
  сбор.
- `verify_slices.py` заново запускает выбранные аналитические builders для
  проверки сохранённых срезов; `audit_stage1.py` выполняет дополнительную
  независимую числовую проверку. Обе команды запускаются отдельно. PDF-генератор
  их не вызывает и не выполняет аналитический пересчёт.
- Совпадение сигнатур операций означает совпадение технического ключа, но не
  доказывает одинаковый пользовательский сценарий, роль, параметры или данные.
- Изменение сохранённой метрики между замерами само по себе не доказывает
  исправление или регрессию кода.
- Пример не покрывает архивы, карту копий источников, ошибки доступа и предельные
  размеры файлов. Для них используются отдельные тесты и рабочие проверки.

## Визуальная демонстрация по фикстуре

`build_synthetic_demo.py` создаёт отдельный комплект в
`output\pdf\synthetic_demo`: копию замороженных синтетических результатов, три
конфигурации и PDF. В копию добавляются только стрессовые строки представления:
длинный кириллический SQL, длинные подписи и явный признак частичного комплекта.
Эта демонстрация не читает исходные ТЖ и не запускает анализатор или
`derive_slices`; её нельзя использовать как доказательство производственной
интеграции.

```powershell
python tools/one_c_tj_report/examples/build_synthetic_demo.py
```

Повторная сборка разрешена только для каталога с маркером соответствующей
синтетической демонстрации и требует `--overwrite`.
