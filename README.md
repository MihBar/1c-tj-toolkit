# 1c-tj-toolkit

## О проекте

1c-tj-toolkit — набор локальных CLI-инструментов для воспроизводимого разбора
технологического журнала 1С. Анализатор читает журналы и архивы, сохраняет
детализацию событий в SQLite и формирует проверяемые метрики и аналитические
срезы в JSON/CSV. Отдельный модуль строит PDF по уже рассчитанным результатам.

Проект рассчитан на изучение, проверку и дальнейшую доработку. Основной анализ
работает локально на стандартной библиотеке Python и не отправляет данные во
внешние сервисы.

## Статус и ограничения

Это ранний проект без стабильного публичного API и гарантии обратной
совместимости между будущими версиями. Поддерживаемые форматы явно указаны в
контрактах; неизвестные версии отклоняются, а не преобразуются автоматически.

Автоматические тесты используют синтетические и обезличенные данные. Они не
являются производственной валидацией, не подтверждают полноту реального ТЖ и не
доказывают производительность на больших журналах. `PASS` верификатора означает
согласованность сохранённого комплекта в пределах реализованных проверок, а не
правильность причинной или экспертной интерпретации результатов.

## Конфиденциальность данных

Не прикладывайте реальные технологические журналы и результаты анализа к
публичным issues, discussions или pull requests. ТЖ, JSON, CSV, SQLite и PDF
могут содержать имена пользователей, серверов и информационных баз, IP-адреса,
внутренние URL, абсолютные пути, SQL и сведения о бизнес-процессах. Для
воспроизведения используйте минимальный синтетический либо необратимо
обезличенный пример без секретов и клиентских идентификаторов.

Сведения об уязвимостях передавайте по правилам [SECURITY.md](SECURITY.md).

## Независимый проект

1c-tj-toolkit является независимым проектом и не связан, не поддерживается и не
аффилирован с фирмой «1С». Упоминание 1С используется только для обозначения
формата анализируемого технологического журнала. Товарные знаки принадлежат их
правообладателям.

Публичный baseline и его ограничения описаны в [BASELINE.md](BASELINE.md). Команды ниже выполняются из корня проекта.

## Лицензии

Основной код и документация распространяются по [MIT License](LICENSE),
copyright (c) 2026 Mikhail Baranov. Включённые шрифты Liberation Sans 2.1.5 остаются
под отдельной [SIL Open Font License 1.1](tools/one_c_tj_report/assets/fonts/LICENSE_LIBERATION)
и не перелицензируются по MIT. Полный перечень и границы применения лицензий:
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Правила подготовки изменений: [CONTRIBUTING.md](CONTRIBUTING.md).

## Состав

| Каталог / файл | Назначение |
|---|---|
| `tools/one_c_tj_analyzer/analyze_1c_tj.py` | Парсер ТЖ и архивов, метрики CALL/SQL/ошибок/блокировок, результат SQLite/JSON/CSV; версия 1.6.1 |
| `tools/one_c_tj_analyzer/derive_slices.py` | Расчёт 26 таблиц по сохранённым результатам: история операций, сравнения, DB-chatty, APDEX, история проблем; версия 1.8.0 |
| `tools/one_c_tj_analyzer/slice_*.py` | Модули расчётов, загрузки данных и настройки срезов |
| `tools/one_c_tj_analyzer/verify_analysis.py` | Проверка целостности и согласованности сохранённых результатов; версия 1.2.0 |
| `tools/one_c_tj_analyzer/verify_event_store.py`, `verify_populations.py` | Проверка идентификаторов, ссылок, SQL-словаря и агрегатов по отдельным событиям |
| `tools/one_c_tj_analyzer/verify_slices.py` | Проверка результатов расчётчика срезов |
| `tools/one_c_tj_analyzer/audit_stage1.py` | Независимая числовая проверка полного набора срезов |
| `tools/one_c_tj_analyzer/configs/` | 6 примеров JSON-конфигураций, включая полный первый этап |
| `tools/one_c_tj_analyzer/tests/` | Автоматические тесты на синтетических данных |
| `tools/one_c_tj_analyzer/*.md` | Инструкции запуска, контракты схемы, срезов, счётчиков, SQL и ошибок |
| `tools/one_c_tj_report/` | 3 генератора PDF: общий отчёт, динамика, история по итерациям |
| `requirements-report.txt` | Зависимость генераторов PDF |
| `requirements-report-test.txt` | Закреплённые зависимости тестов PDF |
| `BASELINE.md` | Состав начального baseline, версии компонентов и границы проверки |
| `.github/workflows/tests.yml` | Тесты анализатора и PDF на Windows и Linux |

Локальный `TRANSFER_MANIFEST.json` описывает исторический перенос файлов. Он исключён из Git; актуальный состав baseline фиксируется коммитом.

## Среда и проверка

Анализатор и расчётчик срезов используют стандартную библиотеку Python 3.10+. Для PDF нужен ReportLab; кириллические Liberation Sans 2.1.5 regular/bold с лицензией поставляются в репозитории. Системный поиск шрифтов не используется. Тесты PDF дополнительно используют pypdf.

Установите Python 3.10+ и задайте команду либо путь к своему интерпретатору в `$TjPython`.

```powershell
$TjPython = 'python'
$TjToolDir = Join-Path $PWD 'tools\one_c_tj_analyzer'

& $TjPython -B "$TjToolDir\analyze_1c_tj.py" --version
& $TjPython -B "$TjToolDir\derive_slices.py" --list-slices
& $TjPython -B -m unittest discover -s "$TjToolDir\tests" -v
```

При подготовке отдельной среды для PDF установите зависимость командой `& $TjPython -m pip install -r .\requirements-report.txt`.
Для запуска PDF-тестов используйте расширенный набор: `& $TjPython -m pip install -r .\requirements-report-test.txt`.

Для Linux/macOS из корня проекта:

```bash
python3 -B tools/one_c_tj_analyzer/analyze_1c_tj.py --version
python3 -B -m unittest discover -s tools/one_c_tj_analyzer/tests -v
```

### Универсальные команды запуска

Обёртки `scripts/run.cmd` для Windows и `scripts/run.sh` для Linux/macOS
определяют корень проекта независимо от текущего каталога, передают аргументы
исходным Python CLI без изменения и возвращают их код завершения. Бизнес-логика
в обёртках не дублируется. Чтобы явно выбрать интерпретатор, задайте переменную
окружения `PYTHON` равной пути к исполняемому файлу Python 3.

```powershell
scripts\run.cmd --help
scripts\run.cmd test
scripts\run.cmd analyze "C:\Path With Spaces\1clogs" --output-dir "C:\Results\run_001"
scripts\run.cmd verify --analysis-dir "C:\Results\run_001"
scripts\run.cmd slices --analysis-dir "C:\Results\run_001" --config .\tools\one_c_tj_analyzer\configs\stage1.full.example.json --output-dir "C:\Results\slices_001"
scripts\run.cmd report --analysis-dir "C:\Results\run_001" --report-config .\tools\one_c_tj_report\configs\overview.example.json --output "C:\Results\report_001.pdf"
```

```bash
./scripts/run.sh --help
./scripts/run.sh test
./scripts/run.sh analyze "/path/with spaces/1clogs" --output-dir "/tmp/tj-results/run_001"
./scripts/run.sh check-data
```

Команды `test-analyzer` и `test-report` запускают наборы тестов по отдельности.
`check-data` проверяет сохранённый обезличенный fixture и его согласованность в
JSON, CSV и SQLite через существующие контрактные тесты PDF-модуля. Для команд
`report`, `test-report`, `test` и `check-data` предварительно установите
зависимости из `requirements-report-test.txt`. Рабочие результаты следует
направлять за пределы репозитория или в исключённые каталоги `data/analysis/` и
`output/`; обёртки намеренно не выбирают каталог результата по умолчанию.

## Рабочий порядок

Исходные журналы задаются явно. В примере ниже замените `C:\Path\To\1clogs` на фактический каталог. Результаты новых запусков сохраняйте в отдельных каталогах внутри проекта.

```powershell
$TjAnalysis = Join-Path $PWD 'data\analysis\run_001'
$TjSlices = Join-Path $PWD 'output\stage1_run_001'
$TjConfig = Join-Path $TjToolDir 'configs\stage1.full.example.json'

# Разбор исходных журналов; если готовый комплект уже есть, начните с его проверки.
& $TjPython -B "$TjToolDir\analyze_1c_tj.py" 'C:\Path\To\1clogs' --output-dir $TjAnalysis --capture-id 'capture-2026-09-03-example' --archive-mode auto
if ($LASTEXITCODE -ne 0) { throw 'Разбор журналов завершился с ошибкой' }

& $TjPython -B "$TjToolDir\verify_analysis.py" --analysis-dir $TjAnalysis
if ($LASTEXITCODE -ne 0) { throw 'Проверка анализа не пройдена' }

& $TjPython -B "$TjToolDir\derive_slices.py" --analysis-dir $TjAnalysis --config $TjConfig --output-dir $TjSlices
if ($LASTEXITCODE -ne 0) { throw 'Расчёт срезов завершился с ошибкой' }

& $TjPython -B "$TjToolDir\verify_slices.py" --analysis-dir $TjAnalysis --slices-dir $TjSlices
if ($LASTEXITCODE -ne 0) { throw 'Проверка срезов не пройдена' }

& $TjPython -B "$TjToolDir\audit_stage1.py" --analysis-dir $TjAnalysis --slices-dir $TjSlices
if ($LASTEXITCODE -ne 0) { throw 'Числовой аудит не пройден' }
```

Обычный запуск, архивы, карта копий, все 21 файл схемы 1.6 и диагностика: [RUNBOOK.md](tools/one_c_tj_analyzer/RUNBOOK.md). Подробности аудита срезов: [STAGE1_RUNBOOK.md](tools/one_c_tj_analyzer/STAGE1_RUNBOOK.md). В примерах APDEX цели T намеренно не заданы: их нужно явно настроить для нужных операций. Перед настройкой сохраните отдельную рабочую копию конфигурации.

Входные ссылки/reparse points отклоняются. Для архивов, несжатых источников,
записей ТЖ и полей CSV действуют явные ресурсные пределы; точные значения и
правила безопасного импорта CSV приведены в RUNBOOK.

`PASS` верификатора означает согласованность сохранённых данных. Изучите также `observation_state` и `completeness`: частичный или пустой комплект может быть согласованным. В схеме 1.5/1.6 проверяются уникальные ID, ссылки, позиции, словарь SQL, покрытие счётчиков и однократное включение событий в суммы. Перцентили пересчитываются по отдельным наблюдениям; усреднение перцентилей групп не допускается. Реальные исходники при этой проверке не читаются. `verify_analysis.py` 1.2.0 не применяет названия предметной области, бизнес-пороги или цели APDEX: они задаются отдельно в конфигурации `derive_slices`.

Расчётчик срезов принимает 1.2–1.6 через строгий загрузчик. Неизвестные версии и несовместимые fingerprints отклоняются; переименование версии в манифесте не является миграцией. Полная детализация использует диск, но CALL и часть агрегатов остаются в памяти; время и пик памяти на реальном полном объёме требуют отдельного замера.

PDF-визуализатор принимает анализ 1.6 / анализатор 1.6.1 и необязательные срезы 1.8 / расчётчик 1.8.0. Старые и неизвестные версии отклоняются. Он проверяет структуру и происхождение файлов, отображает готовые показатели и статусы, не вызывает расчётчик и не читает исходные ТЖ. Контракты данных: [NUMERIC_CONTRACT.md](tools/one_c_tj_analyzer/NUMERIC_CONTRACT.md), [SQL_NORMALIZATION.md](tools/one_c_tj_analyzer/SQL_NORMALIZATION.md).

Для общего PDF настройте отдельный JSON представления (название, дата, разделы, сортировка и top-N):

```powershell
& $TjPython -B .\tools\one_c_tj_report\build_report.py --analysis-dir $TjAnalysis --report-config .\tools\one_c_tj_report\configs\overview.example.json --output .\output\report_run_001.pdf
```

Все три точки входа используют общий загрузчик, модель и оформление. `--slices-dir` передаёт готовый комплект срезов; `--overwrite` явно разрешает замену PDF. Повреждённый вход завершает команду с ошибкой и не заменяет существующий PDF. [Настройки и ограничения](tools/one_c_tj_report/README.md).

Настройка аналитики (`derive_slices`) и настройка представления PDF разделены.
Полный воспроизводимый пример от исходных синтетических `.log` до трёх PDF,
включая отдельные `verify_analysis`, `verify_slices`, `audit_stage1`, запуск из
другого рабочего каталога и один замер без срезов: [интеграционный пример](tools/one_c_tj_report/examples/README.md).
Все JSON/CSV этого прохода создаются настоящими производителями; малый
синтетический набор не проверяет производительность на полном реальном объёме.

[Контракт универсального PDF-визуализатора 1.0](tools/one_c_tj_report/CONTRACT.md) разделяет аналитику и представление, описывает допустимые входы, состояния отсутствующих данных и ограничения интерпретации.

Схема 1.6 раздельно сохраняет все EXCP/QERR, уникальные затронутые CALL и версионированные гипотезы инцидентов. [Контракт ошибок](tools/one_c_tj_analyzer/ERROR_DETAIL.md).

## Перенос

Схема анализа 1.5 сохраняет все DBPOSTGRS и решения о CALL в SQLite и дополнительных CSV. Контракт, карта источников и неизменённое правило выбора CALL: [EVENT_DETAIL.md](tools/one_c_tj_analyzer/EVENT_DETAIL.md).

Проект выделен из прежнего рабочего каталога с анализатором и отчётами. Исходный каталог сохранён отдельно; локальный манифест переноса не является перечнем файлов текущего baseline.

Перенесены скрипты, тесты, примеры конфигураций и инструкции. Исходные ТЖ, рассчитанные данные, готовые отчёты, кэши Python и прежние разовые скрипты из `work/` в этот комплект не входят. Каталог `data/analysis/run_001` в командах — место для будущего либо отдельно скопированного готового комплекта, он пока не заполнен.
