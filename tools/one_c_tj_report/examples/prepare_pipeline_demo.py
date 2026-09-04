"""Prepare raw synthetic TJ inputs and configs for the full producer pipeline.

The script writes only source ``.log`` files and explicit configuration files.
Analyzer and slice JSON/CSV are intentionally left to the real command-line
producers documented in ``examples/README.md``.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil


REPORT_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = REPORT_DIR.parents[1]
MARKER = ".synthetic-producer-pipeline.json"

OPERATION_LONG = (
    "ОбщийМодуль.ИнтеграционнаяПроверка."
    "ФормированиеОченьДлинногоСинтетическогоОтчетаСКириллицей"
)
OPERATION_FAST = (
    "Документ.СинтетическийЗаказ."
    "ПроведениеСПроверкойРезервовИВзаиморасчетов"
)
OPERATION_SPARSE = "РегламентноеЗадание.СинтетическаяСверкаОстатков"
USER = "СинтетическийПользователь"

SERIES_MEASUREMENTS = [
    "m01@2026-09-01",
    "m02@2026-09-02",
    "m03@2026-09-03",
]
SINGLE_MEASUREMENT = "only@2026-09-01"

LONG_SQL = (
    "SELECT Заказы.Ссылка, Заказы.Номер, Контрагенты.Наименование, "
    "Остатки.Номенклатура, Остатки.КоличествоОстаток "
    "FROM Документ_ЗаказКлиента Заказы "
    "LEFT JOIN Справочник_Контрагенты Контрагенты "
    "ON Контрагенты.Ссылка = Заказы.Контрагент "
    "LEFT JOIN РегистрНакопления_ТоварыНаСкладах Остатки "
    "ON Остатки.Склад = Заказы.Склад "
    "WHERE Заказы.Проведен = 1 AND Заказы.Комментарий = 'СИНТЕТИКА' "
    "AND Остатки.КоличествоОстаток < 100 ORDER BY Контрагенты.Наименование"
)


def _json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _quote(value: object) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _record(event: str, end_us: int, duration_us: int, **attributes: object) -> str:
    minute, remainder = divmod(end_us, 60_000_000)
    second, micros = divmod(remainder, 1_000_000)
    fields = ",".join(
        f"{key}={_quote(value)}"
        for key, value in attributes.items()
        if value is not None
    )
    return f"{minute:02}:{second:02}.{micros:06}-{duration_us},{event},5,{fields}\n"


def _call_block(
    *,
    ordinal: int,
    signature: str,
    duration_us: int,
    db_count: int,
    error: bool = False,
    lock: bool = False,
    cpu: object | None = "auto",
    out_bytes: object | None = "auto",
) -> str:
    end_us = ordinal * 20_000_000
    session = f"S{ordinal:02}"
    common = {
        "Usr": USER,
        "OSThread": "7",
        "SessionID": session,
        "Context": signature,
    }
    call_attributes: dict[str, object | None] = dict(common)
    if cpu == "auto":
        call_attributes["CpuTime"] = duration_us // 3
    elif cpu is not None:
        call_attributes["CpuTime"] = cpu
    call_attributes.update(
        {
            "Memory": 0 if ordinal == 1 else 1024 * ordinal,
            "MemoryPeak": 4096 * ordinal,
            "InBytes": 128 * ordinal,
        }
    )
    if out_bytes == "auto":
        call_attributes["OutBytes"] = 2048 * ordinal
    elif out_bytes is not None:
        call_attributes["OutBytes"] = out_bytes

    records = [_record("CALL", end_us, duration_us, **call_attributes)]
    interval_start = end_us - duration_us
    for index in range(db_count):
        db_end = interval_start + max(1, duration_us // 3) + index * 1_000
        records.append(
            _record(
                "DBPOSTGRS",
                db_end,
                30_000 + index * 2_000,
                **common,
                RowsAffected=0 if index % 2 == 0 else None,
                Sql=LONG_SQL + f" /* вызов {ordinal}, запрос {index + 1} */",
            )
        )
    if error:
        records.append(
            _record(
                "EXCP",
                end_us - 100_000,
                10_000,
                **common,
                Descr=(
                    "Синтетическая ошибка проверки длинного сообщения: "
                    "объект не найден, исходные пользовательские данные отсутствуют"
                ),
            )
        )
    if lock:
        records.append(
            _record(
                "TLOCK",
                end_us - 200_000,
                750_000,
                **common,
            )
        )
    return "".join(records)


def _measurement_text(name: str) -> str:
    if name == "m01":
        long_values = [2_000_000, 2_200_000, 2_400_000, 2_600_000]
        fast_values = [600_000, 700_000, 800_000]
        sparse_values = [1_100_000]
        db_counts = 2
    elif name == "m02":
        long_values = [1_400_000, 1_600_000, 1_800_000, 2_000_000]
        fast_values = []
        sparse_values = [900_000, 1_000_000]
        db_counts = 4
    elif name == "m03":
        long_values = [3_000_000, 3_200_000, 3_400_000, 3_600_000]
        fast_values = [500_000, 600_000, 700_000]
        sparse_values = []
        db_counts = 6
    else:
        raise ValueError(f"unknown synthetic measurement: {name}")

    blocks: list[str] = []
    ordinal = 1
    for index, duration in enumerate(long_values):
        blocks.append(
            _call_block(
                ordinal=ordinal,
                signature=OPERATION_LONG,
                duration_us=duration,
                db_count=db_counts,
                error=index == len(long_values) - 1,
                lock=index == 1,
            )
        )
        ordinal += 1
    for index, duration in enumerate(fast_values):
        blocks.append(
            _call_block(
                ordinal=ordinal,
                signature=OPERATION_FAST,
                duration_us=duration,
                db_count=1 + (index % 2),
                cpu="bad" if name == "m03" and index == 0 else "auto",
                out_bytes=None if name == "m03" and index == 1 else "auto",
            )
        )
        ordinal += 1
    for duration in sparse_values:
        blocks.append(
            _call_block(
                ordinal=ordinal,
                signature=OPERATION_SPARSE,
                duration_us=duration,
                db_count=0,
                cpu=None,
                out_bytes=None,
            )
        )
        ordinal += 1
    return "".join(blocks)


def _write_log(path: Path, text: str, *, damaged_tail: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = b"\xef\xbb\xbf" + text.encode("utf-8")
    if damaged_tail:
        payload += b"\x00synthetic-binary-tail"
    path.write_bytes(payload)


def analytics_config() -> dict:
    return {
        "config_version": "1.0",
        "slices": [
            "data_quality",
            "operation_history",
            "operation_history_all_users",
            "measurement_comparisons",
            "comparability",
            "db_chatty",
            "db_chatty_calls",
            "db_chatty_fast_calls",
            "db_chatty_duration",
            "db_chatty_coverage",
            "db_chatty_changes",
            "apdex",
            "apdex_calls",
            "apdex_uncovered",
            "apdex_coverage",
            "apdex_overall",
            "apdex_composition",
            "apdex_changes",
            "problem_registry",
            "problem_history",
            "problem_improved",
            "problem_persisting",
            "problem_worsened",
            "problem_new",
            "problem_unchecked",
            "problem_rule_coverage",
        ],
        "measurement_ids": None,
        "expected_bundle_id": None,
        "data_quality": {
            "min_call_count": 2,
            "db_linkage_warning_percent": 95,
        },
        "operations": {
            "series_baseline_measurement_id": SERIES_MEASUREMENTS[0],
            "measurement_order": SERIES_MEASUREMENTS,
            "min_comparison_count": 2,
        },
        "db_chatty": {
            "thresholds": [1, 3, 5],
            "duration_bounds_seconds": [1, 2, 5],
            "fast_call_max_seconds": 1,
        },
        "apdex": {
            "targets": [
                {
                    "signature": OPERATION_LONG,
                    "t_seconds": 2,
                    "status": "engineering_proposal",
                    "source": "Синтетическая цель только для интеграционной проверки",
                }
            ],
            "classes": [
                {
                    "class_id": "synthetic-fast-operation",
                    "signatures": [OPERATION_FAST],
                    "t_seconds": 0.5,
                    "status": "engineering_proposal",
                    "source": "Синтетическая групповая цель только для проверки",
                }
            ],
            "min_call_count": 2,
            "failure_policy": "latency_only",
            "confirmed_failures": {"bundle_id": None, "calls": []},
        },
        "problems": {
            "series_id": "synthetic-producer-integration",
            "rules": [
                {
                    "rule_id": "synthetic-p95-above-2s",
                    "metric": "operation.p95_us",
                    "operator": ">",
                    "threshold": 2_000_000,
                    "min_call_count": 2,
                    "source": "Синтетический диагностический порог; не SLA",
                },
                {
                    "rule_id": "synthetic-chatty-call-above-3",
                    "metric": "db_chatty.calls_above_threshold_count",
                    "db_events_threshold": 3,
                    "operator": ">",
                    "threshold": 0,
                    "min_call_count": 1,
                    "source": "Синтетический профиль DB/CALL; не диагноз причины",
                },
                {
                    "rule_id": "synthetic-apdex-deficit",
                    "metric": "apdex.deficit",
                    "operator": ">",
                    "threshold": 0.2,
                    "min_call_count": 2,
                    "source": "Синтетический порог APDEX; не согласованный SLA",
                },
            ],
        },
    }


def single_analytics_config() -> dict:
    config = analytics_config()
    config["operations"]["series_baseline_measurement_id"] = SINGLE_MEASUREMENT
    config["operations"]["measurement_order"] = [SINGLE_MEASUREMENT]
    config["problems"]["series_id"] = "synthetic-producer-single"
    return config


def report_config(kind: str) -> dict:
    title = {
        "overview": "Синтетический обзор полного производственного контура",
        "comparison": "Синтетическое сравнение замеров полного контура",
        "history": "Синтетическая история замеров полного контура",
    }[kind]
    common: dict[str, object] = {
        "report_config_version": "1.0",
        "report_kind": kind,
        "title": title,
        "document_notice": (
            "СИНТЕТИЧЕСКИЕ ДАННЫЕ. Результат интеграционной проверки; "
            "не пользовательские журналы, не SLA и не проверка производительности."
        ),
        "locale": "ru-RU",
        "report_date": "2026-09-03",
        "labels": {
            "measurements": {
                SERIES_MEASUREMENTS[0]: "Замер 1: исходные синтетические условия",
                SERIES_MEASUREMENTS[1]: "Замер 2: измененная синтетическая нагрузка",
                SERIES_MEASUREMENTS[2]: "Замер 3: частично поврежденный источник",
            },
            "users": {USER: "Синтетический пользователь"},
            "operations": {
                OPERATION_LONG: "Длинная операция формирования отчета",
                OPERATION_FAST: "Проведение синтетического заказа",
                OPERATION_SPARSE: "Сверка остатков с неполными счетчиками",
            },
        },
        "format": {
            "digits": 3,
            "duration": "s",
            "volume": "MiB",
            "show_paths": False,
            "show_sql": True,
        },
        "fonts": {"profile": "liberation-sans"},
    }
    if kind == "overview":
        common.update(
            {
                "sections": [
                    "provenance",
                    "sources",
                    "quality",
                    "operations",
                    "sql",
                    "errors",
                    "locks",
                    "db_chatty_summary",
                    "apdex",
                    "apdex_overall",
                    "problems",
                ],
                "tables": {
                    "operations": {
                        "sort": [{"field": "p95_us", "direction": "desc"}],
                        "top_n": 2,
                    },
                    "heavy_sql": {"top_n": 1},
                    "errors": {"top_n": 2},
                    "locks": {"top_n": 2},
                    "db_chatty": {"top_n": 2},
                    "apdex": {"top_n": 2},
                    "apdex_overall": {
                        "sort": [{"field": "apdex_denominator", "direction": "desc"}],
                        "top_n": 1,
                    },
                    "problem_registry": {"top_n": 3},
                },
            }
        )
    elif kind == "comparison":
        common.update(
            {
                "sections": [
                    "provenance",
                    "quality",
                    "comparisons",
                    "db_chatty_comparison",
                    "apdex_changes",
                    "problem_views",
                ],
                "tables": {
                    "measurement_comparisons": {"top_n": 3},
                    "db_chatty_changes": {"top_n": 2},
                    "apdex_changes": {"top_n": 2},
                    "problem_improved": {"top_n": 2},
                    "problem_persisting": {"top_n": 2},
                    "problem_worsened": {"top_n": 2},
                    "problem_new": {"top_n": 2},
                    "problem_unchecked": {"top_n": 2},
                },
            }
        )
    else:
        common.update(
            {
                "sections": [
                    "provenance",
                    "quality",
                    "operations",
                    "operations_all_users",
                    "problem_history",
                ],
                "tables": {
                    "operation_history": {"top_n": 3},
                    "operation_history_all_users": {"top_n": 2},
                    "problem_history": {"top_n": 3},
                },
            }
        )
    return common


def single_report_config(kind: str = "overview", *, with_slices: bool = False) -> dict:
    sections = {
        "overview": [
            "provenance",
            "sources",
            "quality",
            "operations",
            "sql",
            "errors",
            "locks",
        ],
        "comparison": ["provenance", "quality", "comparisons"],
        "history": ["provenance", "quality", "operations", "problem_history"],
    }[kind]
    tables = (
        {
            "operations": {"top_n": 3},
            "heavy_sql": {"top_n": 1},
            "errors": {"top_n": 2},
            "locks": {"top_n": 2},
        }
        if kind == "overview"
        else {}
    )
    return {
        "report_config_version": "1.0",
        "report_kind": kind,
        "title": {
            "overview": "Однозамерный синтетический отчет без срезов",
            "comparison": (
                "Однозамерное синтетическое сравнение с готовыми срезами"
                if with_slices
                else "Однозамерная синтетическая проверка сравнения без срезов"
            ),
            "history": (
                "Однозамерная синтетическая история с готовыми срезами"
                if with_slices
                else "Однозамерная синтетическая проверка истории без срезов"
            ),
        }[kind],
        "document_notice": (
            "СИНТЕТИЧЕСКИЕ ДАННЫЕ. Проверка одного замера "
            + ("с готовым каталогом срезов." if with_slices else "без каталога срезов.")
        ),
        "locale": "ru-RU",
        "report_date": "2026-09-03",
        "labels": {
            "measurements": {SINGLE_MEASUREMENT: "Единственный синтетический замер"},
            "users": {USER: "Синтетический пользователь"},
            "operations": {
                OPERATION_LONG: "Длинная операция формирования отчета",
                OPERATION_FAST: "Проведение синтетического заказа",
                OPERATION_SPARSE: "Сверка остатков с неполными счетчиками",
            },
        },
        "sections": sections,
        "tables": tables,
        "format": {
            "digits": 3,
            "duration": "s",
            "volume": "MiB",
            "show_paths": False,
            "show_sql": True,
        },
        "fonts": {"profile": "liberation-sans"},
    }


def prepare(destination: Path, overwrite: bool = False) -> Path:
    destination = Path(destination).resolve()
    marker = destination / MARKER
    if destination.exists():
        if not marker.is_file():
            raise ValueError(f"refusing non-demo destination: {destination}")
        if not overwrite:
            raise ValueError("synthetic pipeline destination exists; pass --overwrite")
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    _json(
        destination / MARKER,
        {
            "synthetic": True,
            "generator": "prepare_pipeline_demo.py",
            "producer_outputs_are_not_prebuilt": True,
        },
    )

    raw_series = destination / "raw" / "series"
    _write_log(
        raw_series / "m01" / "capture" / "rphost_1" / "26090110.log",
        _measurement_text("m01"),
    )
    _write_log(
        raw_series / "m02" / "capture" / "rphost_1" / "26090210.log",
        _measurement_text("m02"),
    )
    _write_log(
        raw_series / "m03" / "capture" / "rphost_1" / "26090310.log",
        _measurement_text("m03"),
        damaged_tail=True,
    )
    _write_log(
        destination
        / "raw"
        / "single"
        / "only"
        / "capture"
        / "rphost_1"
        / "26090110.log",
        _measurement_text("m01"),
    )

    configs = destination / "configs"
    _json(configs / "analytics.series.json", analytics_config())
    _json(configs / "analytics.single.json", single_analytics_config())
    _json(configs / "overview.series.json", report_config("overview"))
    _json(configs / "comparison.series.json", report_config("comparison"))
    _json(configs / "history.series.json", report_config("history"))
    for kind in ("overview", "comparison", "history"):
        _json(
            configs / f"{kind}.single-no-slices.json",
            single_report_config(kind),
        )
    for kind in ("comparison", "history"):
        _json(
            configs / f"{kind}.single-with-slices.json",
            single_report_config(kind, with_slices=True),
        )
    (destination / "README.txt").write_text(
        "СИНТЕТИЧЕСКИЙ ИНТЕГРАЦИОННЫЙ НАБОР\n\n"
        "raw/ содержит только искусственные исходные ТЖ.\n"
        "analysis/, slices/ и reports/ должны быть созданы настоящими CLI.\n"
        "m03 содержит NUL-хвост; анализатор запускается с --salvage-nul-prefix, "
        "чтобы состояние частичных данных было сохранено производителем.\n",
        encoding="utf-8",
    )
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare raw synthetic logs/configs for the full producer pipeline"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "output" / "pdf" / "producer_pipeline_demo",
    )
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    try:
        destination = prepare(args.output_dir, args.overwrite)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 2
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
