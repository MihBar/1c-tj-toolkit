#!/usr/bin/env python3
"""Deterministic analyzer for 1C:Enterprise technological journal files.

The program contains no report prose generation and no calls to external services.
Given the same input bytes and command-line options it produces the same JSON/CSV
content.  It uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import bisect
import collections
import contextlib
import csv
import datetime as dt
import gzip
import hashlib
import json
import math
import mmap
import os
import re
import statistics
import sqlite3
import stat
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable, Iterator

from numeric_quality import (FIELDS, NUMERIC_RULES_VERSION, QUALITY_CSV_FIELDS, CounterStats,
                             operation_counters, parse_counters)
from sql_normalization import (SQL_NORMALIZATION_VERSION, SQL_FINGERPRINT_ALGORITHM,
                               SQL_CSV_FIELDS, normalize_sql, normalization_status,
                               sql_fingerprint, sql_tables, sql_features)
from record_stream import RecordStream
from source_identity import assign_sources
from event_store import EventStore, CALL_DETAIL_FIELDS, VERSIONS, timestamp as stored_timestamp
from event_linking import LINKAGE_RULES
from error_rules import ERROR_METADATA, ERROR_GROUP_FIELDS, normalize_error, classify_error
from error_store import link_errors, error_rows, error_groups, error_summary
from progress import ProgressReporter


VERSION = "1.6.1"
SCHEMA_VERSION = "1.6"

HEADER_RE = re.compile(
    r"^(?P<minute>\d{2}):(?P<second>\d{2})\.(?P<micros>\d{6})-"
    r"(?P<duration>\d+),(?P<event>[^,\r\n]+),(?P<level>\d+),(?P<rest>.*)$",
    re.S,
)
HEADER_LINE_RE = re.compile(rb"(?m)^\d{2}:\d{2}\.\d{6}-\d+,[^,\r\n]+,\d+,")
FILE_RE = re.compile(
    r"(?P<yy>\d{2})(?P<month>\d{2})(?P<day>\d{2})(?P<hour>\d{2})\.log$",
    re.I,
)
PROCESS_DIR_RE = re.compile(r"^(?:rphost|ragent|rmngr|ras|1cv8c|web|ws)_\d+$", re.I)
WS_RE = re.compile(r"\s+")
BACKGROUND_RE = re.compile(
    r"Регламентн|Фонов|Background|ServerJobExecutor|ScheduledJob|ВыполнитьФоновоеЗадание",
    re.I,
)
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".gz")
SOURCE_READ_ERRORS = (OSError, EOFError, UnicodeError, RuntimeError, tarfile.TarError, zipfile.BadZipFile)
DEFAULT_EXCLUDED_DIRS = {"analysis_output", "analysis_data", ".git", "node_modules", "__pycache__"}
MAX_SOURCE_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_LOG_BYTES = 16 * 1024 * 1024 * 1024


class AnalyzerError(RuntimeError):
    """Expected input/usage error with a stable process exit code."""

    def __init__(self, message: str, exit_code: int = 2):
        super().__init__(message)
        self.exit_code = exit_code


def split_tech_fields(text: str) -> list[str]:
    fields: list[str] = []
    start = 0
    quote: str | None = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote is None:
            if ch in "'\"":
                quote = ch
            elif ch == ",":
                fields.append(text[start:i])
                start = i + 1
        elif ch == quote:
            if i + 1 < len(text) and text[i + 1] == quote:
                i += 1
            else:
                quote = None
        i += 1
    fields.append(text[start:])
    return fields


def parse_attrs(rest: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for item in split_tech_fields(rest):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            quote = value[0]
            value = value[1:-1].replace(quote + quote, quote)
        attrs[key] = value
    return attrs


def clean_text(text: str, limit: int | None = None) -> str:
    value = WS_RE.sub(" ", text or "").strip()
    if limit is not None and len(value) > limit:
        return value[: max(0, limit - 3)] + "..."
    return value


def context_root(context: str) -> str:
    for line in (context or "").splitlines():
        line = line.strip()
        if line:
            return clean_text(line, 900)
    return ""


def nearest_rank(values: list[int], p: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(p * len(ordered)) - 1))
    return ordered[index]


def safe_mean(values: list[int]) -> float:
    return (sum(values) / len(values)) if values else 0.0


def median_value(values: list[int]) -> float:
    return round(float(statistics.median(values)), 3) if values else 0.0


def canonical_path(path: Path) -> str:
    return str(path.resolve())


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def is_link_or_reparse(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def archive_suffix(path: Path) -> str:
    lower = path.name.lower()
    for suffix in sorted(ARCHIVE_SUFFIXES, key=len, reverse=True):
        if lower.endswith(suffix):
            return suffix
    return ""


@dataclass
class SourceRef:
    kind: str
    path: Path
    member: str = ""
    size: int = 0
    dataset_id: str = ""
    measurement_id: str = ""
    process: str = ""
    member_ordinal: int | None = None
    stable_id: str = ""
    version_id: str = ""
    capture_id: str = ""
    origin_id: str = ""
    process_scope: str = ""
    logical_log_key: str = ""
    identity_status: str = ""
    input_root: Path | None = None

    @property
    def source_id(self) -> str:
        return self.display_path

    @property
    def display_path(self) -> str:
        suffix = f"[entry={self.member_ordinal}]" if self.member_ordinal is not None else ""
        return f"{self.path.resolve()}::{self.member}{suffix}" if self.member else str(self.path.resolve())

    @property
    def log_name(self) -> str:
        return PurePosixPath(self.member).name if self.member else self.path.name

    @contextlib.contextmanager
    def open_binary(self) -> Iterator[BinaryIO]:
        if self.input_root is not None:
            try:
                relative = self.path.absolute().relative_to(self.input_root.absolute())
            except ValueError as exc:
                raise OSError("source escapes the selected input root") from exc
            cursor = self.input_root
            for part in relative.parts:
                cursor = cursor / part
                if is_link_or_reparse(cursor):
                    raise OSError("source path contains a link/reparse point")
        if self.kind == "loose":
            with self.path.open("rb") as stream:
                yield stream
            return
        if self.kind == "zip":
            with zipfile.ZipFile(self.path) as archive:
                member = archive.infolist()[self.member_ordinal] if self.member_ordinal is not None else archive.getinfo(self.member)
                if member.filename != self.member:
                    raise OSError("Archive member changed after discovery")
                if member.is_dir() or stat.S_ISLNK(member.external_attr >> 16) or member.file_size > MAX_SOURCE_BYTES:
                    raise OSError("Archive member type or size is not allowed")
                with archive.open(member, "r") as stream:
                    yield stream
            return
        if self.kind == "tar":
            with tarfile.open(self.path, "r:*") as archive:
                member = None
                if self.member_ordinal is not None:
                    for ordinal, candidate in enumerate(archive):
                        if ordinal == self.member_ordinal:
                            member = candidate
                            break
                else:
                    member = archive.getmember(self.member)
                if member is None or member.name != self.member:
                    raise OSError("Archive member changed after discovery")
                if not member.isfile() or member.size > MAX_SOURCE_BYTES:
                    raise OSError("Archive member type or size is not allowed")
                stream = archive.extractfile(member)
                if stream is None:
                    raise OSError(f"archive member is not readable: {self.member}")
                with stream:
                    yield stream
            return
        if self.kind == "gzip":
            with gzip.open(self.path, "rb") as stream:
                yield stream
            return
        raise OSError(f"unsupported source kind: {self.kind}")


@dataclass
class SourceHealth:
    source: SourceRef
    status: str
    reason: str = ""
    nul_offset: int | None = None
    sha256: str = ""
    records: int = 0
    parse_errors: int = 0
    analyzed_bytes: int = 0

    def as_dict(self) -> dict:
        return {
            "source": self.source.display_path,
            "resolved_source": str(self.source.path.resolve()),
            "kind": self.source.kind,
            "member": self.source.member,
            "member_ordinal": self.source.member_ordinal,
            "source_id": self.source.stable_id,
            "source_version_id": self.source.version_id,
            "size_bytes": self.source.size,
            "analyzed_bytes": self.analyzed_bytes,
            "dataset_id": self.source.dataset_id,
            "measurement_id": self.source.measurement_id,
            "process": self.source.process,
            "status": self.status,
            "reason": self.reason,
            "nul_offset": self.nul_offset,
            "sha256": self.sha256,
            "records": self.records,
            "parse_errors": self.parse_errors,
        }


def classify_dataset(root: Path, logical_path: PurePosixPath) -> tuple[str, str, str]:
    parts = list(logical_path.parts)
    process_index: int | None = None
    for index, part in enumerate(parts[:-1]):
        if PROCESS_DIR_RE.match(part):
            process_index = index
            break
    if process_index is None:
        capture_parts = parts[:-1]
        process = logical_path.parent.name
    else:
        capture_parts = parts[:process_index]
        process = parts[process_index]
    dataset_id = "/".join(capture_parts) or "(root)"
    measurement_id = capture_parts[0] if capture_parts else "(root)"
    return dataset_id, measurement_id, process


def should_exclude(path: Path, root: Path, output_dir: Path, excluded_names: set[str]) -> bool:
    if is_within(path, output_dir):
        return True
    try:
        # Keep exclusion matching lexical. Link and reparse-point rejection is
        # enforced separately during discovery and again immediately before read.
        rel_parts = path.absolute().relative_to(root.absolute()).parts[:-1]
    except ValueError:
        return True
    return any(part.lower() in excluded_names for part in rel_parts)


def list_archive_sources(
    archive_path: Path,
    root: Path,
    warnings: list[dict],
) -> list[SourceRef]:
    suffix = archive_suffix(archive_path)
    result: list[SourceRef] = []
    try:
        if suffix == ".zip":
            with zipfile.ZipFile(archive_path) as archive:
                all_infos = archive.infolist()
                if len(all_infos) > MAX_ARCHIVE_MEMBERS:
                    raise OSError(f"archive has more than {MAX_ARCHIVE_MEMBERS} members")
                infos = sorted(((i, item) for i, item in enumerate(all_infos) if not item.is_dir()), key=lambda x: (x[1].filename, x[0]))
                total_log_bytes = 0
                for ordinal, info in infos:
                    if not info.filename.lower().endswith(".log"):
                        continue
                    if stat.S_ISLNK(info.external_attr >> 16):
                        warnings.append({"type": "archive_member_skipped", "path": str(archive_path), "message": f"symbolic-link member rejected: {clean_text(info.filename, 300)}"})
                        continue
                    if info.file_size > MAX_SOURCE_BYTES:
                        warnings.append({"type": "archive_member_skipped", "path": str(archive_path), "message": f"member exceeds {MAX_SOURCE_BYTES} byte source limit: {clean_text(info.filename, 300)}"})
                        continue
                    total_log_bytes += info.file_size
                    if total_log_bytes > MAX_ARCHIVE_LOG_BYTES:
                        raise OSError(f"archive .log members exceed {MAX_ARCHIVE_LOG_BYTES} byte total limit")
                    logical = PurePosixPath(archive_path.relative_to(root).as_posix()) / PurePosixPath(info.filename)
                    dataset_id, measurement_id, process = classify_dataset(root, logical)
                    result.append(SourceRef("zip", archive_path, info.filename, info.file_size, dataset_id, measurement_id, process, ordinal))
        elif suffix in {".tar", ".tar.gz", ".tgz"}:
            with tarfile.open(archive_path, "r:*") as archive:
                members = []
                for ordinal, item in enumerate(archive):
                    if ordinal >= MAX_ARCHIVE_MEMBERS:
                        raise OSError(f"archive has more than {MAX_ARCHIVE_MEMBERS} members")
                    if item.isfile():
                        members.append((ordinal, item))
                members.sort(key=lambda x: (x[1].name, x[0]))
                total_log_bytes = 0
                for ordinal, member in members:
                    if not member.name.lower().endswith(".log"):
                        continue
                    if member.size > MAX_SOURCE_BYTES:
                        warnings.append({"type": "archive_member_skipped", "path": str(archive_path), "message": f"member exceeds {MAX_SOURCE_BYTES} byte source limit: {clean_text(member.name, 300)}"})
                        continue
                    total_log_bytes += member.size
                    if total_log_bytes > MAX_ARCHIVE_LOG_BYTES:
                        raise OSError(f"archive .log members exceed {MAX_ARCHIVE_LOG_BYTES} byte total limit")
                    logical = PurePosixPath(archive_path.relative_to(root).as_posix()) / PurePosixPath(member.name)
                    dataset_id, measurement_id, process = classify_dataset(root, logical)
                    result.append(SourceRef("tar", archive_path, member.name, member.size, dataset_id, measurement_id, process, ordinal))
        elif suffix == ".gz":
            member_name = archive_path.name[:-3]
            if member_name.lower().endswith(".log"):
                logical = PurePosixPath(archive_path.relative_to(root).as_posix()).with_name(member_name)
                dataset_id, measurement_id, process = classify_dataset(root, logical)
                result.append(SourceRef("gzip", archive_path, member_name, archive_path.stat().st_size, dataset_id, measurement_id, process))
    except SOURCE_READ_ERRORS as exc:
        warnings.append({"type": "archive_error", "path": str(archive_path), "message": clean_text(str(exc), 500)})
    if not result:
        warnings.append({"type": "archive_without_logs", "path": str(archive_path), "message": "no readable .log members"})
    return result


def discover_sources(
    root: Path,
    output_dir: Path,
    archive_mode: str,
    excluded_dirs: set[str],
) -> tuple[list[SourceRef], list[dict], list[dict]]:
    warnings: list[dict] = []
    archive_inventory: list[dict] = []
    excluded_names = {name.lower() for name in DEFAULT_EXCLUDED_DIRS | excluded_dirs}
    def discovery_error(exc):
        warnings.append({"type": "discovery_error", "path": str(getattr(exc, "filename", None) or root),
                         "message": clean_text(str(exc), 500)})

    files = []
    for directory, dirs, names in os.walk(root, onerror=discovery_error, followlinks=False):
        kept_dirs = []
        for name in sorted(dirs):
            path = Path(directory) / name
            try:
                if is_link_or_reparse(path):
                    warnings.append({"type": "symlink_skipped", "path": str(path), "message": "directory link/reparse point is not traversed"})
                    continue
            except OSError as exc:
                discovery_error(exc)
                continue
            if not should_exclude(path, root, output_dir, excluded_names):
                kept_dirs.append(name)
        dirs[:] = kept_dirs
        for name in sorted(names):
            path = Path(directory)/name
            if should_exclude(path, root, output_dir, excluded_names):
                continue
            if path.suffix.lower() != ".log" and not archive_suffix(path):
                continue
            try:
                if is_link_or_reparse(path):
                    warnings.append({"type": "symlink_skipped", "path": str(path), "message": "file link/reparse point is not read"})
                    continue
                info = path.stat()
                if stat.S_ISREG(info.st_mode):
                    files.append((path, info.st_size))
            except OSError as exc:
                discovery_error(exc)
    files.sort(key=lambda item: (item[0].as_posix().lower(), item[0].as_posix()))
    loose_paths = [path for path, _ in files if path.suffix.lower() == ".log"]
    sources = []
    for path, size in files:
        if path.suffix.lower() == ".log":
            logical = PurePosixPath(path.relative_to(root).as_posix())
            dataset_id, measurement_id, process = classify_dataset(root, logical)
            sources.append(SourceRef("loose", path, "", size, dataset_id, measurement_id, process))
    archives = [(path, size) for path, size in files if archive_suffix(path)]
    for archive, archive_size in archives:
        suffix = archive_suffix(archive)
        stem_name = archive.name[: -len(suffix)] if suffix else archive.stem
        extracted_candidates = [archive.parent / stem_name]
        has_extracted = any(candidate in path.parents for candidate in extracted_candidates for path in loose_paths)
        include = archive_mode == "always" or (archive_mode == "auto" and not has_extracted)
        if archive_mode == "never":
            include = False
        status = "included" if include else ("skipped_extracted_copy_present" if has_extracted else "skipped_by_option")
        archive_inventory.append({
            "path": str(archive),
            "size_bytes": archive_size,
            "status": status,
        })
        if include:
            sources.extend(list_archive_sources(archive, root, warnings))

    for source in sources:
        source.input_root = root
    sources.sort(key=lambda source: source.source_id.lower())
    return sources, archive_inventory, warnings


def hash_stream(stream: BinaryIO, max_bytes: int = MAX_SOURCE_BYTES, on_bytes=None) -> tuple[str, int | None, bytes, int]:
    digest = hashlib.sha256()
    nul_offset: int | None = None
    first = bytearray()
    offset = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        if offset + len(chunk) > max_bytes:
            raise OSError(f"uncompressed source exceeds {max_bytes} byte limit")
        digest.update(chunk)
        if on_bytes is not None:
            on_bytes(len(chunk))
        if len(first) < 256 * 1024:
            first.extend(chunk[: 256 * 1024 - len(first)])
        if nul_offset is None:
            pos = chunk.find(b"\x00")
            if pos >= 0:
                nul_offset = offset + pos
        offset += len(chunk)
    return digest.hexdigest(), nul_offset, bytes(first), offset


def complete_utf8_tj_prefix_bytes(source: SourceRef, nul_offset: int) -> int:
    """Return a conservative byte limit ending before the last possibly partial record.

    A damaged file is salvageable only when its leading bytes are valid UTF-8 and
    contain at least two technological-journal headers.  The last observed record
    is dropped because corruption may have truncated it.  Bytes after the first
    UTF-8 error or NUL are never decoded as journal data.
    """
    if nul_offset <= 0:
        return 0
    with source.open_binary() as stream:
        prefix = stream.read(nul_offset)
    safe_end = len(prefix)
    try:
        prefix.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        safe_end = exc.start
    headers = list(HEADER_LINE_RE.finditer(prefix[:safe_end]))
    if len(headers) < 2:
        return 0
    return headers[-1].start()


def inspect_source(source: SourceRef, hash_sources: bool, salvage_nul_prefix: bool = False, on_bytes=None) -> SourceHealth:
    if source.kind in {"loose", "zip", "tar"} and source.size > MAX_SOURCE_BYTES:
        return SourceHealth(source, "skipped", f"source exceeds {MAX_SOURCE_BYTES} byte limit")
    try:
        if source.kind == "loose" and not hash_sources:
            with source.path.open("rb") as stream:
                first = stream.read(256 * 1024)
                nul_offset = None
                try:
                    with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                        pos = mapped.find(b"\x00")
                        nul_offset = pos if pos >= 0 else None
                except (OSError, ValueError):
                    stream.seek(0)
                    _, nul_offset, first, source.size = hash_stream(stream, on_bytes=on_bytes)
                sha256 = ""
        else:
            with source.open_binary() as stream:
                sha256, nul_offset, first, source.size = hash_stream(stream, on_bytes=on_bytes)
                if not hash_sources:
                    sha256 = ""
    except SOURCE_READ_ERRORS as exc:
        return SourceHealth(source, "skipped", f"read error: {clean_text(str(exc), 500)}")
    if source.size == 0 or first == b"\xef\xbb\xbf":
        return SourceHealth(source, "skipped", "empty file" if source.size == 0 else "empty/BOM marker file", sha256=sha256)
    if nul_offset is not None:
        if salvage_nul_prefix:
            try:
                analyzed_bytes = complete_utf8_tj_prefix_bytes(source, nul_offset)
            except SOURCE_READ_ERRORS as exc:
                return SourceHealth(source, "skipped", "read error during salvage: " + clean_text(str(exc), 500), nul_offset, sha256)
            if analyzed_bytes:
                return SourceHealth(
                    source,
                    "partial_nul_salvaged",
                    f"damaged after byte {nul_offset}; only complete UTF-8 prefix through byte {analyzed_bytes} analyzed",
                    nul_offset,
                    sha256,
                    analyzed_bytes=analyzed_bytes,
                )
        return SourceHealth(source, "skipped", "NUL byte detected; file treated as damaged", nul_offset, sha256)
    if not HEADER_LINE_RE.search(first[3:] if first.startswith(b"\xef\xbb\xbf") else first):
        return SourceHealth(source, "skipped", "no technological-journal header in first 256 KiB", None, sha256)
    if FILE_RE.match(source.log_name) is None:
        return SourceHealth(
            source, "valid_no_timestamp", "non-standard log filename; absolute timestamps unavailable",
            None, sha256, analyzed_bytes=source.size,
        )
    return SourceHealth(source, "valid", "", None, sha256, analyzed_bytes=source.size)


def iter_records(source: SourceRef, byte_limit: int | None = None) -> Iterator[str]:
    for record in RecordStream(source, byte_limit):
        yield record.text


def event_timestamp(source: SourceRef, match: re.Match[str]) -> dt.datetime | None:
    file_match = FILE_RE.match(source.log_name)
    if not file_match:
        return None
    values = {key: int(value) for key, value in file_match.groupdict().items()}
    try:
        return dt.datetime(
            2000 + values["yy"], values["month"], values["day"], values["hour"],
            int(match.group("minute")), int(match.group("second")), int(match.group("micros")),
        )
    except ValueError:
        return None


def actual_measurement_id(source: SourceRef, timestamp: dt.datetime | None) -> str:
    actual_date = timestamp.date().isoformat() if timestamp is not None else "unknown-date"
    return f"{source.measurement_id}@{actual_date}"


@dataclass
class CallRecord:
    call_id: int
    dataset_id: str
    measurement_id: str
    user: str
    signature: str
    context_sample: str
    source: str
    process: str
    end: dt.datetime | None
    start: dt.datetime | None
    duration_us: int
    cpu_us: int | None
    memory: int | None
    memory_peak: int | None
    in_bytes: int | None
    out_bytes: int | None
    rows_affected: int | None
    thread: str
    session: str
    connect_id: str
    numeric_quality: dict
    provenance: dict = field(default_factory=dict)
    db_count: int = 0
    db_duration_us: int = 0
    db_rows_stats: CounterStats = field(default_factory=CounterStats)
    sdbl_count: int = 0
    lock_count: int = 0
    lock_duration_us: int = 0
    error_count: int = 0
    sql: dict[str, list[int]] = field(default_factory=dict)

    @property
    def db_rows(self) -> int | None:
        return self.db_rows_stats.as_dict()["sum_known"]

    @property
    def db_rows_quality(self) -> dict:
        return self.db_rows_stats.as_dict()


@dataclass
class MetricGroup:
    count: int = 0
    duration_us: int = 0
    max_us: int = 0
    durations: list[int] = field(default_factory=list)
    counters: dict = field(default_factory=lambda: {name: CounterStats() for name in FIELDS})

    def add(self, duration_us: int, numeric: dict | None = None) -> None:
        self.count += 1
        self.duration_us += duration_us
        self.max_us = max(self.max_us, duration_us)
        self.durations.append(duration_us)
        if numeric is not None:
            for name, value in numeric.items():
                self.counters[name].add(value)

    def as_dict(self) -> dict:
        return {
            "count": self.count,
            "numeric_quality": {name: stats.as_dict() for name, stats in self.counters.items()},
            "duration_us": self.duration_us,
            "avg_us": round(safe_mean(self.durations), 3),
            "median_us": median_value(self.durations),
            "p95_us": nearest_rank(self.durations, 0.95),
            "p99_us": nearest_rank(self.durations, 0.99),
            "max_us": self.max_us,
            "over_1s": sum(value >= 1_000_000 for value in self.durations),
            "over_5s": sum(value >= 5_000_000 for value in self.durations),
            "over_10s": sum(value >= 10_000_000 for value in self.durations),
            "over_30s": sum(value >= 30_000_000 for value in self.durations),
        }


@dataclass
class SqlGroup(MetricGroup):
    normalized_sql: str = ""
    sample_sql: str = ""
    users: set[str] = field(default_factory=set)
    contexts: set[str] = field(default_factory=set)
    tables: set[str] = field(default_factory=set)
    first_timestamp: dt.datetime | None = None
    last_timestamp: dt.datetime | None = None

    def add_sql(self, duration_us: int, numeric: dict, user: str, context: str, timestamp: dt.datetime | None, sample: str) -> None:
        self.add(duration_us, numeric)
        self.users.add(user)
        if context and len(self.contexts) < 30:
            self.contexts.add(context)
        if sample and not self.sample_sql:
            self.sample_sql = clean_text(sample, 2400)
        for table_name in sql_tables(sample):
            if len(self.tables) < 80:
                self.tables.add(table_name)
        if timestamp is not None:
            self.first_timestamp = timestamp if self.first_timestamp is None else min(self.first_timestamp, timestamp)
            self.last_timestamp = timestamp if self.last_timestamp is None else max(self.last_timestamp, timestamp)


@dataclass
class LockGroup(MetricGroup):
    event: str = ""
    users: set[str] = field(default_factory=set)
    contexts: set[str] = field(default_factory=set)
    linked_call_count: int = 0


class IntervalIndex:
    def __init__(self, calls: list[CallRecord]):
        self.calls = sorted((call for call in calls if call.start and call.end), key=lambda call: (call.start, call.end, call.call_id))
        self.starts = [call.start for call in self.calls]
        self.prefix_max_end: list[dt.datetime] = []
        current = dt.datetime.min
        for call in self.calls:
            current = max(current, call.end or dt.datetime.min)
            self.prefix_max_end.append(current)

    def find(self, timestamp: dt.datetime, session: str) -> CallRecord | None:
        index = bisect.bisect_right(self.starts, timestamp) - 1
        candidates: list[CallRecord] = []
        while index >= 0:
            if self.prefix_max_end[index] < timestamp:
                break
            call = self.calls[index]
            if call.start and call.end and call.start <= timestamp <= call.end:
                candidates.append(call)
            index -= 1
        if not candidates:
            return None
        if session:
            same_session = [call for call in candidates if call.session == session]
            if same_session:
                candidates = same_session
        return max(candidates, key=lambda call: (call.duration_us, -call.call_id))


def signature_for_call(attrs: dict[str, str]) -> tuple[str, str]:
    context = attrs.get("Context", "")
    root = context_root(context)
    if root:
        return root, clean_text(context, 2400)
    parts = [attrs.get("Func", ""), attrs.get("IName", ""), attrs.get("MName", ""), attrs.get("Form", ""), attrs.get("FormItem", "")]
    signature = " | ".join(part for part in parts if part) or "(signature unavailable)"
    return clean_text(signature, 900), clean_text(context, 2400)


def update_time_bounds(dataset: dict, timestamp: dt.datetime | None) -> None:
    if timestamp is None:
        return
    dataset["first_timestamp"] = timestamp if dataset["first_timestamp"] is None else min(dataset["first_timestamp"], timestamp)
    dataset["last_timestamp"] = timestamp if dataset["last_timestamp"] is None else max(dataset["last_timestamp"], timestamp)
    if 8 <= timestamp.hour < 20:
        dataset["day_events"] += 1
    else:
        dataset["night_events"] += 1


def fresh_dataset(source: SourceRef) -> dict:
    return {
        "dataset_id": source.dataset_id,
        "measurement_id": source.measurement_id,
        "files": set(),
        "bytes": 0,
        "records": 0,
        "parse_errors": 0,
        "first_timestamp": None,
        "last_timestamp": None,
        "users": set(),
        "sessions": set(),
        "connect_ids": set(),
        "processes": set(),
        "events": collections.defaultdict(MetricGroup),
        "call_signatures": collections.Counter(),
        "day_events": 0,
        "night_events": 0,
        "background_events": 0,
        "unattributed_timestamp_events": 0,
        "actual_dates": set(),
        "active_minute_buckets": set(),
        "dbpostgrs_per_minute": collections.Counter(),
    }


def analyze_pass_one(valid_health: list[SourceHealth], store: EventStore, progress=None) -> tuple[list[CallRecord], dict[str, dict]]:
    calls: list[CallRecord] = []
    datasets: dict[str, dict] = {}
    call_id = 0
    for health in valid_health:
        source = health.source
        if progress is not None:
            progress.set_detail(source.display_path)
        dataset = datasets.setdefault(source.dataset_id, fresh_dataset(source))
        dataset["files"].add(source.display_path)
        dataset["processes"].add(source.process)
        try:
            byte_limit = health.analyzed_bytes if health.status == "partial_nul_salvaged" else None
            reader = RecordStream(source, byte_limit, on_bytes=progress.advance if progress is not None else None)
            for positioned in reader:
                record = positioned.text
                health.records += 1
                dataset["records"] += 1
                match = HEADER_RE.match(record)
                if match is None:
                    health.parse_errors += 1
                    dataset["parse_errors"] += 1
                    store.issue(source, positioned.byte_start, positioned.byte_end, "invalid_header", "TJ record header cannot be parsed")
                    health.status, health.reason = "partial_read_error", "TJ header parse failure"
                    continue
                attrs = parse_attrs(match.group("rest"))
                if positioned.decoding_replaced:
                    store.issue(source, positioned.byte_start, positioned.byte_end, "invalid_utf8", "Replacement decoding; original byte hash retained")
                    health.status, health.reason = "partial_read_error", "Invalid UTF-8 decoded with replacement"
                duration_us = int(match.group("duration"))
                event = match.group("event").strip()
                timestamp = event_timestamp(source, match)
                update_time_bounds(dataset, timestamp)
                if timestamp is None:
                    dataset["unattributed_timestamp_events"] += 1
                else:
                    dataset["actual_dates"].add(timestamp.date().isoformat())
                    minute_bucket = timestamp.replace(second=0, microsecond=0)
                    dataset["active_minute_buckets"].add(minute_bucket)
                    if event == "DBPOSTGRS":
                        dataset["dbpostgrs_per_minute"][minute_bucket] += 1
                user = attrs.get("Usr", "").strip() or "(not specified)"
                dataset["users"].add(user)
                session = attrs.get("SessionID", "")
                connect_id = attrs.get("t:connectID", "")
                if session:
                    dataset["sessions"].add(session)
                if connect_id:
                    dataset["connect_ids"].add(connect_id)
                numeric = parse_counters(attrs)
                dataset["events"][event].add(duration_us, numeric)
                context = attrs.get("Context", "")
                if user == "(not specified)" or BACKGROUND_RE.search(context):
                    dataset["background_events"] += 1
                if event != "CALL":
                    store.add_event(source, positioned, match, attrs, timestamp, actual_measurement_id(source, timestamp), numeric)
                    continue
                call_id += 1
                signature, context_sample = signature_for_call(attrs)
                dataset["call_signatures"][signature] += 1
                start = timestamp - dt.timedelta(microseconds=duration_us) if timestamp is not None else None
                calls.append(CallRecord(
                    call_id=call_id,
                    dataset_id=source.dataset_id,
                    measurement_id=actual_measurement_id(source, timestamp),
                    user=user,
                    signature=signature,
                    context_sample=context_sample,
                    source=source.display_path,
                    process=source.process,
                    end=timestamp,
                    start=start,
                    duration_us=duration_us,
                    **{name: value["value"] for name, value in numeric.items()},
                    numeric_quality=numeric,
                    thread=attrs.get("OSThread", ""),
                    session=session,
                    connect_id=connect_id,
                ))
                store.add_event(source, positioned, match, attrs, timestamp, actual_measurement_id(source, timestamp), numeric, calls[-1])
            if byte_limit is None and reader.digest.hexdigest() != health.sha256:
                raise AnalyzerError("Source changed between inspection and event ingestion: " + source.display_path)
            if reader.prefix_bytes:
                store.issue(source, 0, reader.prefix_bytes, "leading_non_record_bytes", "Bytes before the first TJ record")
                health.status, health.reason = "partial_read_error", "Non-record prefix before first TJ header"
            health.analyzed_bytes = reader.last_record_end
        except SOURCE_READ_ERRORS as exc:
            health.status = "partial_read_error"
            health.reason = clean_text(str(exc), 500)
            health.analyzed_bytes = reader.last_record_end
            store.issue(source, reader.last_record_end, source.size, "ingestion_read_error", health.reason)
        dataset["bytes"] += health.analyzed_bytes
    return calls, datasets


def build_indexes(calls: list[CallRecord]) -> dict[tuple[str, str, str, str], IntervalIndex]:
    grouped: dict[tuple[str, str, str, str], list[CallRecord]] = collections.defaultdict(list)
    for call in calls:
        if call.thread and call.start and call.end:
            grouped[(call.dataset_id, call.user, call.process, call.thread)].append(call)
    return {key: IntervalIndex(value) for key, value in grouped.items()}


def fresh_linkage(measurement_id: str, dataset_id: str) -> dict:
    return {
        "measurement_id": measurement_id,
        "dataset_id": dataset_id,
        "call_count": 0,
        "calls_without_absolute_time": 0,
        "dbpostgrs_total_count": 0,
        "dbpostgrs_linked_count": 0,
        "dbpostgrs_total_duration_us": 0,
        "dbpostgrs_linked_duration_us": 0,
        "sdbl_total_count": 0,
        "sdbl_linked_count": 0,
        "lock_total_count": 0,
        "lock_linked_count": 0,
        "error_total_count": 0,
        "error_linked_count": 0,
        "unlinked_missing_timestamp": 0,
        "unlinked_missing_thread": 0,
        "unlinked_no_containing_call": 0,
    }


def analyze_pass_two(
    calls: list[CallRecord],
    store: EventStore,
    progress=None,
) -> tuple[
    dict[tuple[str, str], SqlGroup],
    dict[tuple[str, str, str], LockGroup],
    dict[tuple[str, str], dict],
]:
    indexes = build_indexes(calls)
    sql_groups: dict[tuple[str, str], SqlGroup] = {}
    lock_groups: dict[tuple[str, str, str], LockGroup] = {}
    linkage: dict[tuple[str, str], dict] = {}
    for call in calls:
        linkage_key = (call.dataset_id, call.measurement_id)
        stats = linkage.setdefault(linkage_key, fresh_linkage(call.measurement_id, call.dataset_id))
        stats["call_count"] += 1
        if call.start is None or call.end is None:
            stats["calls_without_absolute_time"] += 1

    auxiliary_types = ("SDBL", "TLOCK", "TTIMEOUT", "TDEADLOCK")
    numeric_groups = iter(store._event_numeric_groups(auxiliary_types))
    numeric_group = next(numeric_groups, None)
    for row in store.connection.execute("SELECT * FROM events WHERE event_type IN ('SDBL','TLOCK','TTIMEOUT','TDEADLOCK') ORDER BY source_version_id,byte_start"):
        row_key = (row["source_version_id"], row["byte_start"], row["event_id"])
        if numeric_group is not None and numeric_group[0] < row_key:
            raise ValueError("Auxiliary numeric stream is not aligned with stored events")
        if numeric_group is not None and numeric_group[0] == row_key:
            numeric = numeric_group[1]
            numeric_group = next(numeric_groups, None)
        else:
            numeric = {}
        event, user, timestamp = row["event_type"], row["user"], stored_timestamp(row["end_time_us"])
        measurement_id, dataset_id = row["measurement_id"], row["dataset_id"]
        stats = linkage.setdefault((dataset_id, measurement_id), fresh_linkage(measurement_id, dataset_id))
        duration_us, thread, session = row["duration_us"], row["thread"], row["session"]
        context = context_root(row["context"] or "")
        linked_call: CallRecord | None = None
        if timestamp is not None and thread:
            index = indexes.get((dataset_id, user, row["process"], thread))
            if index is not None:
                linked_call = index.find(timestamp, session)

        category = ""
        if event == "SDBL":
            category = "sdbl"
        elif event in {"TLOCK", "TTIMEOUT", "TDEADLOCK"}:
            category = "lock"
        stats[f"{category}_total_count"] += 1
        if linked_call is not None:
            stats[f"{category}_linked_count"] += 1
        elif timestamp is None:
            stats["unlinked_missing_timestamp"] += 1
        elif not thread:
            stats["unlinked_missing_thread"] += 1
        else:
            stats["unlinked_no_containing_call"] += 1

        if event == "SDBL":
            if linked_call is not None:
                linked_call.sdbl_count += 1
        elif event in {"TLOCK", "TTIMEOUT", "TDEADLOCK"}:
            lock_key = (measurement_id, event, context or "(context unavailable)")
            group = lock_groups.get(lock_key)
            if group is None:
                group = LockGroup(event=event)
                lock_groups[lock_key] = group
            group.add(duration_us, numeric)
            group.users.add(user)
            if context and len(group.contexts) < 30:
                group.contexts.add(context)
            if linked_call is not None:
                group.linked_call_count += 1
                linked_call.lock_count += 1
                linked_call.lock_duration_us += duration_us
        if progress is not None:
            progress.advance(1)
    if numeric_group is not None:
        raise ValueError("Auxiliary numeric stream contains an event outside stored event order")
    calls_by_id = {call.call_id: call for call in calls}
    for row in store.db_rows(include_sql=True):
        measurement_id, dataset_id = row["measurement_id"], row["dataset_id"]
        stats = linkage.setdefault((dataset_id, measurement_id), fresh_linkage(measurement_id, dataset_id))
        duration_us, numeric = row["duration_us"], row["numeric_quality"]
        linked_call = calls_by_id.get(row["call_id"])
        stats["dbpostgrs_total_count"] += 1
        stats["dbpostgrs_total_duration_us"] += duration_us
        if linked_call is not None:
            stats["dbpostgrs_linked_count"] += 1
            stats["dbpostgrs_linked_duration_us"] += duration_us
            linked_call.db_count += 1
            linked_call.db_duration_us += duration_us
            linked_call.db_rows_stats.add(numeric["rows_affected"])
        else:
            reason = row["linkage_reason"]
            stats["unlinked_" + (reason if reason in {"missing_timestamp", "missing_thread"} else "no_containing_call")] += 1
        if row["sql_text_id"] is not None:
            normalized = row["normalized_sql"]
            key = (measurement_id, normalized)
            group = sql_groups.get(key)
            if group is None:
                group = SqlGroup(normalized_sql=normalized)
                sql_groups[key] = group
            group.add_sql(duration_us, numeric, row["user"], context_root(row["context"] or ""), stored_timestamp(row["end_time_us"]), row["sql_text"])
            if linked_call is not None:
                item = linked_call.sql.setdefault(normalized, [0, 0, 0])
                item[0] += 1
                item[1] += duration_us
                item[2] = max(item[2], duration_us)
        if progress is not None:
            progress.advance(1)
    for row in error_rows(store.connection):
        measurement_id, dataset_id = row["measurement_id"], row["dataset_id"]
        stats = linkage.setdefault((dataset_id, measurement_id), fresh_linkage(measurement_id, dataset_id))
        stats["error_total_count"] += 1
        linked_call = calls_by_id.get(row["call_id"])
        if linked_call is not None:
            stats["error_linked_count"] += 1
            linked_call.error_count += 1
        else:
            reason = row["linkage_reason"]
            stats["unlinked_" + (reason if reason in {"missing_timestamp", "missing_thread"} else "no_containing_call")] += 1
        if progress is not None:
            progress.advance(1)
    return sql_groups, lock_groups, linkage


def severity_for_operation(metrics: dict) -> tuple[str, str]:
    if (
        (metrics["count"] >= 2 and metrics["p95_us"] >= 30_000_000)
        or metrics["over_30s"] >= 2
        or metrics["max_us"] >= 120_000_000
        or (metrics["db_per_call"] >= 1_000 and metrics["p95_us"] >= 10_000_000)
    ):
        return "P0", "engineering candidate: repeated >=30 s, max >=120 s, or DB/call >=1000 with p95 >=10 s"
    if (
        metrics["max_us"] >= 30_000_000
        or metrics["p95_us"] >= 5_000_000
        or metrics["duration_us"] >= 30_000_000
        or metrics["db_per_call"] >= 500
        or (metrics["max_out_bytes"] is not None and metrics["max_out_bytes"] >= 10 * 1024 * 1024)
    ):
        return "P1", "engineering candidate: max >=30 s, p95 >=5 s, total >=30 s, DB/call >=500, or output >=10 MiB"
    return "P2", "engineering candidate below deterministic P0/P1 thresholds"


def aggregate_operations(calls: list[CallRecord], scope: str = "dataset") -> list[dict]:
    if scope not in {"dataset", "measurement"}:
        raise ValueError(f"unsupported aggregation scope: {scope}")
    groups: dict[tuple[str, str, str, str], list[CallRecord]] = collections.defaultdict(list)
    for call in calls:
        dataset_group = call.dataset_id if scope == "dataset" else "(measurement aggregate)"
        groups[(call.measurement_id, dataset_group, call.user, call.signature)].append(call)
    result: list[dict] = []
    for (measurement_id, dataset_group, user, signature), group_calls in sorted(groups.items()):
        durations = [call.duration_us for call in group_calls]
        total = sum(durations)
        db_total = sum(call.db_duration_us for call in group_calls)
        db_count = sum(call.db_count for call in group_calls)
        dataset_ids = sorted({call.dataset_id for call in group_calls})
        timestamps = sorted(call.end for call in group_calls if call.end is not None)
        sql_aggregate: dict[str, list[int]] = {}
        for call in group_calls:
            for sql_key, values in call.sql.items():
                item = sql_aggregate.setdefault(sql_key, [0, 0, 0])
                item[0] += values[0]
                item[1] += values[1]
                item[2] = max(item[2], values[2])
        top_sql = sorted(
            ({"normalized_sql": key, "sql_fingerprint_sha256": sql_fingerprint(key),
              "sql_normalization_version": SQL_NORMALIZATION_VERSION,
              "sql_normalization_status": normalization_status(key),
              "count": value[0], "duration_us": value[1], "max_us": value[2]} for key, value in sql_aggregate.items()),
            key=lambda item: (item["duration_us"], item["max_us"], item["normalized_sql"]),
            reverse=True,
        )[:10]
        metrics = {
            "measurement_id": measurement_id,
            "dataset_id": dataset_ids[0] if len(dataset_ids) == 1 else "(multiple datasets)",
            "dataset_ids": dataset_ids,
            "user": user,
            "signature": signature,
            "context_sample": group_calls[0].context_sample,
            "first_timestamp": timestamps[0].isoformat(sep=" ") if timestamps else "",
            "last_timestamp": timestamps[-1].isoformat(sep=" ") if timestamps else "",
            "count": len(group_calls),
            "duration_us": total,
            "avg_us": round(safe_mean(durations), 3),
            "median_us": median_value(durations),
            "p95_us": nearest_rank(durations, 0.95),
            "p99_us": nearest_rank(durations, 0.99),
            "max_us": max(durations),
            "min_us": min(durations),
            "over_1s": sum(value >= 1_000_000 for value in durations),
            "over_5s": sum(value >= 5_000_000 for value in durations),
            "over_10s": sum(value >= 10_000_000 for value in durations),
            "over_30s": sum(value >= 30_000_000 for value in durations),
            **operation_counters(group_calls),
            "db_count": db_count,
            "db_per_call": round(db_count / len(group_calls), 6),
            "db_duration_us": db_total,
            "db_seconds_per_call": round(db_total / len(group_calls) / 1_000_000, 6),
            "sdbl_count": sum(call.sdbl_count for call in group_calls),
            "lock_count": sum(call.lock_count for call in group_calls),
            "lock_duration_us": sum(call.lock_duration_us for call in group_calls),
            "error_count": sum(call.error_count for call in group_calls),
            "coefficient_of_variation": round(statistics.pstdev(durations) / safe_mean(durations), 6) if len(durations) > 1 and safe_mean(durations) else 0.0,
            "max_db_per_call": max(call.db_count for call in group_calls),
            "top_nested_sql": top_sql,
            "call_ids": [call.call_id for call in sorted(group_calls, key=lambda item: item.call_id)],
        }
        severity, severity_rule = severity_for_operation(metrics)
        metrics["priority"] = severity
        metrics["priority_rule"] = severity_rule
        metrics["priority_basis"] = "deterministic_engineering_candidate_not_business_sla"
        result.append(metrics)
    return sorted(result, key=lambda item: (item["duration_us"], item["max_us"], item["signature"]), reverse=True)


def dataset_rows(datasets: dict[str, dict]) -> list[dict]:
    result: list[dict] = []
    for dataset_id, dataset in sorted(datasets.items()):
        first = dataset["first_timestamp"]
        last = dataset["last_timestamp"]
        event_stats = {
            event: metrics.as_dict()
            for event, metrics in sorted(dataset["events"].items())
        }
        active_minutes = len(dataset["active_minute_buckets"])
        dbpostgrs_count = event_stats.get("DBPOSTGRS", {}).get("count", 0)
        busiest_db_minute_count = max(dataset["dbpostgrs_per_minute"].values(), default=0)
        busiest_db_minute = ""
        if busiest_db_minute_count:
            busiest_db_minute = min(
                minute for minute, count in dataset["dbpostgrs_per_minute"].items()
                if count == busiest_db_minute_count
            ).isoformat(sep=" ")
        result.append({
            "dataset_id": dataset_id,
            "measurement_id": dataset["measurement_id"],
            "actual_measurement_ids": [f"{dataset['measurement_id']}@{value}" for value in sorted(dataset["actual_dates"])],
            "files_analyzed": len(dataset["files"]),
            "bytes_analyzed": dataset["bytes"],
            "records": dataset["records"],
            "parse_errors": dataset["parse_errors"],
            "first_timestamp": first.isoformat(sep=" ") if first else "",
            "last_timestamp": last.isoformat(sep=" ") if last else "",
            "calendar_span_seconds": (last - first).total_seconds() if first and last else None,
            "users": sorted(dataset["users"]),
            "sessions": sorted(dataset["sessions"]),
            "connect_ids": sorted(dataset["connect_ids"]),
            "processes": sorted(dataset["processes"]),
            "day_events": dataset["day_events"],
            "night_events": dataset["night_events"],
            "background_events": dataset["background_events"],
            "events_without_absolute_timestamp": dataset["unattributed_timestamp_events"],
            "active_minutes_with_events": active_minutes,
            "dbpostgrs_per_active_minute": round(dbpostgrs_count / active_minutes, 6) if active_minutes else None,
            "busiest_db_minute": busiest_db_minute,
            "busiest_db_minute_count": busiest_db_minute_count,
            "event_stats": event_stats,
            "top_call_signatures": [
                {"signature": signature, "count": count}
                for signature, count in sorted(dataset["call_signatures"].items(), key=lambda item: (item[1], item[0]), reverse=True)[:20]
            ],
        })
    return result


def sql_rows(sql_groups: dict[tuple[str, str], SqlGroup]) -> list[dict]:
    result: list[dict] = []
    measurements_by_sql: dict[str, set[str]] = collections.defaultdict(set)
    for measurement_id, normalized in sql_groups:
        measurements_by_sql[normalized].add(measurement_id)
    for (measurement_id, normalized), group in sql_groups.items():
        metrics = group.as_dict()
        features = sql_features(normalized)
        result.append({
            "measurement_id": measurement_id,
            "measurements_all": sorted(measurements_by_sql[normalized]),
            "measurement_count": len(measurements_by_sql[normalized]),
            "sql_fingerprint_sha256": sql_fingerprint(normalized),
            "sql_normalization_version": SQL_NORMALIZATION_VERSION,
            "sql_normalization_status": normalization_status(normalized),
            "normalized_sql": normalized,
            "sample_sql": group.sample_sql,
            **metrics,
            "count_0_5_to_2s": sum(500_000 <= value <= 2_000_000 for value in group.durations),
            **features,
            "rows_affected": metrics["numeric_quality"]["rows_affected"]["sum_known"],
            "max_rows_affected": metrics["numeric_quality"]["rows_affected"]["max_known"],
            "rows_affected_per_event": metrics["numeric_quality"]["rows_affected"]["mean"],
            "users": sorted(group.users),
            "contexts": sorted(group.contexts),
            "tables": sorted(group.tables),
            "first_timestamp": group.first_timestamp.isoformat(sep=" ") if group.first_timestamp else "",
            "last_timestamp": group.last_timestamp.isoformat(sep=" ") if group.last_timestamp else "",
        })
    return sorted(result, key=lambda item: (item["duration_us"], item["max_us"], item["normalized_sql"]), reverse=True)


def lock_rows(lock_groups: dict[tuple[str, str, str], LockGroup]) -> list[dict]:
    result: list[dict] = []
    for (measurement_id, event, context), group in lock_groups.items():
        result.append({
            "measurement_id": measurement_id,
            "event": event,
            "context": context,
            **group.as_dict(),
            "users": sorted(group.users),
            "linked_call_count": group.linked_call_count,
        })
    return sorted(result, key=lambda item: (item["duration_us"], item["max_us"], item["context"]), reverse=True)


def linkage_rows(linkage: dict[tuple[str, str], dict]) -> list[dict]:
    result: list[dict] = []
    for _, raw in sorted(linkage.items()):
        row = dict(raw)
        row["dbpostgrs_linked_count_percent"] = round(
            raw["dbpostgrs_linked_count"] / raw["dbpostgrs_total_count"] * 100, 6
        ) if raw["dbpostgrs_total_count"] else None
        row["dbpostgrs_linked_duration_percent"] = round(
            raw["dbpostgrs_linked_duration_us"] / raw["dbpostgrs_total_duration_us"] * 100, 6
        ) if raw["dbpostgrs_total_duration_us"] else None
        row["sdbl_linked_count_percent"] = round(
            raw["sdbl_linked_count"] / raw["sdbl_total_count"] * 100, 6
        ) if raw["sdbl_total_count"] else None
        row["lock_linked_count_percent"] = round(
            raw["lock_linked_count"] / raw["lock_total_count"] * 100, 6
        ) if raw["lock_total_count"] else None
        row["error_linked_count_percent"] = round(
            raw["error_linked_count"] / raw["error_total_count"] * 100, 6
        ) if raw["error_total_count"] else None
        result.append(row)
    return result


def metric_delta(current: float | int | None, previous: float | int | None) -> tuple[float | None, float | None]:
    if current is None or previous is None:
        return None, None
    delta = current - previous
    percent = (delta / previous * 100) if previous else None
    return delta, round(percent, 6) if percent is not None else None


def identical_operation_rows(calls: list[CallRecord]) -> list[dict]:
    operations = aggregate_operations(calls, scope="measurement")
    by_signature: dict[str, list[dict]] = collections.defaultdict(list)
    for operation in operations:
        by_signature[operation["signature"]].append(operation)
    result: list[dict] = []
    for signature, rows in sorted(by_signature.items()):
        measurements = {row["measurement_id"] for row in rows}
        if len(measurements) < 2:
            continue
        by_user: dict[str, list[dict]] = collections.defaultdict(list)
        for row in rows:
            by_user[row["user"]].append(row)
        for user, user_rows in sorted(by_user.items()):
            ordered = sorted(
                user_rows,
                key=lambda row: (row["first_timestamp"] or "9999-12-31 23:59:59", row["measurement_id"]),
            )
            previous: dict | None = None
            same_user_measurements = len({item["measurement_id"] for item in user_rows}) >= 2
            for comparison_order, row in enumerate(ordered, start=1):
                comparable = previous is not None and previous["measurement_id"] != row["measurement_id"]
                output = {
                    "signature": signature,
                    "comparison_scope": "same_signature_same_user" if same_user_measurements else "same_signature_different_user_only",
                    "comparability_level": "B" if same_user_measurements else "C",
                    "comparability_reasons": (
                        "same CALL signature and user; role, document, parameters and cold/warm state are unavailable"
                        if same_user_measurements
                        else "same CALL signature only; users differ and role, document, parameters and cold/warm state are unavailable"
                    ),
                    "comparison_order": comparison_order,
                    "measurement_id": row["measurement_id"],
                    "dataset_id": row["dataset_id"],
                    "dataset_ids": row["dataset_ids"],
                    "user": user,
                    "first_timestamp": row["first_timestamp"],
                    "last_timestamp": row["last_timestamp"],
                    "count": row["count"],
                    "avg_us": row["avg_us"],
                    "median_us": row["median_us"],
                    "p95_us": row["p95_us"],
                    "max_us": row["max_us"],
                    "db_per_call": row["db_per_call"],
                    "db_seconds_per_call": row["db_seconds_per_call"],
                    "cpu_percent_of_wall": row["cpu_percent_of_wall"],
                    "out_bytes_per_call": row["out_bytes_per_call"],
                    **{name: row[name] for name in QUALITY_CSV_FIELDS["identical_operations.csv"]},
                    "previous_measurement_id": previous["measurement_id"] if comparable else "",
                    "previous_first_timestamp": previous["first_timestamp"] if comparable else "",
                }
                for name in (
                    "count", "avg_us", "median_us", "p95_us", "max_us",
                    "db_per_call", "db_seconds_per_call", "cpu_percent_of_wall", "out_bytes_per_call",
                ):
                    if comparable:
                        delta, delta_percent = metric_delta(row[name], previous[name])
                        output[f"{name}_delta"] = delta
                        output[f"{name}_delta_percent"] = delta_percent
                    else:
                        output[f"{name}_delta"] = None
                        output[f"{name}_delta_percent"] = None
                result.append(output)
                previous = row
    return sorted(result, key=lambda item: (item["signature"], item["user"], item["comparison_order"]))


def call_row(call: CallRecord) -> dict:
    return {
        **call.provenance,
        "call_id": call.call_id,
        "measurement_id": call.measurement_id,
        "dataset_id": call.dataset_id,
        "user": call.user,
        "signature": call.signature,
        "start_timestamp": call.start.isoformat(sep=" ") if call.start else "",
        "end_timestamp": call.end.isoformat(sep=" ") if call.end else "",
        "duration_us": call.duration_us,
        "cpu_us": call.cpu_us,
        "memory": call.memory,
        "db_count": call.db_count,
        "db_duration_us": call.db_duration_us,
        "db_rows": call.db_rows,
        "rows_affected": call.rows_affected,
        "numeric_quality": call.numeric_quality,
        "db_rows_quality": call.db_rows_quality,
        "sdbl_count": call.sdbl_count,
        "in_bytes": call.in_bytes,
        "out_bytes": call.out_bytes,
        "memory_peak": call.memory_peak,
        "lock_count": call.lock_count,
        "lock_duration_us": call.lock_duration_us,
        "error_count": call.error_count,
        "process": call.process,
        "source": call.source,
        "context_sample": call.context_sample,
    }


def call_detail_rows(calls: list[CallRecord], limit: int) -> list[dict]:
    heaviest = sorted(calls, key=lambda call: (call.duration_us, call.call_id), reverse=True)[:limit]
    return [call_row(call) for call in heaviest]


def call_observation_rows(calls: list[CallRecord]) -> list[dict]:
    return [call_row(call) for call in sorted(calls, key=lambda call: call.call_id)]


def json_ready(value):
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, dt.datetime):
        return value.isoformat(sep=" ")
    raise TypeError(f"unsupported JSON value: {type(value)!r}")


def csv_scalar(value) -> str | int | float:
    if value is None:
        return ""
    if isinstance(value, (list, set, tuple)):
        if any(isinstance(item, (dict, list, set, tuple)) for item in value):
            return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=json_ready)
        return " | ".join(str(item) for item in sorted(value))
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return value


def write_csv(path: Path, rows: list[dict], fieldnames: list[str] | None = None) -> None:
    if fieldnames is None:
        fieldnames = []
        seen: set[str] = set()
        for row in rows:
            for key in row:
                if key not in seen:
                    seen.add(key)
                    fieldnames.append(key)
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_scalar(row.get(key)) for key in fieldnames})


def csv_operation_rows(operations: list[dict]) -> list[dict]:
    fields = [
        "measurement_id", "dataset_id", "user", "priority", "priority_rule", "priority_basis", "signature", "count",
        "first_timestamp", "last_timestamp",
        "duration_us", "avg_us", "median_us", "p95_us", "p99_us", "max_us", "min_us",
        "over_1s", "over_5s", "over_10s", "over_30s", "cpu_us", "cpu_percent_of_wall",
        "memory", "memory_per_call", "memory_max", "memory_peak_avg", "memory_peak_median", "memory_peak_p95",
        "db_count", "db_per_call", "db_duration_us", "db_seconds_per_call", "max_db_per_call",
        "rows_affected", "in_bytes", "in_bytes_per_call", "out_bytes", "out_bytes_per_call",
        "max_out_bytes", "memory_peak_max", "lock_count", "lock_duration_us", "error_count",
        "coefficient_of_variation", "unattributed_us_floor", "unattributed_percent_floor", "attribution_overflow_us", "context_sample",
    ]
    return [{key: operation.get(key) for key in fields + QUALITY_CSV_FIELDS["operations.csv"]} for operation in operations]


def csv_sql_rows(rows: list[dict]) -> list[dict]:
    fields = [
        "measurement_id", "measurements_all", "measurement_count", "sql_fingerprint_sha256", "count", "duration_us", "avg_us", "median_us", "p95_us", "p99_us", "max_us",
        "over_1s", "over_5s", "over_10s", "over_30s", "rows_affected", "max_rows_affected",
        "count_0_5_to_2s", "has_join", "has_case", "has_distinct", "has_order_by", "has_group_by",
        "has_union", "has_temp_table", "has_limit_or_top",
        "users", "contexts", "tables", "first_timestamp", "last_timestamp", "normalized_sql", "sample_sql",
    ]
    return [{key: row.get(key) for key in fields + QUALITY_CSV_FIELDS["heavy_sql.csv"] + SQL_CSV_FIELDS} for row in rows]


def output_is_nonempty(path: Path) -> bool:
    return path.exists() and any(path.iterdir())


def has_source_problems(health, warnings):
    return any(
        item.status in {"partial_read_error", "partial_nul_salvaged"}
        or (item.status == "skipped" and not item.reason.startswith(("empty file", "empty/BOM marker")))
        for item in health
    ) or any(item.get("type") in {"archive_error", "discovery_error"} for item in warnings)


def write_outputs(
    output_dir: Path,
    input_root: Path,
    archive_mode: str,
    salvage_nul_prefix: bool,
    archive_inventory: list[dict],
    warnings: list[dict],
    health: list[SourceHealth],
    datasets: list[dict],
    operations: list[dict],
    identical: list[dict],
    sql: list[dict],
    errors: list[dict],
    locks: list[dict],
    linkage: list[dict],
    top_calls: list[dict],
    call_observations: list[dict],
    detail_artifacts: dict,
    source_map: dict,
    errors_summary: dict,
) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    source_manifest_lines = [
        "\t".join((item.source.source_id, str(item.source.size), item.sha256 or "UNHASHED", item.status))
        for item in sorted(health, key=lambda value: value.source.source_id.lower())
    ]
    source_set_hash = hashlib.sha256("\n".join(source_manifest_lines).encode("utf-8")).hexdigest()
    material_source_problem = has_source_problems(health, warnings)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        **VERSIONS,
        **ERROR_METADATA,
        "publication_state": "complete",
        "source_processing_complete": not material_source_problem,
        "collection_completeness": "unknown",
        "event_detail_scope": ["CALL", "DBPOSTGRS", "EXCP", "QERR"],
        "artifacts": detail_artifacts,
        "capture_id": source_map["capture_id"],
        "capture_identity_status": source_map["capture_identity_status"],
        "linkage_rules": LINKAGE_RULES,
        "numeric_rules_version": NUMERIC_RULES_VERSION,
        "sql_normalization_version": SQL_NORMALIZATION_VERSION,
        "sql_fingerprint_algorithm": SQL_FINGERPRINT_ALGORITHM,
        "analyzer": "1C technological journal deterministic analyzer",
        "analyzer_version": VERSION,
        "input_root": str(input_root.resolve()),
        "archive_mode": archive_mode,
        "salvage_nul_prefix": salvage_nul_prefix,
        "source_set_hash_sha256": source_set_hash,
        "source_content_hashes_complete": bool(health) and all(bool(item.sha256) for item in health),
        "analysis_complete": not material_source_problem,
        "absolute_timestamps_complete": all(item.status != "valid_no_timestamp" for item in health) and not any(d["events_without_absolute_timestamp"] for d in datasets),
        "units": {
            "duration_fields": "microseconds unless field name explicitly contains seconds",
            "memory_fields": "bytes as recorded by the technological journal",
            "io_fields": "bytes",
            "cpu_percent_of_wall": "percent",
        },
        "method": {
            "processing": "inspection full hash, one source ingestion; all subsequent aggregates read stored events; analyzed_bytes is the last complete record boundary",
            "numeric_counters": "valid/missing/empty/invalid/out_of_range; unavailable values are null; sums use available values, means divide by available_count; coverage and sum_complete are separate",
            "cpu_population": "CpuTime and CALL duration from the same CALLs with valid CpuTime; residual and overflow use their linked DB duration only; coverage is separate",
            "call_signature": "first non-empty Context line, else stable CALL fields",
            "median": "conventional sample median; for even N the two central values are averaged",
            "p95_p99": "nearest-rank",
            "sql_normalization": "PostgreSQL tokens; temporary relation identities numbered by first reference; literals abstracted, identifiers/operators/list arity retained; full Sql input, never sample_sql; ambiguous lexical input retained as explicit raw_fallback; see SQL_NORMALIZATION.md",
            "db_to_call_link": "same dataset, process, user and OSThread; timestamp within CALL interval; same SessionID preferred; longest containing CALL selected",
            "top_nested_sql": "preview limited to 10 patterns; complete DB events and assignments are in analysis.sqlite and db_observations.csv",
            "source_deduplication": "source_identity/v1: identical content is deduplicated only within the same logical source; independent sources are retained",
            "sdbl_wall_time": "not added to CALL wall time",
            "error_incident": "same_call_exact_payload/v1: uniquely linked same CALL, complete identity and full Context, exact full payload after allowlisted wrappers; no time-window inference; hypotheses only",
            "error_category": "deterministic text-marker classification; category is not a root-cause attribution",
            "priority_rules": "deterministic engineering candidate thresholds, not a business SLA",
            "calendar_span_warning": "first-to-last timestamp is an observation span, not pure test duration",
            "active_minute_density": "distinct wall-clock minute buckets containing at least one parsed event; not elapsed test time",
            "comparison_order": "actual first CALL timestamp; folder names are not used as chronology when timestamps exist",
            "unattributed_time": "max(0, CALL wall - CpuTime - linked DBPOSTGRS time); a lower-bound accounting residual, not a localized cause",
            "attribution_overflow": "max(0, CpuTime + linked DBPOSTGRS time - CALL wall); indicates counters/intervals are not safely additive",
            "nul_salvage": "optional; only valid UTF-8 bytes before the first corruption marker are considered and the last possibly incomplete TJ record is dropped",
        },
        "counts": {
            "sources_discovered": len(health),
            "sources_analyzed": sum(item.status in {"valid", "valid_no_timestamp", "partial_read_error", "partial_nul_salvaged"} for item in health),
            "sources_skipped": sum(item.status.startswith("skipped") for item in health),
            "sources_skipped_as_duplicates": sum(item.status == "skipped_duplicate" for item in health),
            "datasets": len(datasets),
            "operations": len(operations),
            "identical_operation_rows": len(identical),
            "sql_patterns": len(sql),
            "error_signatures": len(errors),
            "error_events": errors_summary["event_count"],
            "affected_calls": errors_summary["affected_call_count"],
            "suspected_incidents": errors_summary["suspected_incident_count"],
            "lock_signatures": len(locks),
            "linkage_rows": len(linkage),
            "call_observations": len(call_observations),
            "db_observations": detail_artifacts["db_observations.csv"]["row_count"],
            "event_links": detail_artifacts["event_links.csv"]["row_count"],
            "link_candidates": detail_artifacts["link_candidates.csv"]["row_count"],
        },
        "warnings": warnings,
        "archive_inventory": archive_inventory,
        "files": [item.as_dict() for item in health],
        "datasets": datasets,
        "operations": operations,
        "identical_operations": identical,
        "heavy_sql": sql,
        "errors": errors,
        "error_summary": errors_summary,
        "locks": locks,
        "linkage": linkage,
        "top_calls": top_calls,
    }
    json_path = output_dir / "analysis_metrics.json"
    json_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True, default=json_ready) + "\n",
        encoding="utf-8",
    )
    outputs = [json_path]
    csv_specs = [
        ("files.csv", [item.as_dict() for item in health], [
            "source_id", "source_version_id", "member_ordinal",
            "source", "resolved_source", "kind", "member", "size_bytes", "analyzed_bytes", "dataset_id", "measurement_id", "process",
            "status", "reason", "nul_offset", "sha256", "records", "parse_errors",
        ]),
        ("datasets.csv", [{**row, "event_stats": row["event_stats"], "top_call_signatures": row["top_call_signatures"]} for row in datasets], [
            "dataset_id", "measurement_id", "actual_measurement_ids", "files_analyzed", "bytes_analyzed", "records", "parse_errors",
            "first_timestamp", "last_timestamp", "calendar_span_seconds", "users", "sessions", "connect_ids",
            "processes", "day_events", "night_events", "background_events", "events_without_absolute_timestamp",
            "active_minutes_with_events", "dbpostgrs_per_active_minute", "busiest_db_minute", "busiest_db_minute_count",
            "event_stats", "top_call_signatures",
        ]),
        ("operations.csv", csv_operation_rows(operations), [
            "measurement_id", "dataset_id", "user", "priority", "priority_rule", "priority_basis", "signature", "count",
            "first_timestamp", "last_timestamp",
            "duration_us", "avg_us", "median_us", "p95_us", "p99_us", "max_us", "min_us",
            "over_1s", "over_5s", "over_10s", "over_30s", "cpu_us", "cpu_percent_of_wall",
            "memory", "memory_per_call", "memory_max", "memory_peak_avg", "memory_peak_median", "memory_peak_p95",
            "db_count", "db_per_call", "db_duration_us", "db_seconds_per_call", "max_db_per_call",
            "rows_affected", "in_bytes", "in_bytes_per_call", "out_bytes", "out_bytes_per_call",
            "max_out_bytes", "memory_peak_max", "lock_count", "lock_duration_us", "error_count",
            "coefficient_of_variation", "unattributed_us_floor", "unattributed_percent_floor", "attribution_overflow_us", "context_sample",
        ]),
        ("identical_operations.csv", identical, [
            "signature", "comparison_scope", "comparability_level", "comparability_reasons", "comparison_order", "measurement_id", "dataset_id", "dataset_ids", "user",
            "first_timestamp", "last_timestamp", "count", "avg_us",
            "median_us", "p95_us", "max_us", "db_per_call", "db_seconds_per_call", "cpu_percent_of_wall",
            "out_bytes_per_call", "previous_measurement_id", "previous_first_timestamp",
            "count_delta", "count_delta_percent", "avg_us_delta", "avg_us_delta_percent",
            "median_us_delta", "median_us_delta_percent", "p95_us_delta", "p95_us_delta_percent",
            "max_us_delta", "max_us_delta_percent", "db_per_call_delta", "db_per_call_delta_percent",
            "db_seconds_per_call_delta", "db_seconds_per_call_delta_percent",
            "cpu_percent_of_wall_delta", "cpu_percent_of_wall_delta_percent",
            "out_bytes_per_call_delta", "out_bytes_per_call_delta_percent",
        ]),
        ("heavy_sql.csv", csv_sql_rows(sql), [
            *SQL_CSV_FIELDS,
            "measurement_id", "measurements_all", "measurement_count", "sql_fingerprint_sha256", "count", "duration_us", "avg_us", "median_us", "p95_us", "p99_us", "max_us",
            "over_1s", "over_5s", "over_10s", "over_30s", "rows_affected", "max_rows_affected",
            "count_0_5_to_2s", "has_join", "has_case", "has_distinct", "has_order_by", "has_group_by",
            "has_union", "has_temp_table", "has_limit_or_top",
            "users", "contexts", "tables", "first_timestamp", "last_timestamp", "normalized_sql", "sample_sql",
        ]),
        ("errors.csv", errors, ERROR_GROUP_FIELDS),
        ("locks.csv", locks, [
            "measurement_id", "event", "context", "count", "duration_us", "avg_us", "median_us", "p95_us",
            "p99_us", "max_us", "over_1s", "over_5s", "over_10s", "over_30s", "users", "linked_call_count",
        ]),
        ("linkage.csv", linkage, [
            "measurement_id", "dataset_id", "call_count", "calls_without_absolute_time",
            "dbpostgrs_total_count", "dbpostgrs_linked_count", "dbpostgrs_linked_count_percent",
            "dbpostgrs_total_duration_us", "dbpostgrs_linked_duration_us", "dbpostgrs_linked_duration_percent",
            "sdbl_total_count", "sdbl_linked_count", "sdbl_linked_count_percent",
            "lock_total_count", "lock_linked_count", "lock_linked_count_percent",
            "error_total_count", "error_linked_count", "error_linked_count_percent",
            "unlinked_missing_timestamp", "unlinked_missing_thread", "unlinked_no_containing_call",
        ]),
        ("top_calls.csv", top_calls, [
            "call_id", "measurement_id", "dataset_id", "user", "signature", "start_timestamp", "end_timestamp",
            "duration_us", "cpu_us", "db_count", "db_duration_us", "db_rows", "sdbl_count", "in_bytes",
            "out_bytes", "memory", "memory_peak", "lock_count", "lock_duration_us", "error_count", "process", "source",
            "context_sample",
        ]),
        ("call_observations.csv", call_observations, [
            "call_id", "measurement_id", "dataset_id", "user", "signature", "start_timestamp", "end_timestamp",
            "duration_us", "cpu_us", "db_count", "db_duration_us", "db_rows", "sdbl_count", "in_bytes",
            "out_bytes", "memory", "memory_peak", "lock_count", "lock_duration_us", "error_count", "process", "source",
            "context_sample",
        ]),
    ]
    for filename, rows, fieldnames in csv_specs:
        fieldnames = fieldnames + QUALITY_CSV_FIELDS.get(filename, [])
        if filename in {"call_observations.csv", "top_calls.csv"}:
            fieldnames += CALL_DETAIL_FIELDS
        path = output_dir / filename
        write_csv(path, rows, fieldnames)
        outputs.append(path)
    return outputs


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deterministic analysis of 1C:Enterprise technological journal files. No PDF or generated conclusions.",
    )
    parser.add_argument("input_dir", type=Path, help="Folder containing .log files and/or supported archives")
    parser.add_argument("-o", "--output-dir", type=Path, help="Output folder; default: <input>/analysis_data")
    parser.add_argument("--archive-mode", choices=("auto", "always", "never"), default="auto", help="auto skips an archive when its extracted sibling folder exists")
    parser.add_argument("--exclude-dir", action="append", default=[], help="Directory name to skip recursively; may be repeated")
    parser.add_argument("--hash-sources", action="store_true", help="Retained CLI option; schema 1.6 always hashes uncompressed source streams")
    parser.add_argument("--source-map", type=Path, help="Saved logical source map; explicitly maps physical copies to one source")
    parser.add_argument("--capture-id", help="Stable capture identity; reuse it or source_map.json across relocated runs")
    parser.add_argument(
        "--salvage-nul-prefix",
        action="store_true",
        help="Analyze only complete UTF-8 records before binary/NUL corruption; damaged remainder stays excluded",
    )
    parser.add_argument("--top-calls", type=int, default=200, help="Number of individual slowest CALL rows to export")
    parser.add_argument("--overwrite", action="store_true", help="Allow replacing files in a non-empty output folder")
    parser.add_argument("--progress", action="store_true", help="Write runtime progress and approximate ETA to stderr")
    parser.add_argument("--progress-format", choices=("text", "jsonl"), default="text", help="Progress output format; default: text")
    parser.add_argument("--progress-interval", type=float, default=1.0, help="Minimum seconds between progress updates; default: 1.0")
    parser.add_argument("--version", action="version", version=VERSION)
    return parser.parse_args(argv)


def run(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.input_dir.resolve()
    if not root.exists():
        raise AnalyzerError(f"input folder does not exist: {root}", 2)
    if not root.is_dir():
        raise AnalyzerError(f"input path is not a folder: {root}", 2)
    output_dir = (args.output_dir or (root / "analysis_data")).resolve()
    if output_dir == root:
        raise AnalyzerError("output folder must not be the input root", 2)
    if output_is_nonempty(output_dir) and not args.overwrite:
        raise AnalyzerError(f"output folder is not empty; use --overwrite or another path: {output_dir}", 5)
    if args.top_calls < 0:
        raise AnalyzerError("--top-calls must be non-negative", 2)
    if not math.isfinite(args.progress_interval) or args.progress_interval <= 0:
        raise AnalyzerError("--progress-interval must be a finite positive number", 2)

    progress = ProgressReporter(args.progress, args.progress_format, args.progress_interval)
    active_progress = progress if args.progress else None
    progress.start("source_discovery")
    sources, archive_inventory, warnings = discover_sources(
        root, output_dir, args.archive_mode, set(args.exclude_dir),
    )
    progress.finish(f"{len(sources)} source(s)")
    progress.start("source_inspection", sum(source.size for source in sources), "bytes")
    health = []
    for source in sources:
        progress.set_detail(source.display_path)
        health.append(inspect_source(
            source, True, args.salvage_nul_prefix,
            active_progress.advance if active_progress is not None else None,
        ))
    progress.finish(f"{len(health)} source(s) inspected")
    progress.start("source_identity", len(health), "sources")
    try:
        source_map = assign_sources(health, root, args.source_map, args.capture_id)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        raise AnalyzerError("Invalid logical source identity: " + str(exc)) from exc
    salvaged = [item for item in health if item.status == "partial_nul_salvaged"]
    if salvaged:
        warnings.append({
            "type": "partial_nul_prefix_salvage",
            "path": str(root),
            "message": (
                f"{len(salvaged)} damaged source prefix(es) analyzed through complete UTF-8 records; "
                f"{sum(item.analyzed_bytes for item in salvaged)} bytes included and all damaged remainders excluded"
            ),
        })
    duplicate_count = sum(item.status == "skipped_duplicate" for item in health)
    if duplicate_count:
        warnings.append({
            "type": "logical_source_duplicates",
            "path": str(root),
            "message": f"{duplicate_count} mapped copies excluded; all physical locations retained in analysis.sqlite",
        })
    valid_health = [item for item in health if item.status in {"valid", "valid_no_timestamp", "partial_nul_salvaged"}]
    progress.finish(f"{len(valid_health)} source(s) selected")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".tj-detail-", dir=output_dir.parent) as staging:
        stage = Path(staging)
        store = EventStore(stage / "analysis.sqlite")
        phase = "source_ingestion"
        try:
            store.add_sources(health)
            progress.start("source_ingestion", sum(item.analyzed_bytes for item in valid_health), "bytes")
            calls, raw_datasets = analyze_pass_one(valid_health, store, active_progress)
            progress.finish(f"{sum(item.records for item in valid_health)} record(s)")
            phase = "stored_event_linkage"
            db_event_count = None
            if active_progress is not None:
                db_event_count = store.connection.execute("SELECT count(*) FROM db_events").fetchone()[0]
                progress.start("db_event_linkage", db_event_count, "events")
                store.on_db_link = active_progress.advance
            store.link_db()
            store.on_db_link = None
            if active_progress is not None:
                progress.finish()
            error_event_count = None
            if active_progress is not None:
                error_event_count = store.connection.execute("SELECT count(*) FROM error_events").fetchone()[0]
                progress.start("error_event_linkage", error_event_count, "events")
                store.on_error_link = active_progress.advance
            link_errors(store)
            store.on_error_link = None
            if active_progress is not None:
                progress.finish()
            phase = "stored_event_aggregation"
            if active_progress is not None:
                aggregate_event_count = store.connection.execute(
                    "SELECT count(*) FROM events WHERE event_type IN ('SDBL','TLOCK','TTIMEOUT','TDEADLOCK')"
                ).fetchone()[0] + db_event_count + error_event_count
                progress.start("stored_event_aggregation", aggregate_event_count, "events")
            sql_groups, lock_groups, raw_linkage = analyze_pass_two(calls, store, active_progress)
            datasets = dataset_rows(raw_datasets)
            operations = aggregate_operations(calls)
            identical = identical_operation_rows(calls)
            sql = sql_rows(sql_groups)
            errors = error_groups(store.connection)
            errors_summary = error_summary(store.connection)
            locks = lock_rows(lock_groups)
            linkage = linkage_rows(raw_linkage)
            top_calls = call_detail_rows(calls, args.top_calls)
            call_observations = call_observation_rows(calls)
            if active_progress is not None:
                progress.finish()
            phase = "result_export"
            progress.start("result_export")
            artifacts = store.finish(health, source_map, stage)
            write_outputs(stage, root, args.archive_mode, args.salvage_nul_prefix, archive_inventory, warnings, health,
                          datasets, operations, identical, sql, errors, locks, linkage, top_calls, call_observations,
                          artifacts, source_map, errors_summary)
            progress.finish()
            # Validate the completed bundle before replacing any user output.
            from slice_input import load_bundle
            phase = "result_verification"
            progress.start("result_verification")
            load_bundle(stage)
            progress.finish()
            phase = "result_publication"
            progress.start("result_publication")
            output_dir.mkdir(parents=True, exist_ok=True)
            names = sorted(p.name for p in stage.iterdir() if p.name != "analysis_metrics.json")
            names.append("analysis_metrics.json")
            for name in names:
                os.replace(stage/name, output_dir/name)
            outputs = [output_dir/name for name in names]
            progress.finish(f"{len(outputs)} file(s) written")
        except (OSError, sqlite3.Error) as exc:
            raise AnalyzerError(f"{phase} failed; result is not a validated publication: {exc}") from exc
        finally:
            store.close()
    print(json.dumps({
        "status": ("partial" if has_source_problems(health, warnings) else "ok") if valid_health else "no_valid_logs",
        "input": str(root),
        "output": str(output_dir),
        "sources_analyzed": len(valid_health),
        "datasets": len(datasets),
        "calls": len(calls),
        "sql_patterns": len(sql),
        "error_signatures": len(errors),
        "files_written": [str(path) for path in outputs],
    }, ensure_ascii=False, indent=2))
    return 0 if valid_health else 4


def main() -> None:
    # Windows service shells may expose a legacy single-byte encoding even when
    # paths and user names contain Cyrillic. Reconfigure only console streams;
    # result files use explicit UTF-8 encodings.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass
    try:
        raise SystemExit(run())
    except AnalyzerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(exc.exit_code)


if __name__ == "__main__":
    main()
