"""Optional console progress reporting for the analyzer.

Progress is deliberately kept outside saved analysis artifacts. Durations and
throughput are runtime observations and must not affect deterministic output.
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from typing import Callable, TextIO


PHASE_RANGES = {
    "source_discovery": (0.0, 1.0),
    "source_inspection": (1.0, 20.0),
    "source_identity": (20.0, 21.0),
    "source_ingestion": (21.0, 65.0),
    "db_event_linkage": (65.0, 75.0),
    "error_event_linkage": (75.0, 78.0),
    "stored_event_aggregation": (78.0, 90.0),
    "result_export": (90.0, 97.0),
    "result_verification": (97.0, 99.0),
    "result_publication": (99.0, 100.0),
}


@dataclass
class PhaseState:
    name: str
    total: int | None
    unit: str
    completed: int
    started_at: float
    detail: str = ""


def format_duration(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "calculating"
    value = int(round(seconds))
    hours, remainder = divmod(value, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def format_units(value: float, unit: str) -> str:
    if unit != "bytes":
        return f"{int(value)} {unit}"
    amount = float(value)
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(amount) < 1024.0 or suffix == "TiB":
            return f"{amount:.1f} {suffix}" if suffix != "B" else f"{int(amount)} B"
        amount /= 1024.0
    raise AssertionError("unreachable")


class ProgressReporter:
    """Throttled text or JSON Lines reporter writing only to a console stream."""

    def __init__(
        self,
        enabled: bool = False,
        output_format: str = "text",
        interval: float = 1.0,
        stream: TextIO | None = None,
        clock: Callable[[], float] = time.monotonic,
        eta_warmup_seconds: float = 3.0,
    ) -> None:
        self.enabled = enabled
        self.output_format = output_format
        self.interval = interval
        self.stream = stream if stream is not None else sys.stderr
        self.clock = clock
        self.eta_warmup_seconds = eta_warmup_seconds
        self.started_at = clock()
        self.phase: PhaseState | None = None
        self.last_emit_at: float | None = None
        self.last_overall_fraction = 0.0
        self.last_rate_at = self.started_at
        self.smoothed_overall_rate: float | None = None

    def start(self, name: str, total: int | None = None, unit: str = "items", detail: str = "") -> None:
        if name not in PHASE_RANGES:
            raise ValueError(f"unknown progress phase: {name}")
        now = self.clock()
        self.phase = PhaseState(name, total, unit, 0, now, detail)
        self._emit(now, force=True)

    def set_detail(self, detail: str) -> None:
        if self.phase is not None:
            self.phase.detail = detail

    def advance(self, amount: int = 1, detail: str | None = None) -> None:
        if self.phase is None:
            return
        self.phase.completed += amount
        if detail is not None:
            self.phase.detail = detail
        self._emit(self.clock())

    def finish(self, detail: str | None = None) -> None:
        if self.phase is None:
            return
        if detail is not None:
            self.phase.detail = detail
        if self.phase.total is not None:
            self.phase.completed = self.phase.total
        self._emit(self.clock(), force=True, finished=True)

    def _phase_fraction(self, finished: bool) -> float | None:
        if self.phase is None:
            return None
        if finished:
            return 1.0
        if self.phase.total is None:
            return None
        if self.phase.total <= 0:
            return 1.0
        return max(0.0, min(1.0, self.phase.completed / self.phase.total))

    def _emit(self, now: float, force: bool = False, finished: bool = False) -> None:
        if not self.enabled or self.phase is None:
            return
        if not force and self.last_emit_at is not None and now - self.last_emit_at < self.interval:
            return
        phase_fraction = self._phase_fraction(finished)
        lower, upper = PHASE_RANGES[self.phase.name]
        overall_percent = upper if finished else lower if phase_fraction is None else lower + (upper - lower) * phase_fraction
        overall_fraction = overall_percent / 100.0
        delta_time = now - self.last_rate_at
        delta_progress = overall_fraction - self.last_overall_fraction
        if delta_time > 0 and delta_progress > 0:
            current_rate = delta_progress / delta_time
            self.smoothed_overall_rate = (
                current_rate if self.smoothed_overall_rate is None
                else 0.25 * current_rate + 0.75 * self.smoothed_overall_rate
            )
            self.last_rate_at = now
            self.last_overall_fraction = overall_fraction
        elapsed = max(0.0, now - self.started_at)
        eta = 0.0 if overall_fraction >= 1.0 else None
        if (
            overall_fraction < 1.0
            and elapsed >= self.eta_warmup_seconds
            and self.smoothed_overall_rate is not None
            and self.smoothed_overall_rate > 0
        ):
            eta = (1.0 - overall_fraction) / self.smoothed_overall_rate
        phase_elapsed = max(0.0, now - self.phase.started_at)
        rate = self.phase.completed / phase_elapsed if phase_elapsed > 0 and self.phase.completed else None
        payload = {
            "type": "progress",
            "phase": self.phase.name,
            "phase_progress_percent": None if phase_fraction is None else round(phase_fraction * 100.0, 1),
            "overall_progress_percent": round(overall_percent, 1),
            "completed_units": self.phase.completed,
            "total_units": self.phase.total,
            "unit": self.phase.unit,
            "rate_per_second": None if rate is None else round(rate, 3),
            "elapsed_seconds": round(elapsed, 3),
            "eta_seconds": None if eta is None else round(eta, 3),
            "detail": self.phase.detail or None,
        }
        if self.output_format == "jsonl":
            line = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        else:
            phase_percent = "--" if phase_fraction is None else f"{phase_fraction * 100.0:.1f}%"
            units = format_units(self.phase.completed, self.phase.unit)
            if self.phase.total is not None:
                units += " / " + format_units(self.phase.total, self.phase.unit)
            rate_text = "--" if rate is None else format_units(rate, self.phase.unit) + "/s"
            detail = f" | {self.phase.detail}" if self.phase.detail else ""
            line = (
                f"[{self.phase.name}] {phase_percent} | overall ~{overall_percent:.1f}% | "
                f"{units} | {rate_text} | elapsed {format_duration(elapsed)} | ETA {format_duration(eta)}{detail}"
            )
        print(line, file=self.stream, flush=True)
        self.last_emit_at = now
