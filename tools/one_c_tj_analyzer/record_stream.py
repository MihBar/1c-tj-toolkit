"""Streaming TJ records with positions in the original uncompressed byte stream."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

PARSER_VERSION = "2.0"
MAX_RECORD_BYTES = 16 * 1024 * 1024
_HEADER = re.compile(rb"^\d{2}:\d{2}\.\d{6}-\d+,[^,\r\n]+,\d+,")
_NEWLINE = re.compile(rb"\r\n|\r|\n")


@dataclass
class Record:
    text: str
    byte_start: int
    byte_end: int
    record_ordinal: int
    line_start: int
    line_end: int
    raw_record_sha256: str
    decoding_replaced: bool


class RecordStream:
    def __init__(self, source, byte_limit=None, max_record_bytes=None):
        self.source, self.byte_limit = source, byte_limit
        self.max_record_bytes = MAX_RECORD_BYTES if max_record_bytes is None else max_record_bytes
        self.digest = hashlib.sha256()
        self.bytes_read = 0
        self.prefix_bytes = 0
        self.last_record_end = 0

    def lines(self, stream):
        buffer, offset, line_number = b"", 0, 1
        while True:
            remaining = 64 * 1024 if self.byte_limit is None else min(64 * 1024, self.byte_limit - self.bytes_read)
            block = stream.read(remaining) if remaining else b""
            self.bytes_read += len(block)
            self.digest.update(block)
            buffer += block
            consumed = 0
            for match in _NEWLINE.finditer(buffer):
                if block and match.end() == len(buffer) and match.group() == b"\r":
                    break
                end = match.end()
                yield buffer[consumed:end], offset + consumed, offset + end, line_number
                line_number += 1
                consumed = end
            buffer, offset = buffer[consumed:], offset + consumed
            if len(buffer) > self.max_record_bytes:
                raise RuntimeError(f"TJ line exceeds {self.max_record_bytes} byte limit")
            if not block:
                if buffer:
                    yield buffer, offset, offset + len(buffer), line_number
                break

    def __iter__(self):
        chunks, ordinal, record_bytes = [], 0, 0
        start = line_start = end = line_end = 0

        def record():
            raw = b"".join(chunks)
            try:
                text = raw.decode("utf-8-sig", errors="strict")
                replaced = False
            except UnicodeDecodeError:
                text, replaced = raw.decode("utf-8-sig", errors="replace"), True
            return Record(text.rstrip("\r\n"), start, end, ordinal, line_start, line_end,
                          hashlib.sha256(raw).hexdigest(), replaced)

        with self.source.open_binary() as stream:
            for line, byte_start, byte_end, line_number in self.lines(stream):
                header_line = line[3:] if byte_start == 0 and line.startswith(b"\xef\xbb\xbf") else line
                if _HEADER.match(header_line):
                    if chunks:
                        self.last_record_end = end
                        yield record()
                    ordinal += 1
                    chunks, start, line_start, record_bytes = [], byte_start, line_number, 0
                if ordinal:
                    chunks.append(line)
                    record_bytes += len(line)
                    if record_bytes > self.max_record_bytes:
                        raise RuntimeError(f"TJ record exceeds {self.max_record_bytes} byte limit")
                    end, line_end = byte_end, line_number
                else:
                    self.prefix_bytes = byte_end
            if chunks:
                self.last_record_end = end
                yield record()
