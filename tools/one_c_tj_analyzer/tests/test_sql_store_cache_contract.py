"""Regression contract for the EventStore.add_sql in-process cache."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import event_store
from event_store import EventStore
from source_identity import identity
from sql_normalization import (
    SQL_NORMALIZATION_VERSION,
    normalize_sql,
    normalization_status,
    sql_fingerprint,
)


SQL_TABLES = ("sql_texts", "sql_patterns", "sql_normalizations")


class SqlStoreCacheContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tj-sql-store-cache-test-")
        self.addCleanup(self.temp.cleanup)
        self.store = EventStore(Path(self.temp.name) / "analysis.sqlite")
        self.addCleanup(self.store.close)
        self.connection = self.store.connection

    def counts(self) -> dict[str, int]:
        return {
            table: self.connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in SQL_TABLES
        }

    def expected_rows(self, sql: str) -> tuple[dict, dict, dict]:
        text_id = identity("sql-text/v1", sql)
        normalized = normalize_sql(sql)
        fingerprint = sql_fingerprint(normalized)
        pattern_id = identity(
            "sql-pattern/v1", SQL_NORMALIZATION_VERSION, fingerprint
        )
        status = normalization_status(normalized)
        return (
            {
                "sql_text_id": text_id,
                "sql_text": sql,
                "sql_text_sha256": hashlib.sha256(sql.encode("utf-8")).hexdigest(),
            },
            {
                "pattern_id": pattern_id,
                "normalization_version": SQL_NORMALIZATION_VERSION,
                "normalized_sql": normalized,
                "sql_fingerprint_sha256": fingerprint,
                "normalization_status": status,
            },
            {
                "sql_text_id": text_id,
                "normalization_version": SQL_NORMALIZATION_VERSION,
                "pattern_id": pattern_id,
                "state": status,
            },
        )

    def assert_exact_rows(self, sql: str) -> None:
        expected_text, expected_pattern, expected_normalization = self.expected_rows(sql)
        actual_text = dict(
            self.connection.execute(
                "SELECT * FROM sql_texts WHERE sql_text_id=?",
                (expected_text["sql_text_id"],),
            ).fetchone()
        )
        actual_pattern = dict(
            self.connection.execute(
                "SELECT * FROM sql_patterns WHERE pattern_id=?",
                (expected_pattern["pattern_id"],),
            ).fetchone()
        )
        actual_normalization = dict(
            self.connection.execute(
                "SELECT * FROM sql_normalizations WHERE sql_text_id=?",
                (expected_text["sql_text_id"],),
            ).fetchone()
        )
        self.assertEqual(actual_text, expected_text)
        self.assertEqual(actual_pattern, expected_pattern)
        self.assertEqual(actual_normalization, expected_normalization)

    @staticmethod
    def existence_selects(statements: list[str]) -> list[str]:
        prefix = "SELECT 1 FROM SQL_TEXTS WHERE SQL_TEXT_ID="
        return [
            statement
            for statement in statements
            if statement.lstrip().upper().startswith(prefix)
        ]

    def test_none_and_empty_return_none_without_sql_dictionary_queries_or_rows(self):
        statements = []
        self.connection.set_trace_callback(statements.append)
        try:
            self.assertIsNone(self.store.add_sql(None))
            self.assertIsNone(self.store.add_sql(""))
        finally:
            self.connection.set_trace_callback(None)

        self.assertEqual(self.existence_selects(statements), [])
        self.assertEqual(
            self.counts(),
            {"sql_texts": 0, "sql_patterns": 0, "sql_normalizations": 0},
        )

    def test_repeat_before_and_after_commit_returns_one_id_and_selects_only_once(self):
        sql = "SELECT field FROM physical WHERE id=1"
        expected_id = identity("sql-text/v1", sql)
        statements = []
        self.connection.set_trace_callback(statements.append)
        try:
            first_id = self.store.add_sql(sql)
            repeated_id = self.store.add_sql(sql)
            self.store.commit()
            post_commit_id = self.store.add_sql(sql)
        finally:
            self.connection.set_trace_callback(None)

        self.assertEqual(
            (first_id, repeated_id, post_commit_id),
            (expected_id, expected_id, expected_id),
        )
        self.assertEqual(
            len(self.existence_selects(statements)),
            1,
            "Repeated SQL must use the per-store cache instead of querying sql_texts",
        )
        self.assertEqual(
            self.counts(),
            {"sql_texts": 1, "sql_patterns": 1, "sql_normalizations": 1},
        )
        self.assert_exact_rows(sql)

    def test_existing_sqlite_rows_are_cached_after_the_first_lookup(self):
        sql = "SELECT existing_value FROM physical WHERE id=7"
        expected_text, expected_pattern, expected_normalization = self.expected_rows(sql)
        event_store.insert(self.connection, "sql_texts", expected_text)
        event_store.insert(self.connection, "sql_patterns", expected_pattern)
        event_store.insert(self.connection, "sql_normalizations", expected_normalization)
        self.connection.commit()

        statements = []
        self.connection.set_trace_callback(statements.append)
        try:
            first_id = self.store.add_sql(sql)
            repeated_id = self.store.add_sql(sql)
        finally:
            self.connection.set_trace_callback(None)

        self.assertEqual(first_id, expected_text["sql_text_id"])
        self.assertEqual(repeated_id, expected_text["sql_text_id"])
        self.assertEqual(len(self.existence_selects(statements)), 1)
        self.assertEqual(
            self.counts(),
            {"sql_texts": 1, "sql_patterns": 1, "sql_normalizations": 1},
        )
        self.assert_exact_rows(sql)

    def test_direct_connection_commit_rechecks_once_then_caches_the_row(self):
        sql = "SELECT externally_committed FROM physical"
        expected_id = identity("sql-text/v1", sql)
        statements = []
        self.connection.set_trace_callback(statements.append)
        try:
            self.assertEqual(self.store.add_sql(sql), expected_id)
            self.connection.commit()
            self.assertEqual(self.store.add_sql(sql), expected_id)
            self.assertEqual(self.store.add_sql(sql), expected_id)
        finally:
            self.connection.set_trace_callback(None)

        self.assertEqual(len(self.existence_selects(statements)), 2)
        self.assertEqual(
            self.counts(),
            {"sql_texts": 1, "sql_patterns": 1, "sql_normalizations": 1},
        )
        self.assert_exact_rows(sql)

    def test_distinct_sql_texts_with_one_normalized_pattern_share_only_pattern_row(self):
        first = "SELECT value FROM tt1 WHERE id=1"
        second = "select value from tt9 where id=2"
        self.assertNotEqual(first, second)
        self.assertEqual(normalize_sql(first), normalize_sql(second))

        first_id = self.store.add_sql(first)
        second_id = self.store.add_sql(second)

        self.assertNotEqual(first_id, second_id)
        self.assertEqual(
            self.counts(),
            {"sql_texts": 2, "sql_patterns": 1, "sql_normalizations": 2},
        )
        pattern_ids = {
            row[0]
            for row in self.connection.execute(
                "SELECT pattern_id FROM sql_normalizations ORDER BY sql_text_id"
            )
        }
        self.assertEqual(len(pattern_ids), 1)
        self.assert_exact_rows(first)
        self.assert_exact_rows(second)

    def test_raw_fallback_and_unicode_preserve_exact_text_ids_hashes_and_rows(self):
        fallback_sql = "SELECT /* broken"
        unicode_sql = "SELECT 'Привет, мир' AS сообщение FROM физическая_таблица"
        self.assertEqual(normalization_status(normalize_sql(fallback_sql)), "raw_fallback")
        self.assertEqual(normalization_status(normalize_sql(unicode_sql)), "normalized")

        returned = [self.store.add_sql(sql) for sql in (fallback_sql, unicode_sql)]

        self.assertEqual(
            returned,
            [identity("sql-text/v1", fallback_sql), identity("sql-text/v1", unicode_sql)],
        )
        self.assertEqual(
            self.counts(),
            {"sql_texts": 2, "sql_patterns": 2, "sql_normalizations": 2},
        )
        self.assert_exact_rows(fallback_sql)
        self.assert_exact_rows(unicode_sql)

    def test_partial_dictionary_failure_is_not_cached_and_retry_after_rollback_succeeds(self):
        sql = "SELECT value FROM physical"
        real_insert = event_store.insert

        def fail_normalization(connection, table, row, **kwargs):
            if table == "sql_normalizations":
                raise sqlite3.IntegrityError("injected normalization failure")
            return real_insert(connection, table, row, **kwargs)

        with patch.object(event_store, "insert", side_effect=fail_normalization):
            with self.assertRaisesRegex(sqlite3.IntegrityError, "injected normalization failure"):
                self.store.add_sql(sql)

        self.assertEqual(
            self.counts(),
            {"sql_texts": 1, "sql_patterns": 1, "sql_normalizations": 0},
        )
        self.assertNotIn(identity("sql-text/v1", sql), self.store._sql_text_ids)

        self.connection.rollback()
        self.assertEqual(
            self.counts(),
            {"sql_texts": 0, "sql_patterns": 0, "sql_normalizations": 0},
        )
        self.assertEqual(self.store.add_sql(sql), identity("sql-text/v1", sql))
        self.assertEqual(
            self.counts(),
            {"sql_texts": 1, "sql_patterns": 1, "sql_normalizations": 1},
        )
        self.assert_exact_rows(sql)

    def test_rollback_discards_pending_cache_and_repeated_call_recreates_rows(self):
        sql = "SELECT rollback_value FROM physical"
        expected_id = identity("sql-text/v1", sql)
        self.assertEqual(self.store.add_sql(sql), expected_id)

        self.connection.rollback()
        self.assertEqual(
            self.counts(),
            {"sql_texts": 0, "sql_patterns": 0, "sql_normalizations": 0},
        )
        self.assertEqual(self.store.add_sql(sql), expected_id)
        self.assertEqual(
            self.counts(),
            {"sql_texts": 1, "sql_patterns": 1, "sql_normalizations": 1},
        )
        self.assert_exact_rows(sql)

    def test_direct_connection_rollback_is_detected_before_cache_hit(self):
        sql = "SELECT external_rollback FROM physical"
        expected_id = identity("sql-text/v1", sql)
        statements = []
        self.connection.set_trace_callback(statements.append)
        try:
            self.assertEqual(self.store.add_sql(sql), expected_id)
            self.connection.rollback()
            self.assertEqual(self.store.add_sql(sql), expected_id)
        finally:
            self.connection.set_trace_callback(None)

        self.assertEqual(len(self.existence_selects(statements)), 2)
        self.assertEqual(
            self.counts(),
            {"sql_texts": 1, "sql_patterns": 1, "sql_normalizations": 1},
        )
        self.assert_exact_rows(sql)

    def test_close_clears_cache_and_does_not_return_stale_id(self):
        sql = "SELECT closed_store FROM physical"
        self.store.add_sql(sql)

        self.store.close()

        self.assertEqual(self.store._sql_text_ids, set())
        self.assertEqual(self.store._pending_sql_text_ids, set())
        with self.assertRaises(AttributeError):
            self.store.add_sql(sql)


if __name__ == "__main__":
    unittest.main()
