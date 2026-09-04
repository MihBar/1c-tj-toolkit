"""SQL identities and bundle provenance; synthetic SQL/TJ only."""
from __future__ import annotations

import contextlib
import csv
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import analyze_1c_tj as analyzer
from sql_normalization import (SQL_NORMALIZATION_VERSION, LEGACY_SQL_NORMALIZATION_VERSION,
                               SQL_CSV_FIELDS, normalize_sql, normalization_status,
                               sql_fingerprint, sql_features, sql_tables)
from slice_input import load_bundle
from slice_config import SliceError
from derive_slices import run as derive
from verify_analysis import verify as verify_analysis
from verify_slices import verify as verify_slices


class SqlNormalizationTests(unittest.TestCase):
    def same(self, first, second):
        a, b = normalize_sql(first), normalize_sql(second)
        self.assertEqual(normalization_status(a), "normalized", a)
        self.assertEqual(normalization_status(b), "normalized", b)
        self.assertEqual(a, b)
        self.assertEqual(sql_fingerprint(a), sql_fingerprint(b))

    def different(self, first, second):
        a, b = normalize_sql(first), normalize_sql(second)
        self.assertNotEqual(a, b)
        self.assertNotEqual(sql_fingerprint(a), sql_fingerprint(b))

    def test_temporary_renaming_retains_two_identities_and_repeated_uses(self):
        self.same("SELECT a.id FROM pg_temp.tt12 a JOIN pg_temp.tt34 b ON a.id=b.id JOIN pg_temp.tt12 c ON b.x=c.x",
                  "select a.id from pg_temp.tt900 a join pg_temp.tt1 b on a.id=b.id join pg_temp.tt900 c on b.x=c.x")
        normalized = normalize_sql("SELECT * FROM tt9 a JOIN tt1 b ON a.x=b.x JOIN tt9 c ON c.x=b.x")
        self.assertEqual(normalized.count("<temp:1>"), 2)
        self.assertEqual(normalized.count("<temp:2>"), 1)

    def test_self_join_cannot_merge_with_two_relations(self):
        self.different("SELECT * FROM tt1 a JOIN tt2 b ON a.id=b.id",
                       "SELECT * FROM tt1 a JOIN tt1 b ON a.id=b.id")
        self.different("SELECT * FROM tt1 a JOIN tt2 b ON a.id=b.id JOIN tt1 c ON b.id=c.id",
                       "SELECT * FROM tt1 a JOIN tt2 b ON a.id=b.id JOIN tt2 c ON b.id=c.id")

    def test_unaliased_qualifiers_before_from_and_mixed_qualification(self):
        self.same('SELECT tt11.id, pg_temp.tt22.x FROM pg_temp.tt11 JOIN tt22 ON tt11.id=tt22.id',
                  'SELECT tt71.id, pg_temp.tt82.x FROM tt71 JOIN pg_temp.tt82 ON tt71.id=tt82.id')
        self.same('SELECT "tt11".id FROM "pg_temp"."tt11"', 'SELECT tt78.id FROM pg_temp.tt78')
        self.same('SELECT tt11.*, pg_temp.tt22.* FROM tt11 JOIN tt22 ON tt11.id=tt22.id',
                  'SELECT tt71.*, pg_temp.tt82.* FROM tt71 JOIN tt82 ON tt71.id=tt82.id')
        self.same('SELECT tt11.id FROM tt11 WHERE EXISTS (SELECT 1 FROM tt22 WHERE tt22.id=tt11.id)',
                  'SELECT tt99.id FROM tt99 WHERE EXISTS (SELECT 2 FROM tt88 WHERE tt88.id=tt99.id)')

    def test_comma_relations_and_dml(self):
        pairs = [
            ('SELECT * FROM tt1, tt2 WHERE tt1.id=tt2.id', 'SELECT * FROM tt42, tt87 WHERE tt42.id=tt87.id'),
            ('SELECT * FROM tt1 a JOIN tt2 b ON a.id=b.id, tt3 c', 'SELECT * FROM tt91 a JOIN tt92 b ON a.id=b.id, tt93 c'),
            ('UPDATE tt1 SET x=1 FROM tt2 WHERE tt1.id=tt2.id', 'UPDATE tt9 SET x=8 FROM tt7 WHERE tt9.id=tt7.id'),
            ('INSERT INTO tt1 (x) SELECT x FROM tt2', 'INSERT INTO tt31 (x) SELECT x FROM tt32'),
            ('DELETE FROM tt1 USING tt2 WHERE tt1.id=tt2.id', 'DELETE FROM tt51 USING tt52 WHERE tt51.id=tt52.id'),
            ('CREATE TEMP TABLE work_a AS SELECT field1 FROM public.base; SELECT work_a.field1 FROM work_a',
             'CREATE TEMP TABLE work_b AS SELECT field1 FROM public.base; SELECT work_b.field1 FROM work_b'),
            ('CREATE TEMP TABLE tt1 (x int); DROP TABLE tt1', 'CREATE TEMP TABLE tt2 (x int); DROP TABLE tt2'),
            ('SELECT tt1.* FROM ONLY (tt1)', 'SELECT tt8.* FROM ONLY (tt8)'),
            ('SELECT tt1.id FROM (tt1 JOIN tt2 ON tt1.id=tt2.id)', 'SELECT tt9.id FROM (tt9 JOIN tt8 ON tt9.id=tt8.id)'),
        ]
        for first, second in pairs:
            with self.subTest(sql=first):
                self.same(first, second)
        normalized = normalize_sql(pairs[5][0])
        self.assertIn('public . base', normalized)
        self.assertNotIn('work_a', normalized)

    def test_alias_cte_and_physical_identifiers_are_not_temp_names(self):
        self.same('SELECT tt7.id FROM tt1 tt7', 'SELECT tt7.id FROM tt2 tt7')
        self.same('SELECT a.tt7 FROM tt1 a', 'SELECT a.tt7 FROM tt2 a')
        for first, second in [
            ('SELECT * FROM public.tt1', 'SELECT * FROM public.tt2'),
            ('SELECT f.tt1 FROM physical f', 'SELECT f.tt2 FROM physical f'),
            ('SELECT field1 FROM physical1', 'SELECT field2 FROM physical1'),
            ('SELECT * FROM physical1', 'SELECT * FROM physical2'),
            ('SELECT * FROM "physical 1"', 'SELECT * FROM "physical 2"'),
            ('SELECT * FROM "Abc"', 'SELECT * FROM "abc"'),
            ('SELECT "a  b" FROM physical', 'SELECT "a b" FROM physical'),
            ('WITH tt1 AS (SELECT 1) SELECT * FROM tt1', 'WITH tt2 AS (SELECT 1) SELECT * FROM tt2'),
            ('SELECT "field""1" FROM t', 'SELECT "field""2" FROM t'),
            ('SELECT * FROM tt1 a JOIN "TT1" b ON a.id=b.id', 'SELECT * FROM tt1 a JOIN tt1 b ON a.id=b.id'),
        ]:
            with self.subTest(sql=first):
                self.different(first, second)
        self.assertIn('tt1 . x', normalize_sql('SELECT tt1.x FROM public.physical tt1'))
        self.assertIn('pg_temp . field . x', normalize_sql('SELECT pg_temp.field.x FROM physical pg_temp'))

    def test_nested_alias_shadows_outer_temp_qualifier(self):
        self.same('SELECT tt1.x FROM tt1 WHERE EXISTS (SELECT tt8.x FROM physical tt8 WHERE tt8.x=tt1.x)',
                  'SELECT tt2.x FROM tt2 WHERE EXISTS (SELECT tt8.x FROM physical tt8 WHERE tt8.x=tt2.x)')
        self.assertIn('tt1 . x from physical tt1', normalize_sql('SELECT tt1.x FROM tt1 WHERE EXISTS (SELECT tt1.x FROM physical tt1)'))

    def test_literals_and_sql_inside_them_are_opaque(self):
        values = ["'JOIN pg_temp.tt999 WHERE x=1'", "'O''Brien -- /* SELECT */'",
                  "$$JOIN tt88 $inner$ WHERE x=1$inner$ $$", "$tag$ FROM tt3 $other$ $tag$",
                  r"E'quote\' FROM tt1 -- \\x42'", "U&'d\\0061ta'", "N'value'"]
        for literal in values:
            with self.subTest(literal=literal):
                self.same('SELECT '+literal+' FROM tt1', "SELECT 'other' FROM tt2")
                self.assertEqual(sql_tables('SELECT '+literal+' FROM tt1'), ['tt1'])
        self.same('SELECT 1, 1.2e-3, .5, 0xFF, 0o77, 0b11, 1_000',
                  'SELECT 9, 4.6e+7, .2, 0xAB, 0o11, 0b00, 9_000')
        self.same("SELECT B'010'", "SELECT X'f'")
        self.different("SELECT B'010'", "SELECT '010'")
        self.different("SELECT '1'", "SELECT 1")

    def test_comments_token_boundaries_and_string_continuations(self):
        self.same('SELECT/* outer /* nested FROM tt99 */ x */a.x FROM tt1 a -- JOIN tt9\n WHERE a.x=1',
                  'select a.x from tt2 a where a.x=9')
        self.same("SELECT 'a'\n'b'", "SELECT 'different'")
        self.same("SELECT E'a'\n'\\\'b'", "SELECT E'other'")
        self.same("SELECT B'10'\n'01'", "SELECT B'111'")
        self.different("SELECT 'a' 'b'", "SELECT 'ab'")
        self.different('SELECT a/*comment*/b FROM t', 'SELECT ab FROM t')
        self.different('SELECT 1-- hidden\n+2', 'SELECT 1-- hidden +2')

    def test_expression_structure_operators_parameters_and_ordinals(self):
        for first, second in [
            ('SELECT x-1 FROM t', 'SELECT x+1 FROM t'),
            ('SELECT (a+b)*c FROM t', 'SELECT a+b*c FROM t'),
            ('SELECT a FROM t WHERE a IN (1,2,3,4)', 'SELECT a FROM t WHERE a IN (1,2,3,4,5)'),
            ('SELECT a,b FROM t ORDER BY 1', 'SELECT a,b FROM t ORDER BY 2'),
            ('SELECT a,b FROM t GROUP BY 1,2', 'SELECT a,b FROM t GROUP BY 1,1'),
            ('SELECT a,b FROM t GROUP BY (1)', 'SELECT a,b FROM t GROUP BY (2)'),
            ('SELECT x::numeric(10,2) FROM t', 'SELECT x::numeric(12,4) FROM t'),
            ('SELECT CAST(x AS varchar(10)) FROM t', 'SELECT CAST(x AS varchar(20)) FROM t'),
            ('SELECT $1 + $1', 'SELECT $1 + $2'),
            ("SELECT a->'x' FROM t", "SELECT a->>'x' FROM t"),
            ('SELECT a*b FROM t', 'SELECT a/b FROM t'),
            ('SELECT a FROM t UNION SELECT a FROM u', 'SELECT a FROM t UNION ALL SELECT a FROM u'),
            ('SELECT CASE WHEN a=1 THEN b ELSE c END FROM t', 'SELECT CASE WHEN a=1 THEN c ELSE b END FROM t'),
        ]:
            with self.subTest(sql=first):
                self.different(first, second)
        self.same('SELECT x*-1, x+2 FROM t', 'SELECT x * - 9, x + 5 FROM t')

    def test_feature_flags_ignore_literals_comments_and_quoted_identifiers(self):
        sql = "SELECT 'join case distinct order by group by union limit', \"JOIN\" FROM physical -- JOIN tt8"
        self.assertFalse(any(sql_features(normalize_sql(sql)).values()))
        features = sql_features(normalize_sql('SELECT DISTINCT a.x FROM tt1 a JOIN tt2 b ON a.x=b.x ORDER BY a.x LIMIT 1'))
        self.assertTrue(all(features[k] for k in ('has_distinct', 'has_join', 'has_temp_table', 'has_order_by', 'has_limit_or_top')))

    def test_ambiguous_or_unterminated_input_is_explicit_lossless_fallback(self):
        for sql in ("SELECT 'unterminated", 'SELECT $tag$x$other$', 'SELECT /* broken',
                    'SELECT (1', 'SELECT [1)', r"SELECT 'x\'", 'SELECT U&"d\\0061t" FROM t'):
            with self.subTest(sql=sql):
                normalized = normalize_sql(sql)
                self.assertEqual(normalization_status(normalized), 'raw_fallback')
                self.assertEqual(json.loads(normalized[len('<raw-sql> '):]), sql)
                self.assertTrue(all(v is None for v in sql_features(normalized).values()))

    def test_new_fingerprints_have_domain_and_version(self):
        sql = 'select x from physical'
        self.assertEqual(sql_fingerprint(sql, LEGACY_SQL_NORMALIZATION_VERSION), hashlib.sha256(sql.encode()).hexdigest())
        self.assertNotEqual(sql_fingerprint(sql), sql_fingerprint(sql, LEGACY_SQL_NORMALIZATION_VERSION))
        self.assertEqual(sql_fingerprint(sql), hashlib.sha256(('1c-tj-sql\0'+SQL_NORMALIZATION_VERSION+'\0'+sql).encode()).hexdigest())
        with self.assertRaises(ValueError):
            sql_fingerprint(sql, 'future')


class SqlBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='tj-sql-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root/'analysis'

    def make(self, queries=None):
        queries = queries or ['SELECT * FROM tt1 a JOIN tt2 b ON a.x=b.x',
                              'SELECT * FROM tt9 a JOIN tt8 b ON a.x=b.x',
                              'SELECT * FROM tt9 a JOIN tt9 b ON a.x=b.x']
        path = self.root/'logs'/'capture'/'rphost_1'/'26090310.log'
        path.parent.mkdir(parents=True)
        records = ["00:10.000000-10000000,CALL,5,Usr=User,OSThread=7,SessionID=1,Context='Operation',CpuTime=100\n"]
        for i, sql in enumerate(queries, 1):
            escaped = sql.replace("'", "''")
            records.append(f"00:0{i}.000000-{i*100},DBPOSTGRS,5,Usr=User,OSThread=7,SessionID=1,Sql='{escaped}'\n")
        path.write_text(''.join(records), encoding='utf-8')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(analyzer.run([str(self.root/'logs'), '-o', str(self.out)]), 0)
        self.manifest = json.loads((self.out/'analysis_metrics.json').read_text(encoding='utf-8'))
        return load_bundle(self.out)

    def save(self):
        (self.out/'analysis_metrics.json').write_text(json.dumps(self.manifest, ensure_ascii=False), encoding='utf-8')

    def rewrite_sql_csv(self, change=None, remove_fields=()):
        path = self.out/'heavy_sql.csv'
        with path.open(encoding='utf-8-sig', newline='') as stream:
            reader = csv.DictReader(stream)
            fields = [f for f in reader.fieldnames if f not in remove_fields]
            rows = list(reader)
        for i, row in enumerate(rows):
            if change:
                change(i, row)
        with path.open('w', encoding='utf-8-sig', newline='') as stream:
            writer = csv.DictWriter(stream, fields, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(rows)

    def test_synthetic_aggregation_linkage_versions_and_consumer_roundtrip(self):
        bundle = self.make()
        self.assertEqual(bundle.manifest['schema_version'], '1.6')
        self.assertEqual(bundle.sql_normalization_version, SQL_NORMALIZATION_VERSION)
        self.assertEqual(sorted(r['count'] for r in self.manifest['heavy_sql']), [1, 2])
        nested = self.manifest['operations'][0]['top_nested_sql']
        self.assertEqual(sorted(r['count'] for r in nested), [1, 2])
        self.assertEqual({r['sql_fingerprint_sha256'] for r in nested}, {r['sql_fingerprint_sha256'] for r in self.manifest['heavy_sql']})
        self.assertEqual(verify_analysis(self.out)[1], 0)
        config = self.root/'config.json'
        config.write_text('{"config_version":"1.0","slices":["data_quality","operation_history"]}', encoding='utf-8')
        slices = self.root/'slices'
        with contextlib.redirect_stdout(io.StringIO()):
            derive(['--analysis-dir', str(self.out), '--config', str(config), '--output', str(slices)])
        self.assertEqual(verify_slices(self.out, slices)['status'], 'PASS')
        manifest_path = slices/'slice_manifest.json'
        saved = json.loads(manifest_path.read_text(encoding='utf-8'))
        self.assertEqual(saved['input_sql_normalization_version'], SQL_NORMALIZATION_VERSION)
        saved['input_sql_normalization_version'] = LEGACY_SQL_NORMALIZATION_VERSION
        manifest_path.write_text(json.dumps(saved), encoding='utf-8')
        with self.assertRaisesRegex(SliceError, 'SQL normalization version'):
            verify_slices(self.out, slices)

    def test_full_sql_after_sample_cutoff_changes_signature(self):
        prefix = 'SELECT ' + ', '.join('p.field'+str(i) for i in range(500)) + ' FROM physical p WHERE '
        queries = [prefix+'p.ending_a=1', prefix+'p.ending_b=1', prefix+'p.ending_a=9']
        self.make(queries)
        rows = self.manifest['heavy_sql']
        self.assertEqual(sorted(r['count'] for r in rows), [1, 2])
        self.assertEqual(len({r['sample_sql'] for r in rows}), 1)
        self.assertTrue(all(len(r['sample_sql']) == 2400 and len(r['normalized_sql']) > 2400 for r in rows))
        self.assertEqual({r['sql_fingerprint_sha256'] for r in rows}, {sql_fingerprint(normalize_sql(q)) for q in queries})

    def test_rejects_missing_or_unknown_manifest_version_and_algorithm(self):
        self.make()
        for field in ('sql_normalization_version', 'sql_fingerprint_algorithm'):
            value = self.manifest.pop(field)
            self.save()
            with self.assertRaises(SliceError):
                load_bundle(self.out)
            self.manifest[field] = 'future'
            self.save()
            with self.assertRaises(SliceError):
                load_bundle(self.out)
            self.manifest[field] = value
        self.save()

    def test_rejects_mixed_rows_even_if_json_csv_and_hash_agree(self):
        self.make()
        row = self.manifest['heavy_sql'][0]
        row['sql_normalization_version'] = LEGACY_SQL_NORMALIZATION_VERSION
        row['sql_fingerprint_sha256'] = sql_fingerprint(row['normalized_sql'], LEGACY_SQL_NORMALIZATION_VERSION)
        self.rewrite_sql_csv(lambda i, r: r.update({k: row[k] for k in ('sql_normalization_version', 'sql_fingerprint_sha256')}) if i == 0 else None)
        self.save()
        with self.assertRaisesRegex(SliceError, 'normalization version mismatch'):
            load_bundle(self.out)

    def test_rejects_nested_mismatch_and_wrong_hash(self):
        self.make()
        row = self.manifest['operations'][0]['top_nested_sql'][0]
        row['sql_normalization_version'] = LEGACY_SQL_NORMALIZATION_VERSION
        self.save()
        with self.assertRaisesRegex(SliceError, 'normalization version mismatch'):
            load_bundle(self.out)
        row['sql_normalization_version'] = SQL_NORMALIZATION_VERSION
        row['sql_fingerprint_sha256'] = '0'*64
        self.save()
        with self.assertRaisesRegex(SliceError, 'SQL fingerprint'):
            load_bundle(self.out)
        row['normalized_sql'] = None
        self.save()
        with self.assertRaisesRegex(SliceError, 'Invalid SQL row'):
            load_bundle(self.out)

    def test_fallback_status_roundtrips_and_cannot_be_disguised(self):
        self.make(['SELECT /* broken'])
        self.assertEqual(self.manifest['heavy_sql'][0]['sql_normalization_status'], 'raw_fallback')
        self.assertEqual(verify_analysis(self.out)[1], 0)
        self.manifest['heavy_sql'][0]['sql_normalization_status'] = 'normalized'
        self.rewrite_sql_csv(lambda i, r: r.update(sql_normalization_status='normalized'))
        self.save()
        with self.assertRaisesRegex(SliceError, 'normalization status mismatch'):
            load_bundle(self.out)

    def test_rejects_missing_version_header_even_for_empty_sql_table(self):
        self.make([''])
        self.rewrite_sql_csv(remove_fields=SQL_CSV_FIELDS)
        with self.assertRaisesRegex(SliceError, 'normalization header'):
            load_bundle(self.out)

    def test_legacy_schema13_keeps_explicit_legacy_provenance_in_loader(self):
        self.make(['select x from physical'])
        self.manifest['schema_version'] = '1.3'
        self.manifest['analyzer_version'] = '1.3.0'
        # The current writer uses explicit error counters; this fixture emulates
        # the complete old format, including the empty legacy error table.
        from slice_input import HEADERS
        from error_rules import ERROR_METADATA
        for key in ERROR_METADATA:
            self.manifest.pop(key, None)
        self.manifest.pop('error_summary', None)
        with (self.out/'errors.csv').open('w', encoding='utf-8-sig', newline='') as stream:
            csv.writer(stream).writerow(HEADERS['errors'])
        self.manifest.pop('sql_normalization_version')
        self.manifest.pop('sql_fingerprint_algorithm')
        for row in self.manifest['heavy_sql']:
            for key in SQL_CSV_FIELDS:
                row.pop(key)
            row['sql_fingerprint_sha256'] = sql_fingerprint(row['normalized_sql'], LEGACY_SQL_NORMALIZATION_VERSION)
        for row in self.manifest['operations'][0]['top_nested_sql']:
            for key in SQL_CSV_FIELDS + ['sql_fingerprint_sha256']:
                row.pop(key)
        self.rewrite_sql_csv(lambda i, r: r.update(sql_fingerprint_sha256=sql_fingerprint(r['normalized_sql'], LEGACY_SQL_NORMALIZATION_VERSION)), SQL_CSV_FIELDS)
        self.save()
        self.assertEqual(load_bundle(self.out).sql_normalization_version, LEGACY_SQL_NORMALIZATION_VERSION)
        self.manifest['sql_normalization_version'] = SQL_NORMALIZATION_VERSION
        self.save()
        with self.assertRaisesRegex(SliceError, 'Legacy schema'):
            load_bundle(self.out)


if __name__ == '__main__':
    unittest.main()
