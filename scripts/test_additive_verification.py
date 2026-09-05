"""Exact values/types and multiplicity checks for event-stream accumulators."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import benchmark_verification as bench
from verify_additive import POPULATIONS, additive_groups


class AdditiveTests(unittest.TestCase):
    def assert_typed_equal(self, old, new):
        self.assertIs(type(old), type(new))
        self.assertEqual(old, new)
        if isinstance(old, dict):
            for key in old:
                self.assert_typed_equal(old[key], new[key])

    def test_exact_equivalence_including_large_integer_sums_and_signed_counters(self):
        with tempfile.TemporaryDirectory(prefix='tj-additive-equivalence-') as temporary:
            con, _, _ = bench.build(Path(temporary)/'data.sqlite', 96, 'few_large')
            try:
                for large in (False, True):
                    if large:
                        con.execute('UPDATE events SET duration_us=?', (2**63-1,))
                        con.execute("UPDATE numeric_values SET state='valid',value_int=?,raw_value=? WHERE field_name='memory'", (-2**63, str(-2**63)))
                        con.execute("UPDATE numeric_values SET state='valid',value_int=?,raw_value=? WHERE field_name='cpu_us'", (2**63-1, str(2**63-1)))
                    for family, (width, population) in POPULATIONS.items():
                        recorded = bench.Queries(con)
                        groups = additive_groups(recorded, family, bench.require)
                        self.assertEqual(recorded.count, 2)
                        for key, accumulator in groups.items():
                            with self.subTest(large=large, family=family, key=key):
                                selection = 'SELECT event_id FROM ('+population+') WHERE '+' AND '.join(f'g{i}=?' for i in range(width))
                                old = bench.exact_stats(con, selection, key, bench.require)
                                new = bench.exact_stats(con, selection, key, bench.require, accumulator.as_dict())
                                self.assert_typed_equal(old, new)
                                if large and old['count'] > 1:
                                    self.assertGreater(new['duration_us'], 2**63-1)
                                    self.assertLess(new['numeric_quality']['memory']['sum_known'], -2**63)
                # Several error/DB children of a CALL never enter this population JOIN.
                self.assertEqual(sum(s.count for s in additive_groups(con, 'dataset', bench.require).values()), 293)
                self.assertEqual(sum(s.count for s in additive_groups(con, 'lock', bench.require).values()), 96)
            finally:
                con.close()

    def test_numeric_and_normalization_multiplicity_are_rejected(self):
        mutations = [
            "DELETE FROM numeric_values WHERE rowid=(SELECT min(rowid) FROM numeric_values)",
            "INSERT INTO numeric_values SELECT event_id,'extra',raw_value,value_int,state,unit,reason_code FROM numeric_values LIMIT 1",
            "CREATE TABLE copied_numeric AS SELECT * FROM numeric_values; INSERT INTO copied_numeric SELECT * FROM numeric_values; DROP TABLE numeric_values; ALTER TABLE copied_numeric RENAME TO numeric_values",
            "INSERT INTO sql_normalizations SELECT sql_text_id,'second-version',pattern_id,state FROM sql_normalizations",
        ]
        with tempfile.TemporaryDirectory(prefix='tj-additive-corruption-') as temporary:
            for i, sql in enumerate(mutations):
                with self.subTest(mutation=i):
                    con, _, _ = bench.build(Path(temporary)/f'{i}.sqlite', 96, 'few_large')
                    try:
                        con.executescript(sql)
                        with self.assertRaises(AssertionError):
                            additive_groups(con, 'sql' if i == 3 else 'dataset', bench.require)
                    finally:
                        con.close()

    def test_manifest_corruptions_rejected_by_frozen_and_streaming_blocks(self):
        frozen = json.loads((bench.ROOT/'tools/one_c_tj_analyzer/tests/fixtures/verifier_baseline_blocks.json').read_text(encoding='utf-8'))
        blocks, _ = bench.extract_blocks()
        with tempfile.TemporaryDirectory(prefix='tj-additive-metrics-') as temporary:
            con, env, _ = bench.build(Path(temporary)/'data.sqlite', 96, 'few_large')
            try:
                targets = {'dataset_stats': env['manifest']['datasets'][0]['event_stats']['DBPOSTGRS'],
                           'heavy_sql': env['manifest']['heavy_sql'][0], 'locks': env['manifest']['locks'][0]}
                for name, target in targets.items():
                    original = copy.deepcopy(target)
                    for field in ('count','duration_us','avg_us','max_us','over_1s','count_0_5_to_2s','median_us','p95_us','p99_us','numeric_quality'):
                        with self.subTest(block=name, field=field):
                            if field == 'numeric_quality':
                                target[field]['cpu_us']['available_count'] += 1
                            else:
                                target[field] += 1
                            for code in (compile(frozen['blocks'][name]['source'], '<baseline>', 'exec'), blocks[name]):
                                with self.assertRaises(AssertionError):
                                    exec(code, env)
                            target.clear()
                            target.update(copy.deepcopy(original))
            finally:
                con.close()


if __name__ == '__main__':
    unittest.main()
