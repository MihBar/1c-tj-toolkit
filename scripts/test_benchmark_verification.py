"""Check that the baseline executes real assertions and deterministic fixtures."""
from pathlib import Path
import json
import copy
import tempfile
import unittest

import benchmark_verification as bench


class BenchmarkTests(unittest.TestCase):
    def test_empty_groups_null_keys_and_duplicate_source_location(self):
        baseline = json.loads((bench.ROOT / 'tools/one_c_tj_analyzer/tests/fixtures/verifier_baseline_blocks.json').read_text(encoding='utf-8'))
        current, _ = bench.extract_blocks()
        with tempfile.TemporaryDirectory(prefix='tj-empty-counts-') as temporary:
            con, env, _ = bench.build(Path(temporary)/'data.sqlite', 96, 'few_large')
            try:
                # Last source becomes genuinely empty. Its CALL has no linked errors.
                empty_call = env['calls'][-1]['event_id']
                con.execute('DELETE FROM numeric_values WHERE event_id=?', (empty_call,))
                con.execute('DELETE FROM call_events WHERE event_id=?', (empty_call,))
                con.execute('DELETE FROM events WHERE event_id=?', (empty_call,))
                env['manifest']['files'][-1]['records'] = 0
                env['manifest']['datasets'][-1].update(records=0, events_without_absolute_timestamp=0)
                env['calls'].append(dict(event_id=None, error_count=0))
                env['manifest']['datasets'].append(dict(dataset_id=None, files_analyzed=0, bytes_analyzed=0,
                    records=0, parse_errors=0, events_without_absolute_timestamp=0))
                env['manifest']['linkage'].append(dict(measurement_id=None, dataset_id=None, error_total_count=0, error_linked_count=0))
                item = copy.deepcopy(env['manifest']['files'][0])
                item.update(source='synthetic/duplicate', status='skipped_duplicate', records=0, parse_errors=0)
                con.execute('INSERT INTO source_locations VALUES (?,?,?,?,?,?,?)',
                    (bench.identity('location/v1', item['source']), item['source_version_id'], 'file', item['source'], None, None, item['source']))
                env['manifest']['files'].append(item)
                env['files'][item['source']] = item
                for name in ('source_counts', 'dataset_sources', 'error_calls', 'error_linkage'):
                    for code in (compile(baseline['blocks'][name]['source'], '<baseline>', 'exec'), current[name]):
                        exec(code, env)
                item['records'] = 1
                for code in (compile(baseline['blocks']['source_counts']['source'], '<baseline>', 'exec'), current['source_counts']):
                    with self.assertRaisesRegex(AssertionError, 'duplicate source counted twice'):
                        exec(code, env)
            finally:
                con.close()

    def test_bulk_counts_match_frozen_baseline_and_have_constant_query_counts(self):
        baseline = json.loads((bench.ROOT / 'tools/one_c_tj_analyzer/tests/fixtures/verifier_baseline_blocks.json').read_text(encoding='utf-8'))
        current, _ = bench.extract_blocks()
        expected_counts = {'source_counts': 2, 'dataset_sources': 1, 'error_calls': 1, 'error_linkage': 1}
        with tempfile.TemporaryDirectory(prefix='tj-count-equivalence-') as temporary:
            for distribution in ('few_large', 'many_small', 'skewed'):
                con, env, _ = bench.build(Path(temporary) / (distribution+'.sqlite'), 96, distribution)
                try:
                    for name, count in expected_counts.items():
                        with self.subTest(distribution=distribution, block=name):
                            old = compile(baseline['blocks'][name]['source'], '<frozen-baseline>', 'exec')
                            outcomes = []
                            for code in (old, current[name]):
                                checks = []
                                def check(condition, message):
                                    checks.append((bool(condition), message))
                                    bench.require(condition, message)
                                recorder = bench.Queries(con)
                                env.update(connection=recorder, require=check)
                                exec(code, env)
                                outcomes.append(checks)
                            self.assertEqual(outcomes[0], outcomes[1])
                            self.assertEqual(recorder.count, count)
                finally:
                    con.close()

    def test_fixture_reproducibility_and_all_block_assertions(self):
        blocks, _ = bench.extract_blocks()
        with tempfile.TemporaryDirectory(prefix="tj-benchmark-test-") as temporary:
            root = Path(temporary)
            con, env, first = bench.build(root / "first.sqlite", 96, "many_small")
            other, _, second = bench.build(root / "second.sqlite", 96, "many_small")
            try:
                self.assertEqual(first, second)
                self.assertGreater(first["event_count"], 0)
                for code in blocks.values():
                    exec(code, env)
                manifest = env["manifest"]
                nested = next(o for o in manifest["operations"] if o["top_nested_sql"])
                targets = {
                    "source_counts": (next(iter(env["files"].values())), "records"),
                    "dataset_sources": (manifest["datasets"][0], "records"),
                    "dataset_stats": (manifest["datasets"][0]["event_stats"]["CALL"], "count"),
                    "heavy_sql": (manifest["heavy_sql"][0], "count"),
                    "locks": (manifest["locks"][0], "count"),
                    "nested_sql": (nested["top_nested_sql"][0], "count"),
                    "error_calls": (env["calls"][0], "error_count"),
                    "error_linkage": (manifest["linkage"][0], "error_total_count"),
                }
                self.assertEqual(set(targets), set(blocks))
                for name, (row, field) in targets.items():
                    with self.subTest(block=name):
                        old = row[field]
                        row[field] = old + 1
                        try:
                            with self.assertRaises(AssertionError):
                                exec(blocks[name], env)
                        finally:
                            row[field] = old
            finally:
                con.close()
                other.close()


if __name__ == "__main__":
    unittest.main()
