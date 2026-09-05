# Verification benchmarks

The verifier batches simple counts and streams additive dataset, SQL and lock
statistics. Exact medians/percentiles retain the original per-group count/distinct
and ordered-duration queries. Python integer sums and numeric-quality rules are
unchanged; no full event cache is introduced.

The frozen reference blocks are in
`tools/one_c_tj_analyzer/tests/fixtures/verifier_baseline_blocks.json`, from
revision `9ed05c88dd52c4ebb9739f46f1370c9ca86563db`.
Run from the repository root with Python 3.10+:

```powershell
python -B -m unittest discover -s tools/one_c_tj_analyzer/tests -v
python -B -m unittest discover -s scripts -p "test_*verification.py" -v
python -B scripts/benchmark_verification.py --output tmp/counts --reference-counts tools/one_c_tj_analyzer/tests/fixtures/verifier_baseline_blocks.json --repeats 5
python -B scripts/benchmark_verification.py --output tmp/additive --reference-additive tools/one_c_tj_analyzer/tests/fixtures/verifier_baseline_blocks.json --repeats 5
python -B scripts/final_verifier_audit.py --output tmp/full-audit
```

Output directories must be new. Benchmarks use disposable synthetic data, never a
running analyzer's bundle. The block benchmark defaults to 240/720 observations
per auxiliary event type, three group distributions, and a 60-second cooperative
budget. Full audit reads the actual baseline modules from Git, needs that revision
available locally, and runs isolated workers with a 30-second timeout each.
The Windows workers lower their own scheduling priority.

## Validation and limits

The final audit passed 329 analyzer tests and six benchmark tests. Correct full
results matched recursively including types; all 12 additional corruptions were
rejected. For simultaneous wrong SQL median and maximum, the first diagnostic
changed from median_us to max_us because additive fields are compared first.
Input hashes remained unchanged in all 42 full-verifier workers, with no source
log opening or input-write attempts.

On small synthetic full bundles (293/313 events), median milliseconds changed
from 150 to 161 for few groups, 199 to 196 for many groups, and 208 to 192 for skew.
SQL statements changed from 1509 to 1471 and from 2110 to 1852. Live worker peak
working sets were about 29–33 MiB, including Python/imports; memory reduction is
not established. Environment: Windows, Python 3.12.14, SQLite 3.53.1.

Repeated block measurements with 2209 events showed fewer queries and lower SQL/
lock times for many groups, but slower dataset statistics and overhead for few
groups. These results are not a universal speedup claim or a large production
benchmark. Remaining costs include exact order statistics, per-event numeric
lookups, repeated DB exports, nested SQL and error-group queries. Independent
integrity/evidence checks are intentionally retained.

Raw timing reports and machine-specific test logs are local artifacts rather than
versioned fixtures. Each benchmark saves parameters, source hashes, timings and
query plans so measurements can be reproduced on the target environment.
