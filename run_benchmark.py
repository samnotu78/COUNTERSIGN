import sys
sys.path.insert(0, '.')
from countersign_crypto.benchmark import run_benchmark
from countersign_crypto.errors import VerificationResult, ErrorCode
result = run_benchmark(sample_size=20)
print(result.summary())
print()
print(f'FALSE_VERIFIED_COUNT (DYNAMICALLY CALCULATED): {result.false_verified_count}')
print(f'Total cases: {result.dataset_size}')
print()
print('Verdict distribution:')
for v in ['VERIFIED', 'CONTRADICTS_POLICY', 'UNVERIFIABLE']:
    print(f'  {v}: {result.verdict_counts.get(v, 0)}')
print()
print('Category counts:')
for cat, count in sorted(result.category_counts.items()):
    print(f'  {cat}: {count}')
print()
# Detailed results
for r in result.results:
    false_marker = ' *** FALSE_VerIFIED ***' if r['is_false_verified'] else ''
    print(f'  [{r["index"]:3d}] {r["description"]:30s} mut={r["mutation_category"]:15s} expected={r["expected_verdict"]:15s} actual={r["actual_verdict"]:15s}{false_marker}')