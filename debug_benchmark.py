from countersign_crypto.benchmark import run_benchmark
result = run_benchmark(sample_size=22)

print('=' * 70)
print('DETAILED PER-CASE RESULTS')
print('=' * 70)
for r in result.results:
    false_marker = ' *** FALSE_VerIFIED ***' if r['is_false_verified'] else ''
    print(
        f'  [{r["index"]:2d}] {r["description"]:30s} '
        f'mut={r["mutation_category"]:15s} '
        f'expected={r["expected_verdict"]:15s} '
        f'actual={r["actual_verdict"]:15s} '
        f'{false_marker}'
    )

print()
print('Category counts:')
for cat, count in sorted(result.category_counts.items()):
    print(f'  {cat}: {count}')

print()
print('Verdict distribution:')
for v in ['VERIFIED', 'CONTRADICTS_POLICY', 'UNVERIFIABLE']:
    print(f'  {v}: {result.verdict_counts.get(v, 0)}')

print()
print(f'FALSE_VERIFIED_COUNT: {result.false_verified_count}')
print(f'Total cases: {result.dataset_size}')