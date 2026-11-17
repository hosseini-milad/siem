"""Run from repository root: python -m scripts.benchmark_ml --help."""
import argparse
import json
import platform
from pathlib import Path
from time import perf_counter
from urllib.request import Request, urlopen

import numpy as np

from app.services.machine_learning import ModelManager, feature_matrix, prepare_raw, train


def summarize(samples):
    return {'p50_ms': float(np.percentile(samples, 50)),
            'p95_ms': float(np.percentile(samples, 95)), 'max_ms': max(samples),
            'eps_at_p95': 10000000 / float(np.percentile(samples, 95))}


def main():
    parser = argparse.ArgumentParser(description='10000-row latency benchmark; synthetic results are not a production SLA')
    parser.add_argument('--model-dir', required=True)
    parser.add_argument('--raw-json', required=True, help='JSON array of exactly 10000 unlabelled original rows')
    parser.add_argument('--synthetic', action='store_true', help='Create a synthetic 150-tree model in a NEW model directory and raw JSON file')
    parser.add_argument('--url', help='Running API base URL for actual HTTP tests, e.g. http://127.0.0.1:8000')
    parser.add_argument('--threads', type=int, default=2)
    parser.add_argument('--repeats', type=int, default=20)
    parser.add_argument('--output')
    args = parser.parse_args()
    if args.repeats < 5:
        parser.error('Use at least five repeats')
    if args.synthetic:
        if Path(args.model_dir).exists() or Path(args.raw_json).exists():
            parser.error('Synthetic mode requires new paths; it never overwrites an existing model or input')
        blocks = [[{'_id': f'{b}-{i}', 'Label': 'attack' if i % 2 else 'benign',
                    'signal': str(i % 2), 'Timestamp': str(b * 10000 + i),
                    'Src IP': f'10.0.0.{i % 100}', 'Dst IP': f'10.1.0.{i % 50}',
                    'Dst Port': str(i % 20),
                    **{f'n{j}': str(((i * (j + 3)) % 997) / 997) for j in range(60)}}
                   for i in range(10000)] for b in range(5)]
        manager = ModelManager(args.model_dir, args.threads)
        artifact = train(blocks, args.threads)
        artifact['benchmark_synthetic'] = True
        manager.publish(artifact)
        raw = [{k: v for k, v in row.items() if k != 'Label'} for row in blocks[-1]]
        Path(args.raw_json).write_text(json.dumps(raw))
        del blocks
    else:
        manager = ModelManager(args.model_dir, args.threads)
        raw = json.loads(Path(args.raw_json).read_text())
    if len(raw) != 10000:
        parser.error('Exactly 10000 raw rows are required')
    predictor = manager.require()
    prepared, _ = prepare_raw(raw, predictor.artifact['normalization_schema'], predictor.artifact['behavior_bounds'])
    matrix = feature_matrix(prepared, predictor.names)
    report = {'synthetic': bool(args.synthetic or predictor.artifact.get('benchmark_synthetic')), 'threads': args.threads, 'features': len(predictor.names),
              'trees': predictor.booster.num_trees(), 'platform': platform.platform(),
              'model_version': predictor.version, 'batch_size': 10000, 'repeats': args.repeats}
    operations = {'raw_service': lambda: predictor.predict(records=raw, raw=True),
                  'matrix_service': lambda: predictor.predict(matrix=matrix),
                  'native_inference': lambda: predictor.probabilities(matrix)}
    if args.url:
        def http_call(endpoint, body):
            encoded = json.dumps(body).encode()
            def call():
                request = Request(args.url.rstrip('/') + '/api/v1/ml/' + endpoint,
                                  data=encoded, headers={'Content-Type': 'application/json'})
                with urlopen(request, timeout=60) as response:
                    result = json.load(response)
                assert result['count'] == 10000 and result['model_version'] == predictor.version
                return result
            return call
        operations['raw_http_no_persistence'] = http_call('predict', {
            'model_version': predictor.version, 'records': raw})
        operations['raw_http_with_mongodb_write'] = http_call('predict', {
            'model_version': predictor.version, 'records': raw, 'persist': True})
        operations['matrix_http'] = http_call('predict-matrix', {
            'model_version': predictor.version, 'matrix': matrix.tolist()})
    for name, operation in operations.items():
        for _ in range(3):
            operation()
        samples = []
        for _ in range(args.repeats):
            started = perf_counter()
            operation()
            samples.append((perf_counter() - started) * 1000)
        report[name] = summarize(samples)
        print(name, report[name], flush=True)
    output = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(output + '\n')
    print(output)


if __name__ == '__main__':
    main()
