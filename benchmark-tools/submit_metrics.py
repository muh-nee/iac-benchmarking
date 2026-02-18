#!/usr/bin/env python3
"""Submit FP evaluation metrics to Datadog."""

import json
import os
import sys
from datetime import datetime, UTC
from pathlib import Path

from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v2.api.metrics_api import MetricsApi
from datadog_api_client.v2.model.metric_intake_type import MetricIntakeType
from datadog_api_client.v2.model.metric_payload import MetricPayload
from datadog_api_client.v2.model.metric_point import MetricPoint
from datadog_api_client.v2.model.metric_series import MetricSeries


BENCHMARK_TOOLS = ['checkov', 'cloudrail', 'kics', 'snyk', 'terrascan', 'tfsec']


def main():
    results_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('results/fp_eval_results.json')
    
    if not results_path.exists():
        print(f"Results file not found: {results_path}")
        sys.exit(1)
    
    results = json.loads(results_path.read_text())
    summary = results.get('summary', {})
    tp = summary.get('true_positives', {})
    fp = summary.get('expected_false_positives', {})
    tc = summary.get('tool_comparison', {})
    fc = summary.get('filtering_comparison', {})
    
    configuration = Configuration()
    configuration.api_key['apiKeyAuth'] = os.environ['DD_API_KEY']
    configuration.api_key['appKeyAuth'] = os.environ['DD_APP_KEY']
    
    timestamp = int(datetime.now(UTC).timestamp())
    
    metrics = [
        ('iac.fp_eval.total_findings', summary.get('total_findings', 0)),
        ('iac.fp_eval.correct', summary.get('correct', 0)),
        ('iac.fp_eval.errors', summary.get('errors', 0)),
        ('iac.fp_eval.accuracy', summary.get('accuracy', 0) * 100),
        ('iac.fp_eval.tp_total', tp.get('total', 0)),
        ('iac.fp_eval.tp_correct', tp.get('correct', 0)),
        ('iac.fp_eval.tp_accuracy', tp.get('accuracy', 0) * 100),
        ('iac.fp_eval.fp_total', fp.get('total', 0)),
        ('iac.fp_eval.fp_correct', fp.get('correct', 0)),
        ('iac.fp_eval.fp_accuracy', fp.get('accuracy', 0) * 100),
        ('iac.fp_eval.total_test_cases', tc.get('total_test_cases', 0)),
        ('iac.fp_eval.detection_rate.datadog_iac_scanner', tc.get('datadog_iac_scanner', {}).get('detection_rate', 0) * 100),
    ]
    
    # Add detection rates for each benchmark tool
    for tool in BENCHMARK_TOOLS:
        tool_data = tc.get(tool, {})
        metrics.append((f'iac.fp_eval.detection_rate.{tool}', tool_data.get('detection_rate', 0) * 100))
    
    # Add filtering comparison metrics
    if fc:
        wof = fc.get('without_filtering', {})
        wf = fc.get('with_filtering', {})
        imp = fc.get('improvement', {})
        
        metrics.extend([
            ('iac.fp_eval.without_filter.total', wof.get('total_findings', 0)),
            ('iac.fp_eval.without_filter.precision', wof.get('precision', 0) * 100),
            ('iac.fp_eval.with_filter.total', wf.get('total_findings', 0)),
            ('iac.fp_eval.with_filter.precision', wf.get('precision', 0) * 100),
            ('iac.fp_eval.with_filter.recall', wf.get('recall', 0) * 100),
            ('iac.fp_eval.filter.fps_filtered', imp.get('fps_filtered', 0)),
            ('iac.fp_eval.filter.reduction_pct', imp.get('findings_reduction_pct', 0) * 100),
            ('iac.fp_eval.filter.precision_improvement', imp.get('precision_improvement', 0) * 100),
        ])
    
    with ApiClient(configuration) as api_client:
        api = MetricsApi(api_client)
        for name, value in metrics:
            series = MetricSeries(
                metric=name,
                type=MetricIntakeType.GAUGE,
                points=[MetricPoint(timestamp=timestamp, value=value)],
                tags=['dataset:terraform', 'tool:datadog-iac-scanner'],
            )
            api.submit_metrics(body=MetricPayload(series=[series]))
            print(f'Submitted {name}: {value}')
    
    print('Metrics submitted successfully!')


if __name__ == '__main__':
    main()
