#!/usr/bin/env python3
"""
Submit IAC FP evaluation metrics to Datadog.

Usage:
    python submit_metrics.py fp_eval_results.json
"""

import argparse
import json
import os
import sys
from datetime import datetime, UTC
from pathlib import Path

try:
    from datadog_api_client import ApiClient, Configuration
    from datadog_api_client.v2.api.metrics_api import MetricsApi
    from datadog_api_client.v2.model.metric_intake_type import MetricIntakeType
    from datadog_api_client.v2.model.metric_payload import MetricPayload
    from datadog_api_client.v2.model.metric_point import MetricPoint
    from datadog_api_client.v2.model.metric_series import MetricSeries
except ImportError:
    print("Error: datadog-api-client not installed. Run: pip install datadog-api-client")
    sys.exit(1)


def submit_metrics(results_file: Path, dataset_tag: str = "terraform"):
    """Submit metrics to Datadog."""
    
    api_key = os.getenv("DD_API_KEY")
    app_key = os.getenv("DD_APP_KEY")

    if not api_key or not app_key:
        print("Error: DD_API_KEY and DD_APP_KEY must be set")
        sys.exit(1)

    # Load results
    results = json.loads(results_file.read_text())
    summary = results.get("summary", {})

    configuration = Configuration()
    configuration.api_key["apiKeyAuth"] = api_key
    configuration.api_key["appKeyAuth"] = app_key

    timestamp = int(datetime.now(UTC).timestamp())

    metrics_to_submit = [
        ("iac.fp_eval.total_findings", summary.get("total_findings", 0)),
        ("iac.fp_eval.high_confidence", summary.get("high_confidence", 0)),
        ("iac.fp_eval.low_confidence", summary.get("low_confidence", 0)),
        ("iac.fp_eval.errors", summary.get("errors", 0)),
        ("iac.fp_eval.accuracy", summary.get("accuracy", 0) * 100),  # As percentage
    ]

    with ApiClient(configuration) as api_client:
        metrics_api = MetricsApi(api_client)

        for metric_name, value in metrics_to_submit:
            series = MetricSeries(
                metric=metric_name,
                type=MetricIntakeType.GAUGE,
                points=[MetricPoint(timestamp=timestamp, value=value)],
                tags=[f"dataset:{dataset_tag}", "tool:iac_scanning"],
            )
            
            try:
                metrics_api.submit_metrics(body=MetricPayload(series=[series]))
                print(f"Submitted {metric_name}: {value}")
            except Exception as e:
                print(f"Error submitting {metric_name}: {e}")

    print("\nMetrics submitted successfully!")


def main():
    parser = argparse.ArgumentParser(description="Submit IAC FP eval metrics to Datadog")
    parser.add_argument("results_file", type=Path, help="Path to evaluation results JSON")
    parser.add_argument("--dataset", default="terraform", help="Dataset tag")

    args = parser.parse_args()

    if not args.results_file.exists():
        print(f"Error: Results file not found: {args.results_file}")
        sys.exit(1)

    submit_metrics(args.results_file, args.dataset)


if __name__ == "__main__":
    main()
