#!/usr/bin/env python3
"""Generate GitHub Actions summary from FP evaluation results."""

import json
import sys
from pathlib import Path


def main():
    results_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('results/fp_eval_results.json')
    
    if not results_path.exists():
        print("No results available")
        return
    
    results = json.loads(results_path.read_text())
    summary = results.get('summary', {})
    tp = summary.get('true_positives', {})
    fp = summary.get('expected_false_positives', {})
    tc = summary.get('tool_comparison', {})
    
    accuracy = summary.get('accuracy', 0)
    status = '✅' if accuracy >= 0.8 else '⚠️'
    
    print(f'### {status} Overall Accuracy: {accuracy:.1%}')
    print('')
    print('| Category | Correct | Total | Accuracy |')
    print('|----------|---------|-------|----------|')
    print(f'| True Positives (expect HIGH) | {tp.get("correct", 0)} | {tp.get("total", 0)} | {tp.get("accuracy", 0):.1%} |')
    print(f'| Expected FPs (expect LOW) | {fp.get("correct", 0)} | {fp.get("total", 0)} | {fp.get("accuracy", 0):.1%} |')
    print(f'| **Overall** | {summary.get("correct", 0)} | {summary.get("total_findings", 0) - summary.get("errors", 0)} | {accuracy:.1%} |')
    print('')
    print(f'Errors: {summary.get("errors", 0)}')
    print('')
    print('### Tool Comparison - Detection Rates')
    print('')
    print('| Tool | Detected | Total | Rate |')
    print('|------|----------|-------|------|')
    
    dd = tc.get('datadog_iac_scanner', {})
    total_cases = tc.get('total_test_cases', 0)
    print(f'| **datadog-iac-scanner** | {dd.get("detected", 0)} | {total_cases} | {dd.get("detection_rate", 0):.1%} |')
    
    tools = ['checkov', 'cloudrail', 'kics', 'snyk', 'terrascan', 'tfsec']
    sorted_tools = sorted(tools, key=lambda t: tc.get(t, {}).get('detection_rate', 0), reverse=True)
    for tool in sorted_tools:
        t = tc.get(tool, {})
        print(f'| {tool} | {t.get("detected", 0)} | {t.get("total", 0)} | {t.get("detection_rate", 0):.1%} |')


if __name__ == '__main__':
    main()
