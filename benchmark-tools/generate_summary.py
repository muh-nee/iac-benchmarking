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
    fc = summary.get('filtering_comparison', {})
    
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
    
    # FP Filtering Comparison
    if fc:
        wof = fc.get('without_filtering', {})
        wf = fc.get('with_filtering', {})
        imp = fc.get('improvement', {})
        
        print('### Datadog IAC Scanner - FP Filtering Comparison')
        print('')
        print('| Configuration | Findings | True Positives | False Positives | Precision | Recall |')
        print('|---------------|----------|----------------|-----------------|-----------|--------|')
        print(f'| **Without FP Filtering** | {wof.get("total_findings", 0)} | {wof.get("true_positives", 0)} | {wof.get("false_positives", 0)} | {wof.get("precision", 0):.1%} | 100% |')
        print(f'| **With FP Filtering** | {wf.get("total_findings", 0)} | {wf.get("true_positives", 0)} | {wf.get("false_positives", 0)} | {wf.get("precision", 0):.1%} | {wf.get("recall", 0):.1%} |')
        print('')
        print(f'**Impact:** {imp.get("fps_filtered", 0)} FPs filtered ({imp.get("fps_filter_rate", 0):.1%}), '
              f'findings reduced by {imp.get("findings_reduction_pct", 0):.1%}, '
              f'precision +{imp.get("precision_improvement", 0):.1%}')
        print('')
    
    print('### Tool Comparison')
    print('')
    print('| Tool | Detected | Total | Det Rate | Findings | Precision |')
    print('|------|----------|-------|----------|----------|-----------|')
    
    dd = tc.get('datadog_iac_scanner', {})
    total_cases = tc.get('total_test_cases', 0)
    wof = fc.get('without_filtering', {}) if fc else {}
    wf = fc.get('with_filtering', {}) if fc else {}
    
    # datadog-iac-scanner without filtering
    print(f'| **datadog-iac-scanner (no filtering)** | {dd.get("detected", 0)} | {total_cases} | {dd.get("detection_rate", 0):.1%} | {wof.get("total_findings", "-")} | {wof.get("precision", 0):.1%} |')
    
    # datadog-iac-scanner with filtering
    print(f'| **datadog-iac-scanner (with filtering)** | {dd.get("detected", 0)} | {total_cases} | {dd.get("detection_rate", 0):.1%} | {wf.get("total_findings", "-")} | {wf.get("precision", 0):.1%} |')
    
    tools = ['checkov', 'cloudrail', 'kics', 'snyk', 'terrascan', 'tfsec']
    sorted_tools = sorted(tools, key=lambda t: tc.get(t, {}).get('detection_rate', 0), reverse=True)
    for tool in sorted_tools:
        t = tc.get(tool, {})
        print(f'| {tool} | {t.get("detected", 0)} | {t.get("total", 0)} | {t.get("detection_rate", 0):.1%} | - | - |')


if __name__ == '__main__':
    main()
