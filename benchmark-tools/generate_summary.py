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
    
    # Introduction
    print('## About This Report')
    print('')
    print('This benchmark evaluates the accuracy of Datadog\'s **IAC False Positive Filtering** feature.')
    print('The scanner is run against 171 Terraform test cases containing known security misconfigurations.')
    print('Each finding is sent to the FP evaluation API, which returns a confidence level:')
    print('')
    print('- **HIGH confidence**: The LLM believes this is a real security issue (not a false positive)')
    print('- **LOW confidence**: The LLM believes this is likely a false positive and should be filtered out')
    print('')
    print('---')
    print('')
    
    # LLM Accuracy Section
    print('## LLM False Positive Detection Accuracy')
    print('')
    print(f'### {status} Overall Accuracy: {accuracy:.1%}')
    print('')
    print('This table shows how accurately the LLM identifies true security issues vs incidental findings.')
    print('')
    print('| Category | Description | Correct | Total | Accuracy |')
    print('|----------|-------------|---------|-------|----------|')
    print(f'| **True Positives** | Real security issues - LLM should return HIGH | {tp.get("correct", 0)} | {tp.get("total", 0)} | {tp.get("accuracy", 0):.1%} |')
    print(f'| **Expected False Positives** | Incidental findings (e.g., missing tags) - LLM should return LOW | {fp.get("correct", 0)} | {fp.get("total", 0)} | {fp.get("accuracy", 0):.1%} |')
    print(f'| **Overall** | Combined accuracy | {summary.get("correct", 0)} | {summary.get("total_findings", 0) - summary.get("errors", 0)} | {accuracy:.1%} |')
    print('')
    
    errors = summary.get("errors", 0)
    if errors > 0:
        print(f'> ⚠️ **Errors: {errors}** - These are findings where the FP evaluation API call failed ')
        print('> (e.g., timeout, rate limiting, or API errors). These are excluded from accuracy calculations.')
    print('')
    print('---')
    print('')
    
    # FP Filtering Comparison
    if fc:
        wof = fc.get('without_filtering', {})
        wf = fc.get('with_filtering', {})
        imp = fc.get('improvement', {})
        
        print('## Value of FP Filtering')
        print('')
        print('This table compares scanner output **with** and **without** the FP filtering feature enabled.')
        print('With filtering, only HIGH confidence findings are reported to users.')
        print('')
        print('| Configuration | Description | Findings | True Positives | False Positives | Precision | Recall |')
        print('|---------------|-------------|----------|----------------|-----------------|-----------|--------|')
        print(f'| **Without FP Filtering** | All scanner findings reported | {wof.get("total_findings", 0)} | {wof.get("true_positives", 0)} | {wof.get("false_positives", 0)} | {wof.get("precision", 0):.1%} | 100% |')
        print(f'| **With FP Filtering** | Only HIGH confidence findings reported | {wf.get("total_findings", 0)} | {wf.get("true_positives", 0)} | {wf.get("false_positives", 0)} | {wf.get("precision", 0):.1%} | {wf.get("recall", 0):.1%} |')
        print('')
        print('**Key Metrics:**')
        print(f'- **Precision** = True Positives / Total Findings (higher is better)')
        print(f'- **Recall** = True Positives retained / All True Positives (100% means no real issues filtered out)')
        print('')
        print(f'**Impact of FP Filtering:**')
        print(f'- 🗑️ **{imp.get("fps_filtered", 0)} false positives filtered** ({imp.get("fps_filter_rate", 0):.1%} of noise removed)')
        print(f'- 📉 **Findings reduced by {imp.get("findings_reduction_pct", 0):.1%}** (less noise for users)')
        print(f'- 📈 **Precision improved by +{imp.get("precision_improvement", 0):.1%}** (more signal, less noise)')
        print('')
        print('---')
        print('')
    
    # Tool Comparison
    print('## Tool Comparison - Detection Rates')
    print('')
    print('This table compares `datadog-iac-scanner` detection rates against other IAC security tools.')
    print('Detection rate = % of test cases where the tool found at least one relevant finding.')
    print('')
    print('> **Note**: Other tools\' detection data comes from the original [iacsecurity/tool-compare](https://github.com/iacsecurity/tool-compare)')
    print('> benchmark. Findings and Precision are only available for `datadog-iac-scanner`.')
    print('')
    print('| Tool | Detected | Total | Detection Rate | Findings | Precision |')
    print('|------|----------|-------|----------------|----------|-----------|')
    
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
    
    print('')
    print('---')
    print('')
    print('## Glossary')
    print('')
    print('| Term | Definition |')
    print('|------|------------|')
    print('| **HIGH confidence** | LLM believes this is a real security issue |')
    print('| **LOW confidence** | LLM believes this is a false positive (noise) |')
    print('| **True Positive** | A real security issue that should be reported |')
    print('| **False Positive** | An incidental finding (e.g., missing tags) that adds noise |')
    print('| **Precision** | % of reported findings that are actual issues |')
    print('| **Recall** | % of actual issues that are reported |')
    print('| **Detection Rate** | % of test cases where the tool found the issue |')
    print('| **Error** | FP evaluation API call failed (timeout, rate limit, etc.) |')


if __name__ == '__main__':
    main()
