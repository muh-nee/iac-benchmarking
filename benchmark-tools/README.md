# IAC False Positive Benchmark

This benchmark evaluates the accuracy of Datadog's IAC false positive filtering by running the `datadog-iac-scanner` against known security issues and measuring how well the LLM-based filtering correctly identifies true positives vs false positives.

## Overview

The benchmark:
1. Scans Terraform test cases with `datadog-iac-scanner`
2. Sends each finding to the FP evaluation API
3. Compares API confidence (HIGH/LOW) against expected outcomes
4. Reports accuracy metrics and compares detection rates across tools

### Evaluation Logic

Each test case represents a **known security issue**. Findings are categorized as:

- **True Positives**: Real security issues the model should flag as HIGH confidence
- **Expected False Positives**: Incidental findings (e.g., missing tags) the model should flag as LOW confidence

| Finding Type | Expected Confidence | Correct When |
|--------------|---------------------|--------------|
| True Positive | HIGH | API returns HIGH |
| Expected FP | LOW | API returns LOW |

### False Positive Assignment Logic

Each test case directory contains a `results_summary.json` file that defines which findings should be treated as **expected false positives**. These are findings that are technically valid but incidental to the security issue being tested.

**Expected false positives include:**
- **Missing tags**: `"'tags' block is missing"`, `"tags is undefined or null"`, `"Missing tags: {\"team\"}"`
- **Shield/WAF associations**: `"does not have shield advanced associated"`
- **Informational findings**: Findings about optional best practices unrelated to the test case's core security issue

**NOT expected false positives (real issues):**
- `publicly_accessible` settings
- `public_network_access_enabled` settings  
- Wildcard IAM permissions (`"*"` in actions or resources)
- The primary security issue the test case was designed to catch

**Example `results_summary.json`:**
```json
{
  "checkov": "yes",
  "kics": "yes",
  "snyk": "no",
  "expected_false_positives": [
    "Ensure that Azure cloud resource has a team tag",
    "'tags' block is missing",
    "does not have shield advanced associated"
  ]
}
```

When the benchmark runs, it matches each finding's message against these patterns. If a match is found, the finding is marked as `expected_fp=True`, and the evaluation expects the API to return LOW confidence (indicating the model correctly identified it as a false positive).

## Prerequisites

- Python 3.10+
- Go 1.21+ (for building the scanner)
- Datadog API keys with `CodeAnalysisRead` permission

## Running Locally

### 1. Build the scanner

```bash
cd /path/to/kics
make build
export SCANNER=$(pwd)/bin/datadog-iac-scanner
```

### 2. Run the scanner on test cases

```bash
cd /path/to/iac-benchmarking/benchmark-tools
./run_scanner.sh $SCANNER
```

To limit the number of test cases:

```bash
./run_scanner.sh $SCANNER --limit 10
```

Or run manually on a specific directory:

```bash
$SCANNER scan \
  --path ../test-cases/terraform/aws/encryption \
  --output-path /tmp \
  --output-name datadog-iac-result.sarif \
  --type terraform
```

> **Note**: The `--type terraform` flag ensures only Terraform files are scanned.

### 3. Run the evaluation

```bash
# Set API keys (must have CodeAnalysisRead permission)
export DD_API_KEY='your-api-key'
export DD_APP_KEY='your-app-key'

# Install dependencies
pip install requests datadog-api-client

# Run evaluation
python fp_eval.py
```

### Command-line options

```bash
python fp_eval.py --help

Options:
  --test-cases-dir DIR   Directory containing test cases (default: ../test-cases/terraform)
  --output FILE          Output file for results (default: ../results/fp_eval_results.json)
  --workers N            Number of concurrent API workers (default: 3)
  --limit N              Limit number of test cases (0 = all)
```

### Quick test with limited cases

```bash
python fp_eval.py --limit 10 --workers 3
```

## Running in CI

The benchmark runs as a GitHub Actions workflow in the [DataDog/kics](https://github.com/DataDog/kics) repository. It clones the [muh-nee/iac-benchmarking](https://github.com/muh-nee/iac-benchmarking) repo for test cases.

### Workflow location

```
.github/workflows/fp-benchmark.yml
```

### Triggering the workflow

The workflow is configured as `workflow_dispatch`, meaning it's manually triggered:

1. Go to **Actions** → **False Positive Benchmark**
2. Click **Run workflow**
3. Configure inputs:
   - `test_case_limit`: Limit test cases (0 = all)
   - `workers`: Concurrent API workers (default: 3)

### Required secrets

The workflow requires these repository secrets:

| Secret | Description |
|--------|-------------|
| `DD_API_KEY` | Datadog API key with `CodeAnalysisRead` permission |
| `DD_APP_KEY` | Datadog Application key |

### Workflow outputs

- **GitHub Summary**: Accuracy tables and tool comparison
- **Artifacts**: Full JSON results (`fp-benchmark-results`)
- **Datadog Metrics**: Submitted to Datadog for dashboarding

### Metrics submitted

| Metric | Description |
|--------|-------------|
| `iac.fp_eval.accuracy` | Overall accuracy (%) |
| `iac.fp_eval.tp_accuracy` | True positive accuracy (%) |
| `iac.fp_eval.fp_accuracy` | Expected FP accuracy (%) |
| `iac.fp_eval.total_findings` | Total findings evaluated |
| `iac.fp_eval.detection_rate.datadog_iac_scanner` | Our detection rate (%) |
| `iac.fp_eval.detection_rate.{tool}` | Other tools' detection rates |
| `iac.fp_eval.without_filter.precision` | Precision without FP filtering (%) |
| `iac.fp_eval.with_filter.precision` | Precision with FP filtering (%) |
| `iac.fp_eval.with_filter.recall` | Recall with FP filtering (%) |
| `iac.fp_eval.filter.fps_filtered` | Number of FPs filtered out |
| `iac.fp_eval.filter.precision_improvement` | Precision improvement from filtering (%) |

## Understanding the results

### Sample output

```
============================================================
EVALUATION SUMMARY
============================================================
Total findings evaluated: 450
Errors: 5

TRUE POSITIVES (expect HIGH):
  Total: 320, Correct: 295, Accuracy: 92.2%

EXPECTED FALSE POSITIVES (expect LOW):
  Total: 125, Correct: 110, Accuracy: 88.0%

OVERALL ACCURACY: 90.8%
============================================================

================================================================================
DATADOG IAC SCANNER - FP FILTERING COMPARISON
================================================================================
Configuration             Findings   TPs     FPs     Precision    Recall    
--------------------------------------------------------------------------------
Without FP Filtering      450        320     130     71.1%        100%      
With FP Filtering         320        295     25      92.2%        92.2%     
--------------------------------------------------------------------------------
Impact: 105 FPs filtered (80.8%), findings reduced by 28.9%, precision +21.1%
================================================================================

==========================================================================================
TOOL COMPARISON
==========================================================================================
Tool                                Detected   Total    Det Rate   Findings   Precision 
------------------------------------------------------------------------------------------
datadog-iac-scanner (no filtering)  145        171      84.8%      450        71.1%     
datadog-iac-scanner (with filtering)145        171      84.8%      320        92.2%     
------------------------------------------------------------------------------------------
cloudrail                           123        171      71.9%      -          -         
kics                                108        171      63.2%      -          -         
checkov                             102        171      59.6%      -          -         
snyk                                80         171      46.8%      -          -         
terrascan                           79         171      46.2%      -          -         
tfsec                               73         171      42.7%      -          -         
==========================================================================================
```

### Result JSON structure

```json
{
  "summary": {
    "total_findings": 450,
    "errors": 5,
    "correct": 405,
    "accuracy": 0.908,
    "true_positives": {
      "total": 320,
      "correct": 295,
      "accuracy": 0.922
    },
    "expected_false_positives": {
      "total": 125,
      "correct": 110,
      "accuracy": 0.880
    },
    "tool_comparison": {
      "total_test_cases": 171,
      "datadog_iac_scanner": {
        "detected": 145,
        "detection_rate": 0.848
      },
      "checkov": { "detected": 120, "total": 171, "detection_rate": 0.702 }
    },
    "filtering_comparison": {
      "without_filtering": {
        "total_findings": 450,
        "true_positives": 320,
        "false_positives": 130,
        "precision": 0.711
      },
      "with_filtering": {
        "total_findings": 320,
        "true_positives": 295,
        "false_positives": 25,
        "precision": 0.922,
        "recall": 0.922
      },
      "improvement": {
        "findings_reduced": 130,
        "findings_reduction_pct": 0.289,
        "fps_filtered": 105,
        "fps_filter_rate": 0.808,
        "precision_improvement": 0.211
      }
    }
  },
  "results": [
    {
      "rule_id": "aws-s3-bucket-encryption",
      "test_case": "s3_bucket_non_encrypted",
      "message": "S3 bucket encryption is not enabled",
      "confidence": "HIGH",
      "reason": "The S3 bucket lacks encryption...",
      "is_correct": true,
      "expected_fp": false
    }
  ]
}
```

## Updating expected false positives

Some findings are incidental to the test case (e.g., missing tags on resources). These are marked as "expected false positives" in `results_summary.json`:

```json
{
  "checkov": "yes",
  "cloudrail": "yes",
  "kics": "yes",
  "snyk": "yes",
  "terrascan": "yes",
  "tfsec": "yes",
  "expected_false_positives": [
    "Ensure that Azure cloud resource has a team tag",
    "'tags' block is missing"
  ]
}
```

To bulk-update expected FPs based on evaluation results:

```bash
python update_expected_fps.py
```

This reads `fp_eval_results.json` and updates `results_summary.json` files for findings with LOW confidence, excluding actual security issues like:
- `publicly_accessible` settings
- `public_network_access_enabled`
- Wildcard IAM permissions

## Files

| File | Description |
|------|-------------|
| `fp_eval.py` | Main evaluation script |
| `run_scanner.sh` | Helper to run scanner on all test cases |
| `update_expected_fps.py` | Bulk update expected FPs from results |
| `generate_summary.py` | Generate GitHub Actions summary |
| `check_threshold.py` | Check accuracy meets threshold |
| `submit_metrics.py` | Submit metrics to Datadog |
| `requirements.txt` | Python dependencies |
| `../results/fp_eval_results.json` | Evaluation results output |
| `../test-cases/terraform/` | Test case directories |

## Troubleshooting

### "No files were scanned"

Make sure to include the `--type` flag:

```bash
$SCANNER scan --path <path> --type terraform --output-path <output> --output-name result.sarif
```

### 403 Forbidden from API

Your API keys need `CodeAnalysisRead` permission. Check with your team for keys with the correct scope.

### Rate limiting

The script has built-in retry logic with backoff. Reduce workers if you hit rate limits:

```bash
python fp_eval.py --workers 1
```
