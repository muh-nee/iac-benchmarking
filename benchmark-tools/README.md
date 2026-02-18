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

============================================================
TOOL COMPARISON - DETECTION RATES
============================================================
Tool                      Detected   Total      Rate
-------------------------------------------------------
datadog-iac-scanner       145        171        84.8%
checkov                   120        171        70.2%
kics                      115        171        67.3%
snyk                      98         171        57.3%
tfsec                     95         171        55.6%
terrascan                 85         171        49.7%
cloudrail                 72         171        42.1%
============================================================
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
