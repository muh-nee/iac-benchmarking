# Datadog IAC False Positive Filtering Benchmark

This repository benchmarks the accuracy of Datadog's **IAC false positive filtering** feature. It measures how well the LLM-based filtering correctly identifies true security issues vs incidental findings that should be filtered out.

> **Note**: This repository is forked from [iacsecurity/tool-compare](https://github.com/iacsecurity/tool-compare), which provides Terraform test cases with known security misconfigurations. We've extended it with tooling to evaluate Datadog's false positive filtering API.

## Purpose

The benchmark answers two key questions:

1. **Detection Rate**: Does `datadog-iac-scanner` detect security issues as well as or better than other IAC tools?
2. **FP Filtering Accuracy**: Does the LLM-based filtering correctly distinguish real issues from noise?

### What We Measure

| Metric | Description |
|--------|-------------|
| **Detection Rate** | % of test cases where the scanner found at least one finding |
| **Precision (without filtering)** | % of raw findings that are actual security issues |
| **Precision (with filtering)** | % of HIGH confidence findings that are actual issues |
| **Recall** | % of real issues retained after filtering |
| **FP Filter Rate** | % of incidental findings correctly filtered out |

## How It Works

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Test Cases     │───▶│ datadog-iac-     │───▶│  SARIF Results  │
│  (Terraform)    │    │ scanner          │    │                 │
└─────────────────┘    └──────────────────┘    └────────┬────────┘
                                                        │
                                                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Accuracy       │◀───│  FP Evaluation   │◀───│  Each Finding   │
│  Report         │    │  API             │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

1. **Scan**: Run `datadog-iac-scanner` on 171 Terraform test cases
2. **Evaluate**: Send each HIGH/MEDIUM finding to the FP evaluation API
3. **Compare**: Check if API confidence (HIGH/LOW) matches expected outcome
4. **Report**: Generate accuracy metrics and tool comparisons

## Test Case Structure

Each test case in `test-cases/terraform/` represents a **known security misconfiguration**:

```
test-cases/terraform/aws/encryption/at-rest/s3_bucket_non_encrypted/
├── main.tf                 # Terraform code with intentional security issue
└── results_summary.json    # Ground truth: which tools detect it + expected FPs
```

### Evaluation Logic

| Finding Type | Expected API Response | Correct When |
|--------------|----------------------|--------------|
| True Positive (real issue) | HIGH confidence | API returns HIGH |
| Expected False Positive (noise) | LOW confidence | API returns LOW |

### False Positive Classification

Each `results_summary.json` defines which findings are **expected false positives** (incidental to the test case):

```json
{
  "checkov": "yes",
  "kics": "yes",
  "snyk": "no",
  "expected_false_positives": [
    "'tags' block is missing",
    "does not have shield advanced associated",
    "Missing tags: {\"team\"}"
  ]
}
```

**Classified as Expected FPs:**
- Missing resource tags
- Shield/WAF associations
- Informational best practices unrelated to the core issue

**NOT Expected FPs (real issues):**
- `publicly_accessible` settings
- `public_network_access_enabled`
- Wildcard IAM permissions
- The primary security issue being tested

---

## Running the Benchmark

### Prerequisites

- Python 3.10+
- Go 1.21+ (for building the scanner)
- Datadog API keys with `CodeAnalysisRead` permission

### Local Execution

#### 1. Build the scanner

```bash
cd /path/to/DataDog/kics
make build
export SCANNER=$(pwd)/bin/datadog-iac-scanner
```

#### 2. Run the scanner on test cases

```bash
cd /path/to/iac-benchmarking/benchmark-tools
./run_scanner.sh $SCANNER
```

#### 3. Run the evaluation

```bash
export DD_API_KEY='your-api-key'
export DD_APP_KEY='your-app-key'

pip install -r requirements.txt
python fp_eval.py
```

#### Command-line options

```bash
python fp_eval.py --help

Options:
  --test-cases-dir DIR   Directory containing test cases (default: ../test-cases/terraform)
  --output FILE          Output file for results (default: ../results/fp_eval_results.json)
  --workers N            Number of concurrent API workers (default: 3)
  --limit N              Limit number of test cases (0 = all)
```

### CI Execution

The benchmark runs weekly via GitHub Actions in [DataDog/kics](https://github.com/DataDog/kics):

```
.github/workflows/fp-benchmark.yml
```

**Schedule**: Every Monday at 4 AM UTC

**Manual trigger**: Actions → False Positive Benchmark → Run workflow

**Required secrets**:
| Secret | Description |
|--------|-------------|
| `DD_API_KEY` | Datadog API key with `CodeAnalysisRead` permission |
| `DD_APP_KEY` | Datadog Application key |

---

## Understanding Results

### Sample Output

```
============================================================
EVALUATION SUMMARY
============================================================
Total findings evaluated: 1116
Errors: 5

TRUE POSITIVES (expect HIGH):
  Total: 425, Correct: 383, Accuracy: 90.1%

EXPECTED FALSE POSITIVES (expect LOW):
  Total: 691, Correct: 566, Accuracy: 81.9%

OVERALL ACCURACY: 85.0%
============================================================

================================================================================
DATADOG IAC SCANNER - FP FILTERING COMPARISON
================================================================================
Configuration             Findings   TPs     FPs     Precision    Recall    
--------------------------------------------------------------------------------
Without FP Filtering      1116       425     691     38.1%        100%      
With FP Filtering         508        383     125     75.4%        90.1%     
--------------------------------------------------------------------------------
Impact: 566 FPs filtered (81.9%), findings reduced by 54.5%, precision +37.3%
================================================================================

==========================================================================================
TOOL COMPARISON
==========================================================================================
Tool                                Detected   Total    Det Rate   Findings   Precision 
------------------------------------------------------------------------------------------
datadog-iac-scanner (no filtering)  161        171      94.2%      1116       38.1%     
datadog-iac-scanner (with filtering)161        171      94.2%      508        75.4%     
------------------------------------------------------------------------------------------
cloudrail                           123        171      71.9%      -          -         
kics                                108        171      63.2%      -          -         
checkov                             102        171      59.6%      -          -         
snyk                                80         171      46.8%      -          -         
terrascan                           79         171      46.2%      -          -         
tfsec                               73         171      42.7%      -          -         
==========================================================================================
```

### Metrics Submitted to Datadog

| Metric | Description |
|--------|-------------|
| `iac.fp_eval.accuracy` | Overall accuracy (%) |
| `iac.fp_eval.tp_accuracy` | True positive accuracy (%) |
| `iac.fp_eval.fp_accuracy` | Expected FP accuracy (%) |
| `iac.fp_eval.detection_rate.datadog_iac_scanner` | Detection rate (%) |
| `iac.fp_eval.without_filter.precision` | Precision without filtering (%) |
| `iac.fp_eval.with_filter.precision` | Precision with filtering (%) |
| `iac.fp_eval.filter.precision_improvement` | Precision gain from filtering (%) |

---

## Updating the Benchmark

### Adding New Test Cases

1. Create a new directory under `test-cases/terraform/{cloud}/{category}/{issue_name}/`
2. Add `main.tf` with intentional security misconfiguration
3. Add `results_summary.json` with ground truth:

```json
{
  "checkov": "yes",
  "cloudrail": "no",
  "kics": "yes",
  "snyk": "no",
  "terrascan": "no",
  "tfsec": "yes",
  "expected_false_positives": []
}
```

4. Run locally to verify detection

### Updating Expected False Positives

After running an evaluation, review LOW confidence findings. If they are truly incidental:

```bash
# Automatically update results_summary.json files based on evaluation
python update_expected_fps.py
```

This script:
- Reads `fp_eval_results.json`
- Finds findings marked LOW confidence
- Adds them to `expected_false_positives` in each test case
- Excludes actual security issues (publicly_accessible, wildcards, etc.)

### Manual Review

For findings that need human judgment:

1. Run evaluation: `python fp_eval.py`
2. Review `results/fp_eval_results.json`
3. For incorrect classifications, update `results_summary.json` manually

---

## Files Reference

| File | Description |
|------|-------------|
| `fp_eval.py` | Main evaluation script |
| `run_scanner.sh` | Run scanner on all test cases |
| `generate_summary.py` | Generate GitHub Actions summary |
| `submit_metrics.py` | Submit metrics to Datadog |
| `check_threshold.py` | Fail CI if accuracy below threshold |
| `update_expected_fps.py` | Bulk update expected FPs |
| `requirements.txt` | Python dependencies |

---

## Troubleshooting

### "No files were scanned"

Include the `--type` flag:

```bash
$SCANNER scan --path <path> --type terraform --output-path <output> --output-name result.sarif
```

### 403 Forbidden from API

API keys need `CodeAnalysisRead` permission. Verify your keys have the correct scope.

### Staging vs Production

Ensure API keys match the endpoint:
- **Production**: `api.datadoghq.com` (default)
- **Staging**: `dd.datad0g.com`

### Rate Limiting

Reduce concurrent workers:

```bash
python fp_eval.py --workers 1
```
