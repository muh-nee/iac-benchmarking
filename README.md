![MIT License](https://img.shields.io/github/license/iacsecurity/tool-compare)
![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)

> **Fork Notice**: This repository is forked from [iacsecurity/tool-compare](https://github.com/iacsecurity/tool-compare), which provides Terraform test cases with known security misconfigurations and compares detection rates across IAC security tools. We've extended it with tooling to evaluate Datadog's false positive filtering API.

# Datadog IAC False Positive Filtering Benchmark

This repository benchmarks the accuracy of Datadog's **IAC false positive filtering** feature. It measures how well the LLM-based filtering correctly identifies true security issues vs incidental findings that should be filtered out.

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

## Repository Structure

```
iac-benchmarking/
├── benchmark-tools/           # Evaluation scripts and documentation
│   ├── fp_eval.py            # Main evaluation script
│   ├── run_scanner.sh        # Run scanner on all test cases
│   ├── generate_summary.py   # GitHub Actions summary generation
│   ├── submit_metrics.py     # Submit metrics to Datadog
│   ├── update_expected_fps.py# Bulk update expected false positives
│   └── README.md             # Detailed benchmark documentation
├── test-cases/               # Terraform test cases with known issues
│   └── terraform/
│       ├── aws/              # AWS security misconfigurations
│       ├── azure/            # Azure security misconfigurations
│       └── hcl_language_complexity/  # HCL edge cases
└── results/                  # Evaluation output (gitignored)
```

## Quick Start

### Prerequisites

- Python 3.10+
- Go 1.21+ (for building the scanner)
- Datadog API keys with `CodeAnalysisRead` permission

### Run Locally

```bash
# 1. Build the scanner
cd /path/to/DataDog/kics
make build
export SCANNER=$(pwd)/bin/datadog-iac-scanner

# 2. Clone this repo and run scanner on test cases
cd /path/to/iac-benchmarking/benchmark-tools
./run_scanner.sh $SCANNER

# 3. Run evaluation
export DD_API_KEY='your-api-key'
export DD_APP_KEY='your-app-key'
pip install -r requirements.txt
python fp_eval.py
```

### Run in CI

The benchmark runs weekly (Mondays 4 AM UTC) via GitHub Actions in [DataDog/kics](https://github.com/DataDog/kics):

```
.github/workflows/fp-benchmark.yml
```

Manual trigger: **Actions** → **False Positive Benchmark** → **Run workflow**

See [benchmark-tools/README.md](benchmark-tools/README.md) for detailed documentation.

---

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

### Evaluation Logic

Each test case represents a **known security misconfiguration**. Findings are categorized as:

| Finding Type | Expected API Response | Correct When |
|--------------|----------------------|--------------|
| True Positive (real issue) | HIGH confidence | API returns HIGH |
| Expected False Positive (noise) | LOW confidence | API returns LOW |

### False Positive Classification

Each `results_summary.json` defines which findings are **expected false positives**:

```json
{
  "checkov": "yes",
  "kics": "yes",
  "expected_false_positives": [
    "'tags' block is missing",
    "does not have shield advanced associated"
  ]
}
```

**Expected FPs** (incidental findings):
- Missing resource tags
- Shield/WAF associations
- Informational best practices

**NOT Expected FPs** (real issues):
- `publicly_accessible` settings
- Wildcard IAM permissions
- The primary security issue being tested

---

## Sample Results

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

---

## Updating the Benchmark

### Adding New Test Cases

1. Create directory: `test-cases/terraform/{cloud}/{category}/{issue_name}/`
2. Add `main.tf` with intentional security misconfiguration
3. Add `results_summary.json` with ground truth:

```json
{
  "checkov": "yes",
  "kics": "yes",
  "snyk": "no",
  "expected_false_positives": []
}
```

4. Run locally to verify detection

### Updating Expected False Positives

After running an evaluation, review LOW confidence findings:

```bash
cd benchmark-tools
python update_expected_fps.py
```

This automatically updates `results_summary.json` files based on evaluation results.

---

## Original Tool Comparison Data

This repository contains detection rate data from the original [iacsecurity/tool-compare](https://github.com/iacsecurity/tool-compare) project, comparing multiple IAC security tools.

### Tools Compared

| Tool | Vendor | License |
|------|--------|---------|
| [Checkov](https://github.com/bridgecrewio/checkov) | Bridgecrew | OSS |
| [Cloudrail](https://www.indeni.com/cloudrail) | Indeni | Freemium |
| [Kics](https://github.com/Checkmarx/kics) | Checkmarx | OSS |
| [Snyk](https://snyk.io/) | Snyk | Freemium |
| [Terrascan](https://github.com/accurics/terrascan) | Accurics | OSS |
| [Tfsec](https://github.com/tfsec/tfsec) | Aqua Security | OSS |

### Historical Detection Rates (from original repo)

| Tool | Terraform AWS | Terraform Azure | Total |
|------|---------------|-----------------|-------|
| Cloudrail | 93% | 35% | 72% |
| Kics | 94% | 23% | 65% |
| Checkov | 69% | 47% | 59% |
| Snyk | 62% | 30% | 48% |
| Terrascan | 73% | 8% | 47% |
| Tfsec | 61% | 18% | 43% |

---

## Contributing

### To the Benchmark

- **Add test cases**: Create new directories under `test-cases/terraform/` with `main.tf` and `results_summary.json`
- **Improve evaluation**: Submit PRs to `benchmark-tools/` scripts
- **Update documentation**: Keep README files current

### Original Repository

This repo is forked from [iacsecurity/tool-compare](https://github.com/iacsecurity/tool-compare). For contributions related to the original tool comparison project, please contribute upstream.
