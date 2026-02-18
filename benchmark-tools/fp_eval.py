#!/usr/bin/env python3
"""
IAC False Positive Evaluation Script

Evaluates SARIF results from datadog-iac-scanner against the FP filtering API.
All test cases in iac-benchmarking are known true positives, so:
- HIGH confidence = correct (model correctly identified as real issue)
- LOW confidence = incorrect (model incorrectly flagged as false positive)

Usage:
    # Set environment variables
    export DD_API_KEY="your-api-key"
    export DD_APP_KEY="your-app-key"
    
    # Run evaluation
    python fp_eval.py --test-cases-dir ../test-cases/terraform --workers 3
    
    # Limit to a few test cases for quick testing
    python fp_eval.py --test-cases-dir ../test-cases/terraform --limit 5
"""

import argparse
import base64
import concurrent.futures
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import requests


API_URL = "https://dd.datad0g.com/api/v2/static-analysis-ai/false-positive/evaluate"
BENCHMARK_TOOLS = ["checkov", "cloudrail", "kics", "snyk", "terrascan", "tfsec"]


@dataclass
class Finding:
    rule_id: str
    message: str
    severity: str
    file_path: str
    start_line: int
    end_line: int
    test_case_path: str
    expected_fp: bool = False  # True if this finding is expected to be a false positive


def load_results_summary(test_case_dir: Path) -> dict:
    """Load results_summary.json data."""
    summary_path = test_case_dir / "results_summary.json"
    if not summary_path.exists():
        return {}
    
    try:
        return json.loads(summary_path.read_text())
    except json.JSONDecodeError:
        return {}


def load_expected_fps(test_case_dir: Path) -> list[str]:
    """Load expected false positive patterns from results_summary.json."""
    data = load_results_summary(test_case_dir)
    return data.get("expected_false_positives", [])


def get_tool_detections(test_case_dir: Path) -> dict[str, bool]:
    """Get which tools detected the issue for this test case."""
    data = load_results_summary(test_case_dir)
    return {
        tool: data.get(tool, "").lower() == "yes"
        for tool in BENCHMARK_TOOLS
    }


def is_expected_fp(message: str, expected_fps: list[str]) -> bool:
    """Check if a finding message matches any expected FP pattern."""
    for pattern in expected_fps:
        if pattern.lower() in message.lower():
            return True
    return False


def parse_sarif(test_case_dir: Path) -> list[Finding]:
    """Parse SARIF results from a test case directory."""
    findings = []
    sarif_path = test_case_dir / "sarif" / "datadog-iac-result.sarif"
    
    if not sarif_path.exists():
        return findings

    try:
        sarif = json.loads(sarif_path.read_text())
    except json.JSONDecodeError as e:
        print(f"  Warning: Failed to parse {sarif_path}: {e}")
        return findings

    # Load expected FPs for this test case
    expected_fps = load_expected_fps(test_case_dir)

    for run in sarif.get("runs", []):
        rules_by_id = {
            r.get("id"): r 
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules_by_id.get(rule_id, {})
            
            # Get severity from rule properties or infer from level
            severity = rule.get("properties", {}).get("severity", "")
            if not severity:
                level = result.get("level", "warning")
                level_map = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}
                severity = level_map.get(level, "MEDIUM")
            severity = severity.upper()

            # Only evaluate HIGH and MEDIUM severity findings
            if severity not in ("HIGH", "MEDIUM"):
                continue

            message = result.get("message", {}).get("text", rule_id)
            
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                region = phys.get("region", {})
                
                file_path = artifact.get("uri", "main.tf")
                # Normalize path to just filename
                if "/" in file_path:
                    file_path = file_path.split("/")[-1]
                
                findings.append(Finding(
                    rule_id=rule_id,
                    message=message,
                    severity=severity,
                    file_path=file_path,
                    start_line=region.get("startLine", 1),
                    end_line=region.get("endLine", region.get("startLine", 1) + 3),
                    test_case_path=str(test_case_dir),
                    expected_fp=is_expected_fp(message, expected_fps),
                ))
    
    return findings


def call_fp_api(finding: Finding, file_content: str, api_key: str, app_key: str) -> tuple[str, str]:
    """Call the false positive evaluation API."""
    data = {
        "data": {
            "type": "false_positive_request",
            "id": f"{finding.rule_id}_{finding.start_line}",
            "attributes": {
                "tool": "Datadog IaC Scanning",
                "category": "security",
                "message": finding.message,
                "start_line": finding.start_line,
                "end_line": finding.end_line,
                "path": finding.file_path,
                "file_content_base64": base64.b64encode(file_content.encode()).decode(),
            },
        }
    }
    
    headers = {
        "Content-Type": "application/json",
        "DD-API-KEY": api_key,
        "DD-APPLICATION-KEY": app_key,
    }
    
    for attempt in range(3):
        try:
            resp = requests.post(API_URL, json=data, headers=headers, timeout=60)
            resp.raise_for_status()
            result = resp.json()
            return (
                result.get("data", {}).get("attributes", {}).get("confidence", "ERROR"),
                result.get("data", {}).get("attributes", {}).get("reason", ""),
            )
        except requests.exceptions.HTTPError as e:
            if resp.status_code == 429:
                # Rate limited, wait longer
                time.sleep(5 * (attempt + 1))
                continue
            if attempt == 2:
                return "ERROR", f"HTTP {resp.status_code}: {str(e)}"
            time.sleep(2 ** attempt)
        except Exception as e:
            if attempt == 2:
                return "ERROR", str(e)
            time.sleep(2 ** attempt)
    
    return "ERROR", "Max retries exceeded"


def evaluate_finding(finding: Finding, api_key: str, app_key: str) -> dict:
    """Evaluate a single finding."""
    src_file = Path(finding.test_case_path) / finding.file_path
    if not src_file.exists():
        return {
            "rule_id": finding.rule_id,
            "test_case": Path(finding.test_case_path).name,
            "message": finding.message,
            "confidence": "ERROR",
            "reason": f"File not found: {src_file}",
            "is_correct": False,
            "expected_fp": finding.expected_fp,
        }
    
    content = src_file.read_text()
    conf, reason = call_fp_api(finding, content, api_key, app_key)
    
    # Determine correctness based on expected_fp flag
    # - If expected_fp=True: LOW = correct (model correctly identified FP)
    # - If expected_fp=False: HIGH = correct (model correctly identified TP)
    if finding.expected_fp:
        is_correct = conf == "LOW"
        expected = "FP"
    else:
        is_correct = conf == "HIGH"
        expected = "TP"
    
    status = "✓" if is_correct else "✗"
    fp_marker = " [expected FP]" if finding.expected_fp else ""
    print(f"  {finding.message[:60]}... in {Path(finding.test_case_path).name}: {conf} {status}{fp_marker}")
    
    return {
        "rule_id": finding.rule_id,
        "test_case": Path(finding.test_case_path).name,
        "message": finding.message,
        "file_path": finding.file_path,
        "start_line": finding.start_line,
        "severity": finding.severity,
        "confidence": conf,
        "reason": reason,
        "is_correct": is_correct,
        "expected_fp": finding.expected_fp,
        "expected": expected,
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate IAC false positive filtering")
    parser.add_argument(
        "--test-cases-dir",
        type=Path,
        default=Path("../test-cases/terraform"),
        help="Directory containing test cases (default: ../test-cases/terraform)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("../results/fp_eval_results.json"),
        help="Output file for results (default: ../results/fp_eval_results.json)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.environ.get("WORKERS", "3")),
        help="Number of concurrent API workers (default: 3)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit number of test cases to evaluate (0 = all)",
    )
    args = parser.parse_args()

    # Check for required environment variables
    api_key = os.environ.get("DD_API_KEY")
    app_key = os.environ.get("DD_APP_KEY")
    
    if not api_key or not app_key:
        print("Error: DD_API_KEY and DD_APP_KEY environment variables are required")
        print("\nUsage:")
        print("  export DD_API_KEY='your-api-key'")
        print("  export DD_APP_KEY='your-app-key'")
        print("  python fp_eval.py")
        sys.exit(1)

    # Find all test cases
    test_cases_dir = args.test_cases_dir.resolve()
    if not test_cases_dir.exists():
        print(f"Error: Test cases directory not found: {test_cases_dir}")
        sys.exit(1)

    print(f"Scanning for test cases in: {test_cases_dir}")
    
    # Collect all findings from SARIF files and tool comparison data
    all_findings = []
    test_case_count = 0
    tool_comparison = defaultdict(lambda: {"detected": 0, "total": 0})
    dd_scanner_detected = 0
    total_test_cases = 0
    
    for main_tf in sorted(test_cases_dir.rglob("main.tf")):
        if args.limit > 0 and test_case_count >= args.limit:
            break
        
        test_case_dir = main_tf.parent
        findings = parse_sarif(test_case_dir)
        
        # Collect tool comparison data
        tool_detections = get_tool_detections(test_case_dir)
        has_summary = any(tool_detections.values()) or load_results_summary(test_case_dir)
        
        if has_summary or findings:
            total_test_cases += 1
            for tool, detected in tool_detections.items():
                tool_comparison[tool]["total"] += 1
                if detected:
                    tool_comparison[tool]["detected"] += 1
            
            # Our scanner detected if we have any findings
            if findings:
                dd_scanner_detected += 1
        
        if findings:
            test_case_count += 1
            all_findings.extend(findings)

    print(f"\nFound {len(all_findings)} HIGH/MEDIUM findings across {test_case_count} test cases")

    if not all_findings:
        print("No findings to evaluate. Make sure you've run the scanner first:")
        print("  datadog-iac-scanner scan --path <test-case> --output-path <test-case>/sarif --output-name datadog-iac-result.sarif")
        
        # Write empty results
        args.output.parent.mkdir(parents=True, exist_ok=True)
        results = {
            "summary": {
                "total_findings": 0,
                "high_confidence": 0,
                "low_confidence": 0,
                "errors": 0,
                "accuracy": 1.0,
            },
            "results": [],
        }
        args.output.write_text(json.dumps(results, indent=2))
        return

    print(f"\nEvaluating with {args.workers} workers...")
    print("-" * 60)

    # Evaluate concurrently
    def eval_wrapper(finding):
        return evaluate_finding(finding, api_key, app_key)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        results_list = list(executor.map(eval_wrapper, all_findings))

    # Calculate summary statistics
    errors = sum(1 for r in results_list if r["confidence"] == "ERROR")
    total = len(results_list)
    non_error = total - errors
    
    # Split by expected type
    tp_results = [r for r in results_list if not r.get("expected_fp", False) and r["confidence"] != "ERROR"]
    fp_results = [r for r in results_list if r.get("expected_fp", False) and r["confidence"] != "ERROR"]
    
    tp_correct = sum(1 for r in tp_results if r["confidence"] == "HIGH")
    tp_total = len(tp_results)
    tp_accuracy = tp_correct / tp_total if tp_total > 0 else 0
    
    fp_correct = sum(1 for r in fp_results if r["confidence"] == "LOW")
    fp_total = len(fp_results)
    fp_accuracy = fp_correct / fp_total if fp_total > 0 else 0
    
    correct = sum(1 for r in results_list if r.get("is_correct", False))
    accuracy = correct / non_error if non_error > 0 else 0

    # Build tool comparison stats
    dd_detection_rate = dd_scanner_detected / total_test_cases if total_test_cases > 0 else 0
    tool_comparison_stats = {}
    for tool in BENCHMARK_TOOLS:
        stats = tool_comparison[tool]
        rate = stats["detected"] / stats["total"] if stats["total"] > 0 else 0
        tool_comparison_stats[tool] = {
            "detected": stats["detected"],
            "total": stats["total"],
            "detection_rate": rate,
        }

    summary = {
        "total_findings": total,
        "errors": errors,
        "correct": correct,
        "accuracy": accuracy,
        "true_positives": {
            "total": tp_total,
            "correct": tp_correct,
            "accuracy": tp_accuracy,
        },
        "expected_false_positives": {
            "total": fp_total,
            "correct": fp_correct,
            "accuracy": fp_accuracy,
        },
        "tool_comparison": {
            "total_test_cases": total_test_cases,
            "datadog_iac_scanner": {
                "detected": dd_scanner_detected,
                "detection_rate": dd_detection_rate,
            },
            **tool_comparison_stats,
        },
    }

    # Print summary
    print(f"\n{'=' * 60}")
    print("EVALUATION SUMMARY")
    print(f"{'=' * 60}")
    print(f"Total findings evaluated: {total}")
    print(f"Errors: {errors}")
    print(f"")
    print(f"TRUE POSITIVES (expect HIGH):")
    print(f"  Total: {tp_total}, Correct: {tp_correct}, Accuracy: {tp_accuracy:.1%}")
    print(f"")
    print(f"EXPECTED FALSE POSITIVES (expect LOW):")
    print(f"  Total: {fp_total}, Correct: {fp_correct}, Accuracy: {fp_accuracy:.1%}")
    print(f"")
    print(f"OVERALL ACCURACY: {accuracy:.1%}")
    print(f"{'=' * 60}")
    
    # Print tool comparison
    print(f"\n{'=' * 60}")
    print("TOOL COMPARISON - DETECTION RATES")
    print(f"{'=' * 60}")
    print(f"{'Tool':<25} {'Detected':<10} {'Total':<10} {'Rate':<10}")
    print(f"{'-' * 55}")
    
    # Our scanner first
    print(f"{'datadog-iac-scanner':<25} {dd_scanner_detected:<10} {total_test_cases:<10} {dd_detection_rate:.1%}")
    
    # Sort other tools by detection rate
    sorted_tools = sorted(
        BENCHMARK_TOOLS,
        key=lambda t: tool_comparison_stats[t]["detection_rate"],
        reverse=True
    )
    for tool in sorted_tools:
        stats = tool_comparison_stats[tool]
        print(f"{tool:<25} {stats['detected']:<10} {stats['total']:<10} {stats['detection_rate']:.1%}")
    
    print(f"{'=' * 60}")

    # Write results
    args.output.parent.mkdir(parents=True, exist_ok=True)
    results = {"summary": summary, "results": results_list}
    args.output.write_text(json.dumps(results, indent=2))
    print(f"\nResults written to: {args.output}")

    # Exit with error if accuracy is below threshold
    if accuracy < 0.8:
        print(f"\n⚠️  Overall accuracy {accuracy:.1%} is below 80% threshold")
        sys.exit(1)
    else:
        print(f"\n✅ Overall accuracy {accuracy:.1%} meets threshold")


if __name__ == "__main__":
    main()
