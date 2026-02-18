#!/usr/bin/env python3
"""
IAC False Positive Evaluation Tool

Runs KICS on test cases (optionally), calls the Datadog FP API, and evaluates results
against ground truth (test cases are known true positives).

Usage:
    # Use existing KICS results
    python iac_fp_eval.py --test-cases-dir ../test-cases/terraform

    # Re-run KICS to generate fresh SARIF
    python iac_fp_eval.py --test-cases-dir ../test-cases/terraform --run-kics
"""

import argparse
import base64
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any

import requests


@dataclass
class Finding:
    """A single KICS finding."""
    rule_id: str
    message: str
    severity: str
    file_path: str
    start_line: int
    end_line: int
    test_case_path: str  # Path to the test case directory


@dataclass
class EvaluationResult:
    """Result of FP evaluation for a finding."""
    finding: Finding
    confidence: str  # HIGH, LOW, or ERROR
    reason: str
    is_correct: bool  # True if prediction matches ground truth


@dataclass
class EvaluationSummary:
    """Summary of evaluation results."""
    total_findings: int = 0
    high_confidence: int = 0  # Predicted as true positive (correct for this dataset)
    low_confidence: int = 0   # Predicted as false positive (incorrect for this dataset)
    errors: int = 0
    precision: float = 0.0    # For FP detection: we expect 0% since all are TP
    accuracy: float = 0.0     # Overall accuracy
    results: list = field(default_factory=list)


class IaCFPEvaluator:
    """Evaluates IAC findings using the Datadog FP API."""

    API_URL = "https://dd.datad0g.com/api/v2/static-analysis-ai/false-positive/evaluate"

    def __init__(self, api_key: str, app_key: str, max_workers: int = 3):
        self.api_key = api_key
        self.app_key = app_key
        self.max_workers = max_workers
        self.session = requests.Session()
        self.results_lock = Lock()

    def run_kics_sarif(self, test_case_dir: Path) -> dict | None:
        """Run KICS on a test case and return SARIF output."""
        try:
            # Remove old sarif if exists
            sarif_path = test_case_dir / "kics_results.sarif"
            if sarif_path.exists():
                sarif_path.unlink()

            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", f"{test_case_dir}:/src",
                    "checkmarx/kics:latest",
                    "scan", "-p", "/src",
                    "-o", "/src",
                    "--report-formats", "sarif",
                    "--output-name", "kics_results"
                ],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if sarif_path.exists():
                return json.loads(sarif_path.read_text())
            return None
        except Exception as e:
            print(f"Error running KICS on {test_case_dir}: {e}")
            return None

    def parse_sarif_results(self, test_case_dir: Path, sarif_filename: str = "datadog-iac-result.sarif") -> list[Finding]:
        """Parse SARIF results into findings (works with datadog-iac-scanner or KICS SARIF)."""
        findings = []
        
        # Try different SARIF locations
        sarif_paths = [
            test_case_dir / "sarif" / sarif_filename,  # datadog-iac-scanner output
            test_case_dir / sarif_filename,
            test_case_dir / "kics_results.sarif",  # Fallback to KICS format
        ]
        
        sarif_path = None
        for path in sarif_paths:
            if path.exists():
                sarif_path = path
                break
        
        if not sarif_path:
            return findings

        try:
            sarif = json.loads(sarif_path.read_text())
        except json.JSONDecodeError:
            return findings

        for run in sarif.get("runs", []):
            rules_by_id = {}
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                rules_by_id[rule.get("id")] = rule

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                rule = rules_by_id.get(rule_id, {})
                
                # Get severity from rule properties or result level
                severity = rule.get("properties", {}).get("severity", "")
                if not severity:
                    # Check result level
                    level = result.get("level", "warning")
                    level_mapping = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
                    severity = level_mapping.get(level, "MEDIUM")
                
                if isinstance(severity, str):
                    severity = severity.upper()

                # Only process HIGH and MEDIUM severity
                if severity not in ("HIGH", "MEDIUM"):
                    continue

                message = result.get("message", {}).get("text", rule_id)
                
                for location in result.get("locations", []):
                    phys_loc = location.get("physicalLocation", {})
                    artifact_loc = phys_loc.get("artifactLocation", {})
                    region = phys_loc.get("region", {})
                    
                    file_path = artifact_loc.get("uri", "main.tf")
                    # Remove leading path components to get just the filename
                    if "/" in file_path:
                        file_path = file_path.split("/")[-1]
                    
                    start_line = region.get("startLine", 1)
                    end_line = region.get("endLine", start_line + 3)

                    findings.append(Finding(
                        rule_id=rule_id,
                        message=message,
                        severity=severity,
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line,
                        test_case_path=str(test_case_dir),
                    ))

        return findings

    def parse_kics_text_results(self, test_case_dir: Path) -> list[Finding]:
        """Parse existing KICS text results into findings (fallback)."""
        findings = []
        kics_file = test_case_dir / "kics_results.txt"
        
        if not kics_file.exists():
            return findings

        content = kics_file.read_text()
        main_tf = test_case_dir / "main.tf"
        
        if not main_tf.exists():
            return findings

        # Pattern: "Rule Name, Severity: LEVEL, Results: N"
        pattern = r'^([^,]+), Severity: (HIGH|MEDIUM|LOW|INFO), Results: \d+'
        
        for match in re.finditer(pattern, content, re.MULTILINE):
            rule_name = match.group(1).strip()
            severity = match.group(2)
            
            # Only process HIGH and MEDIUM severity for FP evaluation
            if severity not in ("HIGH", "MEDIUM"):
                continue

            # Find the line number from the context
            line_pattern = rf'{re.escape(rule_name)}.*?\[1\]: /src/main\.tf:(\d+)'
            line_match = re.search(line_pattern, content, re.DOTALL)
            
            start_line = 1
            if line_match:
                start_line = int(line_match.group(1))

            # Extract description
            desc_pattern = rf'{re.escape(rule_name)}.*?Description: ([^\n]+)'
            desc_match = re.search(desc_pattern, content, re.DOTALL)
            description = desc_match.group(1) if desc_match else rule_name

            findings.append(Finding(
                rule_id=rule_name.replace(" ", "_").replace(",", ""),
                message=description,
                severity=severity,
                file_path="main.tf",
                start_line=start_line,
                end_line=start_line + 3,  # Approximate
                test_case_path=str(test_case_dir),
            ))

        return findings

    def call_fp_api(self, finding: Finding, file_content: str) -> tuple[str, str]:
        """Call the Datadog FP API."""
        file_content_base64 = base64.b64encode(file_content.encode("utf-8")).decode("utf-8")

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
                    "file_content_base64": file_content_base64,
                },
            }
        }

        headers = {
            "Content-Type": "application/json",
            "DD-API-KEY": self.api_key,
            "DD-APPLICATION-KEY": self.app_key,
        }

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.session.post(
                    self.API_URL, json=data, headers=headers, timeout=60
                )
                response.raise_for_status()
                result = response.json()
                
                confidence = result.get("data", {}).get("attributes", {}).get("confidence", "ERROR")
                reason = result.get("data", {}).get("attributes", {}).get("reason", "")
                return confidence, reason
                
            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:
                    return "ERROR", str(e)
                time.sleep(2 ** attempt)

        return "ERROR", "Max retries exceeded"

    def evaluate_finding(
        self, 
        finding: Finding, 
        results: list[EvaluationResult]
    ):
        """Evaluate a single finding."""
        try:
            # Read the source file
            main_tf = Path(finding.test_case_path) / finding.file_path
            if not main_tf.exists():
                with self.results_lock:
                    results.append(EvaluationResult(
                        finding=finding,
                        confidence="ERROR",
                        reason="Source file not found",
                        is_correct=False,
                    ))
                return

            file_content = main_tf.read_text()

            print(f"  Evaluating: {finding.rule_id} in {Path(finding.test_case_path).name}")
            
            confidence, reason = self.call_fp_api(finding, file_content)
            
            # For this benchmark, all test cases are TRUE POSITIVES
            # So HIGH confidence = correct, LOW confidence = incorrect
            is_correct = confidence == "HIGH"
            
            print(f"    -> {confidence} ({'✓' if is_correct else '✗'})")

            with self.results_lock:
                results.append(EvaluationResult(
                    finding=finding,
                    confidence=confidence,
                    reason=reason,
                    is_correct=is_correct,
                ))

        except Exception as e:
            print(f"    -> ERROR: {e}")
            with self.results_lock:
                results.append(EvaluationResult(
                    finding=finding,
                    confidence="ERROR",
                    reason=str(e),
                    is_correct=False,
                ))

    def evaluate_test_cases(self, test_cases_dir: Path, use_sarif: bool = True) -> EvaluationSummary:
        """Evaluate all test cases in a directory."""
        all_findings: list[Finding] = []

        # Find all test cases (directories with main.tf)
        for main_tf in test_cases_dir.rglob("main.tf"):
            test_case_dir = main_tf.parent
            
            # Try SARIF first if enabled, fall back to text
            if use_sarif:
                findings = self.parse_sarif_results(test_case_dir)
                if not findings:
                    findings = self.parse_kics_text_results(test_case_dir)
            else:
                findings = self.parse_kics_text_results(test_case_dir)
            
            all_findings.extend(findings)

        print(f"\nFound {len(all_findings)} HIGH/MEDIUM findings to evaluate\n")

        if not all_findings:
            return EvaluationSummary()

        # Evaluate findings concurrently
        results: list[EvaluationResult] = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [
                executor.submit(self.evaluate_finding, finding, results)
                for finding in all_findings
            ]
            concurrent.futures.wait(futures)

        # Calculate summary
        summary = EvaluationSummary(
            total_findings=len(results),
            high_confidence=sum(1 for r in results if r.confidence == "HIGH"),
            low_confidence=sum(1 for r in results if r.confidence == "LOW"),
            errors=sum(1 for r in results if r.confidence == "ERROR"),
            results=[{
                "rule_id": r.finding.rule_id,
                "test_case": Path(r.finding.test_case_path).name,
                "confidence": r.confidence,
                "reason": r.reason,
                "is_correct": r.is_correct,
            } for r in results],
        )

        # Calculate accuracy (for this benchmark, HIGH = correct since all are TP)
        non_error = summary.total_findings - summary.errors
        if non_error > 0:
            summary.accuracy = summary.high_confidence / non_error

        return summary


def main():
    parser = argparse.ArgumentParser(description="IAC False Positive Evaluation")
    parser.add_argument(
        "--test-cases-dir",
        type=Path,
        default=Path(__file__).parent.parent / "test-cases" / "terraform",
        help="Directory containing test cases",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("fp_eval_results.json"),
        help="Output file for results",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=3,
        help="Number of concurrent workers",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit number of findings to evaluate (0 = all)",
    )
    parser.add_argument(
        "--use-sarif",
        action="store_true",
        default=True,
        help="Use SARIF results from datadog-iac-scanner (default: True)",
    )
    parser.add_argument(
        "--no-sarif",
        action="store_true",
        help="Use text results instead of SARIF",
    )

    args = parser.parse_args()

    api_key = os.getenv("DD_API_KEY")
    app_key = os.getenv("DD_APP_KEY")

    if not api_key or not app_key:
        print("Error: DD_API_KEY and DD_APP_KEY must be set")
        sys.exit(1)

    evaluator = IaCFPEvaluator(api_key, app_key, max_workers=args.workers)
    
    use_sarif = args.use_sarif and not args.no_sarif
    
    print(f"Evaluating test cases in: {args.test_cases_dir}")
    print(f"Using SARIF: {use_sarif}")
    summary = evaluator.evaluate_test_cases(args.test_cases_dir, use_sarif=use_sarif)

    # Print summary
    print("\n" + "=" * 50)
    print("EVALUATION SUMMARY")
    print("=" * 50)
    print(f"Total findings evaluated: {summary.total_findings}")
    print(f"HIGH confidence (correct): {summary.high_confidence}")
    print(f"LOW confidence (incorrect): {summary.low_confidence}")
    print(f"Errors: {summary.errors}")
    print(f"Accuracy: {summary.accuracy:.1%}")
    print("=" * 50)

    # Save results
    output_data = {
        "summary": {
            "total_findings": summary.total_findings,
            "high_confidence": summary.high_confidence,
            "low_confidence": summary.low_confidence,
            "errors": summary.errors,
            "accuracy": summary.accuracy,
        },
        "results": summary.results,
    }
    
    args.output.write_text(json.dumps(output_data, indent=2))
    print(f"\nResults saved to: {args.output}")

    # Exit with error if accuracy is too low
    if summary.accuracy < 0.8:
        print(f"\n⚠️  Accuracy below 80% threshold!")
        sys.exit(1)


if __name__ == "__main__":
    main()
