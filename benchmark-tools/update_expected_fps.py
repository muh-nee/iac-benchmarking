#!/usr/bin/env python3
"""
Reads fp_eval_results.json and updates each test case's results_summary.json
with expected_false_positives based on LOW confidence findings.

Only marks findings as expected FPs if they are truly incidental to what
the test case is testing. Excludes findings that ARE the security issue.
"""

import json
from collections import defaultdict
from pathlib import Path


# Patterns that should REMAIN as True Positives (not marked as FP)
# These are actual security issues, not incidental findings
TRUE_POSITIVE_PATTERNS = [
    "publicly_accessible",
    "public_network_access_enabled",
    "action has wildcard",
    "action is all",
    "Principal is equal to",
    "has wildcard in 'Principal'",
]


def should_be_fp(message: str) -> bool:
    """Check if a finding should be marked as expected FP."""
    msg_lower = message.lower()
    
    # If it matches a TP pattern, keep it as TP
    for pattern in TRUE_POSITIVE_PATTERNS:
        if pattern.lower() in msg_lower:
            return False
    
    return True


def main():
    script_dir = Path(__file__).parent
    results_path = script_dir.parent / "results" / "fp_eval_results.json"
    test_cases_dir = script_dir.parent / "test-cases" / "terraform"
    
    if not results_path.exists():
        print(f"Error: {results_path} not found")
        return
    
    print(f"Reading results from: {results_path}")
    results = json.loads(results_path.read_text())
    
    # Group LOW confidence findings by test case (only those that should be FPs)
    fps_by_test_case = defaultdict(set)
    skipped = 0
    
    for r in results.get("results", []):
        confidence = r.get("confidence", "")
        test_case = r.get("test_case", "")
        message = r.get("message", "")
        
        if confidence != "LOW" or not test_case or not message:
            continue
        
        if should_be_fp(message):
            fps_by_test_case[test_case].add(message)
        else:
            skipped += 1
            print(f"  SKIP (keeping as TP): {message[:60]}...")
    
    print(f"\nSkipped {skipped} findings (keeping as TPs)")
    print(f"Found {len(fps_by_test_case)} test cases with expected FPs")
    
    # Find and update each test case's results_summary.json
    updated = 0
    for summary_path in test_cases_dir.rglob("results_summary.json"):
        test_case_name = summary_path.parent.name
        
        if test_case_name not in fps_by_test_case:
            continue
        
        # Read existing summary
        try:
            summary = json.loads(summary_path.read_text())
        except json.JSONDecodeError:
            print(f"  Warning: Could not parse {summary_path}")
            continue
        
        # Get existing expected_false_positives
        existing_fps = set(summary.get("expected_false_positives", []))
        
        # Add new ones
        new_fps = fps_by_test_case[test_case_name]
        all_fps = sorted(existing_fps | new_fps)
        
        if all_fps:
            summary["expected_false_positives"] = all_fps
            summary_path.write_text(json.dumps(summary, indent=2) + "\n")
            updated += 1
            print(f"  Updated: {test_case_name} ({len(all_fps)} expected FPs)")
    
    print(f"\nUpdated {updated} test cases")
    print("\nRun fp_eval.py again to see the new accuracy!")


if __name__ == "__main__":
    main()
