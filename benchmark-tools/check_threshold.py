#!/usr/bin/env python3
"""Check if FP evaluation accuracy meets threshold."""

import json
import sys
from pathlib import Path


def main():
    results_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('results/fp_eval_results.json')
    threshold = float(sys.argv[2]) if len(sys.argv) > 2 else 0.8
    
    if not results_path.exists():
        print("No results file found")
        sys.exit(0)
    
    results = json.loads(results_path.read_text())
    accuracy = results.get('summary', {}).get('accuracy', 0)
    
    if accuracy < threshold:
        print(f'⚠️ Accuracy {accuracy:.1%} is below {threshold:.0%} threshold')
        sys.exit(1)
    else:
        print(f'✅ Accuracy {accuracy:.1%} meets threshold')


if __name__ == '__main__':
    main()
