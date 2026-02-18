#!/bin/bash
# Run datadog-iac-scanner on all test cases to generate SARIF files
#
# Usage:
#   ./run_scanner.sh /path/to/datadog-iac-scanner [--limit N]

set -e

SCANNER="${1:-}"
LIMIT="${2:-0}"

if [ -z "$SCANNER" ]; then
    echo "Usage: ./run_scanner.sh /path/to/datadog-iac-scanner [--limit N]"
    echo ""
    echo "Example:"
    echo "  ./run_scanner.sh ~/dev/kics/bin/datadog-iac-scanner"
    echo "  ./run_scanner.sh ~/dev/kics/bin/datadog-iac-scanner --limit 5"
    exit 1
fi

if [ ! -x "$SCANNER" ]; then
    echo "Error: Scanner not found or not executable: $SCANNER"
    echo ""
    echo "Build it first:"
    echo "  cd ~/dev/kics && make build"
    exit 1
fi

# Handle --limit argument
if [ "$LIMIT" = "--limit" ]; then
    LIMIT="${3:-0}"
fi

cd "$(dirname "$0")/.."

TOTAL=$(find test-cases/terraform -name "main.tf" | wc -l | tr -d ' ')
echo "Found $TOTAL test cases"

if [ "$LIMIT" != "0" ]; then
    echo "Limiting to $LIMIT test cases"
fi

COUNT=0

find test-cases/terraform -name "main.tf" -exec dirname {} \; | sort | while read test_case; do
    COUNT=$((COUNT + 1))
    
    if [ "$LIMIT" != "0" ] && [ "$COUNT" -gt "$LIMIT" ]; then
        echo "Reached limit of $LIMIT test cases"
        break
    fi
    
    echo "[$COUNT/$TOTAL] Scanning: $test_case"
    mkdir -p "$test_case/sarif"
    
    "$SCANNER" scan \
        --path "$test_case" \
        --output-path "$test_case/sarif" \
        --output-name "datadog-iac-result.sarif" \
        --type terraform \
        --log-level error 2>&1 || echo "  Warning: scan failed for $test_case"
done

echo ""
echo "Scanning complete!"
echo "Generated SARIF files:"
find test-cases/terraform -name "datadog-iac-result.sarif" | wc -l | tr -d ' '
