#!/bin/bash

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FINDINGS_FILE="$SCRIPT_DIR/findings.json"

# Check if findings.json exists
if [ ! -f "$FINDINGS_FILE" ]; then
    echo "Error: findings.json not found at $FINDINGS_FILE"
    exit 1
fi

echo "=== SecureCodeBox Rust Scanner Findings Summary ==="
echo

# Total findings (dynamic)
TOTAL=$(jq 'length' "$FINDINGS_FILE")
echo "Total findings: $TOTAL"

# Count by severity (dynamic)
echo -e "\nFindings by severity:"
jq -r 'group_by(.severity) | map("  \(.[0].severity): \(length)") | .[]' "$FINDINGS_FILE" | sort -r

# Count by scanner (dynamic)
echo -e "\nFindings by scanner:"
jq -r 'group_by(.scanner) | map("  \(.[0].scanner): \(length)") | .[]' "$FINDINGS_FILE" | sort

# Dynamic summary table
echo -e "\n=== Summary Table ==="
echo "┌─────────────────────────────────────────────────────────────"
echo "│ Tool         │ Findings │ Details"
echo "├─────────────────────────────────────────────────────────────"

# cargo-audit row (dynamic)
AUDIT_COUNT=$(jq '[.[] | select(.scanner == "cargo-audit")] | length' "$FINDINGS_FILE")
AUDIT_DETAILS=$(jq -r '[.[] | select(.scanner == "cargo-audit")] | group_by(.severity) | map("\(length) \(.[0].severity)") | join(", ")' "$FINDINGS_FILE")
printf "│ %-12s │ %8s │ %s\n" "cargo-audit" "$AUDIT_COUNT" "$AUDIT_DETAILS"

# cargo-geiger row (dynamic)
GEIGER_COUNT=$(jq '[.[] | select(.scanner == "cargo-geiger")] | length' "$FINDINGS_FILE")
GEIGER_DETAILS=$(jq -r '[.[] | select(.scanner == "cargo-geiger")] | if length > 0 then .[0].attributes | "Unsafe code: \(.unsafe_code_used)/\(.unsafe_code_total) (\(.unsafe_percentage)%)" else "No findings" end' "$FINDINGS_FILE")
printf "│ %-12s │ %8s │ %s\n" "cargo-geiger" "$GEIGER_COUNT" "$GEIGER_DETAILS"

# clippy row (dynamic)
CLIPPY_COUNT=$(jq '[.[] | select(.scanner == "clippy")] | length' "$FINDINGS_FILE")
CLIPPY_DETAILS=$(jq -r '[.[] | select(.scanner == "clippy")] | if length > 0 then map(.attributes.lint_name) | unique | join(", ") else "No findings" end' "$FINDINGS_FILE")
printf "│ %-12s │ %8s │ %s\n" "clippy" "$CLIPPY_COUNT" "$CLIPPY_DETAILS"

echo "└─────────────────────────────────────────────────────────────"

# List all findings (dynamic)
echo -e "\n=== All Findings List ==="
jq -r 'to_entries | .[] | "\(.key + 1). [\(.value.severity)] \(.value.name) (\(.value.scanner))"' "$FINDINGS_FILE"

# High severity vulnerabilities with CVEs (dynamic)
HIGH_COUNT=$(jq '[.[] | select(.severity == "HIGH")] | length' "$FINDINGS_FILE")
if [ "$HIGH_COUNT" -gt 0 ]; then
    echo -e "\n=== High Severity Vulnerabilities ($HIGH_COUNT found) ==="
    jq -r '.[] | select(.severity == "HIGH") | "• \(.name)\n  CVE: \(.attributes.cve // "N/A")\n  Package: \(.attributes.package)@\(.attributes.installed_version)\n  Fix: \(.attributes.patched_versions)"' "$FINDINGS_FILE"
fi