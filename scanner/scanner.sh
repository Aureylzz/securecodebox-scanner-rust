#!/bin/bash

# Logging to stderr
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

# Initialize JSON result
RESULT='{
  "scan_type": "rust-multi-scanner",
  "scan_timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
  "project_path": "'$(pwd)'",
  "cargo_audit": null,
  "cargo_deny": null,
  "cargo_geiger": null,
  "clippy": null
}'

# Setup environment
export HOME=/tmp/scanner-home
export CARGO_HOME="$HOME/.cargo"
mkdir -p "$CARGO_HOME"
cd /scan || exit 1

log "Starting scan in $(pwd)"

# 1. CARGO-AUDIT - Exit code 1 means vulnerabilities found, not an error!
if [ -f "Cargo.lock" ]; then
    log "Running cargo-audit..."
    
    # Run cargo-audit and capture output
    AUDIT_OUT=$(cargo audit --json 2>&1) || AUDIT_EXIT=$?
    
    # Exit codes: 0 = no vulns, 1 = vulns found, 2+ = error
    if [ "${AUDIT_EXIT:-0}" -le 1 ] && echo "$AUDIT_OUT" | jq . >/dev/null 2>&1; then
        # Valid JSON output from cargo-audit
        RESULT=$(echo "$RESULT" | jq --argjson audit "$AUDIT_OUT" '.cargo_audit = $audit')
        log "cargo-audit completed (exit code: ${AUDIT_EXIT:-0})"
    else
        # Not valid JSON or real error
        ERROR_JSON=$(jq -n --arg err "$AUDIT_OUT" '{error: $err}')
        RESULT=$(echo "$RESULT" | jq --argjson audit "$ERROR_JSON" '.cargo_audit = $audit')
        log "cargo-audit error"
    fi
else
    RESULT=$(echo "$RESULT" | jq '.cargo_audit = {"warning": "No Cargo.lock file found"}')
fi

# 2. CARGO-DENY
if command -v cargo-deny >/dev/null 2>&1 && [ -f "Cargo.lock" ]; then
    log "Running cargo-deny..."
    
    cat > deny.toml << 'DENYEOF'
[licenses]
unlicensed = "deny"
allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-3-Clause", "ISC", "Unicode-DFS-2016"]

[bans]
multiple-versions = "warn"
DENYEOF
    
    DENY_OUT=$(cargo deny check 2>&1) || true
    DENY_JSON=$(jq -n --arg output "$DENY_OUT" '{output: $output}')
    RESULT=$(echo "$RESULT" | jq --argjson deny "$DENY_JSON" '.cargo_deny = $deny')
    log "cargo-deny completed"
    
    rm -f deny.toml
fi

# 3. CARGO-GEIGER
if command -v cargo-geiger >/dev/null 2>&1 && [ -f "Cargo.lock" ]; then
    log "Running cargo-geiger..."
    
    if GEIGER_OUT=$(timeout 30 cargo geiger --quiet 2>&1); then
        # Look for the summary line
        if SUMMARY=$(echo "$GEIGER_OUT" | grep -E "^\s*[0-9]+/[0-9]+" | tail -1); then
            UNSAFE_USED=$(echo "$SUMMARY" | grep -oE '^[[:space:]]*[0-9]+' | tr -d '[:space:]')
            UNSAFE_TOTAL=$(echo "$SUMMARY" | grep -oE '[0-9]+[[:space:]]*$' | tr -d '[:space:]')
        else
            UNSAFE_USED="0"
            UNSAFE_TOTAL="0"
        fi
        
        GEIGER_JSON=$(jq -n \
            --arg used "${UNSAFE_USED:-0}" \
            --arg total "${UNSAFE_TOTAL:-0}" \
            '{unsafe_code_used: ($used | tonumber), unsafe_code_total: ($total | tonumber)}')
        RESULT=$(echo "$RESULT" | jq --argjson geiger "$GEIGER_JSON" '.cargo_geiger = $geiger')
        log "cargo-geiger completed: ${UNSAFE_USED:-0}/${UNSAFE_TOTAL:-0} unsafe"
    else
        RESULT=$(echo "$RESULT" | jq '.cargo_geiger = {"error": "timeout or failed"}')
    fi
fi

# 4. CLIPPY
if command -v cargo >/dev/null 2>&1; then
    log "Building project for clippy..."
    if cargo build --all-targets >&2 2>&1; then
        log "Running clippy..."
        CLIPPY_JSON=$(cargo clippy --all-targets --message-format=json 2>/dev/null | \
            grep '"reason":"compiler-message"' | \
            jq -s '[.[] | select(.message.code != null)]' || echo "[]")
        
        CLIPPY_COUNT=$(echo "$CLIPPY_JSON" | jq 'length')
        CLIPPY_RESULT=$(jq -n --argjson msgs "$CLIPPY_JSON" --arg count "$CLIPPY_COUNT" \
            '{total_warnings: ($count | tonumber), messages: $msgs}')
        RESULT=$(echo "$RESULT" | jq --argjson clippy "$CLIPPY_RESULT" '.clippy = $clippy')
        log "clippy completed: $CLIPPY_COUNT warnings"
    else
        RESULT=$(echo "$RESULT" | jq '.clippy = {"error": "build failed"}')
    fi
fi

# Write results
RESULTS_FILE="${RESULTS_FILE:-/home/securecodebox/scan-results.json}"
mkdir -p "$(dirname "$RESULTS_FILE")" 2>/dev/null || true
echo "$RESULT" > "$RESULTS_FILE" 2>/dev/null || echo "$RESULT" > /tmp/scan-results.json
chmod 644 "$RESULTS_FILE" 2>/dev/null || true

# Output to stdout
echo "$RESULT"

log "Scan completed"
