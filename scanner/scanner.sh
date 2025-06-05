#!/bin/bash
# SecureCodeBox Enhanced Rust Scanner Script
# Runs multiple security and quality tools: cargo-audit, cargo-deny, cargo-geiger, and clippy

# Function to output valid JSON even in error cases
output_error_json() {
    local error_message="$1"
    local output_file="${RESULTS_FILE:-/home/securecodebox/scan-results.json}"
    
    cat > "$output_file" <<EOF
{
    "scan_type": "rust-multi-scanner",
    "scan_timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "cargo_audit": {
        "vulnerabilities": {
            "found": false,
            "count": 0,
            "list": []
        },
        "warnings": [{
            "message": "$error_message",
            "kind": "scanner-error"
        }]
    },
    "cargo_deny": null,
    "cargo_geiger": null,
    "clippy": null
}
EOF
    chmod 644 "$output_file"
    log "Error JSON written to $output_file"
}

# Diagnostic output goes to stderr to keep stdout clean for JSON
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

log "Starting Enhanced Rust security scan..."

# SecureCodeBox expects results at this specific location
# For local runs, use /tmp if the default location isn't writable
DEFAULT_RESULTS="/home/securecodebox/scan-results.json"
if [ -z "$RESULTS_FILE" ]; then
    if [ -w "$(dirname "$DEFAULT_RESULTS" 2>/dev/null)" ] || mkdir -p "$(dirname "$DEFAULT_RESULTS")" 2>/dev/null; then
        RESULTS_FILE="$DEFAULT_RESULTS"
    else
        RESULTS_FILE="/tmp/scan-results.json"
        log "Using fallback location: $RESULTS_FILE"
    fi
fi
log "Results will be written to: $RESULTS_FILE"

# Work around cargo's requirement for a writable home directory
export HOME=/tmp/scanner-home
mkdir -p "$HOME/.cargo"

log "Scanner versions:"
command -v cargo-audit >/dev/null 2>&1 && log " - cargo-audit: $(cargo audit --version 2>&1)" || log " - cargo-audit: NOT INSTALLED"
command -v cargo-deny >/dev/null 2>&1 && log " - cargo-deny: $(cargo deny --version 2>&1)" || log " - cargo-deny: NOT INSTALLED"
command -v cargo-geiger >/dev/null 2>&1 && log " - cargo-geiger: $(cargo geiger --version 2>&1)" || log " - cargo-geiger: NOT INSTALLED"
command -v cargo-clippy >/dev/null 2>&1 && log " - clippy: $(cargo clippy --version 2>&1)" || log " - clippy: NOT INSTALLED"

# Initialize result structure
COMBINED_RESULTS=$(cat <<EOF
{
    "scan_type": "rust-multi-scanner",
    "scan_timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "project_path": "$(pwd)",
    "cargo_audit": null,
    "cargo_deny": null,
    "cargo_geiger": null,
    "clippy": null
}
EOF
)

# Function to run a tool and capture its output
run_tool() {
    local tool_name="$1"
    local tool_command="$2"
    local temp_output=$(mktemp)
    local temp_errors=$(mktemp)
    
    log "Running $tool_name..."
    
    if timeout 300 bash -c "$tool_command" > "$temp_output" 2> "$temp_errors"; then
        local exit_code=$?
        log "$tool_name completed with exit code: $exit_code"
        
        if [ -s "$temp_output" ]; then
            echo "$(<"$temp_output")"
        else
            log "WARNING: $tool_name produced no output"
            log "Error output: $(<"$temp_errors")"
            echo "null"
        fi
    else
        local exit_code=$?
        log "ERROR: $tool_name failed with exit code: $exit_code"
        log "Error output:"
        cat "$temp_errors" >&2
        echo "null"
    fi
    
    rm -f "$temp_output" "$temp_errors"
}

# Check for Cargo.toml (required for all tools)
if [ ! -f "Cargo.toml" ]; then
    log "ERROR: No Cargo.toml found in $(pwd)"
    output_error_json "No Cargo.toml file found in scan directory"
    exit 0
fi

# 1. Run cargo-audit for vulnerability scanning
if [ -f "Cargo.lock" ]; then
    # Note: cargo-audit exit codes: 0=no vulns, 1=vulns found, 2+=error
    AUDIT_TEMP=$(mktemp)
    if cargo audit --json > "$AUDIT_TEMP" 2>&1; then
        AUDIT_EXIT=$?
        if [ $AUDIT_EXIT -eq 0 ] || [ $AUDIT_EXIT -eq 1 ]; then
            AUDIT_RESULT=$(cat "$AUDIT_TEMP")
            COMBINED_RESULTS=$(echo "$COMBINED_RESULTS" | jq --argjson audit "$AUDIT_RESULT" '.cargo_audit = $audit')
        else
            log "ERROR: cargo-audit failed with exit code $AUDIT_EXIT"
            cat "$AUDIT_TEMP" >&2
            COMBINED_RESULTS=$(echo "$COMBINED_RESULTS" | jq '.cargo_audit = {"error": "cargo-audit failed"}')
        fi
    else
        AUDIT_EXIT=$?
        log "ERROR: cargo-audit command failed with exit code $AUDIT_EXIT"
        cat "$AUDIT_TEMP" >&2
        COMBINED_RESULTS=$(echo "$COMBINED_RESULTS" | jq '.cargo_audit = {"error": "cargo-audit command failed"}')
    fi
    rm -f "$AUDIT_TEMP"
else
    log "WARNING: No Cargo.lock found - skipping cargo-audit"
    COMBINED_RESULTS=$(echo "$COMBINED_RESULTS" | jq '.cargo_audit = {"warning": "No Cargo.lock file found"}')
fi

# 2. Run cargo-deny for license and dependency checks
if command -v cargo-deny >/dev/null 2>&1; then
    # First, create a basic deny.toml if it doesn't exist
    if [ ! -f "deny.toml" ]; then
        log "Creating default deny.toml configuration..."
        cat > deny.toml <<'DENY_CONFIG'
[bans]
multiple-versions = "warn"
wildcards = "allow"
skip-tree = []

[licenses]
confidence-threshold = 0.8
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-3-Clause",
    "ISC",
]
copyleft = "warn"

[sources]
unknown-registry = "warn"
unknown-git = "warn"
DENY_CONFIG
    fi

    # cargo-deny requires Cargo.lock
    if [ -f "Cargo.lock" ]; then
        # Run cargo-deny check and capture output as JSON-like structure
        DENY_OUTPUT=$(mktemp)
        if cargo deny check --format json 2>/dev/null > "$DENY_OUTPUT"; then
            DENY_RESULT=$(cat "$DENY_OUTPUT")
        else
            # If JSON format fails, try to capture text output
            DENY_TEXT=$(cargo deny check 2>&1) || true
            DENY_RESULT=$(jq -n --arg text "$DENY_TEXT" '{format: "text", output: $text}')
        fi
        rm -f "$DENY_OUTPUT"
        COMBINED_RESULTS=$(echo "$COMBINED_RESULTS" | jq --argjson deny "$DENY_RESULT" '.cargo_deny = $deny')
    else
        log "WARNING: No Cargo.lock found - skipping cargo-deny"
        COMBINED_RESULTS=$(echo "$COMBINED_RESULTS" | jq '.cargo_deny = {"warning": "No Cargo.lock file found"}')
    fi
else
    log "WARNING: cargo-deny not installed - skipping license and dependency checks"
    COMBINED_RESULTS=$(echo "$COMBINED_RESULTS" | jq '.cargo_deny = {"warning": "Tool not installed"}')
fi

# 3. Run cargo-geiger for unsafe code detection
if command -v cargo-geiger >/dev/null 2>&1; then
    if [ -f "Cargo.lock" ]; then
        # cargo-geiger doesn't have native JSON output, so we'll capture and parse text
        GEIGER_OUTPUT=$(cargo geiger --no-default-features 2>&1) || true
        
        # Extract key metrics from geiger output
        UNSAFE_USED=$(echo "$GEIGER_OUTPUT" | grep -oP '(?<=Metric output format: x/y)[[:space:]]+\K[0-9]+' | head -1 || echo "0")
        UNSAFE_TOTAL=$(echo "$GEIGER_OUTPUT" | grep -oP '(?<=Metric output format: x/y)[[:space:]]+[0-9]+/\K[0-9]+' | head -1 || echo "0")
        
        GEIGER_RESULT=$(jq -n \
            --arg output "$GEIGER_OUTPUT" \
            --arg used "$UNSAFE_USED" \
            --arg total "$UNSAFE_TOTAL" \
            '{
                unsafe_code_used: ($used | tonumber),
                unsafe_code_total: ($total | tonumber),
                raw_output: $output
            }')
        
        COMBINED_RESULTS=$(echo "$COMBINED_RESULTS" | jq --argjson geiger "$GEIGER_RESULT" '.cargo_geiger = $geiger')
    else
        log "WARNING: No Cargo.lock found - skipping cargo-geiger"
        COMBINED_RESULTS=$(echo "$COMBINED_RESULTS" | jq '.cargo_geiger = {"warning": "No Cargo.lock file found"}')
    fi
else
    log "WARNING: cargo-geiger not installed - skipping unsafe code analysis"
    COMBINED_RESULTS=$(echo "$COMBINED_RESULTS" | jq '.cargo_geiger = {"warning": "Tool not installed"}')
fi

# 4. Run clippy for code quality issues
# Build the project first to ensure dependencies are available
log "Building project for clippy analysis..."
if cargo build --all-targets >&2 2>&1; then
    # Run clippy with JSON output
    CLIPPY_OUTPUT=$(cargo clippy --all-targets --message-format=json 2>&1) || true
    
    # Filter only compiler messages (clippy warnings/errors)
    CLIPPY_MESSAGES=$(echo "$CLIPPY_OUTPUT" | jq -s '[.[] | select(.reason == "compiler-message")]' 2>/dev/null || echo "[]")
    
    CLIPPY_RESULT=$(jq -n --argjson messages "$CLIPPY_MESSAGES" '{
        total_warnings: ($messages | length),
        messages: $messages
    }')
    
    COMBINED_RESULTS=$(echo "$COMBINED_RESULTS" | jq --argjson clippy "$CLIPPY_RESULT" '.clippy = $clippy')
else
    log "WARNING: Build failed - skipping clippy"
    COMBINED_RESULTS=$(echo "$COMBINED_RESULTS" | jq '.clippy = {"warning": "Build failed"}')
fi

# Write combined results
echo "$COMBINED_RESULTS" > "$RESULTS_FILE"
chmod 644 "$RESULTS_FILE" 2>/dev/null || true
log "Combined scan results written to $RESULTS_FILE ($(stat -c%s "$RESULTS_FILE" 2>/dev/null || echo "unknown") bytes)"

# Also output to stdout for docker run capture
echo "$COMBINED_RESULTS"

log "Enhanced scanner completed successfully"