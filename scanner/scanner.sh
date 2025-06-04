#!/bin/bash
# Don't use 'set -e' as we need to handle exit codes ourselves

# Function to output valid JSON even in error cases
output_error_json() {
    local error_message="$1"
    # When running in SecureCodeBox, write to the expected location
    local output_file="${RESULTS_FILE:-/home/securecodebox/scan-results.json}"
    
    cat > "$output_file" <<EOF
{
    "vulnerabilities": {
        "found": false,
        "count": 0,
        "list": []
    },
    "warnings": [{
        "message": "$error_message",
        "kind": "scanner-error"
    }]
}
EOF
    log "Error JSON written to $output_file"
}

# Diagnostic output goes to stderr to keep stdout clean for JSON
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

log "Starting Rust security scan..."

# Determine output location - SecureCodeBox sets this, otherwise use stdout
RESULTS_FILE="${RESULTS_FILE:-/home/securecodebox/scan-results.json}"
log "Results will be written to: $RESULTS_FILE"

# Work around the /nonexistent home directory issue
# Set HOME to a writable location
export HOME=/tmp/scanner-home
mkdir -p "$HOME/.cargo"

log "Scanner version: $(cargo audit --version 2>&1)"
log "Working directory: $(pwd)"
log "HOME directory: $HOME"
log "Directory contents:"
ls -la >&2

# Check for Cargo.lock
if [ -f "Cargo.lock" ]; then
    log "Found Cargo.lock file"
    
    # Check if we can read it
    if [ ! -r "Cargo.lock" ]; then
        log "ERROR: Cannot read Cargo.lock file"
        output_error_json "Cannot read Cargo.lock file - permission denied"
        exit 0
    fi
    
    log "Running cargo-audit..."
    
    # Create temporary files for output
    TEMP_OUTPUT=$(mktemp)
    TEMP_ERRORS=$(mktemp)
    
    # Run cargo-audit and capture the exit code
    timeout 300 cargo audit --json > "$TEMP_OUTPUT" 2> "$TEMP_ERRORS"
    exit_code=$?
    
    log "Cargo-audit exited with code: $exit_code"
    
    # cargo-audit exit codes:
    # 0 = No vulnerabilities found
    # 1 = Vulnerabilities found (this is a "success" case for us!)
    # 2+ = Actual errors
    
    if [ $exit_code -eq 0 ] || [ $exit_code -eq 1 ]; then
        # Both 0 and 1 are successful runs
        if [ $exit_code -eq 0 ]; then
            log "No vulnerabilities found"
        else
            log "Vulnerabilities detected"
        fi
        
        # Check if we got valid JSON output
        if [ -s "$TEMP_OUTPUT" ]; then
            # Write to the expected location for SecureCodeBox
            cp "$TEMP_OUTPUT" "$RESULTS_FILE"
            log "JSON output written to $RESULTS_FILE ($(stat -c%s "$TEMP_OUTPUT") bytes)"
            
            # Also output to stdout for manual testing
            if [ "$RESULTS_FILE" != "/dev/stdout" ]; then
                cat "$TEMP_OUTPUT"
            fi
        else
            log "WARNING: No JSON output from cargo-audit"
            log "Stderr output:"
            cat "$TEMP_ERRORS" >&2
            # Output empty but valid JSON
            output_error_json "cargo-audit produced no JSON output"
        fi
    else
        # Exit code 2 or higher indicates an actual error
        log "ERROR: cargo-audit failed with exit code: $exit_code"
        log "Stderr output:"
        cat "$TEMP_ERRORS" >&2
        
        output_error_json "cargo-audit failed with exit code $exit_code"
    fi
    
    # Cleanup
    rm -f "$TEMP_OUTPUT" "$TEMP_ERRORS"
else
    log "No Cargo.lock found in $(pwd)"
    output_error_json "No Cargo.lock file found in scan directory"
fi

log "Scan completed"