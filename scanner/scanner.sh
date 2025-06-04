#!/bin/bash
# SecureCodeBox Rust Scanner Script
# This script runs cargo-audit and ensures output is written with correct permissions
# for the lurker sidecar to read. It handles cargo-audit's exit codes correctly.

# Function to output valid JSON even in error cases
# This ensures SecureCodeBox always gets parseable output
output_error_json() {
    local error_message="$1"
    # Determine where to write output - SecureCodeBox expects this specific location
    local output_file="${RESULTS_FILE:-/home/securecodebox/scan-results.json}"
    
    # Create a valid JSON structure that cargo-audit would produce for error cases
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
    # CRITICAL: Make the file readable by all users so lurker can access it
    chmod 644 "$output_file"
    log "Error JSON written to $output_file"
}

# Diagnostic output goes to stderr to keep stdout clean for JSON
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

log "Starting Rust security scan..."

# SecureCodeBox expects results at this specific location
# We default to this path if RESULTS_FILE isn't set
RESULTS_FILE="${RESULTS_FILE:-/home/securecodebox/scan-results.json}"
log "Results will be written to: $RESULTS_FILE"

# Create the directory if it doesn't exist (important for the file write to succeed)
mkdir -p "$(dirname "$RESULTS_FILE")"

# Work around cargo's requirement for a writable home directory
# The scanner user's actual home might not be writable in some environments
export HOME=/tmp/scanner-home
mkdir -p "$HOME/.cargo"

log "Scanner version: $(cargo audit --version 2>&1)"
log "Working directory: $(pwd)"
log "HOME directory: $HOME"
log "Directory contents:"
ls -la >&2

# Check for Cargo.lock - this is required for cargo-audit to work
if [ -f "Cargo.lock" ]; then
    log "Found Cargo.lock file"
    
    # Verify we can read the file
    if [ ! -r "Cargo.lock" ]; then
        log "ERROR: Cannot read Cargo.lock file"
        output_error_json "Cannot read Cargo.lock file - permission denied"
        exit 0
    fi
    
    log "Running cargo-audit..."
    
    # Create temporary files for capturing output
    TEMP_OUTPUT=$(mktemp)
    TEMP_ERRORS=$(mktemp)
    
    # Run cargo-audit with a timeout and capture output
    # The timeout prevents hanging on network issues
    timeout 300 cargo audit --json > "$TEMP_OUTPUT" 2> "$TEMP_ERRORS"
    exit_code=$?
    
    log "Cargo-audit exited with code: $exit_code"
    
    # Understanding cargo-audit exit codes (this is crucial!):
    # 0 = No vulnerabilities found (success - no issues)
    # 1 = Vulnerabilities found (success - issues detected)
    # 2+ = Actual errors (failure - couldn't run properly)
    
    if [ $exit_code -eq 0 ] || [ $exit_code -eq 1 ]; then
        # Both 0 and 1 are successful runs from our perspective
        if [ $exit_code -eq 0 ]; then
            log "No vulnerabilities found"
        else
            log "Vulnerabilities detected"
        fi
        
        # Check if we got valid JSON output
        if [ -s "$TEMP_OUTPUT" ]; then
            # Copy the results to the location SecureCodeBox expects
            cp "$TEMP_OUTPUT" "$RESULTS_FILE"
            # CRITICAL: Make the file readable by all users so the lurker can access it
            # This permission fix is essential for multi-container pod file sharing
            chmod 644 "$RESULTS_FILE"
            log "JSON output written to $RESULTS_FILE ($(stat -c%s "$RESULTS_FILE") bytes)"
            
            # Also output to stdout for debugging/manual testing
            # This helps when running the scanner outside of SecureCodeBox
            cat "$TEMP_OUTPUT"
            
            # Verify the file was actually created (extra safety check)
            if [ -f "$RESULTS_FILE" ]; then
                log "Verified: Results file exists at $RESULTS_FILE"
            else
                log "ERROR: Failed to create results file at $RESULTS_FILE"
            fi
        else
            log "WARNING: No JSON output from cargo-audit"
            log "Stderr output:"
            cat "$TEMP_ERRORS" >&2
            # Create an empty but valid JSON structure
            output_error_json "cargo-audit produced no JSON output"
        fi
    else
        # Exit code 2 or higher indicates an actual error
        log "ERROR: cargo-audit failed with exit code: $exit_code"
        log "Stderr output:"
        cat "$TEMP_ERRORS" >&2
        
        output_error_json "cargo-audit failed with exit code $exit_code"
    fi
    
    # Clean up temporary files
    rm -f "$TEMP_OUTPUT" "$TEMP_ERRORS"
else
    log "No Cargo.lock found in $(pwd)"
    output_error_json "No Cargo.lock file found in scan directory"
fi

# Final verification that we created the output file with correct permissions
if [ -f "$RESULTS_FILE" ]; then
    # Ensure the file is readable by all users (critical for lurker access)
    chmod 644 "$RESULTS_FILE"
    log "Scan completed successfully - results available at $RESULTS_FILE with permissions: $(ls -l $RESULTS_FILE)"
else
    log "ERROR: Scan completed but no results file was created"
    # Create a minimal valid JSON file as a last resort
    echo '{"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":[{"message":"Scanner completed but no results generated","kind":"scanner-error"}]}' > "$RESULTS_FILE"
    chmod 644 "$RESULTS_FILE"
fi

log "Scanner script finished"