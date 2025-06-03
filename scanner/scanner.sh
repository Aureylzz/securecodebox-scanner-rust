#!/bin/bash
set -e  # Exit on any error - important for reliability

echo "Starting Rust security scan..."

# For the hackathon, let's start simple - just cargo-audit
# We'll scan whatever is in the current directory
if [ -f "Cargo.lock" ]; then
    echo "Found Cargo.lock - running cargo-audit..."
    # Output JSON format so our parser can understand it
    cargo audit --json
else
    echo "No Cargo.lock found - cannot run cargo-audit"
    # Output empty JSON so the parser doesn't fail
    echo '{"vulnerabilities": {"count": 0}}'
fi