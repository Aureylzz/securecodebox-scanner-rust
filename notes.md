# Notes

This document is just a small notebook to help me track my progress, jot down my ideas, and possibly reuse this workflow later when creating the documentation or preparing the PowerPoint presentation.

## Steps

### Step 1 - Docker Container Creation

- **Docker image preparation**: We built a container with the Rust toolchain, so we make sure we have a constant scanning regardless of where it runs.
- **JSON output**: We use cargo audit --json because structured data is easier for the parser to process than human-readable text.

### Step 2 - Test Vulnerability Creation

I've created a small rust binary with `'time = "0.1"'` which is known to have a vulnerability. This serves as our test case to verify the scanner works correctly.

### Step 3 - Scanner Implementation

Successfully built the Docker image with:

- **Base image**: rust:1.87-slim (resolved earlier version conflicts)
- **Security tools**: cargo-audit v0.21.2 installed with locked dependencies
- **Non-root user**: Scanner runs as 'scanner' user for security
- **Build time**: ~79 seconds (mostly cargo-audit compilation)

### Step 4 - First Successful Scan

Ran the scanner against our vulnerable test crate and successfully detected RUSTSEC-2020-0071:

- **Vulnerability**: Potential segfault in the time crate v0.1.45
- **Severity**: High (CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **Impact**: Can cause crashes in multithreaded programs on Unix-like systems
- **Output format**: JSON with structured vulnerability data ready for parsing

The scanner correctly identified that time 0.1.45 has a known vulnerability where environment variables are set without synchronization, potentially causing segfaults in multithreaded programs. This proves our scanner is working!

### Step 5 - Scanner Exit Code Issue and Resolution

Discovered that cargo-audit returns exit code 1 when vulnerabilities are found, which our script initially treated as an error:

- **Problem**: Scanner reported "failed" when it actually found vulnerabilities successfully
- **Root cause**: cargo-audit uses exit code 1 to indicate "vulnerabilities found" (not an error!)
- **Solution**: Modified scanner.sh to treat exit codes 0 and 1 as success, only 2+ as actual errors

Also addressed the home directory issue:

- **Problem**: System user had HOME=/nonexistent
- **Workaround**: Set HOME=/tmp/scanner-home in script
- **Better fix**: Changed Dockerfile to use `useradd -m` instead of `adduser --system`

### Step 6 - Parser Implementation

Created Node.js parser to transform cargo-audit JSON into SecureCodeBox findings:

- **Extracts**: RUSTSEC IDs, CVE numbers, CVSS scores, affected versions
- **Calculates**: Severity from CVSS data (HIGH if A:H, C:H, or I:H)
- **Preserves**: Full descriptions, remediation advice, and metadata
- **Output**: SecureCodeBox-compatible finding format

### Step 7 - Integration Testing

Built comprehensive test suite (test-full-integration.sh):

- **Test 1**: Vulnerable project - correctly detects time crate vulnerability
- **Test 2**: Safe project - reports zero vulnerabilities
- **Test 3**: Missing Cargo.lock - handles gracefully with warning

All tests passed! The complete pipeline works end-to-end.

### Future enhancements

- Add cargo-deny for license compliance
- Integrate clippy for code quality issues
- Add cargo-geiger for unsafe code detection
- Create comprehensive test suite

## Technical Insights

### Docker BuildKit Resolution

Initially encountered BuildKit errors due to leftover Docker Desktop symlinks after switching to native Docker on WSL2. Resolved by understanding that:

- Docker Desktop created symlinks in `/usr/local/lib/docker/cli-plugins/`
- These pointed to `/mnt/wsl/docker-desktop/` which no longer existed
- Native Docker installation uses different paths

### Rust Version Compatibility

Learned about transitive dependency requirements:

- cargo-audit itself works with Rust 1.81+
- But its dependencies (ICU libraries) required Rust 1.82+
- Using `--locked` flag prevents pulling newer incompatible versions
- Upgrading to Rust 1.87 provided sufficient headroom

### Understanding cargo-audit Exit Codes

Key learning: cargo-audit uses exit codes to communicate results, not just success/failure:

- Exit code 0: No vulnerabilities found
- Exit code 1: Vulnerabilities found (this is a SUCCESS case!)
- Exit code 2+: Actual errors

This is similar to grep - exit code 1 means "no matches" which is still a successful run.

## Ideas

- Consider caching cargo-audit installation in a separate build stage to speed up builds
- Add a configuration file to customize which checks to run
- Implement severity filtering (only report HIGH/CRITICAL)
- Add progress indicators for long-running scans

## Commands

Create the directories structure:
`mkdir -p scanner parser helm/templates examples tests`

Build the scanner:
`docker build -t scb-rust-scan:dev ./scanner`

Run a scan:
`docker run --rm -v "$(pwd)/tests/vulnerable_crate":/scan scb-rust-scan:dev > scan-output.json`

Build the parser:
`docker build -t scb-rust-parser:dev ./parser`

Parse results:
`docker run --rm -v "$(pwd)/scan-output.json":/tmp/scan.json scb-rust-parser:dev /tmp/scan.json`

Run integration tests:
`cd tests/integration && ./test-full-integration.sh`

## Links

- <https://hub.docker.com/_/rust>
- <https://github.com/RustSec/rustsec>
- <https://rustsec.org/advisories/RUSTSEC-2020-0071.html>
