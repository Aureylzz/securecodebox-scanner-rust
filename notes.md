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

## Next Steps

### Immediate tasks

1. Create the parser to transform cargo-audit JSON into SecureCodeBox findings format
2. Test with more complex projects (multiple vulnerabilities, no vulnerabilities)
3. Add error handling for projects without Cargo.lock

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

## Links

- <https://hub.docker.com/_/rust>
- <https://github.com/RustSec/rustsec>
- <https://rustsec.org/advisories/RUSTSEC-2020-0071.html>
