# SecureCodeBox Rust Scanner Tests

This directory contains all test materials for the Rust security scanner. These tests verify that the scanner correctly detects vulnerabilities and integrates properly with SecureCodeBox.

## Structure

- `integration/` - Integration tests that verify the complete scanner pipeline
- `fixtures/` - Test projects and data used by the tests
  - `vulnerable_crate/` - A Rust project with a known vulnerability for testing

## Running Tests

### Prerequisites

Before running tests, ensure you have:

1. Docker installed and running
2. Built the scanner and parser images:

   ```bash
   docker build -t scb-rust-scan:dev ./scanner
   docker build -t scb-rust-parser:dev ./parser
   ```

3. `jq` installed for JSON processing: `sudo apt-get install jq`

### Full Integration Test

The integration test suite verifies three key scenarios:

```bash
cd tests/integration
./test-full-integration.sh
```

This test suite verifies:

1. **Vulnerability Detection**: Tests that the scanner correctly identifies RUSTSEC-2020-0071 in the time crate v0.1.45
2. **Clean Project Handling**: Verifies that projects without vulnerabilities report zero findings
3. **Error Handling**: Ensures the scanner gracefully handles missing Cargo.lock files

### Understanding the Test Project

The `fixtures/vulnerable_crate` directory contains a minimal Rust project that depends on time crate version 0.1.45. This version has a known vulnerability (RUSTSEC-2020-0071) that causes potential segfaults in multithreaded programs.

This vulnerability was chosen because:

- It's a real security issue, not a contrived example
- It's reliably detected by cargo-audit
- It demonstrates the scanner's ability to identify transitive dependencies with vulnerabilities

### Expected Results

When running the integration tests, you should see:

```
Test 1: ✓ SUCCESS: Expected 1 vulnerability, found 1
- Finding name: RUSTSEC-2020-0071: Potential segfault in the time crate
- Severity: HIGH
- Affected package: time@0.1.45

Test 2: ✓ SUCCESS: Expected 0 vulnerabilities, found 0

Test 3: ✓ SUCCESS: Correctly handled missing Cargo.lock
```

## Adding New Test Cases

To add new test scenarios:

1. Create a new fixture in `fixtures/` with the specific vulnerability or configuration you want to test
2. Add a new test section in `test-full-integration.sh`
3. Update this README with the new test description

### Example: Testing a Different Vulnerability

```bash
# Create a new test fixture
mkdir -p fixtures/another_vulnerable_crate
cd fixtures/another_vulnerable_crate

# Add a dependency with a known vulnerability
echo '[package]
name = "test_crate"
version = "0.1.0"
edition = "2021"

[dependencies]
# Add a crate with known vulnerabilities here
tokio = "0.1.15"  # Example: has RUSTSEC-2021-0124
' > Cargo.toml

# Generate the lock file
cargo generate-lockfile
```

## Manual Testing

You can also run individual components manually for debugging:

### Test Scanner Only

```bash
docker run --rm -v "$(pwd)/fixtures/vulnerable_crate":/scan scb-rust-scan:dev
```

### Test Parser Only

```bash
# First run scanner and save output
docker run --rm -v "$(pwd)/fixtures/vulnerable_crate":/scan scb-rust-scan:dev > scan-output.json

# Then test parser
docker run --rm -v "$(pwd)/scan-output.json":/tmp/scan.json scb-rust-parser:dev /tmp/scan.json
```

## Continuous Integration

These tests are designed to be run in CI/CD pipelines. The integration test script returns appropriate exit codes:

- 0: All tests passed
- 1: One or more tests failed

This makes it easy to integrate into GitHub Actions, GitLab CI, or other CI systems.
