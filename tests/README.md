# SecureCodeBox Rust Scanner Tests

This directory contains all test materials for the Rust security scanner.

## Structure

- `integration/` - Integration tests that verify the complete scanner pipeline
- `fixtures/` - Test projects and data used by the tests

## Running Tests

### Full Integration Test

Run the complete integration test suite:

```bash
cd tests/integration
./test-full-integration.sh
```

This test verifies:

1. Detection of known vulnerabilities (using `fixtures/vulnerable_crate`)
2. Correct handling of projects without vulnerabilities
3. Graceful handling of missing Cargo.lock files

### Test Fixtures

#### vulnerable_crate

A minimal Rust project with a known vulnerability (time crate 0.1.45 - RUSTSEC-2020-0071).
Used to verify the scanner correctly detects and reports vulnerabilities.

## Adding New Tests

When adding new test cases:

1. Place integration tests in `integration/`
2. Place test data and projects in `fixtures/`
3. Update this README with test descriptions

## Prerequisites

- Docker must be installed and running
- Scanner and parser images must be built:

  ```bash
  docker build -t scb-rust-scan:dev ../../scanner
  docker build -t scb-rust-parser:dev ../../parser
  ```
