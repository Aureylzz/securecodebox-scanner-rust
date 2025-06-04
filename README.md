# SecureCodeBox Rust security scanner

A security scanner for [SecureCodeBox](https://www.securecodebox.io/) that detects vulnerabilities in Rust projects by analyzing their dependencies against the [RustSec Advisory Database](https://rustsec.org/).

## Project overview

This scanner integrates cargo-audit into SecureCodeBox, enabling automated security scanning of Rust projects in our CI/CD pipeline. It identifies known vulnerabilities in dependencies and provides actionable remediation advice.

### Key Features

- Detects security vulnerabilities in Rust dependencies
- Transforms findings into SecureCodeBox's standardized format
- Fully containerized for consistent execution
- Easy integration via Helm chart
- Runs with proper security isolation (non-root users)

## Table of contents

1. [Understanding the SecureCodeBox Architecture](#understanding-the-securecodebox-architecture)
2. [Rust Security Tools Selection](#rust-security-tools-selection)
3. [Usage](#usage)
4. [Development](#development)
5. [Docker Images](#docker-images)
6. [SecureCodeBox Integration](#securecodebox-integration)

## Prerequisites

**For running the scanner:**

- Docker installed and running

```bash
# If you have a deprecation warning, during the build, about buildx, run the following commands:

# Create the directory structure where Docker expects to find CLI plugins
sudo mkdir -p /usr/local/lib/docker/cli-plugins

# Create a symbolic link pointing to the buildx plugin location to allow Docker to find buildx regardless of which path it checks
sudo ln -s /usr/lib/docker/cli-plugins/docker-buildx /usr/local/lib/docker/cli-plugins/docker-buildx
```

**For SecureCodeBox deployment:**

- Kubernetes cluster
- Helm
- SecureCodeBox operator installed

**For development:**

- `jq` - for JSON processing in tests: `sudo apt-get install jq`
- `git` - for cloning the repository

## Understanding the SecureCodeBox architecture

### SecureCodeBox Components

SecureCodeBox orchestrates security scanners through these components:

1. **Scanner Container**: Runs cargo-audit to detect vulnerabilities
2. **Lurker Sidecar**: Captures scanner output automatically
3. **Parser Container**: Transforms cargo-audit JSON into SecureCodeBox findings
4. **Helm Chart**: Defines deployment configuration
5. **ScanType CRD**: Tells SecureCodeBox how to execute scans

### Workflow

1. User creates a Scan custom resource
2. SecureCodeBox creates a Job with scanner + lurker containers  
3. Scanner analyzes Rust project and outputs JSON
4. Lurker captures the results
5. Parser transforms to SecureCodeBox format
6. Findings are stored and displayed

### Repository structure

```
securecodebox-scanner-rust/
├── scanner/          # Scanner container that runs cargo-audit
├── parser/           # Parser container that transforms results
├── helm/            # Helm chart for SecureCodeBox deployment
├── tests/           # Integration tests and fixtures
└── examples/        # Example usage (coming soon)
```

## Rust Security Tools Selection

Currently implemented:

1. **cargo-audit**: Vulnerability scanner for dependencies
   - Checks Cargo.lock against RustSec Advisory Database
   - Identifies known CVEs and security advisories

Future enhancements planned:

- cargo-deny: Supply chain security and license compliance
- clippy: Security-focused lints
- cargo-geiger: Unsafe code detection

## Usage

### Quick Demo

Run the scanner on a Rust project with known vulnerabilities:

```bash
# Clone and test with the vulnerable example
docker run --rm -v "$(pwd)/tests/fixtures/vulnerable_crate":/scan \
  aureylz/scb-rust-scan:latest
```

### Running the Complete Pipeline

```bash
# 1. Scan a Rust project (must contain Cargo.lock)
docker run --rm -v /path/to/rust/project:/scan \
  aureylz/scb-rust-scan:latest > scan-results.json

# 2. Parse results into SecureCodeBox format
docker run --rm -v $(pwd)/scan-results.json:/tmp/scan.json \
  -e SCAN_RESULTS_FILE=/tmp/scan.json \
  aureylz/scb-rust-parser:latest
```

### Example Output

The scanner detects vulnerabilities like RUSTSEC-2020-0071:

```json
  {
    "name": "RUSTSEC-2020-0071: Potential segfault in the time crate",
    "description": "Bla bla bla",
    "category": "Vulnerable Dependency",
    "severity": "HIGH",
    "osi_layer": "APPLICATION",
    "attributes": {
      "rustsec_id": "RUSTSEC-2020-0071",
      "package": "time",
      "affected_versions": ">=0.2.23",
      "installed_version": "0.1.45",
      "date": "2020-11-18",
      "url": "https://github.com/time-rs/time/issues/293",
      "cve": "CVE-2020-26235",
      "cvss": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
      "categories": "code-execution, memory-corruption",
      "keywords": "segfault",
      "patched_versions": ">=0.2.23",
      "unaffected_versions": "=0.2.0, =0.2.1, =0.2.2, =0.2.3, =0.2.4, =0.2.5, =0.2.6"
    },
    "location": "time@0.1.45"
  }
```

## Development

### Building Images

```bash
# Build scanner
docker build -t scb-rust-scan:dev ./scanner

# Build parser  
docker build -t scb-rust-parser:dev ./parser
```

### Running Tests

```bash
# Run integration test suite
cd tests/integration
./test-full-integration.sh
```

The test suite verifies:

- Detection of known vulnerabilities
- Handling of safe projects
- Graceful error handling

### Project Structure Details

- `scanner/scanner.sh`: Bash script that runs cargo-audit and handles results
- `parser/parser.js`: Node.js script that transforms findings
- `helm/`: Complete Helm chart for SecureCodeBox deployment
- `tests/fixtures/vulnerable_crate`: Test project with known vulnerability

## Docker Images

Official images are available on Docker Hub:

- Scanner: `aureylz/scb-rust-scan:latest`
- Parser: `aureylz/scb-rust-parser:latest`

Versioned tags are also available (e.g., `v0.1.1`, `v0.1.2`).

## SecureCodeBox Integration

### Installing the Scanner

```bash
# Install via Helm
helm install rust-scanner ./helm

# Verify installation
kubectl get scantypes
kubectl get parsedefinitions
```

### Running a Scan in SecureCodeBox

```yaml
apiVersion: "execution.securecodebox.io/v1"
kind: Scan
metadata:
  name: rust-project-scan
spec:
  scanType: rust-scan
  volumes:
    - name: project-code
      hostPath:
        path: /path/to/rust/project
  volumeMounts:
    - name: project-code
      mountPath: /scan
```

### Configuration Options

The Helm chart supports various configuration options in `values.yaml`:

- Scanner/parser image versions
- Resource limits
- Scan timeout
- Environment variables

## Contributing

Contributions are welcome! Areas for improvement:

- Add support for cargo-deny, clippy, cargo-geiger
- Implement severity filtering options
- Add support for private registries
- Improve error messages and logging

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
