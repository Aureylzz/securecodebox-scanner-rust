# SecureCodeBox Rust security scanner

## Project overview

This project implements a personnal scanner for SecureCodeBox that analyzes Rust code for security issues. It will integrate several Rust tools in
order to provide a simple analysis containin:

- Dependency vulnerabilities analysis
- Code quality issues analysis
- Potential security flaws.

## Table of contents

1. [Understanding the SecureCodeBox Architecture](#understanding-the-securecodebox-architecture)
2. [Rust Security Tools Selection](#rust-security-tools-selection)
3. [Usage](#usage)
4. [Development](#development)

## Prerequisites

**Having Docker installed and able to run.**  
If you have a deprecation warning, during the build, about buildx, run the following commands:

```bash
# Create the directory structure where Docker expects to find CLI plugins
sudo mkdir -p /usr/local/lib/docker/cli-plugins

# Create a symbolic link pointing to the buildx plugin location to allow Docker to find buildx regardless of which path it checks
sudo ln -s /usr/lib/docker/cli-plugins/docker-buildx /usr/local/lib/docker/cli-plugins/docker-buildx
```

**Additional tools needed for development and testing:**

- `jq` - for JSON processing in tests: `sudo apt-get install jq`
- `git` - for cloning the repository

## Understanding the SecureCodeBox architecture

### SecureCodeBox functionning

Before implementing the scanner, we need to understand how SecureCodeBox works...

It's divided into 5 core components:

1. **Scanner Container**: Run the security tool (in our case, it will be a Rust security tool)
2. **Lurker Sidecar**: Capture the scanner output and store it in a kind of S3 local storage
3. **Parser Container**: Transform the raw scanner output into SecureCodeBox's standardized format
4. **Helm Chart**: Define the scanner configuration and deployment specifications (at the moment, it's the most mystic part for me...)
5. **ScanType CRD**: Custom Resource Definition that tells SecureCodeBox how to run the scanner

In my understanding, the workflow seems to be the following:

1. User creates Scan CR
2. Operator creates Scanner Job
3. Scanner runs
4. Lurker captures output
5. Parser transforms results
6. Findings stored

### Repository structure

```bash
┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ tree -I 'target'
.
├── examples
├── LICENSE
├── notes.md
├── parser
│   ├── Dockerfile
│   ├── package.json
│   └── parser.js
├── README.md
├── scanner
│   ├── Dockerfile
│   └── scanner.sh
└── tests
    ├── fixtures
    │   └── vulnerable_crate
    │       ├── Cargo.lock
    │       ├── Cargo.toml
    │       └── src
    │           └── main.rs
    └── integration
        └── test-full-integration.sh
```

#### The scanner directory

It will contain the Docker image that will run the Rust security tools. This is where the work begins because it's the heart of the scanner. Without it, there's nothing to parse or deploy...

#### The parser directory

It will transform the raw tool output into SecureCodeBox's finding format. It's a kind of adapter between what Rust tools say and what SecureCodeBox understands.

#### The helm directory

As I said, it's kinda mystical now, but it's simply a package manager for Kubernetes. It tells SecureCodeBox "here's how to run my scanner" in a standardized way.

## Rust Security Tools Selection

For a minimal Rust security analysis, we imagined to integrate several tools:

1. **cargo-audit:** A vulnerability scanner for dependencies
   - Checks Cargo.lock against RustSec Advisory Database
   - Identifies known security vulnerabilities in dependencies

2. **cargo-deny:** Supply chain security
   - Checks for security advisories
   - License compliance
   - Duplicate dependencies
   - Banned dependencies

3. **clippy:** Rust linter with security-focused lints
   - Detects common mistakes and anti-patterns
   - Includes security-relevant checks

4. **cargo-geiger:** Unsafe code detection
   - Counts unsafe code usage
   - Helps identify potential security risks

(Nota Bene: At this stage, I'm not sure everything will be implemented for the end of the Hackathon...)

## Usage

### Running the Scanner

To scan a Rust project for vulnerabilities:

```bash
# Build the scanner image
docker build -t scb-rust-scan:dev ./scanner

# Run the scanner on a Rust project (must contain Cargo.lock)
docker run --rm -v /path/to/rust/project:/scan scb-rust-scan:dev
```

### Running the Complete Pipeline

```bash
# Build both images
docker build -t scb-rust-scan:dev ./scanner
docker build -t scb-rust-parser:dev ./parser

# Run scanner and save output
docker run --rm -v /path/to/rust/project:/scan scb-rust-scan:dev > scan-results.json

# Parse the results
docker run --rm -v $(pwd)/scan-results.json:/tmp/scan.json scb-rust-parser:dev /tmp/scan.json
```

## Development

### Testing

Run the integration test suite:

```bash
cd tests/integration
./test-full-integration.sh
```

This will test:

- Detection of known vulnerabilities
- Handling of safe projects  
- Graceful error handling for missing Cargo.lock
