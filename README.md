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

## Understanding the SecureCodeBox architecture

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

## Rust Security Tools Selection

For a minimal Rust security analysis, we imagined to integrate several tools:

### Primary Tools

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
