# SecureCodeBox Rust Security Scanner

A PoC security scanner for [SecureCodeBox](https://www.securecodebox.io/) that detects vulnerabilities in Rust projects by analyzing their dependencies against the [RustSec Advisory Database](https://rustsec.org/).

## Overview

This scanner integrates cargo-audit into SecureCodeBox, in order to automate security scanning of Rust projects in a CI/CD pipeline. It identifies known vulnerabilities in dependencies and provides actionable remediation advice.

**Features:**

- Detects security vulnerabilities in Rust dependencies (CVEs, RustSec advisories)
- Transforms findings into SecureCodeBox's standardized format
- Fully containerized
- Supports both local file paths and MinIO URLs
- Easy integration via Helm chart

## Quick Start

### Prerequisites

- Kubernetes cluster
- Helm
- SecureCodeBox operator installed

### Installation

1. **Add the Helm repository** (if not already added):

```bash
helm repo add securecodebox https://charts.securecodebox.io
helm repo update
```

2. **Install SecureCodeBox operator** (if not already installed):

```bash
kubectl create namespace securecodebox-system
helm install securecodebox-operator securecodebox/operator --namespace securecodebox-system --version 4.5.0
```

3. **Install the Rust scanner**:

```bash
# Clone this repository
git clone https://github.com/Aureylzz/securecodebox-scanner-rust
cd securecodebox-scanner-rust

# Install the scanner
helm install rust-scanner ./helm
```

### Running a Scan

Create a scan resource to analyze a Rust project:

```yaml
apiVersion: execution.securecodebox.io/v1
kind: Scan
metadata:
  name: my-rust-project-scan
spec:
  scanType: rust-scanner
  volumes:
    - name: project-code
      persistentVolumeClaim:
        claimName: my-rust-project-pvc
  volumeMounts:
    - name: project-code
      mountPath: /scan
```

Apply the scan:

```bash
kubectl apply -f scan.yaml
kubectl get scan my-rust-project-scan -w
```

## Architecture

The scanner consists of two main components:

1. **Scanner Container** (`aureylz/scb-rust-scan:v0.1.1`)
   - Runs cargo-audit to detect vulnerabilities
   - Outputs results in JSON format
   - Writes to `/home/securecodebox/scan-results.json`

2. **Parser Container** (`aureylz/scb-rust-parser:v0.1.3`)
   - Transforms cargo-audit JSON into SecureCodeBox findings
   - Supports both file paths and HTTP/HTTPS URLs (MinIO)
   - Maps severity levels from CVSS scores

## Configuration

### Helm Values

Key configuration options in `values.yaml`:

```yaml
scanner:
  image:
    repository: aureylz/scb-rust-scan
    tag: v0.1.1
  resources:
    limits:
      memory: "512Mi"
      cpu: "1000m"
    requests:
      memory: "256Mi"
      cpu: "250m"

parser:
  image:
    repository: aureylz/scb-rust-parser
    tag: v0.1.3
  resources:
    limits:
      memory: "256Mi"
      cpu: "500m"
```

### Advanced Configuration

Override default values during installation:

```bash
helm install rust-scanner ./helm \
  --set scanner.image.tag=v0.1.1 \
  --set parser.image.tag=v0.1.3 \
  --set scanner.resources.limits.memory=1Gi
```

## Usage Examples

### Scanning from Git Repository

```yaml
apiVersion: execution.securecodebox.io/v1
kind: Scan
metadata:
  name: rust-git-scan
spec:
  scanType: rust-scanner
  initContainers:
    - name: git-clone
      image: alpine/git
      command: ["git", "clone", "https://github.com/your-org/rust-project.git", "/scan"]
      volumeMounts:
        - name: scan-workspace
          mountPath: /scan
  volumes:
    - name: scan-workspace
      emptyDir: {}
  volumeMounts:
    - name: scan-workspace
      mountPath: /scan
```

### Scanning Multiple Projects

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: rust-security-scans
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: scan-trigger
            image: bitnami/kubectl
            command:
            - /bin/bash
            - -c
            - |
              for project in project1 project2 project3; do
                kubectl create scan ${project}-scan --from=scan-template.yaml
              done
```

## Vulnerability Detection

The scanner detects various types of security issues:

- **Memory safety vulnerabilities** (buffer overflows, use-after-free)
- **Known CVEs** in dependencies
- **Unmaintained packages** warnings
- **Security advisories** from RustSec database

### Example Finding

```json
{
  "name": "RUSTSEC-2020-0071: Potential segfault in the time crate",
  "severity": "HIGH",
  "category": "Vulnerable Dependency",
  "attributes": {
    "package": "time",
    "installed_version": "0.1.45",
    "patched_versions": ">=0.2.23",
    "cve": "CVE-2020-26235",
    "cvss": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
  }
}
```