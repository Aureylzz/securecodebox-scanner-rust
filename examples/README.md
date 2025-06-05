# Demo time

For the demo purpose of the hackathon, I've replayed step by step the full PoC locally. 

Also I have created some tools to make the reading easier at the end.

```bash
┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ docker --version
Docker version 28.2.2, build e6534b4

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kind --version
kind version 0.29.0

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kubectl version --client
Client Version: v1.33.1
Kustomize Version: v5.6.0

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ helm version --short
v3.18.2+g04cad46

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ jq --version
jq-1.7

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ docker build -t scb-rust-scan:latest ./scanner
DEPRECATED: The legacy builder is deprecated and will be removed in a future release.
            BuildKit is currently disabled; enable it by removing the DOCKER_BUILDKIT=0
            environment-variable.

Sending build context to Docker daemon  13.31kB
Step 1/10 : FROM rust:1.87-slim
 ---> 6ed37a08d480
Step 2/10 : RUN apt-get update     && apt-get install -y --no-install-recommends git curl jq pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
 ---> Using cache
 ---> a80f553438cf
Step 3/10 : RUN cargo install cargo-audit --version 0.21.2     && cargo install cargo-deny --version 0.18.2     && cargo install cargo-geiger
 ---> Using cache
 ---> 96913aa1b614
Step 4/10 : RUN rustup component add clippy
 ---> Using cache
 ---> c3adf2df92b5
Step 5/10 : COPY scanner.sh /usr/local/bin/scanner.sh
 ---> Using cache
 ---> 82ca138e7838
Step 6/10 : RUN chmod 755 /usr/local/bin/scanner.sh
 ---> Using cache
 ---> 0d1f25e59780
Step 7/10 : RUN useradd -m -d /home/scanner scanner
 ---> Using cache
 ---> d6db74c45973
Step 8/10 : USER scanner
 ---> Using cache
 ---> b2f409dc786d
Step 9/10 : WORKDIR /scan
 ---> Using cache
 ---> 44ec8c90652f
Step 10/10 : ENTRYPOINT ["/usr/local/bin/scanner.sh"]
 ---> Using cache
 ---> 6d800fc56017
Successfully built 6d800fc56017
Successfully tagged scb-rust-scan:latest

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ docker build -t scb-rust-parser:latest ./parser
DEPRECATED: The legacy builder is deprecated and will be removed in a future release.
            BuildKit is currently disabled; enable it by removing the DOCKER_BUILDKIT=0
            environment-variable.

Sending build context to Docker daemon  27.14kB
Step 1/9 : FROM node:20-alpine
 ---> 367a28bb5439
Step 2/9 : WORKDIR /app
 ---> Using cache
 ---> fd44b46359d4
Step 3/9 : COPY package*.json ./
 ---> Using cache
 ---> 28b7ee748025
Step 4/9 : RUN npm install --production || true
 ---> Using cache
 ---> 722cd8225ee6
Step 5/9 : COPY parser.js ./
 ---> Using cache
 ---> e10fee164ab4
Step 6/9 : RUN chmod +x parser.js
 ---> Using cache
 ---> 05bd72590b82
Step 7/9 : RUN mkdir -p /home/securecodebox &&     chown -R node:node /home/securecodebox &&     chown -R node:node /app
 ---> Using cache
 ---> 7151a92eb706
Step 8/9 : USER 1000
 ---> Using cache
 ---> 9dabe2b4dbee
Step 9/9 : ENTRYPOINT ["node", "/app/parser.js"]
 ---> Using cache
 ---> 275e8dbb5589
Successfully built 275e8dbb5589
Successfully tagged scb-rust-parser:latest

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ docker images | grep scb-rust | sort
scb-rust-parser   latest      275e8dbb5589   3 hours ago         135MB
scb-rust-scan     latest      6d800fc56017   24 minutes ago      1.41GB

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kubectl cluster-info
Kubernetes control plane is running at https://127.0.0.1:46047
CoreDNS is running at https://127.0.0.1:46047/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kubectl get nodes
NAME                     STATUS   ROLES           AGE   VERSION
scb-demo-control-plane   Ready    control-plane   21h   v1.33.1

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kind load docker-image scb-rust-scan:latest --name scb-demo
Image: "scb-rust-scan:latest" with ID "sha256:6d800fc560178f1666249a3ca9753f99728631f443c4f1307e9c75a8c33523fb" not yet present on node "scb-demo-control-plane", loading...

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kind load docker-image scb-rust-parser:latest --name scb-demo
Image: "scb-rust-parser:latest" with ID "sha256:275e8dbb55893c83926be8879deeb72bd2be9e0972d48d7e87033cb4112163b8" found to be already present on all nodes.

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ docker exec -it scb-demo-control-plane crictl images | grep scb-rust
docker.io/library/scb-rust-parser               dev                      47ae448bade05       137MB
docker.io/library/scb-rust-parser               latest                   275e8dbb55893       137MB
docker.io/library/scb-rust-scan                 latest                   6d800fc560178       1.44GB

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kubectl get pods -n securecodebox-system
NAME                                                READY   STATUS    RESTARTS   AGE
securecodebox-controller-manager-7f8c7989d7-nt6c5   1/1     Running   0          21h
securecodebox-operator-minio-7f756c7d47-zlns6       1/1     Running   0          21h

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ helm install rust-scanner ./helm --values local_kubernetes/demo-values.yaml
I0605 19:41:41.865698  461406 warnings.go:110] "Warning: unknown field \"spec.extractResults.parameters\""
NAME: rust-scanner
LAST DEPLOYED: Thu Jun  5 19:41:41 2025
NAMESPACE: default
STATUS: deployed
REVISION: 1
TEST SUITE: None

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kubectl get scantypes
NAME           IMAGE
rust-scanner   docker.io/library/scb-rust-scan:latest

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kubectl get parsedefinitions
NAME                  IMAGE
rust-scanner-parser   docker.io/library/scb-rust-parser:latest

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kubectl apply -f local_kubernetes/json-parser-for-demo.yaml
parsedefinition.execution.securecodebox.io/json created

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kubectl patch parsedefinition json --type='json' -p='[{"op": "replace", "path": "/spec/image", "value": "docker.io/library/scb-rust-parser:latest"}]'
parsedefinition.execution.securecodebox.io/json patched

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kubectl get parsedefinitions
NAME                  IMAGE
json                  docker.io/library/scb-rust-parser:latest
rust-scanner-parser   docker.io/library/scb-rust-parser:latest

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kubectl create configmap security-demo-project \
  --from-file=Cargo.toml=tests/fixtures/security_demo/Cargo.toml \
  --from-file=Cargo.lock=tests/fixtures/security_demo/Cargo.lock \
  --from-file=main.rs=tests/fixtures/security_demo/src/main.rs \
  --from-file=deny.toml=tests/fixtures/security_demo/deny.toml
configmap/security-demo-project created

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kubectl get configmap security-demo-project
NAME                    DATA   AGE
security-demo-project   4      9s

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ cat examples/demo-security-scan.yaml
apiVersion: execution.securecodebox.io/v1
kind: Scan
metadata:
  name: rust-security-demo
spec:
  scanType: rust-scanner
  volumes:
    - name: scan-target
      configMap:
        name: security-demo-project
  volumeMounts:
    - name: scan-target
      mountPath: /scan/Cargo.toml
      subPath: Cargo.toml
    - name: scan-target
      mountPath: /scan/Cargo.lock
      subPath: Cargo.lock
    - name: scan-target
      mountPath: /scan/src/main.rs
      subPath: main.rs
    - name: scan-target
      mountPath: /scan/deny.toml
      subPath: deny.toml
┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kubectl apply -f examples/demo-security-scan.yaml
scan.execution.securecodebox.io/rust-security-demo created

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kubectl get scan rust-security-demo -w
NAME                 TYPE           STATE      FINDINGS
rust-security-demo   rust-scanner   Scanning
rust-security-demo   rust-scanner   ScanCompleted
rust-security-demo   rust-scanner   Parsing
rust-security-demo   rust-scanner   ParseCompleted
rust-security-demo   rust-scanner   HookProcessing
rust-security-demo   rust-scanner   Done

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kubectl get scan rust-security-demo -o yaml | grep -A10 "status:"
status:
  findingDownloadLink: http://securecodebox-operator-minio.securecodebox-system.svc.cluster.local:9000/securecodebox/scan-955e99cc-1476-4fe9-bcce-2084f86bac86/findings.json?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=admin%2F20250605%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250605T174451Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-Amz-Signature=dedad1c897f187c11554ea172715fbcf6ac804c0cb58c137589e6537e64ba31e
  findingHeadLink: http://securecodebox-operator-minio.securecodebox-system.svc.cluster.local:9000/securecodebox/scan-955e99cc-1476-4fe9-bcce-2084f86bac86/findings.json?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=admin%2F20250605%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250605T174451Z&X-Amz-Expires=43200&X-Amz-SignedHeaders=host&X-Amz-Signature=6b05ccf7101ecc59415e7f55d94e16fdf1de3f823c14d02cb54c84db417e884e
  findings:
    severities: {}
  rawResultDownloadLink: http://securecodebox-operator-minio.securecodebox-system.svc.cluster.local:9000/securecodebox/scan-955e99cc-1476-4fe9-bcce-2084f86bac86/scan-results.json?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=admin%2F20250605%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250605T174451Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-Amz-Signature=97e71a231aabb967e89008cadf59623b31dd2452fc43031a9659cd4b61d13ac7
  rawResultFile: scan-results.json
  rawResultHeadLink: http://securecodebox-operator-minio.securecodebox-system.svc.cluster.local:9000/securecodebox/scan-955e99cc-1476-4fe9-bcce-2084f86bac86/scan-results.json?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=admin%2F20250605%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250605T174451Z&X-Amz-Expires=43200&X-Amz-SignedHeaders=host&X-Amz-Signature=a9e9ebded0f323b7cc6b3e328478333543eda29df65d8d447f5cf8497e0f5bd1
  rawResultType: json
  state: Done

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ kubectl get jobs
NAME                             STATUS     COMPLETIONS   DURATION   AGE
parse-rust-security-demo-69mz8   Complete   1/1           3s         2m12s
scan-rust-security-demo-h8pvw    Complete   1/1           25s        2m37s

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ docker run --rm -v "$(pwd)/tests/fixtures/security_demo":/scan scb-rust-scan:latest 2>/dev/null | \
  jq '{
    scan_type: .scan_type,
    audit_vulns: .cargo_audit.vulnerabilities.count,
    deny_executed: (.cargo_deny.output != null),
    unsafe_code: .cargo_geiger.unsafe_code_used,
    clippy_warnings: .clippy.total_warnings
  }'
{
  "scan_type": "rust-multi-scanner",
  "audit_vulns": 6,
  "deny_executed": true,
  "unsafe_code": 49,
  "clippy_warnings": 6
}

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ docker run --rm -v "$(pwd)/tests/fixtures/security_demo":/scan scb-rust-scan:latest 2>/dev/null > temp-scan.json

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ docker run --rm -v "$(pwd)/temp-scan.json":/tmp/scan.json scb-rust-parser:latest /tmp/scan.json 2>&1 | grep -E "(Processing|Total findings|DEBUG)"
INFO: Processing scan results from: /tmp/scan.json
DEBUG: Detected file path input, reading from disk...
DEBUG: Successfully parsed JSON for scan type: rust-multi-scanner
DEBUG: Processing 6 vulnerabilities from cargo-audit
DEBUG: cargo-geiger found 49/341 unsafe code usages
DEBUG: Processing 6 messages from clippy
DEBUG: Total findings created: 9

┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ cat ./examples/show-findings-summary.sh
#!/bin/bash

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FINDINGS_FILE="$SCRIPT_DIR/findings.json"

# Check if findings.json exists
if [ ! -f "$FINDINGS_FILE" ]; then
    echo "Error: findings.json not found at $FINDINGS_FILE"
    exit 1
fi

echo "=== SecureCodeBox Rust Scanner Findings Summary ==="
echo

# Total findings (dynamic)
TOTAL=$(jq 'length' "$FINDINGS_FILE")
echo "Total findings: $TOTAL"

# Count by severity (dynamic)
echo -e "\nFindings by severity:"
jq -r 'group_by(.severity) | map("  \(.[0].severity): \(length)") | .[]' "$FINDINGS_FILE" | sort -r

# Count by scanner (dynamic)
echo -e "\nFindings by scanner:"
jq -r 'group_by(.scanner) | map("  \(.[0].scanner): \(length)") | .[]' "$FINDINGS_FILE" | sort

# Dynamic summary table
echo -e "\n=== Summary Table ==="
echo "┌─────────────────────────────────────────────────────────────"
echo "│ Tool         │ Findings │ Details"
echo "├─────────────────────────────────────────────────────────────"

# cargo-audit row (dynamic)
AUDIT_COUNT=$(jq '[.[] | select(.scanner == "cargo-audit")] | length' "$FINDINGS_FILE")
AUDIT_DETAILS=$(jq -r '[.[] | select(.scanner == "cargo-audit")] | group_by(.severity) | map("\(length) \(.[0].severity)") | join(", ")' "$FINDINGS_FILE")
printf "│ %-12s │ %8s │ %s\n" "cargo-audit" "$AUDIT_COUNT" "$AUDIT_DETAILS"

# cargo-geiger row (dynamic)
GEIGER_COUNT=$(jq '[.[] | select(.scanner == "cargo-geiger")] | length' "$FINDINGS_FILE")
GEIGER_DETAILS=$(jq -r '[.[] | select(.scanner == "cargo-geiger")] | if length > 0 then .[0].attributes | "Unsafe code: \(.unsafe_code_used)/\(.unsafe_code_total) (\(.unsafe_percentage)%)" else "No findings" end' "$FINDINGS_FILE")
printf "│ %-12s │ %8s │ %s\n" "cargo-geiger" "$GEIGER_COUNT" "$GEIGER_DETAILS"

# clippy row (dynamic)
CLIPPY_COUNT=$(jq '[.[] | select(.scanner == "clippy")] | length' "$FINDINGS_FILE")
CLIPPY_DETAILS=$(jq -r '[.[] | select(.scanner == "clippy")] | if length > 0 then map(.attributes.lint_name) | unique | join(", ") else "No findings" end' "$FINDINGS_FILE")
printf "│ %-12s │ %8s │ %s\n" "clippy" "$CLIPPY_COUNT" "$CLIPPY_DETAILS"

echo "└─────────────────────────────────────────────────────────────"

# List all findings (dynamic)
echo -e "\n=== All Findings List ==="
jq -r 'to_entries | .[] | "\(.key + 1). [\(.value.severity)] \(.value.name) (\(.value.scanner))"' "$FINDINGS_FILE"

# High severity vulnerabilities with CVEs (dynamic)
HIGH_COUNT=$(jq '[.[] | select(.severity == "HIGH")] | length' "$FINDINGS_FILE")
if [ "$HIGH_COUNT" -gt 0 ]; then
    echo -e "\n=== High Severity Vulnerabilities ($HIGH_COUNT found) ==="
    jq -r '.[] | select(.severity == "HIGH") | "• \(.name)\n  CVE: \(.attributes.cve // "N/A")\n  Package: \(.attributes.package)@\(.attributes.installed_version)\n  Fix: \(.attributes.patched_versions)"' "$FINDINGS_FILE"
fi
┌──(aureylz㉿aureylzwin)-[~/securecodebox-scanner-rust]
└─$ ./examples/show-findings-summary.sh
=== SecureCodeBox Rust Scanner Findings Summary ===

Total findings: 9

Findings by severity:
  MEDIUM: 5
  LOW: 2
  HIGH: 2

Findings by scanner:
  cargo-audit: 6
  cargo-geiger: 1
  clippy: 2

=== Summary Table ===
┌─────────────────────────────────────────────────────────────
│ Tool         │ Findings │ Details
├─────────────────────────────────────────────────────────────
│ cargo-audit  │        6 │ 2 HIGH, 4 MEDIUM
│ cargo-geiger │        1 │ Unsafe code: 49/341 (14%)
│ clippy       │        2 │ clippy::missing_safety_doc, dead_code
└─────────────────────────────────────────────────────────────

=== All Findings List ===
1. [MEDIUM] RUSTSEC-2020-0159: Potential segfault in `localtime_r` invocations (cargo-audit)
2. [HIGH] RUSTSEC-2022-0013: Regexes with large repetitions on empty sub-expressions take a very long time to parse (cargo-audit)
3. [HIGH] RUSTSEC-2020-0071: Potential segfault in the time crate (cargo-audit)
4. [MEDIUM] RUSTSEC-2021-0072: Task dropped in wrong thread when aborting `LocalSet` task (cargo-audit)
5. [MEDIUM] RUSTSEC-2021-0124: Data race when sending and receiving after closing a `oneshot` channel (cargo-audit)
6. [MEDIUM] RUSTSEC-2023-0001: reject_remote_clients Configuration corruption (cargo-audit)
7. [MEDIUM] Unsafe Code Usage Detected: 49 occurrences (cargo-geiger)
8. [LOW] Clippy: dead_code (4 occurrences) (clippy)
9. [LOW] Clippy: clippy::missing_safety_doc (2 occurrences) (clippy)

=== High Severity Vulnerabilities (2 found) ===
• RUSTSEC-2022-0013: Regexes with large repetitions on empty sub-expressions take a very long time to parse
  CVE: CVE-2022-24713
  Package: regex@1.5.4
  Fix: >=1.5.5
• RUSTSEC-2020-0071: Potential segfault in the time crate
  CVE: CVE-2020-26235
  Package: time@0.1.45
  Fix: >=0.2.23

```
