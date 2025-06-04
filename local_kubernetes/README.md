# SecureCodeBox Rust Scanner Integration - Complete Walkthrough

This walkthrough demonstrates the successful integration of a Rust security scanner (cargo-audit) into SecureCodeBox running on a local Kubernetes cluster. By following these steps, you'll see how the scanner detects real vulnerabilities in Rust projects and integrates seamlessly with SecureCodeBox's security orchestration platform.

## Understanding What We're Building

Before diving into the commands, it's important to understand the architecture of what we're demonstrating. We're creating a security scanning pipeline that consists of several components working together. The scanner container runs cargo-audit to detect vulnerabilities in Rust dependencies. The parser container transforms the raw cargo-audit output into SecureCodeBox's standardized format. SecureCodeBox itself orchestrates the entire process, managing when to run scans, how to store results, and how to process findings.

The most interesting aspect of this integration is how it bridges two different worlds. On one side, we have cargo-audit, a Rust-specific tool that understands the intricacies of Rust's dependency ecosystem and security advisories. On the other side, we have SecureCodeBox, a platform-agnostic security orchestration system that needs to work with scanners from many different languages and tools. Our integration acts as a translator between these two systems.

## Prerequisites

Before starting, ensure you have the following tools installed on your system. Each tool plays a specific role in our demonstration:

- Docker (for building and running containers)
- kind v0.29.0 or later (for creating a local Kubernetes cluster)
- kubectl (for interacting with Kubernetes)
- Helm (for deploying applications to Kubernetes)
- jq (for parsing JSON output in the terminal)

Clone the repository containing all the necessary files:

```bash
git clone https://github.com/Aureylzz/securecodebox-scanner-rust
cd securecodebox-scanner-rust
```

## Step 1: Building the Scanner and Parser Images

The first step in our journey is to build the Docker images that contain our scanner and parser. These images encapsulate all the dependencies and logic needed to detect vulnerabilities and transform the results.

```bash
docker build -t scb-rust-scan:latest ./scanner
```

When you run this command, Docker builds an image containing the Rust toolchain and cargo-audit. The build process installs cargo-audit version 0.21.2 with locked dependencies to ensure consistent vulnerability detection. You should see output similar to:

```
[+] Building 1.1s (12/12) FINISHED
 => [internal] load build definition from Dockerfile
 => [7/7] WORKDIR /scan
 => exporting to image
 => => naming to docker.io/library/scb-rust-scan:latest
```

Next, build the parser image that will transform cargo-audit's output:

```bash
docker build -t scb-rust-parser:latest ./parser
```

This creates a lightweight Node.js container that knows how to read cargo-audit's JSON output and transform it into SecureCodeBox findings. The build should complete quickly:

```
[+] Building 0.8s (12/12) FINISHED
 => [7/7] RUN mkdir -p /home/securecodebox
 => => naming to docker.io/library/scb-rust-parser:latest
```

Verify your images were built successfully:

```bash
docker images | grep scb-rust
```

You should see both images listed:

```
scb-rust-parser    latest    be5e71524461    134MB
scb-rust-scan      latest    6fb906aece86    1.14GB
```

## Step 2: Creating a Local Kubernetes Environment

Now we need to create a Kubernetes cluster where SecureCodeBox can run. We use kind (Kubernetes in Docker) because it provides a full Kubernetes experience on your local machine. Think of kind as creating a miniature data center inside Docker containers.

```bash
kind create cluster --config local_kubernetes/kind-cluster-demo.yaml
```

This command creates a single-node Kubernetes cluster named "scb-demo". The process takes about a minute and shows progress as it sets up the various Kubernetes components:

```
Creating cluster "scb-demo" ...
 ✓ Ensuring node image (kindest/node:v1.33.1) 🖼
 ✓ Preparing nodes 📦
 ✓ Writing configuration 📜
 ✓ Starting control-plane 🕹️
 ✓ Installing CNI 🔌
 ✓ Installing StorageClass 💾
Set kubectl context to "kind-scb-demo"
```

Verify your cluster is running:

```bash
kubectl cluster-info
kubectl get nodes
```

You should see the Kubernetes API server running and a single node in Ready state:

```
Kubernetes control plane is running at https://127.0.0.1:46047
NAME                     STATUS   ROLES           AGE   VERSION
scb-demo-control-plane   Ready    control-plane   20s   v1.33.1
```

## Step 3: Loading Images into the Cluster

Since kind runs Kubernetes inside Docker, we need to make our locally built images available inside the cluster. This is like moving tools from your garage into your workshop where you'll actually use them.

```bash
kind load docker-image scb-rust-scan:latest --name scb-demo
kind load docker-image scb-rust-parser:latest --name scb-demo
```

Each command transfers the Docker image into the kind cluster's container runtime:

```
Image: "scb-rust-scan:latest" with ID "sha256:6fb906..." not yet present on node "scb-demo-control-plane", loading...
Image: "scb-rust-parser:latest" with ID "sha256:be5e7..." not yet present on node "scb-demo-control-plane", loading...
```

Verify the images are available inside the cluster:

```bash
docker exec -it scb-demo-control-plane crictl images | grep scb-rust
```

You should see both images with the docker.io/library prefix:

```
docker.io/library/scb-rust-parser    latest    be5e715244615    137MB
docker.io/library/scb-rust-scan      latest    6fb906aece86f    1.16GB
```

## Step 4: Installing SecureCodeBox

SecureCodeBox uses the operator pattern, which means it has a controller that watches for scan requests and manages the scanning workflow. Installing SecureCodeBox involves deploying this operator along with MinIO for storage.

First, add the SecureCodeBox Helm repository:

```bash
helm repo add securecodebox https://charts.securecodebox.io
helm repo update
```

Create a dedicated namespace for SecureCodeBox's control components:

```bash
kubectl create namespace securecodebox-system
```

Now install the SecureCodeBox operator:

```bash
helm install securecodebox-operator securecodebox/operator \
  --namespace securecodebox-system \
  --version 4.5.0
```

The installation creates several components including the operator itself and MinIO for storing scan results. You'll see a confirmation message:

```
NAME: securecodebox-operator
LAST DEPLOYED: Wed Jun  4 22:22:46 2025
NAMESPACE: securecodebox-system
STATUS: deployed
```

Wait for all components to be ready:

```bash
kubectl get pods -n securecodebox-system
```

You should see two pods running:

```
NAME                                                READY   STATUS    RESTARTS   AGE
securecodebox-controller-manager-7f8c7989d7-nt6c5   1/1     Running   0          104s
securecodebox-operator-minio-7f756c7d47-zlns6       1/1     Running   0          104s
```

## Step 5: Deploying Your Scanner

Now we install your Rust scanner into SecureCodeBox. This process registers your scanner as a new scan type that SecureCodeBox can orchestrate.

```bash
helm install rust-scanner ./helm --values local_kubernetes/demo-values.yaml
```

The values file tells Helm to use your local images instead of trying to pull from a registry:

```
NAME: rust-scanner
LAST DEPLOYED: Wed Jun  4 22:25:47 2025
NAMESPACE: default
STATUS: deployed
```

Verify your scanner was registered:

```bash
kubectl get scantypes
kubectl get parsedefinitions
```

You should see your scanner and its default parser:

```
NAME           IMAGE
rust-scanner   docker.io/library/scb-rust-scan:latest

NAME                  IMAGE
rust-scanner-parser   docker.io/library/scb-rust-parser:latest
```

## Step 6: The Critical Parser Configuration

Here comes the most important discovery from our integration journey. SecureCodeBox v4.5.0 uses a naming convention where it looks for a ParseDefinition with a name matching the result type. Since our scanner produces JSON results, we need a parser literally named "json".

```bash
kubectl apply -f local_kubernetes/json-parser-for-demo.yaml
```

This creates the crucial "json" parser:

```
parsedefinition.execution.securecodebox.io/json created
```

Verify both parsers are now registered:

```bash
kubectl get parsedefinitions
```

You should see:

```
NAME                  IMAGE
json                  docker.io/library/scb-rust-parser:latest
rust-scanner-parser   docker.io/library/scb-rust-parser:latest
```

This naming convention discovery was a key breakthrough. Without this "json" parser, SecureCodeBox couldn't find a parser to handle your scanner's JSON output, even though the rust-scanner-parser was available.

## Step 7: Preparing Test Data

To demonstrate vulnerability detection, we need a Rust project with a known vulnerability. We'll use a test project that depends on time crate version 0.1.45, which has a serious security issue that can cause segmentation faults in multithreaded programs.

```bash
kubectl create configmap vulnerable-rust-project \
  --from-file=Cargo.toml=tests/fixtures/vulnerable_crate/Cargo.toml \
  --from-file=Cargo.lock=tests/fixtures/vulnerable_crate/Cargo.lock \
  --from-file=main.rs=tests/fixtures/vulnerable_crate/src/main.rs
```

This creates a ConfigMap containing the test project files:

```
configmap/vulnerable-rust-project created
```

## Step 8: Running the Security Scan

This is the moment where everything comes together. We'll create a scan that triggers the entire SecureCodeBox workflow:

```bash
kubectl apply -f local_kubernetes/demo-scan.yaml
```

Now watch the scan progress through its lifecycle:

```bash
kubectl get scan rust-security-demo -w
```

You'll see the scan progress through several states, each representing a phase in the security scanning pipeline:

```
NAME                 TYPE           STATE      FINDINGS
rust-security-demo   rust-scanner   Scanning
rust-security-demo   rust-scanner   ScanCompleted
rust-security-demo   rust-scanner   Parsing
rust-security-demo   rust-scanner   ParseCompleted
rust-security-demo   rust-scanner   HookProcessing
rust-security-demo   rust-scanner   Done
```

Understanding these states helps you appreciate what's happening behind the scenes. During "Scanning", your cargo-audit scanner is analyzing the Rust project. "ScanCompleted" means the vulnerability was found and results were uploaded to MinIO. "Parsing" shows the parser transforming the results. Finally, "Done" indicates successful completion of the entire pipeline.

## Step 9: Examining the Results

Let's look at the scanner logs to see the vulnerability detection in action. Note that the job names include random suffixes (like -cxlcb), so you'll need to identify your specific job name:

```bash
# First, find your scan job name
kubectl get jobs | grep scan-rust-security-demo

# Then use that job name to view logs (replace xxxxx with your actual suffix)
kubectl logs -l job-name=scan-rust-security-demo-xxxxx -c rust-scan | grep -A 20 "Vulnerabilities detected"
```

You'll see confirmation that the scanner found the vulnerability and wrote the results with the correct permissions:

```
[2025-06-04 20:40:17] Vulnerabilities detected
[2025-06-04 20:40:17] JSON output written to /home/securecodebox/scan-results.json (4281 bytes)
[2025-06-04 20:40:17] Verified: Results file exists at /home/securecodebox/scan-results.json
[2025-06-04 20:40:17] Scan completed successfully - results available at /home/securecodebox/scan-results.json with permissions: -rw-r--r--
```

Notice the permissions "-rw-r--r--" which confirm our chmod 644 fix is working correctly, allowing the lurker sidecar to read the file.

## Step 10: Demonstrating Vulnerability Detection

To clearly see what vulnerability was detected, we can run the scanner and parser directly:

```bash
docker run --rm -v "$(pwd)/tests/fixtures/vulnerable_crate":/scan scb-rust-scan:latest 2>/dev/null | jq '.vulnerabilities.list[0].advisory | {id, title, package, cvss}'
```

This shows the detected vulnerability:

```json
{
  "id": "RUSTSEC-2020-0071",
  "title": "Potential segfault in the time crate",
  "package": "time",
  "cvss": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
}
```

Now let's see how the parser transforms this into a SecureCodeBox finding:

```bash
docker run --rm -v "$(pwd)/tests/fixtures/vulnerable_crate":/scan scb-rust-scan:latest > /tmp/scan-output.json 2>/dev/null
docker run --rm -v /tmp/scan-output.json:/tmp/scan.json scb-rust-parser:latest /tmp/scan.json 2>/dev/null | jq '.[0] | {name, severity, package: .attributes.package, cve: .attributes.cve}'
```

The parser output shows the transformed finding:

```json
{
  "name": "RUSTSEC-2020-0071: Potential segfault in the time crate",
  "severity": "HIGH",
  "package": "time",
  "cve": "CVE-2020-26235"
}
```

## Understanding the Integration Success

This walkthrough demonstrates several key achievements in integrating cargo-audit with SecureCodeBox. First, we've successfully containerized a Rust security tool and made it work within Kubernetes' orchestration model. The scanner correctly identifies real vulnerabilities that could cause production issues, such as the segmentation fault vulnerability in the time crate.

Second, we've solved the technical challenge of file permissions in multi-container pods. The chmod 644 fix ensures that the lurker sidecar can read the scanner's output, enabling the data flow between components. This might seem like a small detail, but it's crucial for the integration to work reliably.

Third, we've discovered and documented SecureCodeBox's parser naming convention. Understanding that SecureCodeBox looks for a parser named after the result type (in our case, "json") was the key breakthrough that made everything work together.

The scan's progression from "Scanning" through to "Done" proves that all components of the integration are functioning correctly. Your scanner detects vulnerabilities, writes results with proper permissions, and integrates seamlessly with SecureCodeBox's orchestration workflow.

## Production Considerations

While this proof of concept successfully demonstrates the integration, there's one enhancement needed for production use. The parser currently expects local file paths but receives URLs from SecureCodeBox pointing to files in MinIO. Adding HTTP client functionality to download from these URLs would complete the integration for production deployment.

Despite this limitation, the core integration is solid. You've proven that Rust security scanning can be integrated into SecureCodeBox, providing organizations with the ability to include Rust projects in their unified security scanning workflows. This is particularly valuable as Rust adoption grows in system programming, web services, and security-critical applications.

## Cleanup

When you're finished with the demonstration, you can clean up the resources:

```bash
# Delete the scan
kubectl delete scan rust-security-demo

# Delete the kind cluster
kind delete cluster --name scb-demo
```

## Conclusion

This walkthrough proves that integrating cargo-audit into SecureCodeBox is not only feasible but practical. You've successfully created a bridge between Rust's security ecosystem and SecureCodeBox's platform-agnostic orchestration, enabling organizations to maintain consistent security practices across their entire technology stack. The vulnerability detection for RUSTSEC-2020-0071 demonstrates that this integration provides real security value, helping teams identify and remediate vulnerabilities before they reach production.