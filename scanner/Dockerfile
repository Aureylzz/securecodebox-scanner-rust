# Base image: We took Rust 1.87 version (one of the latest) with the slim variant to reduce the image size by excluding non-essential packages
FROM rust:1.87-slim

# We install some system packages for the security scanner
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl jq \
    && rm -rf /var/lib/apt/lists/*

# We install cargo-audit with specific version and locked dependencies:
#   --locked ensures we use the exact dependency versions from Cargo.lock
#   --version 0.21.2 pins to a specific version for reproducible builds
RUN cargo install --locked --version 0.21.2 cargo-audit

# We copy the scanner script into the container
COPY scanner.sh /usr/local/bin/scanner.sh

# Them we make the scanner script executable
RUN chmod 755 /usr/local/bin/scanner.sh

# We create a non-root user for security best practices
#   --system creates a system user (UID < 1000) without home directory
#   --group creates a group with the same name as the user
RUN adduser --system --group scanner

# Switch to the scanner user for all subsequent operations to make sure the container runs with minimal privileges
USER scanner

# Set the working directory where volumes will be mounted when running the container and define the container's entry point
WORKDIR /scan
ENTRYPOINT ["/usr/local/bin/scanner.sh"]