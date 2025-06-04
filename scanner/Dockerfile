# Base image: Rust 1.87 slim variant for minimal size while including cargo
FROM rust:1.87-slim

# Install system packages required for cargo-audit to work properly
# git: needed by cargo for some dependency operations
# curl: useful for debugging and downloading additional tools
# jq: helps with JSON processing during development
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl jq \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-audit with a specific version for reproducibility
# The --locked flag ensures we use exact dependency versions from Cargo.lock
RUN cargo install --locked --version 0.21.2 cargo-audit

# Copy the scanner script into the container
COPY scanner.sh /usr/local/bin/scanner.sh
RUN chmod 755 /usr/local/bin/scanner.sh

# Create a non-root user for security best practices
# The -m flag creates a home directory, which cargo needs
# Using a dedicated user prevents potential security issues
RUN useradd -m -d /home/scanner scanner

# Switch to the scanner user for all subsequent operations
USER scanner

# Set the working directory where scans will be performed
# SecureCodeBox will mount the target project here
WORKDIR /scan

# Define the entrypoint - SecureCodeBox will call this script
ENTRYPOINT ["/usr/local/bin/scanner.sh"]