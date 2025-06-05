# Base image: Rust 1.87 slim variant for minimal size while including cargo
FROM rust:1.87-slim

# Install system packages required for all tools to work properly
# git: needed by cargo for dependency operations
# curl: useful for debugging and downloading additional tools
# jq: helps with JSON processing during development
# pkg-config, libssl-dev: required for cargo-geiger compilation
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        curl \
        jq \
        pkg-config \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install all security and quality tools
# Note: Remove --locked if you encounter version issues
# You can also remove version specifications to get latest versions
RUN cargo install cargo-audit --version 0.21.2 \
    && cargo install cargo-deny --version 0.18.2 \
    && cargo install cargo-geiger

# Alternative: Install latest versions of all tools
# RUN cargo install cargo-audit cargo-deny cargo-geiger

# Install clippy (comes with rustup)
RUN rustup component add clippy

# Copy the enhanced scanner script into the container
COPY scanner.sh /usr/local/bin/scanner.sh
RUN chmod 755 /usr/local/bin/scanner.sh

# Create a non-root user for security best practices
RUN useradd -m -d /home/scanner scanner

# Switch to the scanner user for all subsequent operations
USER scanner

# Set the working directory where scans will be performed
WORKDIR /scan

# Define the entrypoint
ENTRYPOINT ["/usr/local/bin/scanner.sh"]