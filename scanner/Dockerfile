# Base image: Rust 1.87 slim variant
FROM rust:1.87-slim

# Install system packages
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl jq \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-audit
RUN cargo install --locked --version 0.21.2 cargo-audit

# Copy scanner script
COPY scanner.sh /usr/local/bin/scanner.sh
RUN chmod 755 /usr/local/bin/scanner.sh

# Create user with proper home directory
# Using useradd instead of adduser --system gives us a real home directory
RUN useradd -m -d /home/scanner scanner

# Switch to scanner user
USER scanner

# Set working directory
WORKDIR /scan
ENTRYPOINT ["/usr/local/bin/scanner.sh"]