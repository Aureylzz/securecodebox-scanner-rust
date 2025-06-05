# Use Node.js Alpine image for minimal size and security
FROM node:20-alpine

# Set working directory for the application
WORKDIR /app

# Copy package files first for better Docker layer caching
COPY package*.json ./

# Install production dependencies
RUN npm install --production || true

# Copy the parser script into the container
COPY parser.js ./
RUN chmod +x parser.js

# Create the SecureCodeBox directory and set permissions
RUN mkdir -p /home/securecodebox && \
    chown -R node:node /home/securecodebox && \
    chown -R node:node /app

# CRITICAL: Use numeric UID instead of named user for Kubernetes compatibility
# The 'node' user in Alpine has UID 1000
USER 1000

# SecureCodeBox will mount the scan results and pass the path as argument
ENTRYPOINT ["node", "/app/parser.js"]
