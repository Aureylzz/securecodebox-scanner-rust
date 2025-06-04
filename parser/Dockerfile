# Use Node.js Alpine image for minimal size and security
FROM node:20-alpine

# Set working directory for the application
WORKDIR /app

# Copy package files first for better Docker layer caching
# This allows Docker to reuse layers if dependencies haven't changed
COPY package*.json ./

# Install production dependencies
# The '|| true' allows the build to continue even if there are no dependencies
# Currently we only use Node.js built-in modules, so this is a no-op
RUN npm install --production || true

# Copy the parser script into the container
COPY parser.js ./
RUN chmod +x parser.js

# The node:20-alpine image already has a 'node' user with UID 1000
# We use this existing user instead of creating a new one
# This UID matches our scanner user, which helps with local testing
# though SecureCodeBox handles permissions differently in production

# Create the SecureCodeBox directory and set permissions for the node user
# This is where SecureCodeBox expects to find the findings
RUN mkdir -p /home/securecodebox && \
    chown -R node:node /home/securecodebox && \
    chown -R node:node /app

# Switch to the existing node user (UID 1000)
USER node

# SecureCodeBox will mount the scan results and pass the path as argument
# The parser reads from SCAN_RESULTS_FILE env var or command line argument
ENTRYPOINT ["node", "/app/parser.js"]