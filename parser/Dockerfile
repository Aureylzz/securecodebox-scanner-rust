# We use a Node.js Alpine image to have a minimal size, create an app directory and copy the package files (mandatory for Node in my understanding)
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./

# Then, we install production dependencies, but for now, we're using only built-in Node.js modules
RUN npm install --production || true

# We copy the JS parser script in the container and make it executable
COPY parser.js ./
RUN chmod +x parser.js

# The node:20-alpine image already has a 'node' user with UID 1000
# We'll use this existing user instead of creating a new one
# This matches our scanner user's UID perfectly!

# Create the SecureCodeBox directory and set permissions for the node user
RUN mkdir -p /home/securecodebox && \
    chown -R node:node /home/securecodebox && \
    chown -R node:node /app

# Switch to the existing node user (UID 1000)
USER node

# SecureCodeBox will mount the scan results and pass the path as argument
ENTRYPOINT ["node", "/app/parser.js"]