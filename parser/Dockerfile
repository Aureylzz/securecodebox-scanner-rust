# We use a Node.js Alpine image to have a minimal size, create an app directory and copy the package files (mandatory for Node in my understanding)
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./

# Then, we install production dependencies, but for now, we're using only built-in Node.js modules
RUN npm install --production || true

# We copy the JS parser script in the container and make it executable
COPY parser.js ./
RUN chmod +x parser.js

# Create non-root user (best practices for security)
RUN adduser -D -s /bin/sh parser
USER parser

# SecureCodeBox will mount the scan results and pass the path as argument
ENTRYPOINT ["node", "/app/parser.js"]