ARG NODE_VERSION=22
FROM node:${NODE_VERSION}

# Install build dependencies for native modules
RUN apt-get update && apt-get install -y git python3 make g++

WORKDIR /app

# Copy package files
COPY package.json ./

# Install dependencies
RUN npm install

# Clone marked repo docs at specific commit
RUN git clone https://github.com/markedjs/marked.git /tmp/marked && \
    cd /tmp/marked && \
    git checkout 0a0da515346d2b3dd1662531043fa6925cb73fe3 && \
    cp -r docs /app/docs && \
    rm -rf /tmp/marked

# Copy application code
COPY *.js ./

# Expose ports for app and gdbserver
EXPOSE 80

# Start the application with conditional flag for Node < 24
CMD if [ $(node -v | cut -c2- | cut -d. -f1) -lt 24 ]; then \
        exec node --experimental-async-context-frame index.js; \
    else \
        exec node index.js; \
    fi