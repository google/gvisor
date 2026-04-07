FROM golang:1.24-bullseye AS builder

# Install gcsfuse from GitHub
RUN go install github.com/googlecloudplatform/gcsfuse/v2@latest

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    fuse \
    curl \
    ca-certificates \
    python3 \
    psmisc \
    && rm -rf /var/lib/apt/lists/*

# Copy gcsfuse from builder
COPY --from=builder /go/bin/gcsfuse /usr/local/bin/gcsfuse

# Copy the gcsfuse test script
COPY gcsfuse_test.sh /usr/local/bin/gcsfuse_test.sh
RUN chmod +x /usr/local/bin/gcsfuse_test.sh

# Default to running gcsfuse test
ENTRYPOINT ["/usr/local/bin/gcsfuse_test.sh"]
