FROM golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9 AS builder

# Install gcsfuse from GitHub
RUN go install github.com/googlecloudplatform/gcsfuse/v2@latest

FROM debian:13.7-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

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
