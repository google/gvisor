FROM ubuntu:22.04

# Prevent interactive prompts during package installation.
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    podman \
    fuse-overlayfs \
    iptables \
    iproute2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Add nonprivileged regular user named "nonroot" with uid 1338 and gid 1337.
RUN groupadd --gid 1337 nonroot && \
    useradd --uid 1338 --gid 1337 \
        --create-home \
        --shell /bin/bash \
        --password '' \
        nonroot

# Configure subuid and subgid mappings for root and nonroot users.
RUN echo "root:100000:65536" > /etc/subuid && \
    echo "root:100000:65536" > /etc/subgid && \
    echo "nonroot:100000:65536" >> /etc/subuid && \
    echo "nonroot:100000:65536" >> /etc/subgid

# Set up rootless Podman configuration for nonroot user.
RUN mkdir -p /home/nonroot/.config/containers /tmp/nonroot-runroot /home/nonroot/.local/share/containers/storage && \
    printf '[engine]\ncgroup_manager = "cgroupfs"\n' > /home/nonroot/.config/containers/containers.conf && \
    printf '[storage]\ndriver = "overlay"\nrunroot = "/tmp/nonroot-runroot"\ngraphroot = "/home/nonroot/.local/share/containers/storage"\n\n[storage.options.overlay]\nmount_program = "/usr/bin/fuse-overlayfs"\nignore_chown_errors = "true"\n' > /home/nonroot/.config/containers/storage.conf && \
    chown -R nonroot:nonroot /home/nonroot /tmp/nonroot-runroot

# Configure search registries for container image resolution.
RUN printf 'unqualified-search-registries = ["mirror.gcr.io", "docker.io"]\n' > /etc/containers/registries.conf

