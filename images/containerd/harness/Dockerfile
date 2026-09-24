# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        procps \
        socat \
        libseccomp2 \
        kmod \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
ARG CONTAINERD_MATRIX="1.7.31:v1.28.0 2.0.8:v1.32.0 2.1.7:v1.33.0 2.2.3:v1.34.0"

RUN set -eux; \
    ARCH="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    for entry in ${CONTAINERD_MATRIX}; do \
        ctd="${entry%%:*}"; \
        crictl="${entry##*:}"; \
        dest="/opt/containerd/${ctd}"; \
        mkdir -p "${dest}"; \
        curl -fsSL "https://github.com/containerd/containerd/releases/download/v${ctd}/containerd-${ctd}-linux-${ARCH}.tar.gz" \
            | tar -C "${dest}" -xz; \
        curl -fsSL "https://github.com/kubernetes-sigs/cri-tools/releases/download/${crictl}/crictl-${crictl}-linux-${ARCH}.tar.gz" \
            | tar -C "${dest}/bin" -xz; \
        if [ "$(dpkg --print-architecture)" = "${ARCH}" ]; then \
            "${dest}/bin/containerd" --version; \
            "${dest}/bin/crictl" --version; \
        fi; \
    done

ARG RUNC_VERSION=v1.2.6
ARG CNI_PLUGINS_VERSION=v1.6.2

RUN set -eux; \
    ARCH="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    curl -fsSL "https://github.com/opencontainers/runc/releases/download/${RUNC_VERSION}/runc.${ARCH}" \
        -o /usr/local/sbin/runc; \
    chmod +x /usr/local/sbin/runc; \
    mkdir -p /opt/cni/bin; \
    curl -fsSL "https://github.com/containernetworking/plugins/releases/download/${CNI_PLUGINS_VERSION}/cni-plugins-linux-${ARCH}-${CNI_PLUGINS_VERSION}.tgz" \
        | tar -C /opt/cni/bin -xz

RUN mkdir -p /etc/cni/net.d /etc/containerd/runsc && touch /etc/crictl.yaml
COPY 10-harness.conflist /etc/cni/net.d/10-harness.conflist

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/bin/bash"]
