#!/bin/bash

# Copyright 2019 The gVisor Authors.
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

set -xeo pipefail

declare -r CONTAINERD_VERSION=${CONTAINERD_VERSION:-1.3.0}
declare -r CONTAINERD_MAJOR="$(echo ${CONTAINERD_VERSION} | awk -F '.' '{ print $1; }')"
declare -r CONTAINERD_MINOR="$(echo ${CONTAINERD_VERSION} | awk -F '.' '{ print $2; }')"

# Default to an older version for crictl for containerd <= 1.2.
if [[ "${CONTAINERD_MAJOR}" -eq 1 ]] && [[ "${CONTAINERD_MINOR}" -le 2 ]]; then
  declare -r CRITOOLS_VERSION=${CRITOOLS_VERSION:-1.13.0}
else
  declare -r CRITOOLS_VERSION=${CRITOOLS_VERSION:-1.18.0}
fi

# Helper for Go packages below.
install_helper() {
  PACKAGE="${1}"
  TAG="${2}"

  # Clone the repository.
  mkdir -p "${GOPATH}"/src/$(dirname "${PACKAGE}") && \
     git clone https://"${PACKAGE}" "${GOPATH}"/src/"${PACKAGE}"

  # Checkout and build the repository.
  (cd "${GOPATH}"/src/"${PACKAGE}" && \
      git checkout "${TAG}" && \
      make && \
      make install)
}

# Install dependencies for the crictl tests.
while true; do
  if (apt-get update && apt-get install -y \
      btrfs-tools \
      libseccomp-dev); then
    break
  fi
  result=$?
  if [[ $result -ne 100 ]]; then
    exit $result
  fi
done

# Install containerd & cri-tools.
declare -rx GOPATH=$(mktemp -d --tmpdir gopathXXXXX)
install_helper github.com/containerd/containerd "v${CONTAINERD_VERSION}" "${GOPATH}"
install_helper github.com/kubernetes-sigs/cri-tools "v${CRITOOLS_VERSION}" "${GOPATH}"

# Configure containerd-shim.
#
# Note that for versions <= 1.1 the legacy shim must be installed in /usr/bin,
# which should align with the installer script in head.sh (or master.sh).
if [[ "${CONTAINERD_MAJOR}" -le 1 ]] && [[ "${CONTAINERD_MINOR}" -lt 2 ]]; then
  declare -r shim_config_path=/etc/containerd/gvisor-containerd-shim.toml
  mkdir -p $(dirname ${shim_config_path})
  cat > ${shim_config_path} <<-EOF
    runc_shim = "/usr/bin/containerd-shim"

[runsc_config]
    debug = "true"
    debug-log = "/tmp/runsc-logs/"
    strace = "true"
    file-access = "shared"
EOF
fi

# Configure CNI.
(cd "${GOPATH}" && src/github.com/containerd/containerd/script/setup/install-cni)
cat <<EOF | sudo tee /etc/cni/net.d/10-bridge.conf
{
  "cniVersion": "0.3.1",
  "name": "bridge",
  "type": "bridge",
  "bridge": "cnio0",
  "isGateway": true,
  "ipMasq": true,
  "ipam": {
      "type": "host-local",
      "ranges": [
        [{"subnet": "10.200.0.0/24"}]
      ],
      "routes": [{"dst": "0.0.0.0/0"}]
  }
}
EOF
cat <<EOF | sudo tee /etc/cni/net.d/99-loopback.conf
{
  "cniVersion": "0.3.1",
  "type": "loopback"
}
EOF

# Configure crictl.
cat <<EOF | sudo tee /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
EOF

# Cleanup.
rm -rf "${GOPATH}"
