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

# This script should be run with 'sudo -H'. $HOME must be set correctly because
# we invoke other scripts below that build Go binaries. In some operating
# systems, sudo(8) does not change $HOME by default. In such cases, root user
# ends up creating files in ~/.cache/go-build for the non-root user. This can
# cause future invocations of go build to fail due to permission issues.
if [[ "$EUID" -ne 0 ]]; then
  echo "Run this script with sudo -H"
  exit 1
fi

declare -r CONTAINERD_VERSION=${1:-1.3.0}
CONTAINERD_MAJOR="$(echo "${CONTAINERD_VERSION}" | awk -F '.' '{ print $1; }')"
declare -r CONTAINERD_MAJOR
CONTAINERD_MINOR="$(echo "${CONTAINERD_VERSION}" | awk -F '.' '{ print $2; }')"
declare -r CONTAINERD_MINOR
declare -r CRITOOLS_VERSION=${CRITOOLS_VERSION:-1.18.0}

if [[ "${CONTAINERD_MAJOR}" -eq 1 ]] && [[ "${CONTAINERD_MINOR}" -le 4 ]]; then
  # We're running Go 1.18, but using pre-module containerd and cri-tools.
  export GO111MODULE=off
fi

# containerd < 1.4 doesn't work with cgroupv2 setup, so we check for that here
SYSFS_ROOT=/sys/fs/cgroup
if [[ "$(stat -f -c %T "$SYSFS_ROOT" 2>/dev/null)" == "cgroup2fs" && "${CONTAINERD_MAJOR}" -eq 1 && "${CONTAINERD_MINOR}" -lt 4 ]]; then
  echo "containerd < 1.4 does not work with cgroup2"
  exit 1
fi

# Helper for Go packages below.
install_helper() {
  declare -r PACKAGE="${1}"
  declare -r TAG="${2}"

  # Clone the repository.
  mkdir -p "${GOPATH}"/src/"$(dirname "${PACKAGE}")" && \
     git clone https://"${PACKAGE}" "${GOPATH}"/src/"${PACKAGE}"

  # Checkout and build the repository.
  (cd "${GOPATH}"/src/"${PACKAGE}" && \
      git checkout "${TAG}" && \
      make && \
      make install)
}

# Figure out were btrfs headers are.
#
# Ubuntu 16.04 has only btrfs-tools, while 18.04 has a transitional package,
# and later versions no longer have the transitional package.
source /etc/os-release
declare BTRFS_DEV
if [[ "${VERSION_ID%.*}" -le "18" ]]; then
  BTRFS_DEV="btrfs-tools"
else
  BTRFS_DEV="libbtrfs-dev"
fi
readonly BTRFS_DEV

# Install dependencies for the crictl tests.
export DEBIAN_FRONTEND=noninteractive
while true; do
  apt-get update && apt-get install -y \
    "${BTRFS_DEV}" libseccomp-dev
  result=$?
  if [[ $result -eq 0 ]]; then
    break
  elif [[ $result -ne 100 ]]; then
    exit $result
  fi
done

# Install containerd & cri-tools.
GOPATH=$(mktemp -d --tmpdir gopathXXXXX)
declare -rx GOPATH
install_helper github.com/containerd/containerd "v${CONTAINERD_VERSION}"
install_helper github.com/kubernetes-sigs/cri-tools "v${CRITOOLS_VERSION}"

# Configure containerd-shim.
declare -r shim_config_path=/etc/containerd/runsc/config.toml
mkdir -p "$(dirname "${shim_config_path}")"
tee ${shim_config_path} <<-EOF
log_path = "/tmp/shim-logs/"
log_level = "debug"

[runsc_config]
    debug = "true"
    debug-log = "/tmp/runsc-logs/"
    strace = "true"
    file-access = "shared"
EOF

# Configure CNI.
(cd "${GOPATH}" && src/github.com/containerd/containerd/script/setup/install-cni)
tee /etc/cni/net.d/10-bridge.conf <<EOF
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
tee /etc/cni/net.d/99-loopback.conf <<EOF
{
  "cniVersion": "0.3.1",
  "type": "loopback"
}
EOF

# Configure crictl.
tee /etc/crictl.yaml <<EOF
runtime-endpoint: unix:///run/containerd/containerd.sock
EOF

# Cleanup.
rm -rf "${GOPATH}"
