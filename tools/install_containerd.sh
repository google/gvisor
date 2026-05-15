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

declare -r CONTAINERD_VERSION=${1:-1.7.31}

# Helper for Go packages below.
get_critools_version() {
  declare -r CONTAINERD_VERSION="${1}"
  local CRITOOLS_VERSION="v1.18.0"
  if version=$(curl -sSf "https://raw.githubusercontent.com/containerd/containerd/v${CONTAINERD_VERSION}/script/setup/critools-version" 2>/dev/null); then
    CRITOOLS_VERSION=$(echo "${version}" | tr -d '\r\n')
  fi
  echo "$CRITOOLS_VERSION"
}

get_cni_version() {
  declare -r CONTAINERD_VERSION="${1}"
  local CNI_VERSION="v1.9.0" # Fallback default
  
  if version=$(curl -sSf "https://raw.githubusercontent.com/containerd/containerd/v${CONTAINERD_VERSION}/script/setup/cni-plugins-version" 2>/dev/null); then
    CNI_VERSION=$(echo "${version}" | tr -d '\r\n')
  elif go_mod=$(curl -sSf "https://raw.githubusercontent.com/containerd/containerd/v${CONTAINERD_VERSION}/go.mod" 2>/dev/null); then
    if version=$(echo "${go_mod}" | grep "github.com/containernetworking/plugins" | awk '{print $2}'); then
      if [[ ! -z "${version}" ]]; then
        if [[ ! "${version}" =~ ^v ]]; then
          CNI_VERSION="v${version}"
        else
          CNI_VERSION="${version}"
        fi
      fi
    fi
  fi
  echo "$CNI_VERSION"
}

install_containerd() {
  local version="${1}"
  echo "Installing containerd v${version}..."
  local tmp_dir
  tmp_dir=$(mktemp -d)
  if ! wget -qS "https://github.com/containerd/containerd/releases/download/v${version}/containerd-${version}-linux-amd64.tar.gz" -O "${tmp_dir}/containerd.tar.gz"; then
    echo "Failed to download containerd v${version}"
    rm -rf "${tmp_dir}"
    return 1
  fi
  tar -C /usr/local -xzf "${tmp_dir}/containerd.tar.gz"
  rm -rf "${tmp_dir}"
}

install_crictl() {
  local version="${1}"
  echo "Installing crictl ${version}..."
  local tmp_dir
  tmp_dir=$(mktemp -d)
  if ! wget -qS "https://github.com/kubernetes-sigs/cri-tools/releases/download/${version}/crictl-${version}-linux-amd64.tar.gz" -O "${tmp_dir}/crictl.tar.gz"; then
    echo "Failed to download crictl ${version}"
    rm -rf "${tmp_dir}"
    return 1
  fi
  tar -C /usr/local/bin -xzf "${tmp_dir}/crictl.tar.gz"
  rm -rf "${tmp_dir}"
}

install_cni_binaries() {
  local version="${1}"
  echo "Installing CNI plugins ${version}..."
  mkdir -p /opt/cni/bin
  local tmp_dir
  tmp_dir=$(mktemp -d)
  if ! wget -qS "https://github.com/containernetworking/plugins/releases/download/${version}/cni-plugins-linux-amd64-${version}.tgz" -O "${tmp_dir}/cni.tgz"; then
    echo "Failed to download CNI plugins ${version}"
    rm -rf "${tmp_dir}"
    return 1
  fi
  tar -C /opt/cni/bin -xzf "${tmp_dir}/cni.tgz"
  rm -rf "${tmp_dir}"

  # Write default config
  mkdir -p /etc/cni/net.d
  tee /etc/cni/net.d/10-containerd-net.conflist <<EOF
{
  "cniVersion": "1.0.0",
  "name": "containerd-net",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "cni0",
      "isGateway": true,
      "ipMasq": true,
      "promiscMode": true,
      "ipam": {
        "type": "host-local",
        "ranges": [
          [{
            "subnet": "10.88.0.0/16"
          }],
          [{
            "subnet": "2001:4860:4860::/64"
          }]
        ],
        "routes": [
          { "dst": "0.0.0.0/0" },
          { "dst": "::/0" }
        ]
      }
    },
    {
      "type": "portmap",
      "capabilities": {"portMappings": true}
    }
  ]
}
EOF
}

# Figure out were btrfs headers are.
#
# Ubuntu 16.04 has only btrfs-tools, while 18.04 has a transitional package,
# and later versions no longer have the transitional package.
#
# If we can't detect the VERSION_ID, we assume it's a newer version and use
# libbtrfs-dev.
source /etc/os-release
declare BTRFS_DEV
if [[ ! -z "${VERSION_ID}" && "${VERSION_ID%.*}" -le "18" ]]; then
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

# Install containerd, cri-tools, and CNI plugins.
install_containerd "${CONTAINERD_VERSION}"

MINIMAL_CRITOOLS_VERSION=$(get_critools_version "${CONTAINERD_VERSION}")
install_crictl "${MINIMAL_CRITOOLS_VERSION}"

CNI_VERSION=$(get_cni_version "${CONTAINERD_VERSION}")
install_cni_binaries "${CNI_VERSION}"

# Configure crictl.
tee /etc/crictl.yaml <<EOF
runtime-endpoint: unix:///run/containerd/containerd.sock
EOF

# Cleanup.
# No GOPATH to cleanup anymore.
