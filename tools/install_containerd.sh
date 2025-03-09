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

# Helper to get cri-tools version for the given containerd version.
get_critools_version() {
  declare -r CONTAINERD_PACKAGE="${1}"
  declare -r CONTAINERD_TAG="${2}"
  declare -r CONTAINERD_PATH="${GOPATH}"/src/"${CONTAINERD_PACKAGE}"
  declare -r CRITOOLS_VERSION_FILE="${CONTAINERD_PATH}"/script/setup/critools-version

  local CRITOOLS_VERSION="v1.18.0"
  # If the containerd repository is already cloned, checkout the new tag.
  if [[ -f "$CRITOOLS_VERSION_FILE" ]]; then
    (cd "${CONTAINERD_PATH}" &&  git checkout "${CONTAINERD_TAG}")
    CRITOOLS_VERSION=$(cat "${CRITOOLS_VERSION_FILE}" | tr -d '\r\n')
  fi
  echo "$CRITOOLS_VERSION"
  return 0
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

# Install containerd & cri-tools.
GOPATH=$(mktemp -d --tmpdir gopathXXXXX)
declare -rx GOPATH
install_helper github.com/containerd/containerd "v${CONTAINERD_VERSION}"
declare MINIMAL_CRITOOLS_VERSION
MINIMAL_CRITOOLS_VERSION=$(get_critools_version github.com/containerd/containerd "v${CONTAINERD_VERSION}")
install_helper github.com/kubernetes-sigs/cri-tools "${MINIMAL_CRITOOLS_VERSION}"

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

# Configure CNI, the script install-cni depends on go.mod to determine the
# version of github.com/containernetworking/plugins, it has to be installed
# from containerd's root directory.
(cd "${GOPATH}"/src/github.com/containerd/containerd/ && ./script/setup/install-cni)

# Configure crictl.
tee /etc/crictl.yaml <<EOF
runtime-endpoint: unix:///run/containerd/containerd.sock
EOF

# Cleanup.
rm -rf "${GOPATH}"
