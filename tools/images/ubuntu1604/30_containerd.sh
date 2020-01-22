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

# Helper for Go packages below.
install_helper() {
  PACKAGE="${1}"
  TAG="${2}"
  GOPATH="${3}"

  # Clone the repository.
  mkdir -p "${GOPATH}"/src/$(dirname "${PACKAGE}") && \
     git clone https://"${PACKAGE}" "${GOPATH}"/src/"${PACKAGE}"

  # Checkout and build the repository.
  (cd "${GOPATH}"/src/"${PACKAGE}" && \
      git checkout "${TAG}" && \
      GOPATH="${GOPATH}" make && \
      GOPATH="${GOPATH}" make install)
}

# Install dependencies for the crictl tests.
apt-get install -y btrfs-tools libseccomp-dev

# Install containerd & cri-tools.
GOPATH=$(mktemp -d --tmpdir gopathXXXXX)
install_helper github.com/containerd/containerd v1.2.2 "${GOPATH}"
install_helper github.com/kubernetes-sigs/cri-tools v1.11.0 "${GOPATH}"

# Install gvisor-containerd-shim.
declare -r base="https://storage.googleapis.com/cri-containerd-staging/gvisor-containerd-shim"
declare -r latest=$(mktemp --tmpdir gvisor-containerd-shim-latest.XXXXXX)
declare -r shim_path=$(mktemp --tmpdir gvisor-containerd-shim.XXXXXX)
wget --no-verbose "${base}"/latest -O ${latest}
wget --no-verbose "${base}"/gvisor-containerd-shim-$(cat ${latest}) -O ${shim_path}
chmod +x ${shim_path}
mv ${shim_path} /usr/local/bin

# Configure containerd-shim.
declare -r shim_config_path=/etc/containerd
declare -r shim_config_tmp_path=$(mktemp --tmpdir gvisor-containerd-shim.XXXXXX.toml)
mkdir -p ${shim_config_path}
cat > ${shim_config_tmp_path} <<-EOF
    runc_shim = "/usr/local/bin/containerd-shim"

[runsc_config]
    debug = "true"
    debug-log = "/tmp/runsc-logs/"
    strace = "true"
    file-access = "shared"
EOF
mv ${shim_config_tmp_path} ${shim_config_path}

# Configure CNI.
(cd "${GOPATH}" && GOPATH="${GOPATH}" \
    src/github.com/containerd/containerd/script/setup/install-cni)

# Cleanup the above.
rm -rf "${GOPATH}"
rm -rf "${latest}"
rm -rf "${shim_path}"
rm -rf "${shim_config_tmp_path}"
