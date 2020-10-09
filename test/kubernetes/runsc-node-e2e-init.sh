#!/bin/bash
#
# Copyright 2020 The gVisor Authors.
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

set -o xtrace
set -o errexit
set -o nounset
set -o pipefail

# CONTAINERD_HOME is the directory for containerd.
CONTAINERD_HOME="/home/containerd"

# KUBE_ENV_METADATA is the metadata key for kubernetes envs.
KUBE_ENV_METADATA="kube-env"
if [[ -f "${CONTAINERD_HOME}/${KUBE_ENV_METADATA}" ]]; then
  source "${CONTAINERD_HOME}/${KUBE_ENV_METADATA}"
fi

# CONTAINERD_ENV_METADATA is the metadata key for containerd envs.
CONTAINERD_ENV_METADATA="containerd-env"
if [[ -f "${CONTAINERD_HOME}/${CONTAINERD_ENV_METADATA}" ]]; then
  source "${CONTAINERD_HOME}/${CONTAINERD_ENV_METADATA}"
fi

fetch_metadata() {
  local -r key=$1
  local -r attributes="http://metadata.google.internal/computeMetadata/v1/instance/attributes"
  if curl --fail --retry 5 --retry-delay 3 --silent --show-error -H "X-Google-Metadata-Request: True" "${attributes}/" | \
    grep -q "^${key}$"; then
    curl --fail --retry 5 --retry-delay 3 --silent --show-error -H "X-Google-Metadata-Request: True" \
      "${attributes}/${key}"
  fi
}

# runsc_deploy_path is the path to deploy runsc binary.
runsc_deploy_path=${RUNSC_DEPLOY_PATH-"cri-containerd-staging/runsc"}

# containerd_shim_deploy_path is the path to deploy gvisor-containerd-shim
# binary.
containerd_shim_deploy_path=${CONTAINERD_SHIM_DEPLOY_PATH-"cri-containerd-staging/gvisor-containerd-shim"}

# runsc_platform is the platform to use for runsc.
runsc_platform=${RUNSC_PLATFORM:-"ptrace"}

if [[ -n "${runsc_deploy_path}" ]]; then
  # Download runsc.
  runsc_bin_name=$(curl -f --ipv4 --retry 6 --retry-delay 3 --silent --show-error \
    "https://storage.googleapis.com/${runsc_deploy_path}/latest")
  echo "Use runsc binary ${runsc_bin_name}"

  curl -f --ipv4 -Lo "${runsc_bin_path}" --connect-timeout 20 --max-time 300 \
    --retry 6 --retry-delay 10 "https://storage.googleapis.com/${runsc_deploy_path}/${runsc_bin_name}"
  chmod 755 "${runsc_bin_path}"
fi

if [[ -n "${containerd_shim_deploy_path}" ]]; then
  # Download gvisor containerd shim.
  shim_name="containerd-shim-runsc-v1"
  containerd_shim_bin_name="${shim_name}"-$(curl -f --ipv4 --retry 6 --retry-delay 3 --silent --show-error \
    "https://storage.googleapis.com/${containerd_shim_deploy_path}/latest")
  echo "Use gvisor containerd shim binary ${containerd_shim_bin_name}"

  containerd_shim_bin_path="${CONTAINERD_HOME}/usr/local/bin/${shim_name}"
  curl -f --ipv4 -Lo "${containerd_shim_bin_path}" --connect-timeout 20 --max-time 300 \
    --retry 6 --retry-delay 10 "https://storage.googleapis.com/${containerd_shim_deploy_path}/${containerd_shim_bin_name}"
  chmod 755 "${containerd_shim_bin_path}"
fi

# shim_config_path is the path of gvisor containerd shim config file.
shim_config_path=${SHIM_CONFIG_PATH:-"/run/containerd/runsc/config.toml"}
mkdir -p "$(dirname "${shim_config_path}")"
cat > "${shim_config_path}" <<EOF
binary_name = "${runsc_bin_path}"

[runsc_config]
  platform = "${runsc_platform}"
  net-raw = "true"
  debug = "${RUNSC_DEBUG:-"true"}"
  debug-log = "${RUNSC_DEBUG_LOG:-"/var/log/runsc.log.%ID%.%TIMESTAMP%.%COMMAND%"}"
  strace = "${RUNSC_STRACE:-"false"}"
  log-packets = "${RUNSC_LOG_PACKETS:-"false"}"
EOF

# Initialize containerized mounter.
mount /tmp /tmp -o remount,exec,suid
