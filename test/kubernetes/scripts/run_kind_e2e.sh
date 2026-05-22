#!/bin/bash

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

set -euo pipefail

# Constants
KIND_CLUSTER_NAME="gvisor-e2e"

# Use the default network so the container used for the tests can reach the control plane.
export KIND_EXPERIMENTAL_DOCKER_NETWORK="bridge"

# Ensure kind and kubectl are installed and in PATH
if ! command -v kind &> /dev/null || ! command -v kubectl &> /dev/null; then
  echo "kind or kubectl not found in PATH. Installing locally..."
  LOCAL_BIN="${HOME:-/tmp}/.local/bin"
  mkdir -p "${LOCAL_BIN}"
  export PATH="${LOCAL_BIN}:${PATH}"

  if ! command -v kind &> /dev/null; then
    echo "Downloading kind..."
    curl -Lo "${LOCAL_BIN}/kind" https://kind.sigs.k8s.io/dl/latest/kind-linux-amd64
    chmod +x "${LOCAL_BIN}/kind"
  fi

  if ! command -v kubectl &> /dev/null; then
    echo "Downloading kubectl..."
    curl -Lo "${LOCAL_BIN}/kubectl" "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    chmod +x "${LOCAL_BIN}/kubectl"
  fi
fi

# Build runsc
echo "Building runsc..."
BIN_DIR=$(mktemp -d)
trap 'rm -rf "${BIN_DIR}"' EXIT
make copy TARGETS=runsc DESTINATION="${BIN_DIR}/"
make copy TARGETS=//shim:containerd-shim-runsc-v1 DESTINATION="${BIN_DIR}/"

KUBECONFIG_PATH="${BIN_DIR}/kubeconfig"
KUBECONFIG_INTERNAL_PATH="${BIN_DIR}/kubeconfig_internal"
export KUBECONFIG="${KUBECONFIG_PATH}"

# Create Kind cluster if it doesn't exist or is not running
if ! docker ps --filter "name=${KIND_CLUSTER_NAME}-control-plane" --filter "status=running" --format '{{.Names}}' | grep -q "^${KIND_CLUSTER_NAME}-control-plane$"; then
  echo "Kind cluster ${KIND_CLUSTER_NAME} is not running. Recreating..."
  kind delete cluster --name "${KIND_CLUSTER_NAME}" || true
  echo "Creating Kind cluster ${KIND_CLUSTER_NAME}..."
  cat <<EOF | kind create cluster --name "${KIND_CLUSTER_NAME}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
    runtime_type = "io.containerd.runsc.v1"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
    TypeUrl = "io.containerd.runsc.v1.options"
    ConfigPath = "/etc/containerd/runsc.toml"
EOF
fi

# Export the kubeconfigs to our temporary files. We generate two files:
# - KUBECONFIG_PATH: uses host-mapped loopback address for host-side kubectl commands.
# - KUBECONFIG_INTERNAL_PATH: uses internal container address for testing inside docker.
echo "Exporting kubeconfigs..."
kind export kubeconfig --name "${KIND_CLUSTER_NAME}" --kubeconfig "${KUBECONFIG_PATH}"
kind export kubeconfig --name "${KIND_CLUSTER_NAME}" --kubeconfig "${KUBECONFIG_INTERNAL_PATH}" --internal

# Since DNS resolution is disabled on Docker's default bridge network, inspect the
# control plane's IP address and rewrite the hostname inside kubeconfig_internal to it.
CONTROL_PLANE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${KIND_CLUSTER_NAME}-control-plane")
echo "Rewriting internal kubeconfig to use control plane IP: ${CONTROL_PLANE_IP}"
sed -i "s/gvisor-e2e-control-plane/${CONTROL_PLANE_IP}/g" "${KUBECONFIG_INTERNAL_PATH}"

# Install runsc on the node
NODE="${KIND_CLUSTER_NAME}-control-plane"
echo "Installing runsc on node ${NODE}..."
docker cp "${BIN_DIR}/runsc" "${NODE}:/usr/bin/runsc"
docker exec "${NODE}" chmod +x /usr/bin/runsc

# Also install runsc as the containerd-shim-runsc-v1
docker cp "${BIN_DIR}/containerd-shim-runsc-v1" "${NODE}:/usr/bin/containerd-shim-runsc-v1"
docker exec "${NODE}" chmod +x /usr/bin/containerd-shim-runsc-v1

# Create runsc.toml
echo "Creating runsc.toml..."
cat <<EOF | docker exec -i "${NODE}" tee /etc/containerd/runsc.toml
[runsc_config]
  debug = "true"
  debug-log = "/var/log/runsc/%ID%/gvisor.%COMMAND%.log"
EOF

# Restart containerd to pick up changes
docker exec "${NODE}" systemctl restart containerd

# Apply RuntimeClass
echo "Applying RuntimeClass..."
cat <<EOF | kubectl apply --context "kind-${KIND_CLUSTER_NAME}" -f -
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
EOF

# Label the node
echo "Labeling node..."
kubectl label node "${NODE}" --context "kind-${KIND_CLUSTER_NAME}" --overwrite \
  model=e2e \
  nodepool-type=test-runtime-nodepool \
  runtime=gvisor \
  sandbox.gke.io/runtime=gvisor \
  node.kubernetes.io/instance-type=n2-standard-4

# Run tests
echo "Running E2E tests..."
TEST_TARGETS=("$@")
if (( ${#TEST_TARGETS[@]} == 0 )); then
  TEST_TARGETS=("//test/kubernetes/tests/...")
fi

echo "Executing bazel test via make..."
if ! make test TARGETS="${TEST_TARGETS[*]}" OPTIONS="--test_output=streamed --nocache_test_results --test_env=KUBECONFIG=${KUBECONFIG_INTERNAL_PATH} --test_arg=--kubectl-context=kind-${KIND_CLUSTER_NAME} --test_arg=--test-nodepool-runtime=gvisor"; then
  echo "E2E tests failed! Exporting kind logs..."
  KIND_LOGS_DIR="${BIN_DIR}/kind-logs"
  kind export logs --name "${KIND_CLUSTER_NAME}" "${KIND_LOGS_DIR}" || true
  find "${KIND_LOGS_DIR}" -type f | while read -r log_file; do
    echo "================================================================="
    echo " LOG FILE: ${log_file}"
    echo "================================================================="
    cat "${log_file}" || true
    echo ""
  done
  exit 1
fi
