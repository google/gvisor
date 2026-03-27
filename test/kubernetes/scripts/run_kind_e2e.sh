#!/bin/bash
set -euo pipefail

# Constants
KIND_CLUSTER_NAME="gvisor-e2e"
KUBECONFIG_PATH="${HOME}/.kube/config"

# Build runsc
echo "Building runsc..."
BIN_DIR=$(mktemp -d)
trap 'rm -rf "${BIN_DIR}"' EXIT
make copy TARGETS=runsc DESTINATION="${BIN_DIR}/"
make copy TARGETS=//shim:containerd-shim-runsc-v1 DESTINATION="${BIN_DIR}/"

# Create Kind cluster if it doesn't exist
if ! kind get clusters | grep -q "${KIND_CLUSTER_NAME}"; then
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
  sandbox.gke.io/runtime=gvisor

# Run tests
echo "Running E2E tests..."
TEST_TARGETS="${@:-//test/kubernetes/tests/...}"

if ! command -v bazel &> /dev/null; then
  echo "Error: bazel not found in PATH"
  exit 1
fi

bazel test ${TEST_TARGETS} \
  --test_output=streamed \
  --nocache_test_results \
  --test_env=KUBECONFIG="${KUBECONFIG_PATH}" \
  --test_arg=--kubectl-context="kind-${KIND_CLUSTER_NAME}" \
  --test_arg=--test-nodepool-runtime=gvisor
