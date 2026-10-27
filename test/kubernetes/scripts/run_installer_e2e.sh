#!/bin/bash

# Copyright 2026 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License")
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Exercises the Helm installer on a fresh kind control plane and worker.
# Usage: run_installer_e2e.sh <installer-A.docker.tar> [installer-B.docker.tar]
# The optional B archive must contain a different release payload.
#
# Tools must already be installed. HELM, KUBECTL, KIND and DOCKER select their
# executables. KEEP_CLUSTER=true retains the cluster for inspection.
# TEST_FAILED_ACTIVATION=true adds a final containerd restart failure test.
# CONTAINERD_CONFIG_VERSION=3 migrates the worker config before installation.
# The default leaves the node image's config unchanged.
# ARTIFACTS_DIR must name a nonexistent directory if set. Diagnostics are kept.

set -euo pipefail

if [[ "$#" -lt 1 || "$#" -gt 2 ]]; then
  echo "usage: $0 <installer-A.docker.tar> [installer-B.docker.tar]" >&2
  exit 1
fi
for archive in "$@"; do
  [[ -f "${archive}" ]] || { echo "archive not found: ${archive}" >&2; exit 1; }
done

declare -r REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
declare -r CHART="${REPO_ROOT}/tools/gvisor_k8s_tool/helm/gvisor"
declare -r HELM="${HELM:-helm}"
declare -r KUBECTL="${KUBECTL:-kubectl}"
declare -r KIND="${KIND:-kind}"
declare -r DOCKER="${DOCKER:-docker}"
for tool in "${HELM}" "${KUBECTL}" "${KIND}" "${DOCKER}" python3; do
  command -v "${tool}" >/dev/null || { echo "missing executable: ${tool}" >&2; exit 1; }
done
declare -r CLUSTER="${CLUSTER_NAME:-gvisor-installer-$(date +%s)-$$}"
if [[ ! "${CLUSTER}" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ || "${#CLUSTER}" -gt 40 ]]; then
  echo "CLUSTER_NAME must be a DNS label of at most 40 characters" >&2
  exit 1
fi
for setting in "${KEEP_CLUSTER:-false}" "${TEST_FAILED_ACTIVATION:-false}"; do
  [[ "${setting}" == true || "${setting}" == false ]] || { echo "test switches must be true or false" >&2; exit 1; }
done
declare -r CONTAINERD_CONFIG_VERSION="${CONTAINERD_CONFIG_VERSION:-}"
if [[ -n "${CONTAINERD_CONFIG_VERSION}" && "${CONTAINERD_CONFIG_VERSION}" != 3 ]]; then
  echo "CONTAINERD_CONFIG_VERSION must be unset or 3" >&2
  exit 1
fi
if [[ -n "${ARTIFACTS_DIR:-}" ]]; then
  mkdir "${ARTIFACTS_DIR}"
else
  ARTIFACTS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gvisor-installer-e2e.XXXXXX")"
fi
ARTIFACTS_DIR="$(cd "${ARTIFACTS_DIR}" && pwd)"
readonly ARTIFACTS_DIR
export KUBECONFIG="${ARTIFACTS_DIR}/kubeconfig"
declare -r WORKER="${CLUSTER}-worker"
declare -r CONTROL_PLANE="${CLUSTER}-control-plane"
declare -r NODE_IMAGE="${NODE_IMAGE:-kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a}"
declare -r WORKLOAD_IMAGE="${WORKLOAD_IMAGE:-docker.io/library/busybox:1.37.0}"
declare -r IMAGE_REPOSITORY="gvisor-installer-e2e/${CLUSTER}"
declare -r IMAGE_A="${IMAGE_REPOSITORY}:a"
declare -r IMAGE_B="${IMAGE_REPOSITORY}:b"
declare -r SOURCE_IMAGE="gvisor.dev/images/gvisor-installer:latest"
declare -r RELEASE=installer
declare -r DAEMONSET=installer-gvisor
declare -r SELECTOR="app.kubernetes.io/instance=${RELEASE}"
declare CREATED=false
declare WRAPPER_INSTALLED=false
declare IMAGES_LOADED=false
declare SOURCE_IMAGE_TOUCHED=false
declare SOURCE_IMAGE_ID=""

kube() { "${KUBECTL}" --context "kind-${CLUSTER}" "$@"; }
host() { "${DOCKER}" exec "${WORKER}" "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
log() { echo "== $*"; }

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  if [[ "${WRAPPER_INSTALLED}" == true ]]; then
    host rm -f /usr/local/bin/systemctl /run/gvisor-installer-e2e-restart-failed
  fi
  if [[ "${CREATED}" == true ]]; then
    kube get nodes,pods,daemonsets,runtimeclasses -A -o yaml >"${ARTIFACTS_DIR}/objects.yaml" 2>&1
    kube get events -A --sort-by=.metadata.creationTimestamp >"${ARTIFACTS_DIR}/events.txt" 2>&1
    kube logs -l "${SELECTOR}" --all-containers --prefix >"${ARTIFACTS_DIR}/installer.log" 2>&1
    host cat /var/lib/gvisor-installer/state.json >"${ARTIFACTS_DIR}/state-final.json" 2>&1
    host cat /etc/containerd/config.toml >"${ARTIFACTS_DIR}/containerd-final.toml" 2>&1
    host sh -c 'for p in /proc/[0-9]*/exe; do readlink "$p"; done' >"${ARTIFACTS_DIR}/executables.txt" 2>&1
    if [[ "${status}" -ne 0 ]]; then
      "${KIND}" export logs --name "${CLUSTER}" "${ARTIFACTS_DIR}/kind-logs"
    fi
    if [[ "${KEEP_CLUSTER:-false}" != true ]]; then
      "${KIND}" delete cluster --name "${CLUSTER}"
    else
      echo "Retained cluster ${CLUSTER}. KUBECONFIG=${KUBECONFIG}"
    fi
  fi
  if [[ "${SOURCE_IMAGE_TOUCHED}" == true ]]; then
    if [[ -n "${SOURCE_IMAGE_ID}" ]]; then
      if ! "${DOCKER}" tag "${SOURCE_IMAGE_ID}" "${SOURCE_IMAGE}"; then
        echo "Could not restore ${SOURCE_IMAGE} to ${SOURCE_IMAGE_ID}" >&2
        status=1
      fi
    elif "${DOCKER}" image inspect "${SOURCE_IMAGE}" >/dev/null 2>&1; then
      if ! "${DOCKER}" image rm "${SOURCE_IMAGE}" >/dev/null 2>&1; then
        echo "Could not remove the temporary ${SOURCE_IMAGE} tag" >&2
        status=1
      fi
    fi
  fi
  if [[ "${IMAGES_LOADED}" == true && "${KEEP_CLUSTER:-false}" != true ]]; then
    "${DOCKER}" image rm "${IMAGE_A}" "${IMAGE_B}" >/dev/null 2>&1
  fi
  echo "Diagnostics: ${ARTIFACTS_DIR}"
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_until() {
  local description="$1"
  shift
  local attempt
  for attempt in $(seq 1 120); do
    if "$@"; then return 0; fi
    sleep 2
  done
  fail "timed out: ${description}"
}

state_field() {
  host cat /var/lib/gvisor-installer/state.json |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["active"][sys.argv[1]])' "$1"
}

config_hash() { host sha256sum /etc/containerd/config.toml | cut -d' ' -f1; }
installer_count() { kube get pods -l "${SELECTOR}" -o json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["items"]))'; }
no_installer() { [[ "$(installer_count)" == 0 ]]; }
one_installer() { [[ "$(installer_count)" == 1 ]]; }

assert_plain() {
  [[ "$(kube get pod ordinary -o jsonpath='{.metadata.uid}')" == "${PLAIN_UID}" ]] || fail "ordinary pod was replaced"
  [[ "$(kube get pod ordinary -o jsonpath='{.status.containerStatuses[0].restartCount}')" == 0 ]] || fail "ordinary pod restarted"
  [[ -z "$(kube get pod ordinary -o jsonpath='{.spec.runtimeClassName}')" ]] || fail "ordinary pod acquired a runtime class"
  kube exec ordinary -- test -f /tmp/alive
}

new_pod() {
  local name="$1" runtime="$2"
  python3 - "${name}" "${runtime}" "${WORKER}" "${WORKLOAD_IMAGE}" <<'PY' | kube apply -f -
import json
import sys
name, runtime, worker, image = sys.argv[1:]
spec = {
    "restartPolicy": "Never",
    "nodeSelector": {"kubernetes.io/hostname": worker},
    "containers": [{"name": "busybox", "image": image, "imagePullPolicy": "IfNotPresent",
                    "command": ["sh", "-c", "touch /tmp/alive; sleep 7200"]}],
}
if runtime:
    spec["runtimeClassName"] = runtime
print(json.dumps({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": spec}))
PY
  kube wait --for=condition=Ready "pod/${name}" --timeout=180s
  if [[ -n "${runtime}" ]]; then
    kube exec "${name}" -- uname -a | tee "${ARTIFACTS_DIR}/${name}-uname.txt"
    kube exec "${name}" -- dmesg | tee "${ARTIFACTS_DIR}/${name}-dmesg.txt"
    grep -q 'Starting gVisor' "${ARTIFACTS_DIR}/${name}-dmesg.txt" || fail "pod ${name} did not report gVisor"
  fi
}

assert_generation() {
  local pod="$1" generation="$2" sandbox
  sandbox="$(host crictl pods -o json | python3 -c 'import json,sys; print(next(p["id"] for p in json.load(sys.stdin)["items"] if p["metadata"]["name"] == sys.argv[1] and p["metadata"]["namespace"] == "default"))' "${pod}")"
  # Match both the sandbox ID and an executable from its retained generation.
  # Sidecar binaries are part of the same opaque release fileset as runsc.
  host sh -ec '
    for proc in /proc/[0-9]*; do
      cmd=$(tr "\000" " " <"$proc/cmdline" 2>/dev/null) || continue
      case "$cmd" in *"$1"*)
        exe=$(readlink "$proc/exe") || continue
        case "$exe" in "$2/"*) printf "%s %s\n" "$proc" "$exe"; exit 0;; esac
      esac
    done
    exit 1
  ' sh "${sandbox}" "${generation}" || fail "pod ${pod} has no process from ${generation}"
}

install_chart() {
  local tag="$1"
  "${HELM}" upgrade --install "${RELEASE}" "${CHART}" \
    --namespace default --set-string "image.repository=${IMAGE_REPOSITORY}" \
    --set-string "image.tag=${tag}" --set image.pullPolicy=Never \
    --wait --timeout 8m
  kube rollout status "daemonset/${DAEMONSET}" --timeout=180s
  [[ "$(installer_count)" == 1 ]] || fail "expected exactly one worker installer"
  [[ "$(kube get pods -l "${SELECTOR}" -o jsonpath='{.items[0].spec.nodeName}')" == "${WORKER}" ]] || fail "installer ran on the control plane"
}

log "Validating installer archive tags"
python3 - "${SOURCE_IMAGE}" "$@" <<'PY'
import json
import sys
import tarfile

expected = sys.argv[1]
for filename in sys.argv[2:]:
    with tarfile.open(filename) as archive:
        members = [member for member in archive.getmembers() if member.name == "manifest.json"]
        if len(members) != 1 or not members[0].isfile():
            raise SystemExit(f"{filename}: expected one regular Docker-save manifest.json")
        manifest = json.load(archive.extractfile(members[0]))
        if not isinstance(manifest, list) or len(manifest) != 1 or manifest[0].get("RepoTags") != [expected]:
            raise SystemExit(f"{filename}: expected exactly one image tagged {expected}")
PY

log "Creating isolated cluster ${CLUSTER}"
clusters="$("${KIND}" get clusters)"
if grep -Fxq "${CLUSTER}" <<<"${clusters}" || "${DOCKER}" inspect "${CONTROL_PLANE}" >/dev/null 2>&1 || "${DOCKER}" inspect "${WORKER}" >/dev/null 2>&1; then
  fail "cluster or node already exists, refusing to reuse or delete it: ${CLUSTER}"
fi
for image in "${IMAGE_A}" "${IMAGE_B}"; do
  if "${DOCKER}" image inspect "${image}" >/dev/null 2>&1; then
    fail "test image already exists, refusing to overwrite it: ${image}"
  fi
done
SOURCE_IMAGE_ID="$("${DOCKER}" image inspect -f '{{.Id}}' "${SOURCE_IMAGE}" 2>/dev/null || true)"
cat >"${ARTIFACTS_DIR}/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
  - role: worker
EOF
CREATED=true
"${KIND}" create cluster --name "${CLUSTER}" --image "${NODE_IMAGE}" \
  --config "${ARTIFACTS_DIR}/kind.yaml" --kubeconfig "${KUBECONFIG}" --wait 180s
for node in "${CONTROL_PLANE}" "${WORKER}"; do
  "${DOCKER}" exec "${node}" sh -ec '
    ! command -v runsc
    ! command -v containerd-shim-runsc-v1
    test ! -e /opt/gvisor
    test ! -e /var/lib/gvisor-installer/state.json
    ! grep -q runsc /etc/containerd/config.toml
  '
done

if [[ "${CONTAINERD_CONFIG_VERSION}" == 3 ]]; then
  log "Migrating the worker to containerd config schema 3"
  host containerd --version | tee "${ARTIFACTS_DIR}/containerd-version.txt"
  host test ! -e /etc/containerd/config.toml.installer-e2e-original
  host test ! -e /etc/containerd/config.toml.installer-e2e-v3
  host cp -p /etc/containerd/config.toml /etc/containerd/config.toml.installer-e2e-original
  host cat /etc/containerd/config.toml.installer-e2e-original >"${ARTIFACTS_DIR}/containerd-before-schema3.toml"
  host containerd --config /etc/containerd/config.toml config migrate >"${ARTIFACTS_DIR}/containerd-schema3.toml"
  python3 - "${ARTIFACTS_DIR}/containerd-schema3.toml" <<'PY'
from pathlib import Path
import re
import sys

if not re.search(r"(?m)^version\s*=\s*3\s*$", Path(sys.argv[1]).read_text()):
    raise SystemExit("containerd config migrate did not produce schema version 3")
PY
  "${DOCKER}" cp "${ARTIFACTS_DIR}/containerd-schema3.toml" "${WORKER}:/etc/containerd/config.toml.installer-e2e-v3"
  host containerd --config /etc/containerd/config.toml.installer-e2e-v3 config dump >/dev/null
  host sh -ec '
    cat /etc/containerd/config.toml.installer-e2e-v3 > /etc/containerd/config.toml
    rm /etc/containerd/config.toml.installer-e2e-v3
    /usr/bin/systemctl restart containerd
  '
  kube wait --for=condition=Ready "node/${WORKER}" --timeout=180s
fi

log "Loading installer images"
SOURCE_IMAGE_TOUCHED=true
"${DOCKER}" load -i "$1"
"${DOCKER}" tag "${SOURCE_IMAGE}" "${IMAGE_A}"
IMAGES_LOADED=true
"${KIND}" load docker-image --name "${CLUSTER}" "${IMAGE_A}"
if [[ "$#" == 2 ]]; then
  "${DOCKER}" load -i "$2"
  "${DOCKER}" tag "${SOURCE_IMAGE}" "${IMAGE_B}"
  [[ "$("${DOCKER}" image inspect -f '{{.Id}}' "${IMAGE_A}")" != "$("${DOCKER}" image inspect -f '{{.Id}}' "${IMAGE_B}")" ]] || fail "A and B are the same image"
  "${KIND}" load docker-image --name "${CLUSTER}" "${IMAGE_B}"
fi
new_pod ordinary ""
PLAIN_UID="$(kube get pod ordinary -o jsonpath='{.metadata.uid}')"
[[ -n "${PLAIN_UID}" ]] || fail "ordinary pod UID is empty"
readonly PLAIN_UID

log "Installing generation A on the worker"
install_chart a
host cat /var/lib/gvisor-installer/state.json >"${ARTIFACTS_DIR}/state-a.json"
GENERATION_A="$(state_field generationPath)"
PAYLOAD_A="$(state_field payloadSHA512)"
[[ "${GENERATION_A}" == /* && "${GENERATION_A}" != / ]] || fail "active generation A path must be absolute and nonempty"
[[ "${PAYLOAD_A}" =~ ^[0-9a-f]{128}$ ]] || fail "active generation A payload must have a SHA512 digest"
readonly GENERATION_A PAYLOAD_A
new_pod sandbox-a gvisor
assert_generation sandbox-a "${GENERATION_A}"
assert_plain
"${DOCKER}" exec "${CONTROL_PLANE}" test ! -e /var/lib/gvisor-installer/state.json
baseline_config="$(config_hash)"

log "Opting out removes the installer and preserves the host"
kube label node "${WORKER}" gvisor.dev/install=disabled --overwrite
wait_until "installer removal after opt-out" no_installer
[[ "$(config_hash)" == "${baseline_config}" ]] || fail "opt-out changed containerd config"
[[ "$(state_field generationPath)" == "${GENERATION_A}" ]] || fail "opt-out removed the generation"
kube exec sandbox-a -- test -f /tmp/alive
assert_plain
kube label node "${WORKER}" gvisor.dev/install-
wait_until "installer reenrollment" one_installer
kube rollout status "daemonset/${DAEMONSET}" --timeout=180s

log "Uninstall retains the host installation, reinstall adopts it"
"${HELM}" uninstall "${RELEASE}" --wait --timeout 3m
wait_until "installer uninstall" no_installer
[[ "$(config_hash)" == "${baseline_config}" ]] || fail "uninstall changed containerd config"
[[ "$(state_field generationPath)" == "${GENERATION_A}" ]] || fail "uninstall removed the generation"
install_chart a
[[ "$(state_field generationPath)" == "${GENERATION_A}" ]] || fail "reinstall did not adopt the retained generation"
new_pod sandbox-reinstalled gvisor
assert_generation sandbox-reinstalled "${GENERATION_A}"

if [[ "$#" == 2 ]]; then
  log "Upgrading to distinct payload B and retaining running generation A"
  install_chart b
  host cat /var/lib/gvisor-installer/state.json >"${ARTIFACTS_DIR}/state-b.json"
  generation_b="$(state_field generationPath)"
  payload_b="$(state_field payloadSHA512)"
  [[ "${generation_b}" == /* && "${generation_b}" != / ]] || fail "active generation B path must be absolute and nonempty"
  [[ "${payload_b}" =~ ^[0-9a-f]{128}$ ]] || fail "active generation B payload must have a SHA512 digest"
  [[ "${payload_b}" != "${PAYLOAD_A}" ]] || fail "B must contain a different payload, changing only the image tag is insufficient"
  [[ "${generation_b}" != "${GENERATION_A}" ]] || fail "B reused A's generation"
  kube exec sandbox-a -- test -f /tmp/alive
  assert_generation sandbox-a "${GENERATION_A}"
  new_pod sandbox-b gvisor
  assert_generation sandbox-b "${generation_b}"
  assert_plain

  log "Rolling Helm back to A while existing A and B sandboxes keep working"
  "${HELM}" rollback "${RELEASE}" 1 --wait --timeout 8m
  kube rollout status "daemonset/${DAEMONSET}" --timeout=180s
  [[ "$(state_field generationPath)" == "${GENERATION_A}" ]] || fail "rollback did not select generation A"
  kube exec sandbox-a -- test -f /tmp/alive
  kube exec sandbox-b -- test -f /tmp/alive
  assert_generation sandbox-b "${generation_b}"
  new_pod sandbox-rollback gvisor
  assert_generation sandbox-rollback "${GENERATION_A}"
fi

if [[ "${TEST_FAILED_ACTIVATION:-false}" == true ]]; then
  log "Injecting one failed restart and checking restoration of the prior handler"
  baseline_config="$(config_hash)"
  host test ! -e /usr/local/bin/systemctl
  host test -x /usr/bin/systemctl
  "${DOCKER}" exec -i "${WORKER}" sh -c 'cat > /usr/local/bin/systemctl && chmod 0755 /usr/local/bin/systemctl' <<'EOF'
#!/bin/sh
if [ "$1" = restart ] && [ "$2" = containerd ] && [ ! -e /run/gvisor-installer-e2e-restart-failed ]; then
  touch /run/gvisor-installer-e2e-restart-failed
  echo 'injected installer E2E restart failure' >&2
  exit 1
fi
exec /usr/bin/systemctl "$@"
EOF
  WRAPPER_INSTALLED=true
  printf '[runsc_config]\n  debug = "true"\n' >"${ARTIFACTS_DIR}/failed-activation.toml"
  "${HELM}" upgrade "${RELEASE}" "${CHART}" --reuse-values \
    --set-file "runscConfig=${ARTIFACTS_DIR}/failed-activation.toml"
  rollback_settled() {
    host test -e /run/gvisor-installer-e2e-restart-failed || return 1
    [[ "$(config_hash)" == "${baseline_config}" ]] || return 1
    host cat /var/lib/gvisor-installer/state.json | python3 -c 'import json,sys; s=json.load(sys.stdin); sys.exit(bool(s.get("pending")))' || return 1
    kube logs -l "${SELECTOR}" | grep -q 'previous config rolled back' || return 1
    [[ "$(kube get pods -l "${SELECTOR}" -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}')" == False ]] || return 1
    [[ "$(kube get node "${WORKER}" -o jsonpath='{.metadata.labels.gvisor\.dev/ready}')" == true ]]
  }
  wait_until "activation failure rollback and unready desired convergence" rollback_settled
  [[ "$(state_field generationPath)" == "${GENERATION_A}" ]] || fail "failed activation lost previous generation"
  new_pod sandbox-after-failure gvisor
  assert_generation sandbox-after-failure "${GENERATION_A}"
  host rm /usr/local/bin/systemctl /run/gvisor-installer-e2e-restart-failed
  WRAPPER_INSTALLED=false
fi
assert_plain
log "Installer E2E scenarios passed"
