#!/bin/bash

# Copyright 2018 Google LLC
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

# Fail on any error. Treat unset variables as error. Print commands as executed.
set -eux


###################
# GLOBAL ENV VARS #
###################

readonly WORKSPACE_DIR="${PWD}/git/repo"

# Used to configure RBE.
readonly CLOUD_PROJECT_ID="copybara-shentu"
readonly RBE_PROJECT_ID="projects/${CLOUD_PROJECT_ID}/instances/default_instance"

# Random runtime name to avoid collisions.
readonly RUNTIME="runsc_test_$((RANDOM))"

# Packages that will be built and tested.
readonly BUILD_PACKAGES=("//...")
readonly TEST_PACKAGES=("//pkg/..." "//runsc/..." "//tools/...")

#######################
# BAZEL CONFIGURATION #
#######################

# Install the latest version of Bazel, and log the location and version.
use_bazel.sh latest
which bazel
bazel version

# Load the kvm module
sudo -n -E modprobe kvm

# General Bazel build/test flags.
BAZEL_BUILD_FLAGS=(
  "--show_timestamps"
  "--test_output=errors"
  "--keep_going"
  "--verbose_failures=true"
)

# Bazel build/test for RBE, a super-set of BAZEL_BUILD_FLAGS.
BAZEL_BUILD_RBE_FLAGS=(
  "${BAZEL_BUILD_FLAGS[@]}"
  "--config=remote"
  "--project_id=${CLOUD_PROJECT_ID}"
  "--remote_instance_name=${RBE_PROJECT_ID}"
  "--auth_credentials=${KOKORO_BAZEL_AUTH_CREDENTIAL}"
)

####################
# Helper Functions #
####################

build_everything() {
  FLAVOR="${1}"

  cd ${WORKSPACE_DIR}
  bazel build \
    -c "${FLAVOR}" "${BAZEL_BUILD_RBE_FLAGS[@]}" \
    "${BUILD_PACKAGES[@]}"
}

# Run simple tests runs the tests that require no special setup or
# configuration.
run_simple_tests() {
  cd ${WORKSPACE_DIR}
  bazel test \
    "${BAZEL_BUILD_FLAGS[@]}" \
    "${TEST_PACKAGES[@]}"
}

install_runtime() {
  cd ${WORKSPACE_DIR}
  sudo -n ${WORKSPACE_DIR}/runsc/test/install.sh --runtime ${RUNTIME}
}

# Install dependencies for the crictl tests.
install_crictl_test_deps() {
  # Install containerd.
  sudo -n -E apt-get update
  sudo -n -E apt-get install -y btrfs-tools libseccomp-dev
  # go get will exit with a status of 1 despite succeeding, so ignore errors.
  go get -d github.com/containerd/containerd || true
  cd ${GOPATH}/src/github.com/containerd/containerd
  git checkout v1.2.2
  make
  sudo -n -E make install

  # Install crictl.
  # go get will exit with a status of 1 despite succeeding, so ignore errors.
  go get -d github.com/kubernetes-sigs/cri-tools || true
  cd ${GOPATH}/src/github.com/kubernetes-sigs/cri-tools
  git checkout tags/v1.11.0
  make
  sudo -n -E make install

  # Install gvisor-containerd-shim.
  local latest=/tmp/gvisor-containerd-shim-latest
  local shim_path=/tmp/gvisor-containerd-shim
  wget --no-verbose https://storage.googleapis.com/cri-containerd-staging/gvisor-containerd-shim/latest -O ${latest}
  wget --no-verbose https://storage.googleapis.com/cri-containerd-staging/gvisor-containerd-shim/$(cat ${latest}) -O ${shim_path}
  chmod +x ${shim_path}
  sudo -n -E mv ${shim_path} /usr/local/bin

  # Configure containerd-shim.
  local shim_config_path=/etc/containerd
  local shim_config_tmp_path=/tmp/gvisor-containerd-shim.toml
  sudo -n -E mkdir -p ${shim_config_path}
  cat > ${shim_config_tmp_path} <<-EOF
    runc_shim = "/usr/local/bin/containerd-shim"

    [runsc_config]
      debug = "true"
      debug-log = "/tmp/runsc-logs/"
      strace = "true"
      file-access = "shared"
EOF
  sudo mv ${shim_config_tmp_path} ${shim_config_path}

  # Configure CNI.
  sudo -n -E env PATH=${PATH} ${GOPATH}/src/github.com/containerd/containerd/script/setup/install-cni
}

# Run the tests that require docker.
run_docker_tests() {
  cd ${WORKSPACE_DIR}

  # These names are used to exclude tests not supported in certain
  # configuration, e.g. save/restore not supported with hostnet.
  declare -a variations=("" "-kvm" "-hostnet" "-overlay")
  for v in "${variations[@]}"; do
    # Run runsc tests with docker that are tagged manual.
    bazel test \
      "${BAZEL_BUILD_FLAGS[@]}" \
      --test_env=RUNSC_RUNTIME="${RUNTIME}${v}" \
      //runsc/test/image:image_test \
      //runsc/test/integration:integration_test
  done
}

# Run the tests that require root.
run_root_tests() {
  cd ${WORKSPACE_DIR}
  bazel build //runsc/test/root:root_test
  local root_test=$(find -L ./bazel-bin/ -executable -type f -name root_test | grep __main__)
  if [[ ! -f "${root_test}" ]]; then
    echo "root_test executable not found"
    exit 1
  fi
  sudo -n -E RUNSC_RUNTIME="${RUNTIME}" RUNSC_EXEC=/tmp/"${RUNTIME}"/runsc ${root_test}
}

# Run syscall unit tests.
run_syscall_tests() {
  cd ${WORKSPACE_DIR}
  bazel test "${BAZEL_BUILD_RBE_FLAGS[@]}" \
    --test_tag_filters=runsc_ptrace //test/syscalls/...
}

# Find and rename all test xml and log files so that Sponge can pick them up.
# XML files must be named sponge_log.xml, and log files must be named
# sponge_log.log. We move all such files into KOKORO_ARTIFACTS_DIR, in a
# subdirectory named with the test name.
upload_test_artifacts() {
  cd ${WORKSPACE_DIR}
  find -L "bazel-testlogs" -name "test.xml" -o -name "test.log" -o -name "outputs.zip" |
    tar --create --files-from - --transform 's/test\./sponge_log./' |
    tar --extract --directory ${KOKORO_ARTIFACTS_DIR}
}

# Finish runs at exit, even in the event of an error, and uploads all test
# artifacts.
finish() {
  # Grab the last exit code, we will return it.
  local exit_code=${?}
  upload_test_artifacts
  exit ${exit_code}
}

########
# MAIN #
########

main() {
  # Register finish to run at exit.
  trap finish EXIT

  # Build and run the simple tests.
  build_everything opt
  run_simple_tests

  # So far so good. Install more deps and run the integration tests.
  install_runtime
  install_crictl_test_deps
  run_docker_tests
  run_root_tests

  run_syscall_tests

  # Build other flavors too.
  build_everything dbg

  # No need to call "finish" here, it will happen at exit.
}

# Kick it off.
main
