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

# Fail on any error.
set -e
# Display commands to stderr.
set -x

# Install the latest version of Bazel.
use_bazel.sh latest

# Log the bazel path and version.
which bazel
bazel version

cd git/repo

# Build everything.
bazel build //...

# Test use this variable to determine what runtime to use.
runtime=runsc_test_$((RANDOM))
sudo -n ./runsc/test/install.sh --runtime ${runtime}

# Best effort to uninstall the runtime
uninstallRuntime() {
  sudo -n ./runsc/test/install.sh -u --runtime ${runtime}
}

# Run the tests and upload results.
#
# We turn off "-e" flag because we must move the log files even if the test
# fails.
set +e
bazel test --test_output=errors //...
exit_code=${?}

# This function spawns a subshell to install crictl and containerd.
installCrictl() (
  # Fail on any error.
  set -e
  # Display commands to stderr.
  set -x

  # Install containerd.
  # libseccomp2 needs to be downgraded in order to install libseccomp-dev.
  sudo -n -E apt-get install -y --force-yes libseccomp2=2.1.1-1ubuntu1~trusty4
  sudo -n -E apt-get install -y btrfs-tools libseccomp-dev
  # go get will exit with a status of 1 despite succeeding, so ignore errors.
  go get -d github.com/containerd/containerd || true
  cd ${GOPATH}/src/github.com/containerd/containerd
  git checkout tags/v1.1.4
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
  local shim_path=/tmp/gvisor-containerd-shim
  wget https://storage.googleapis.com/cri-containerd-staging/gvisor-containerd-shim/gvisor-containerd-shim -O ${shim_path}
  chmod +x ${shim_path}
  sudo -n -E mv ${shim_path} /usr/local/bin

  # Configure containerd.
  local shim_config_path=/etc/containerd
  local shim_config_tmp_path=/tmp/gvisor-containerd-shim.toml
  sudo -n -E mkdir -p ${shim_config_path}
  cat > ${shim_config_tmp_path} <<-EOF
    runc_shim = "/usr/local/bin/containerd-shim"

    [runsc_config]
      debug = "true"
      debug-log = "/tmp/runsc-log/"
      strace = "true"
      file-access = "shared"
EOF
  sudo mv ${shim_config_tmp_path} ${shim_config_path}
)

# Install containerd and crictl.
if [[ ${exit_code} -eq 0 ]]; then
  installCrictl
  exit_code=${?}
fi

# Execute local tests that require docker.
if [[ ${exit_code} -eq 0 ]]; then
  # These names are used to exclude tests not supported in certain
  # configuration, e.g. save/restore not supported with hostnet.
  declare -a variations=("" "-kvm" "-hostnet" "-overlay")
  for v in "${variations[@]}"; do
    # Run runsc tests with docker that are tagged manual.
    bazel test --test_output=errors --test_env=RUNSC_RUNTIME=${runtime}${v} \
      //runsc/test/image:image_test \
      //runsc/test/integration:integration_test
    exit_code=${?}
    if [[ ${exit_code} -ne 0 ]]; then
      break
    fi
  done
fi

# Execute local tests that require superuser.
if [[ ${exit_code} -eq 0 ]]; then
  bazel build //runsc/test/root:root_test
  root_test=$(find -L ./bazel-bin/ -executable -type f -name root_test | grep __main__)
  if [[ ! -f "${root_test}" ]]; then
    uninstallRuntime
    echo "root_test executable not found"
    exit 1
  fi
  sudo -n -E RUNSC_RUNTIME=${runtime} ${root_test}
  exit_code=${?}
fi

uninstallRuntime

set -e

# Find and rename all test xml and log files so that Sponge can pick them up.
# XML files must be named sponge_log.xml, and log files must be named
# sponge_log.log. We move all such files into KOKORO_ARTIFACTS_DIR, in a
# subdirectory named with the test name.
for file in $(find -L "bazel-testlogs" -name "test.xml" -o -name "test.log"); do
    newpath=${KOKORO_ARTIFACTS_DIR}/$(dirname ${file})
    extension="${file##*.}"
    mkdir -p "${newpath}" && cp "${file}" "${newpath}/sponge_log.${extension}"
done

exit ${exit_code}
