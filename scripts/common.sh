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

set -xeou pipefail

if [[ -f $(dirname $0)/common_google.sh ]]; then
  source $(dirname $0)/common_google.sh
else
  source $(dirname $0)/common_bazel.sh
fi

# Ensure it attempts to collect logs in all cases.
trap collect_logs EXIT

function set_runtime() {
  RUNTIME=${1:-runsc}
  RUNSC_BIN=/tmp/"${RUNTIME}"/runsc
  RUNSC_LOGS_DIR="$(dirname ${RUNSC_BIN})"/logs
  RUNSC_LOGS="${RUNSC_LOGS_DIR}"/runsc.log.%TEST%.%TIMESTAMP%.%COMMAND%
}

function test_runsc() {
  test --test_arg=--runtime=${RUNTIME} "$@"
}

function install_runsc_for_test() {
  local -r test_name=$1
  shift
  if [[ -z "${test_name}" ]]; then
    echo "Missing mandatory test name"
    exit 1
  fi

  # Add test to the name, so it doesn't conflict with other runtimes.
  set_runtime $(find_branch_name)_"${test_name}"

  # ${RUNSC_TEST_NAME} is set by tests (see dockerutil) to pass the test name
  # down to the runtime.
  install_runsc "${RUNTIME}" \
      --TESTONLY-test-name-env=RUNSC_TEST_NAME \
      --debug \
      --strace \
      --log-packets \
      "$@"
}

# Installs the runsc with given runtime name. set_runtime must have been called
# to set runtime and logs location.
function install_runsc() {
  local -r runtime=$1
  shift

  # Prepare the runtime binary.
  local -r output=$(build //runsc)
  mkdir -p "$(dirname ${RUNSC_BIN})"
  cp -f "${output}" "${RUNSC_BIN}"
  chmod 0755 "${RUNSC_BIN}"

  # Install the runtime.
  sudo "${RUNSC_BIN}" install --experimental=true --runtime="${runtime}" -- --debug-log "${RUNSC_LOGS}" "$@"

  # Clear old logs files that may exist.
  sudo rm -f "${RUNSC_LOGS_DIR}"/*

  # Restart docker to pick up the new runtime configuration.
  sudo systemctl restart docker
}
