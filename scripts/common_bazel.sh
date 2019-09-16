#!/bin/bash

# Copyright 2019 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Install the latest version of Bazel and log the version.
(which use_bazel.sh && use_bazel.sh latest) || which bazel
bazel version

# Switch into the workspace; only necessary if run with kokoro.
if [[ -v KOKORO_GIT_COMMIT ]] && [[ -d git/repo ]]; then
  cd git/repo
elif [[ -v KOKORO_GIT_COMMIT ]] && [[ -d github/repo ]]; then
  cd github/repo
fi

# Set the standard bazel flags.
declare -r BAZEL_FLAGS=(
  "--show_timestamps"
  "--test_output=errors"
  "--keep_going"
  "--verbose_failures=true"
)
if [[ -v KOKORO_BAZEL_AUTH_CREDENTIAL ]] || [[ -v RBE_PROJECT_ID ]]; then
  declare -r RBE_PROJECT_ID="${RBE_PROJECT_ID:-gvisor-rbe}"
  declare -r BAZEL_RBE_FLAGS=(
    "--config=remote"
    "--project_id=${RBE_PROJECT_ID}"
    "--remote_instance_name=projects/${RBE_PROJECT_ID}/instances/default_instance"
  )
fi
if [[ -v KOKORO_BAZEL_AUTH_CREDENTIAL ]]; then
  declare -r BAZEL_RBE_AUTH_FLAGS=(
    "--auth_credentials=${KOKORO_BAZEL_AUTH_CREDENTIAL}"
  )
fi

# Wrap bazel.
function build() {
  bazel build "${BAZEL_RBE_FLAGS[@]}" "${BAZEL_RBE_AUTH_FLAGS[@]}" "${BAZEL_FLAGS[@]}" "$@" 2>&1 |
    tee /dev/fd/2 | grep -E '^  bazel-bin/' | awk '{ print $1; }'
}

function test() {
  bazel test "${BAZEL_RBE_FLAGS[@]}" "${BAZEL_RBE_AUTH_FLAGS[@]}" "${BAZEL_FLAGS[@]}" "$@"
}

function run() {
  local binary=$1
  shift
  bazel run "${binary}" -- "$@"
}

function run_as_root() {
  local binary=$1
  shift
  bazel run --run_under="sudo" "${binary}" -- "$@"
}

function collect_logs() {
  # Zip out everything into a convenient form.
  if [[ -v KOKORO_ARTIFACTS_DIR ]] && [[ -e bazel-testlogs ]]; then
    # Move test logs to Kokoro directory. tar is used to conveniently perform
    # renames while moving files.
    find -L "bazel-testlogs" -name "test.xml" -o -name "test.log" -o -name "outputs.zip" |
      tar --create --files-from - --transform 's/test\./sponge_log./' |
      tar --extract --directory ${KOKORO_ARTIFACTS_DIR}

    # Collect sentry logs, if any.
    if [[ -v RUNSC_LOGS_DIR ]] && [[ -d "${RUNSC_LOGS_DIR}" ]]; then
      local -r logs=$(ls "${RUNSC_LOGS_DIR}")
      if [[ -z "${logs}" ]]; then
        tar --create --gzip --file="${KOKORO_ARTIFACTS_DIR}/${RUNTIME}.tar.gz" -C "${RUNSC_LOGS_DIR}" .
      fi
    fi
  fi
}

function find_branch_name() {
  git branch --show-current || git rev-parse HEAD || bazel info workspace | xargs basename
}
