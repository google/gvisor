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

which bazel
bazel version

# Switch into the workspace; only necessary if run with kokoro.
if [[ -v KOKORO_GIT_COMMIT ]] && [[ -d git/repo ]]; then
  cd git/repo
elif [[ -v KOKORO_GIT_COMMIT ]] && [[ -d github/repo ]]; then
  cd github/repo
fi

# Set the standard bazel flags.
declare -a BAZEL_FLAGS=(
  "--show_timestamps"
  "--test_output=errors"
  "--keep_going"
  "--verbose_failures=true"
)
# If running via kokoro, use the remote config.
if [[ -v KOKORO_ARTIFACTS_DIR ]]; then
  BAZEL_FLAGS+=(
    "--config=remote"
  )
fi
declare -r BAZEL_FLAGS

# Wrap bazel.
function build() {
  bazel build "${BAZEL_FLAGS[@]}" "$@" 2>&1 \
    | tee /dev/fd/2 \
    | grep -E '^  bazel-bin/' \
    | awk '{ print $1; }'
}

function test() {
  bazel test "${BAZEL_FLAGS[@]}" "$@"
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

function query() {
 bazel query "$@"
}

function collect_logs() {
  # Zip out everything into a convenient form.
  if [[ -v KOKORO_ARTIFACTS_DIR ]] && [[ -e bazel-testlogs ]]; then
    # Merge results files of all shards for each test suite.
    for d in `find -L "bazel-testlogs" -name 'shard_*_of_*' | xargs dirname | sort | uniq`; do
      junitparser merge `find $d -name test.xml` $d/test.xml
      cat $d/shard_*_of_*/test.log > $d/test.log
      if ls -ld $d/shard_*_of_*/test.outputs 2>/dev/null; then
        zip -r -1 "$d/outputs.zip" $d/shard_*_of_*/test.outputs
      fi
    done
    find -L "bazel-testlogs" -name 'shard_*_of_*' | xargs rm -rf
    # Move test logs to Kokoro directory. tar is used to conveniently perform
    # renames while moving files.
    find -L "bazel-testlogs" -name "test.xml" -o -name "test.log" -o -name "outputs.zip" |
      tar --create --files-from - --transform 's/test\./sponge_log./' |
      tar --extract --directory ${KOKORO_ARTIFACTS_DIR}

    # Collect sentry logs, if any.
    if [[ -v RUNSC_LOGS_DIR ]] && [[ -d "${RUNSC_LOGS_DIR}" ]]; then
      # Check if the directory is empty or not (only the first line it needed).
      local -r logs=$(ls "${RUNSC_LOGS_DIR}" | head -n1)
      if [[ "${logs}" ]]; then
        local -r archive=runsc_logs_"${RUNTIME}".tar.gz
        if [[ -v KOKORO_BUILD_ARTIFACTS_SUBDIR ]]; then
          echo "runsc logs will be uploaded to:"
          echo "    gsutil cp gs://gvisor/logs/${KOKORO_BUILD_ARTIFACTS_SUBDIR}/${archive} /tmp"
          echo "    https://storage.cloud.google.com/gvisor/logs/${KOKORO_BUILD_ARTIFACTS_SUBDIR}/${archive}"
        fi
        time tar \
          --verbose \
          --create \
          --gzip \
          --file="${KOKORO_ARTIFACTS_DIR}/${archive}" \
          --directory "${RUNSC_LOGS_DIR}" \
          .
      fi
    fi
  fi
}

function find_branch_name() {
  (git branch --show-current \
    || git rev-parse HEAD \
    || bazel info workspace \
    | xargs basename) \
    | tr '/' '-'
}
