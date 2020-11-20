#!/bin/bash

# Copyright 2020 The gVisor Authors.
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

set -x

BAZEL_VERSION="${BAZEL_VERSION:=}"
BENCHMARKS_PROJECT="${BENCHMARKS_PROJECT:=gvisor-benchmarks}"
BENCHMARKS_DATASET="${BENCHMARKS_DATASET:=kokoro}"
BENCHMARKS_TABLE="${BENCHMARKS_TABLE:=benchmarks}"
BENCHMARKS_SUITE="${BENCHMARKS_SUITE:=start}"
BENCHMARKS_UPLOAD="${BENCHMARKS_UPLOAD:=false}"
BENCHMARKS_OFFICIAL="${BENCHMARKS_OFFICIAL:=false}"
BENCHMARKS_PLATFORMS="${BENCHMARKS_PLATFORMS:=ptrace}"
BENCHMARKS_TARGETS="${BENCHMARKS_TARGETS:=//test/benchmarks/base:startup_test}"
BENCHMARKS_ARGS="${BENCHMARKS_ARGS:=-test.bench=.}"

declare RUNSC


function benchmark_platforms() {
  run_platform "runc"
  for platform in ${BENCHMARKS_PLATFORMS}
  do
    install_platform ${platform}
    run_platform ${platform}
    run_platform "${platform}_vfs1"
  done
}

function install_platform(){
  declare -r platform="${1}"
  # shellcheck disable=SC2086
  sudo ${RUNSC} install --runtime=${platform} -- --platform=${platform} --vfs2
  # shellcheck disable=SC2086
  sudo ${RUNSC} install --runtime=${platform}_vfs1 -- --platform=${platform}
  sudo service docker restart
}

function run_platform() {
  declare -r runtime="${1}"
  declare file
  file=$(mktemp --tmpdir "logs.${runtime}.XXXXXX")
  declare -r args="--runtime=${runtime} ${BENCHMARKS_ARGS}"
  # shellcheck disable=SC2086
  bazel run ${BENCHMARKS_TARGETS} -- ${args} | tee "${file}"
  if [[ "${BENCHMARKS_UPLOAD}" == "true" ]]; then
    bazel run //tools/parsers:parser -- parse --file="${file}" --runtime="${runtime}" \
      --suite_name="${BENCHMARKS_SUITE}" --project="${BENCHMARKS_PROJECT}" \
      --dataset="${BENCHMARKS_DATASET}" --table="${BENCHMARKS_TABLE}" \
      --official="${BENCHMARKS_OFFICIAL}"
  fi;
  rm -rf "${file}"
}

if [[ -n ${BAZEL_VERSION} ]]; then
  # Use the release installer.
  curl -L -o "bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh" "https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh"
  chmod a+x "bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh"
  sudo "./bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh"
  rm -f "bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh"
fi;

gcloud auth list
gcloud config list
bq show --format=prettyjson gvisor-benchmarks:kokoro || true



RUNSC=$(bazel build //runsc:runsc |& grep bazel-out)
make load-benchmarks-images; benchmark_platforms
