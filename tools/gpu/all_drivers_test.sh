#!/bin/bash

# Copyright 2023 The gVisor Authors.
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

# Script to easily run GPU tests on all supported driver versions. This should
# be run from the gVisor repo root directory.
set -ueo pipefail

tmp_file="$(mktemp)"
trap "rm -f ${tmp_file}" EXIT

make sudo TARGETS=tools/gpu:main ARGS="list --outfile=${tmp_file}"
read -r -a all_versions <<< "$(cat "${tmp_file}")"

if [[ "${#all_versions[@]}" -eq 0 ]]; then
  echo 'No driver versions found.' >&2
  exit 1
fi

# https://buildkite.com/docs/pipelines/tutorials/parallel-builds
my_shard="${BUILDKITE_PARALLEL_JOB:-0}"
total_shards="${BUILDKITE_PARALLEL_JOB_COUNT:-1}"

counter=0
versions=()
for driver in "${all_versions[@]}"; do
  modulo="$(( "$counter" % "$total_shards" ))"
  explanation="${counter} % ${total_shards} == ${modulo}; we are shard ${my_shard} of $(( ${total_shards} - 1 ))"
  if [[ "$modulo" -eq "$my_shard" ]]; then
    echo "Will test driver ${driver} ($explanation)" >&2
    versions+=("$driver")
  else
    echo "Skipping driver ${driver} ($explanation)" >&2
  fi
  counter="$(( "$counter" + 1 ))"
done

if [[ "${#versions[@]}" -eq 0 ]]; then
  echo "No versions to test on this shard (we are shard ${my_shard} of $(( ${total_shards} - 1 )))." >&2
  exit 0
fi

num_successful=0
for driver in "${versions[@]}"; do
  set +e
  make sudo TARGETS=tools/gpu:main ARGS="install --version ${driver}"
  install_exit_code="$?"
  set -e
  if [[ "$install_exit_code" -ne 0 ]]; then
    echo "Installing driver ${driver} failed. Not testing this version." >&2
    continue
  fi
  make gpu-smoke-tests
  num_successful="$(( "$num_successful" + 1 ))"
done
if [[ "$num_successful" == 0 ]]; then
  echo 'No version was successfully tested.' >&2
  exit 1
fi
