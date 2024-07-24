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

# Script to easily run gpu tests on all supported driver versions. This should
# be run from the gVisor repo root directory.
set -ueo pipefail

tmp_file=$(mktemp)
trap "rm -f ${tmp_file}" EXIT

make sudo TARGETS=tools/gpu:main ARGS="list --outfile=${tmp_file}"
read -r -a versions <<< "$(cat "${tmp_file}")"

num_successful=0
for driver in "${versions[@]}"; do
  set +e
  make sudo TARGETS=tools/gpu:main ARGS="install --version ${driver}"
  install_exit_code=$?
  set -e
  if [[ $install_exit_code -ne 0 ]]; then
    echo "Installing driver ${driver} failed. Not testing this version." >&2
    continue
  fi
  make gpu-smoke-tests
  num_successful="$(( $num_successful + 1 ))"
done
if [[ "$num_successful" == 0 ]]; then
  echo 'No version was successfully tested.' >&2
  exit 1
fi
