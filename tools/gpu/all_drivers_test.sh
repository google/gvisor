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

for driver in "${versions[@]}"; do
  make sudo TARGETS=tools/gpu:main ARGS="install --version ${driver}"
  make gpu-smoke-tests
done
