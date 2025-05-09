#!/bin/bash

# Copyright 2024 The gVisor Authors.
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

# This script outputs a sorted list of CUDA sample tests, one per line.

set -euo pipefail

(
  while IFS= read -r makefile_path; do
    dirname "$makefile_path"
  done < <(find /cuda-samples -type f -name Makefile) \
    | grep -vE '^/cuda-samples$' | grep -vE '/7_libNVVM'

  # cuda-samples/Samples/7_libNVVM is not structured like the other tests.
  # It is built with `cmake` and generates multiple test binaries.
  # The generated ones all follow the pattern of being named after their
  # parent directory name, so we look for that.
  pushd /cuda-samples/Samples/7_libNVVM &>/dev/null
    cmake . &>/dev/null
    make TARGET_ARCH="$(uname -m)" all &>/dev/null
  popd &>/dev/null
  while IFS= read -r dir_path; do
    if [[ -x "$dir_path/$(basename "$dir_path")" ]]; then
      echo "$dir_path"
    fi
  done < <(find /cuda-samples/Samples/7_libNVVM -type d) | sort | uniq
) | sed 's~/cuda-samples/Samples/~~' | sort
