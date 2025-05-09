#!/bin/bash

# Copyright 2025 The gVisor Authors.
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

# This script outputs a list of CUDA features that are present or absent,
# one per line. Each line begins with either "PRESENT: " or "ABSENT: ",
# followed by the feature name.

set -euo pipefail

if [[ "${NVIDIA_DRIVER_CAPABILITIES:-}" != "all" ]]; then
  echo "NVIDIA_DRIVER_CAPABILITIES is not set to 'all'." >&2
  echo "It is set to: '${NVIDIA_DRIVER_CAPABILITIES:-}'" >&2
  echo "Please set it to 'all' and try again." >&2
  exit 1
fi

cd /
nvcc list_features.cu -lcuda -o list_features -Wno-deprecated-gpu-targets
./list_features

# Detect GL by using a simple test that uses it as reference.
if xvfb-run make -C /cuda-samples/Samples/0_Introduction/simpleCUDA2GL TARGET_ARCH="$(uname -m)" testrun &>/dev/null; then
  echo "PRESENT: GL"
else
  echo "ABSENT: GL"
fi
