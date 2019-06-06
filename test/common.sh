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

set -xeo pipefail

BAZEL_BUILD_FLAGS=(
  "--show_timestamps"
  "--test_output=errors"
  "--keep_going"
  "--verbose_failures=true"
)

if [[ -v RBE_PROJECT_ID ]]; then
    BAZEL_BUILD_FLAGS=(
      "${BAZEL_BUILD_FLAGS[@]}"
      "--config=remote"
      "--project_id=${RBE_PROJECT_ID}"
      "--remote_instance_name=projects/${RBE_PROJECT_ID}/instances/default_instance"
    )
fi

# Build the runtime.
bazel build "${BAZEL_BUILD_FLAGS[@]}" //runsc

# Install the runtime.
declare -r RUNTIME=${RUNTIME:-runsc-test}
sudo -n runsc/test/install.sh --runtime ${RUNTIME}
declare -r runsc=$(find bazel-bin/runsc -type f -executable -name "runsc" | head -n1)
