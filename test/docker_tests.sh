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

declare -r RUNTIME=${RUNTIME:-runsc-test}
sudo -n runsc/test/install.sh --runtime ${RUNTIME}

# Run with the default runtime.
bazel test \
    "${BAZEL_BUILD_FLAGS[@]}" \
    --test_env=RUNSC_RUNTIME="" \
    --test_output=all \
    //runsc/test/image:image_test

# These names are used to exclude tests not supported in certain
# configuration, e.g. save/restore not supported with hostnet.
declare -a variations=("" "-kvm" "-hostnet" "-overlay")
for v in "${variations[@]}"; do
  # Run runsc tests with docker that are tagged manual.
  bazel test \
      "${BAZEL_BUILD_FLAGS[@]}" \
      --test_env=RUNSC_RUNTIME="${RUNTIME}${v}" \
      --test_output=all \
      //runsc/test/image:image_test \
      //runsc/test/integration:integration_test
done
