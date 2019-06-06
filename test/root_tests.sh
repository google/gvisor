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

# Run the tests that require root.
declare -r root_test=$(find -L ./bazel-bin/ -executable -type f -name root_test | grep __main__)
sudo -n -E RUNSC_RUNTIME="${RUNTIME}" RUNSC_EXEC=/tmp/"${RUNTIME}"/runsc ${root_test}
