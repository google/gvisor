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

# Find the runsc binary.
declare -r runsc=$(find bazel-bin/runsc -type f -executable -name "runsc" | head -n1)

# run runsc do without root privileges.
unshare -Ur ${runsc} --network=none --TESTONLY-unsafe-nonroot do true
unshare -Ur ${runsc} --TESTONLY-unsafe-nonroot --network=host do --netns=false true

# run runsc do with root privileges.
sudo -n -E ${runsc} do true
