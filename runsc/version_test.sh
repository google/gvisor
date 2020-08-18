#!/bin/bash

# Copyright 2018 The gVisor Authors.
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

set -euf -x -o pipefail

readonly runsc="$1"
readonly version=$($runsc --version)

# Version should should not match VERSION, which is the default and which will
# also appear if something is wrong with workspace_status.sh script.
if [[ $version =~ "VERSION" ]]; then
  echo "FAIL: Got bad version $version"
  exit 1
fi

# Version should contain at least one number.
if [[ ! $version =~ [0-9] ]]; then
  echo "FAIL: Got bad version $version"
  exit 1
fi

echo "PASS: Got OK version $version"
exit 0
