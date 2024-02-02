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

# Check if any changes are in specified paths. The script exits with 0 if no
# changes were detected.

set -xeo pipefail

# Report no changes only for tests branches.
echo "${BUILDKITE_BRANCH}" | grep -q '^test/' || {
  echo "Consider changes everywhere for non-test branches."
  exit 1
}

git fetch origin master
baseid=$(git merge-base origin/master "origin/${BUILDKITE_BRANCH}")

git diff --stat "${baseid}" --exit-code "$@"

echo "No changes detected"
