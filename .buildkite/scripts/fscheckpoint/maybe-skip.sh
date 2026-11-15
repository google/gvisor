#!/bin/bash

# Copyright 2026 The gVisor Authors.
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

# This script executes the argv it gets as arguments, unless it
# determines that the fscheckpoint corpus update should be skipped.

set -euxo pipefail

repo_url="https://github.com/google/gvisor.git"
corpus_branch="fscheckpoint-compat-testing"
head_hash="$(git rev-parse --short=8 HEAD)"

if ls compatibility_testing/*_"${head_hash}" >/dev/null 2>&1; then
  echo "Checkpoint for commit ${head_hash} already exists locally, skipping." >&2
  exit 0
fi

if git ls-remote --exit-code --heads "$repo_url" "refs/heads/${corpus_branch}" >/dev/null 2>&1; then
  git fetch "$repo_url" "refs/heads/${corpus_branch}"
  if git ls-tree --name-only FETCH_HEAD:compatibility_testing 2>/dev/null | grep -q "_${head_hash}$"; then
    echo "Checkpoint for commit ${head_hash} already exists on ${corpus_branch}, skipping." >&2
    exit 0
  fi
fi

echo "Running:" "$@" >&2
exec "$@"
