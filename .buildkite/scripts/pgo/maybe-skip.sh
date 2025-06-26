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

# This script executes the argv it gets as arguments, unless it
# determines that the PGO profile update should be skipped.
# Takes the optional argument '--tolerate-no-profile-changes' which can be
# used to tolerate the case where no profile changes are detected.

set -euxo pipefail

today="$(date +"%Y-%m-%d")"
repo_url="https://github.com/google/gvisor.git"
pgo_branch_name="pgo/update-${today}"

tolerate_no_profile_changes=false
for arg; do
  if [[ "$arg" == '--tolerate-no-profile-changes' ]]; then
    tolerate_no_profile_changes=true
    shift
  fi
done

# If the remote branch already exists, do nothing.
existing_remote="$(git ls-remote --heads "$repo_url" "refs/heads/${pgo_branch_name}" || true)"
if [[ -n "$existing_remote" ]]; then
  echo "Remote branch '$pgo_branch_name' already exists, skipping." >&2
  exit 0
fi

# GitHub CLI authentication.
gh --version
gh auth login --with-token < "$HOME/.github-token"
gh auth setup-git

# If there is already an open PR for PGO update, do nothing.
if [[ "$(gh pr --repo="$repo_url" list --label pgo-update --state open --json title --jq length)" -gt 0 ]]; then
  echo "There is already an open PR for PGO update, skipping." >&2
  PAGER=cat gh pr --repo="$repo_url" list --label pgo-update --state open
  exit 0
fi

if [[ "$tolerate_no_profile_changes" == false ]]; then
  if [[ "$(git status --porcelain runsc/profiles/data | wc -l)" == 0 ]]; then
    echo "No changes to runsc profiles; skipping." >&2
    exit 0
  fi
fi

echo "Running:" "$@" >&2
exec "$@"
