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

set -euxo pipefail

today="$(date +"%Y-%m-%d")"
repo_url="https://github.com/google/gvisor.git"
pgo_branch_name="pgo/update-${today}"

# GitHub CLI authentication.
gh --version
gh auth login --with-token < "$HOME/.github-token"
gh auth setup-git

# Create new branch for the PR and stages changes in it.
git stash
git pull --rebase=true "$repo_url" master
git checkout -b "$pgo_branch_name"
git stash pop
git add runsc/profiles/data
git status

# Commit and push PR branch.
export GIT_AUTHOR_NAME=gvisor-bot
export GIT_AUTHOR_EMAIL=gvisor-bot@google.com
export GIT_COMMITTER_NAME=gvisor-bot
export GIT_COMMITTER_EMAIL=gvisor-bot@google.com
git commit -m "Update runsc profiles for PGO (profile-guided optimizations), $today."
git push --set-upstream "$repo_url" "$pgo_branch_name"

# Send PR.
# The 'yes' command will fail when the `gh` command closes its stdin,
# which the `pipefail` option treats as a total failure.
# So disable this option for this particular command.
set +o pipefail
yes '' | gh pr --repo="$repo_url" create \
  --title="Update runsc profiles for PGO (profile-guided optimizations), $today." \
  --body='This PR updates the runsc profiles for PGO (profile-guided optimizations).' \
  --label=pgo-update --label='ready to pull' \
  --base=master --head="$pgo_branch_name"
set -o pipefail

echo 'PGO profile update PR created.' >&2
