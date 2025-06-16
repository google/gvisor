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

if [[ "$(git status --porcelain | wc -l)" == 0 ]]; then
  echo "No changes to runsc profiles." >&2
  exit 0
fi

today="$(date +"%Y-%m-%d")"
pgo_branch_name="pgo-update-${today}"
git stash
git pull --rebase=true https://github.com/google/gvisor master
git checkout -b "$pgo_branch_name"
git stash pop
git add runsc/profiles
git status
gh auth login --with-token < "$HOME/.github-token"
gh auth setup-git
export GIT_AUTHOR_NAME=gvisor-bot
export GIT_AUTHOR_EMAIL=gvisor-bot@google.com
export GIT_COMMITTER_NAME=gvisor-bot
export GIT_COMMITTER_EMAIL=gvisor-bot@google.com
git commit -m "Update runsc profiles for PGO (profile-guided optimizations), $today."
git push --set-upstream https://github.com/google/gvisor.git "$pgo_branch_name"
gh pr create \
  --title="Update runsc profiles for PGO (profile-guided optimizations), $today." \
  --body='This PR updates the runsc profiles for PGO (profile-guided optimizations).' \
  --label=pgo-update --base=master
echo 'PGO profile update PR created.' >&2
