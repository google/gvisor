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

set -xeou pipefail

# Remember our current directory.
declare orig_dir
orig_dir=$(pwd)
readonly orig_dir

# Record the current working commit.
declare head
head=$(git describe --always)
readonly head

# Create a temporary working directory, and ensure that this directory and all
# subdirectories are cleaned up upon exit.
declare tmp_dir
tmp_dir=$(mktemp -d)
readonly tmp_dir
finish() {
  cd "${orig_dir}"          # Leave tmp_dir.
  rm -rf "${tmp_dir}"       # Remove all contents.
  git checkout -f "${head}" # Restore commit.
}
trap finish EXIT

# Build the exported sources independently of the branch's Git history.
declare -r go_output="${tmp_dir}/output"
make build BAZEL_OPTIONS="" TARGETS="//:go_export"
unzip bazel-bin/go_export.zip -d "${go_output}"

# We expect to have an existing go branch that we will use as the basis for this
# commit. That branch may be empty, but it must exist. We search for this branch
# using the local branch, the "origin" branch, and other remotes, in order.
git fetch --all
declare go_branch
go_branch=$( \
  git show-ref --hash refs/heads/go || \
  git show-ref --hash refs/remotes/origin/go || \
  git show-ref --hash go | head -n 1 \
)
readonly go_branch

# Clone the current repository to the temporary directory, and check out the
# current go_branch directory. We move to the new repository for convenience.
declare repo_orig
repo_orig="$(pwd)"
readonly repo_orig
declare -r repo_new="${tmp_dir}/repository"
git clone . "${repo_new}"
cd "${repo_new}"

# Setup the repository and checkout the branch.
git config user.email "gvisor-bot@google.com"
git config user.name "gVisor bot"
git fetch origin "${go_branch}"
git checkout -b go "${go_branch}"

# Start working on a merge commit that combines the previous history with the
# current history. Note that we don't actually want any changes yet.
#
# N.B. The git behavior changed at some point and the relevant flag was added
# to allow for override, so try the only behavior first then pass the flag.
git merge --no-commit --strategy ours "${head}" || \
  git merge --allow-unrelated-histories --no-commit --strategy ours "${head}"

# Normalize the permissions on the old branch. Note that they should be
# normalized if constructed by this tool, but we do so before the rsync.
find . -type f -exec chmod 0644 {} \;
find . -type d -exec chmod 0755 {} \;

# Sync the exported tree, preserving the existing branch's Git metadata.
rsync --recursive --delete \
  --exclude .git \
  "${go_output}/" .

# Normalize permissions on files retained by rsync as well as new files.
find . -type f -exec chmod 0644 {} \;
find . -type d -exec chmod 0755 {} \;

# Update the current working set and commit.
# If the current working commit has already been committed to the remote go
# branch, then we have nothing to commit here. So allow empty commit. This can
# occur when this script is run parallelly (via pull_request and push events)
# and the push workflow finishes before the pull_request workflow can run this.
git add --all && git commit --allow-empty -m "Merge ${head} (automated)"

# Push the branch back to the original repository.
git remote add orig "${repo_orig}" && git push -f orig go:go
