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

# Discovery the package name from the go.mod file.
declare -r module=$(cat go.mod | grep -E "^module" | cut -d' ' -f2)
declare -r origpwd=$(pwd)
declare -r othersrc=("go.mod" "go.sum" "AUTHORS" "LICENSE")

# Check that gopath has been built.
declare -r gopath_dir="$(pwd)/bazel-bin/gopath/src/${module}"
if ! [ -d "${gopath_dir}" ]; then
  echo "No gopath directory found; build the :gopath target." >&2
  exit 1
fi

# Create a temporary working directory, and ensure that this directory and all
# subdirectories are cleaned up upon exit.
declare -r tmp_dir=$(mktemp -d)
finish() {
  cd # Leave tmp_dir.
  rm -rf "${tmp_dir}"
}
trap finish EXIT

# Record the current working commit.
declare -r head=$(git describe --always)

# We expect to have an existing go branch that we will use as the basis for this
# commit. That branch may be empty, but it must exist. We search for this branch
# using the local branch, the "origin" branch, and other remotes, in order.
git fetch --all
declare -r go_branch=$( \
  git show-ref --hash refs/heads/go || \
  git show-ref --hash refs/remotes/origin/go || \
  git show-ref --hash go | head -n 1 \
)

# Clone the current repository to the temporary directory, and check out the
# current go_branch directory. We move to the new repository for convenience.
declare -r repo_orig="$(pwd)"
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
git merge --no-commit --strategy ours ${head} || \
  git merge --allow-unrelated-histories --no-commit --strategy ours ${head}

# Normalize the permissions on the old branch. Note that they should be
# normalized if constructed by this tool, but we do so before the rsync.
find . -type f -exec chmod 0644 {} \;
find . -type d -exec chmod 0755 {} \;

# Sync the entire gopath_dir.
rsync --recursive --verbose --delete --exclude .git -L "${gopath_dir}/" .

# Add additional files.
for file in "${othersrc[@]}"; do
  cp "${origpwd}"/"${file}" .
done

# Construct a new README.md.
cat > README.md <<EOF
# gVisor

This branch is a synthetic branch, containing only Go sources, that is
compatible with standard Go tools. See the master branch for authoritative
sources and tests.
EOF

# There are a few solitary files that can get left behind due to the way bazel
# constructs the gopath target. Note that we don't find all Go files here
# because they may correspond to unused templates, etc.
declare -ar binaries=( "runsc" "shim/v1" "shim/v2" )
for target in "${binaries[@]}"; do
  mkdir -p "${target}"
  cp "${repo_orig}/${target}"/*.go "${target}/"
done

# Normalize all permissions. The way bazel constructs the :gopath tree may leave
# some strange permissions on files. We don't have anything in this tree that
# should be execution, only the Go source files, README.md, and ${othersrc}.
find . -type f -exec chmod 0644 {} \;
find . -type d -exec chmod 0755 {} \;

# Update the current working set and commit.
git add . && git commit -m "Merge ${head} (automated)"

# Push the branch back to the original repository.
git remote add orig "${repo_orig}" && git push -f orig go:go
