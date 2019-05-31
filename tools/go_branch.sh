#!/bin/bash

set -eo pipefail

# Discovery the package name from the go.mod file.
declare -r gomod="$(pwd)/go.mod"
declare -r module=$(cat "${gomod}" | grep -E "^module" | cut -d' ' -f2)

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

# We expect to have an existing go branch that we will use as the basis for
# this commit. That branch may be empty, but it must exist.
declare -r go_branch=$(git show-ref --heads --hash go)

# Clone the current repository to the temporary directory, and check out the
# current go_branch directory. We move to the new repository for convenience.
declare -r repo_orig="$(pwd)"
declare -r repo_new="${tmp_dir}/repository"
git clone . "${repo_new}"
cd "${repo_new}"
git checkout go

# Start working on a merge commit that combines the previous history with the
# current history. Note that we don't actually want any changes yet.
git merge --allow-unrelated-histories --no-commit --strategy ours ${head}

# Sync the entire gopath_dir and go.mod.
rsync --recursive --verbose --delete --exclude .git --exclude README.md -L "${gopath_dir}/" .
cp "${gomod}" .

# There are a few solitary files that can get left behind due to the way bazel
# constructs the gopath target. Note that we don't find all Go files here
# because they may correspond to unused templates, etc.
cp "${repo_orig}"/runsc/*.go runsc/

# Update the current working set and commit.
git add . && git commit -m "Merge ${head} (automated)"

# Push the branch back to the original repository.
git remote add orig "${repo_orig}" && git push orig go:go
