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

# Makes the release tag appear on GitHub only after the artifacts are uploaded.
#
#   stage    adds release-<name> to the local checkout, before the build.
#   publish  pushes release-<name> to GitHub, after the upload.
#
# Both do nothing unless BUILDKITE_TAG is a staging tag.

set -euo pipefail

declare -r repo_url='https://github.com/google/gvisor.git'

# Holds the tag object between the two modes. Outside refs/tags, so it reaches
# neither `git describe` nor tools/make_release.sh.
declare -r staged_ref='refs/gvisor/staged-release-tag'

usage() {
  echo "usage: $0 <stage|publish>" >&2
  exit 1
}

if [[ "$#" -ne 1 ]]; then
  usage
fi

declare -r staging_tag="${BUILDKITE_TAG:-}"
if [[ "${staging_tag}" != staging-release-* ]]; then
  echo "Not a staged release build; nothing to do." >&2
  exit 0
fi
declare -r tag="${staging_tag#staging-}"

# The object "${tag}" names in the remote; empty if it does not exist.
published_object() {
  git ls-remote "${repo_url}" "refs/tags/${tag}" | head -n 1 | cut -f1
}

case "$1" in
  stage)
    git fetch --no-tags --force "${repo_url}" \
      "refs/tags/${staging_tag}:${staged_ref}"
    git tag -d "${staging_tag}" || true
    if [[ "$(git rev-parse "${staged_ref}^{}")" != "$(git rev-parse HEAD)" ]]; then
      echo "error: ${staging_tag} does not name the commit being built." >&2
      exit 1
    fi
    git tag -f "${tag}" "${staged_ref}^{}"
    # Fail now rather than after the build. The same object means a retry.
    declare -r published="$(published_object)"
    if [[ -n "${published}" && "${published}" != "$(git rev-parse "${staged_ref}")" ]]; then
      echo "error: ${tag} already exists and names something else." >&2
      exit 1
    fi
    ;;

  publish)
    gh auth login --with-token <"${HOME}/.github-token"
    gh auth setup-git
    # Pushes the tag unless it is already published.
    if [[ "$(published_object)" != "$(git rev-parse "${staged_ref}")" ]]; then
      git push "${repo_url}" "${staged_ref}:refs/tags/${tag}"
    fi
    # Keeps `git describe` unambiguous on later builds.
    if git ls-remote --exit-code "${repo_url}" \
        "refs/tags/${staging_tag}" >/dev/null; then
      git push --delete "${repo_url}" "refs/tags/${staging_tag}"
    fi
    ;;

  *)
    usage
    ;;
esac
