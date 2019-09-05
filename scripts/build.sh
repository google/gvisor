#!/bin/bash

# Copyright 2018 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

source $(dirname $0)/common.sh

# Build runsc.
runsc=$(build -c opt //runsc)

# Build packages.
pkg=$(build -c opt --host_force_python=py2 //runsc:runsc-debian)

# Build a repository, if the key is available.
if [[ -v KOKORO_REPO_KEY ]]; then
  repo=$(tools/make_repository.sh "${KOKORO_REPO_KEY}" gvisor-bot@google.com ${pkg})
fi

# Install installs artifacts.
install() {
  local dir="$1"
  mkdir -p "${dir}"
  cp -f "${runsc}" "${dir}"/runsc
  sha512sum "${dir}"/runsc | awk '{print $1 "  runsc"}' > "${dir}"/runsc.sha512
  if [[ -v repo ]]; then
    rm -rf "${dir}"/repo && cp -a "${repo}" "$dir"/repo
  fi
}

# Move the runsc binary into "latest" directory, and also a directory with the
# current date. If the current commit happens to correpond to a tag, then we
# will also move everything into a directory named after the given tag.
if [[ -v KOKORO_ARTIFACTS_DIR ]]; then
  if [[ "${KOKORO_BUILD_NIGHTLY}" == "true" ]]; then
    # The "latest" directory and current date.
    install "${KOKORO_ARTIFACTS_DIR}/nightly/latest"
    install "${KOKORO_ARTIFACTS_DIR}/nightly/$(date -Idate)"
  else
    # Is it a tagged release? Build that instead. In that case, we also try to
    # update the base release directory, in case this is an update. Finally, we
    # update the "release" directory, which has the last released version.
    tags="$(git tag --points-at HEAD)"
    if ! [[ -z "${tags}" ]]; then
      # Note that a given commit can match any number of tags. We have to
      # iterate through all possible tags and produce associated artifacts.
      for tag in ${tags}; do
        name=$(echo "${tag}" | cut -d'-' -f2)
        base=$(echo "${name}" | cut -d'.' -f1)
        install "${KOKORO_ARTIFACTS_DIR}/release/${name}"
        if [[ "${base}" != "${tag}" ]]; then
          install "${KOKORO_ARTIFACTS_DIR}/release/${base}"
        fi
        install "${KOKORO_ARTIFACTS_DIR}/release/latest"
      done
    fi
  fi
fi
