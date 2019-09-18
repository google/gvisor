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

# Install required packages for make_repository.sh et al.
sudo apt-get update && sudo apt-get install -y dpkg-sig coreutils apt-utils

# Build runsc.
runsc=$(build -c opt //runsc)

# Build packages.
pkg=$(build -c opt --host_force_python=py2 //runsc:runsc-debian)

# Build a repository, if the key is available.
if [[ -v KOKORO_REPO_KEY ]]; then
  repo=$(tools/make_repository.sh "${KOKORO_KEYSTORE_DIR}/${KOKORO_REPO_KEY}" gvisor-bot@google.com main ${pkg})
fi

# Install installs artifacts.
install() {
  local -r binaries_dir="$1"
  local -r repo_dir="$2"
  mkdir -p "${binaries_dir}"
  cp -f "${runsc}" "${binaries_dir}"/runsc
  sha512sum "${binaries_dir}"/runsc | awk '{print $1 "  runsc"}' > "${binaries_dir}"/runsc.sha512
  if [[ -v repo ]]; then
    rm -rf "${repo_dir}" && mkdir -p "$(dirname "${repo_dir}")"
    cp -a "${repo}" "${repo_dir}"
  fi
}

# Move the runsc binary into "latest" directory, and also a directory with the
# current date. If the current commit happens to correpond to a tag, then we
# will also move everything into a directory named after the given tag.
if [[ -v KOKORO_ARTIFACTS_DIR ]]; then
  if [[ "${KOKORO_BUILD_NIGHTLY:-false}" == "true" ]]; then
    # The "latest" directory and current date.
    stamp="$(date -Idate)"
    install "${KOKORO_ARTIFACTS_DIR}/nightly/latest" \
            "${KOKORO_ARTIFACTS_DIR}/dists/nightly/latest"
    install "${KOKORO_ARTIFACTS_DIR}/nightly/${stamp}" \
            "${KOKORO_ARTIFACTS_DIR}/dists/nightly/${stamp}"
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
        install "${KOKORO_ARTIFACTS_DIR}/release/${name}" \
                "${KOKORO_ARTIFACTS_DIR}/dists/${name}"
        if [[ "${base}" != "${tag}" ]]; then
          install "${KOKORO_ARTIFACTS_DIR}/release/${base}" \
                  "${KOKORO_ARTIFACTS_DIR}/dists/${base}"
        fi
        install "${KOKORO_ARTIFACTS_DIR}/release/latest" \
                "${KOKORO_ARTIFACTS_DIR}/dists/latest"
      done
    fi
  fi
fi
