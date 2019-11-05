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
sudo apt-get update && sudo apt-get install -y dpkg-sig coreutils apt-utils xz-utils

# Build runsc.
runsc=$(build -c opt //runsc)

# Build packages.
pkgs=$(build -c opt //runsc:runsc-debian)

# Stop here if we have no artifacts directory.
[[ -v KOKORO_ARTIFACTS_DIR ]] || exit 0

# install_raw installs raw artifacts.
install_raw() {
  mkdir -p "$1"
  cp -f "${runsc}" "$1"/runsc
  sha512sum "$1"/runsc | awk '{print $1 "  runsc"}' > "$1"/runsc.sha512
}

# Build a repository, if the key is available.
#
# Note that make_repository.sh script will install packages into the provided
# root, but will output to stdout a directory that can be copied arbitrarily
# into "${KOKORO_ARTIFACTS_DIR}"/dists/XXX. We do things this way because we
# will copy the same repository structure into multiple locations, below.
if [[ -v KOKORO_REPO_KEY ]]; then
  repo=$(tools/make_repository.sh \
          "${KOKORO_KEYSTORE_DIR}/${KOKORO_REPO_KEY}" \
          gvisor-bot@google.com \
          main \
          "${KOKORO_ARTIFACTS_DIR}" \
          ${pkgs})
fi

# install_repo installs a repository.
#
# Note that packages are already installed, as noted above.
install_repo() {
  if [[ -v repo ]]; then
    rm -rf "$1" && mkdir -p "$(dirname "$1")" && cp -a "${repo}" "$1"
  fi
}

# If nightly, install only nightly artifacts.
if [[ "${KOKORO_BUILD_NIGHTLY:-false}" == "true" ]]; then
  # The "latest" directory and current date.
  stamp="$(date -Idate)"
  install_raw  "${KOKORO_ARTIFACTS_DIR}/nightly/latest"
  install_raw  "${KOKORO_ARTIFACTS_DIR}/nightly/${stamp}"
  install_repo "${KOKORO_ARTIFACTS_DIR}/dists/nightly"
else
  # We keep only the latest master raw release.
  install_raw  "${KOKORO_ARTIFACTS_DIR}/master/latest"
  install_repo "${KOKORO_ARTIFACTS_DIR}/dists/master"

  # Is it a tagged release? Build that too.
  tags="$(git tag --points-at HEAD)"
  if ! [[ -z "${tags}" ]]; then
    # Note that a given commit can match any number of tags. We have to iterate
    # through all possible tags and produce associated artifacts.
    for tag in ${tags}; do
      name=$(echo "${tag}" | cut -d'-' -f2)
      base=$(echo "${name}" | cut -d'.' -f1)
      install_raw  "${KOKORO_ARTIFACTS_DIR}/release/${name}"
      install_repo "${KOKORO_ARTIFACTS_DIR}/dists/release"
      install_repo "${KOKORO_ARTIFACTS_DIR}/dists/${base}"
    done
  fi
fi
