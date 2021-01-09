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

if [[ "$#" -le 2 ]]; then
  echo "usage: $0 <private-key> <root> <binaries & packages...>"
  echo "The environment variable NIGHTLY may be set to control"
  echo "whether the nightly packages are produced or not."
  exit 1
fi

set -xeo pipefail
declare -r private_key="$1"; shift
declare -r root="$1"; shift
declare -a binaries
declare -a pkgs

# Collect binaries & packages.
for arg in "$@"; do
  if [[ "${arg}" == *.deb ]] || [[ "${arg}" == *.changes ]]; then
    pkgs+=("${arg}")
  else
    binaries+=("${arg}")
  fi
done

# install_raw installs raw artifacts.
install_raw() {
  for binary in "${binaries[@]}"; do
    # Copy the raw file & generate a sha512sum, sorted by architecture.
    arch=$(file "${binary}" | cut -d',' -f2 | awk '{print $NF}' | tr '-' '_')
    name=$(basename "${binary}")
    mkdir -p "${root}/$1/${arch}"
    cp -f "${binary}" "${root}/$1/${arch}"
    (cd "${root}/$1/${arch}" && sha512sum "${name}" > "${name}.sha512")
  done
}

# install_apt installs an apt repository.
install_apt() {
  tools/make_apt.sh "${private_key}" "$1" "${root}" "${pkgs[@]}"
}

# If nightly, install only nightly artifacts.
if [[ "${NIGHTLY:-false}" == "true" ]]; then
  # The "latest" directory and current date.
  stamp="$(date -Idate)"
  install_raw "nightly/latest"
  install_raw "nightly/${stamp}"
  install_apt "nightly"
else
  # Is it a tagged release? Build that.
  tags="$(git tag --points-at HEAD 2>/dev/null || true)"
  if ! [[ -z "${tags}" ]]; then
    # Note that a given commit can match any number of tags. We have to iterate
    # through all possible tags and produce associated artifacts.
    for tag in ${tags}; do
      name=$(echo "${tag}" | cut -d'-' -f2)
      base=$(echo "${name}" | cut -d'.' -f1)
      install_raw "release/${name}"
      install_raw "release/latest"
      install_apt "release"
      install_apt "${base}"
    done
  else
    # Otherwise, assume it is a raw master commit.
    install_raw "master/latest"
    install_apt "master"
  fi
fi
