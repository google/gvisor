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
declare -r private_key="$1"
shift
declare -r root="$1"
shift
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

export DEBIAN_FRONTEND=noninteractive
# install_raw installs raw artifacts.
#
# Usage: install_raw <dest> [include-python]
#
# Wheels and sdists carry their version in their filename, so unlike the
# architecture-specific tarballs they never overwrite the previous build's
# files. Pass "false" for <include-python> to keep them out of directories that
# are meant to be a fixed-size pointer to the most recent build; otherwise
# those directories grow without bound.
install_raw() {
  local -r dest="$1"
  local -r include_python="${2:-true}"
  for binary in "${binaries[@]}"; do
    local arch file_info name
    # Copy the raw file & generate a sha512sum, sorted by architecture.
    # For tarballs, determine arch from the `runsc` within the tarball.
    case "${binary}" in
      *.tar.bz2)
        arch=$(tar -xjOf "${binary}" runsc | file - | cut -d',' -f2 | awk '{print $NF}' | tr '-' '_')
        ;;
      *.tar.zstd)
        arch=$(tar --zstd -xOf "${binary}" runsc | file - | cut -d',' -f2 | awk '{print $NF}' | tr '-' '_')
        ;;
      *.whl|*.tar.gz)
        arch="python"
        ;;
      *)
        arch=$(file "${binary}" | cut -d',' -f2 | awk '{print $NF}' | tr '-' '_')
        ;;
    esac
    if [[ "${arch}" == "python" ]] && [[ "${include_python}" != "true" ]]; then
      continue
    fi
    name=$(basename "${binary}")
    mkdir -p "${root}/${dest}/${arch}"
    cp -f "${binary}" "${root}/${dest}/${arch}"
    (cd "${root}/${dest}/${arch}" && sha512sum "${name}" >"${name}.sha512")
  done
}

# install_apt installs an apt repository.
install_apt() {
  tools/make_apt.sh "${private_key}" "$1" "${root}" "${pkgs[@]}"
}



# If nightly, install only nightly artifacts.
if [[ "${NIGHTLY:-false}" == "true" ]]; then
  # Install the nightly release.
  # https://gvisor.dev/docs/user_guide/install/#nightly
  stamp="$(date -Idate)"
  # Nightly builds are never published to PyPI, so skip the wheels entirely.
  install_raw "nightly/latest" false
  install_raw "nightly/${stamp}" false
  install_apt "nightly"
else
  # Is it a tagged release? Build that.
  tags="$(git tag --points-at HEAD 2>/dev/null || true)"
  if ! [[ -z "${tags}" ]]; then
    # Note that a given commit can match any number of tags. We have to iterate
    # through all possible tags and produce associated artifacts.
    for tag in ${tags}; do
      # LINT.IfChange
      if [[ "$tag" == "buildkite-test-branch" ]]; then
        continue
      fi
      # LINT.ThenChange(../.buildkite/hooks/pre-command)
      # A staging tag names a release that is still being built.
      if [[ "$tag" == release-*-staging ]]; then
        continue
      fi
      name=$(echo "${tag}" | cut -d'-' -f2)
      base=$(echo "${name}" | cut -d'.' -f1)
      # Install the "specific" release. This is the latest release with the
      # given date.
      # https://gvisor.dev/docs/user_guide/install/#specific-release
      install_raw "release/${base}"
      # Install the "point release".
      # https://gvisor.dev/docs/user_guide/install/#point-release
      install_raw "release/${name}"
      tools/make_python_release.sh upload-wheel "${root}/release/${name}/python"
      # Install the latest release.
      # https://gvisor.dev/docs/user_guide/install/#latest-release
      #
      # Unlike the versioned directories above, this one is overwritten by every
      # release, so it must not accumulate version-named wheels. PyPI is the
      # canonical source for the latest Python package.
      install_raw "release/latest" false

      install_apt "release"
      install_apt "${base}"
    done
  else
    # Otherwise, assume it is a raw master commit.
    # https://gvisor.dev/docs/user_guide/install/#head
    # HEAD builds are never published to PyPI, so skip the wheels entirely.
    install_raw "master/latest" false
    install_apt "master"
  fi
fi
