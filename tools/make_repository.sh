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

# Parse arguments. We require more than two arguments, which are the private
# keyring, the e-mail associated with the signer, and the list of packages.
if [ "$#" -le 3 ]; then
  echo "usage: $0 <private-key> <signer-email> <component> <root> <packages...>"
  exit 1
fi
declare -r private_key=$(readlink -e "$1"); shift
declare -r signer="$1"; shift
declare -r component="$1"; shift
declare -r root="$1"; shift

# Verbose from this point.
set -xeo pipefail

# Create a temporary working directory. We don't remove this, as we ultimately
# print this result and allow the caller to copy wherever they would like.
declare -r tmpdir=$(mktemp -d /tmp/repoXXXXXX)

# Create a temporary keyring, and ensure it is cleaned up.
declare -r keyring=$(mktemp /tmp/keyringXXXXXX.gpg)
cleanup() {
  rm -f "${keyring}"
}
trap cleanup EXIT
gpg --no-default-keyring --keyring "${keyring}" --import "${private_key}" >&2

# Copy the packages into the root.
for pkg in "$@"; do
  name=$(basename "${pkg}" .deb)
  name=$(basename "${name}" .changes)
  arch=${name##*_}
  if [[ "${name}" == "${arch}" ]]; then
    continue # Not a regular package.
  fi
  if [[ "${pkg}" =~ ^.*\.deb$ ]]; then
    # Extract from the debian file.
    version=$(dpkg --info "${pkg}" | grep -E 'Version:' | cut -d':' -f2)
  elif [[ "${pkg}" =~ ^.*\.changes$ ]]; then
    # Extract from the changes file.
    version=$(grep -E 'Version:' "${pkg}" | cut -d':' -f2)
  else
    # Unsupported file type.
    echo "Unknown file type: ${pkg}"
    exit 1
  fi
  version=${version// /} # Trim whitespace.
  mkdir -p "${root}"/pool/"${version}"/binary-"${arch}"
  cp -a "${pkg}" "${root}"/pool/"${version}"/binary-"${arch}"
done

# Ensure all permissions are correct.
find "${root}"/pool -type f -exec chmod 0644 {} \;

# Sign all packages.
for file in "${root}"/pool/*/binary-*/*.deb; do
  dpkg-sig -g "--no-default-keyring --keyring ${keyring}" --sign builder "${file}" >&2
done

# Build the package list.
declare arches=()
for dir in "${root}"/pool/*/binary-*; do
  name=$(basename "${dir}")
  arch=${name##binary-}
  arches+=("${arch}")
  repo_packages="${tmpdir}"/"${component}"/"${name}"
  mkdir -p "${repo_packages}"
  (cd "${root}" && apt-ftparchive --arch "${arch}" packages pool > "${repo_packages}"/Packages)
  (cd "${repo_packages}" && cat Packages | gzip > Packages.gz)
  (cd "${repo_packages}" && cat Packages | xz > Packages.xz)
done

# Build the release list.
cat > "${tmpdir}"/apt.conf <<EOF
APT {
  FTPArchive {
    Release {
      Architectures "${arches[@]}";
      Components "${component}";
    };
  };
};
EOF
(cd "${tmpdir}" && apt-ftparchive -c=apt.conf release . > Release)
rm "${tmpdir}"/apt.conf

# Sign the release.
declare -r digest_opts=("--digest-algo" "SHA512" "--cert-digest-algo" "SHA512")
(cd "${tmpdir}" && gpg --no-default-keyring --keyring "${keyring}" --clearsign "${digest_opts[@]}" -o InRelease Release >&2)
(cd "${tmpdir}" && gpg --no-default-keyring --keyring "${keyring}" -abs "${digest_opts[@]}" -o Release.gpg Release >&2)

# Show the results.
echo "${tmpdir}"
