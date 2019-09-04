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
if [ "$#" -le 2 ]; then
  echo "usage: $0 <private-key> <signer-email> <packages...>"
  exit 1
fi
declare -r private_key=$(readlink -e "$1")
declare -r signer="$2"
shift; shift

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
gpg --no-default-keyring --keyring "${keyring}" --import "${private_key}"

# Export the public key from the keyring.
gpg --no-default-keyring --keyring "${keyring}" --armor --export "${signer}" > "${tmpdir}"/keyFile

# Copy the packages, and ensure permissions are correct.
cp -a "$@" "${tmpdir}" && chmod 0644 "${tmpdir}"/*

# Ensure there are no symlinks hanging around; these may be remnants of the
# build process. They may be useful for other things, but we are going to build
# an index of the actual packages here.
find "${tmpdir}" -type l -exec rm -f {} \;

# Sign all packages.
for file in "${tmpdir}"/*.deb; do
  dpkg-sig -g "--no-default-keyring --keyring ${keyring}" --sign builder "${file}"
done

# Build the package list.
(cd "${tmpdir}" && apt-ftparchive packages . | gzip > Packages.gz)

# Build the release list.
(cd "${tmpdir}" && apt-ftparchive release . > Release)

# Sign the release.
(cd "${tmpdir}" && gpg --no-default-keyring --keyring "${keyring}" --clearsign -o InRelease Release)
(cd "${tmpdir}" && gpg --no-default-keyring --keyring "${keyring}" -abs -o Release.gpg Release)

# Show the results.
echo "${tmpdir}"
