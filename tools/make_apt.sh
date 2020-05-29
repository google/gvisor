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

if [[ "$#" -le 3 ]]; then
  echo "usage: $0 <private-key> <suite> <root> <packages...>"
  exit 1
fi
declare -r private_key=$(readlink -e "$1"); shift
declare -r suite="$1"; shift
declare -r root="$1"; shift

# Ensure that we have the correct packages installed.
function apt_install() {
  while true; do
    sudo apt-get update &&
      sudo apt-get install -y "$@" &&
      true
    result="${?}"
    case $result in
      0)
        break
        ;;
      100)
        # 100 is the error code that apt-get returns.
        ;;
      *)
        exit $result
        ;;
    esac
  done
}
dpkg-sig --help >/dev/null 2>&1       || apt_install dpkg-sig
apt-ftparchive --help >/dev/null 2>&1 || apt_install apt-utils
xz --help >/dev/null 2>&1             || apt_install xz-utils

# Verbose from this point.
set -xeo pipefail

# Create a directory for the release.
declare -r release="${root}/dists/${suite}"
mkdir -p "${release}"

# Create a temporary keyring, and ensure it is cleaned up.
declare -r keyring=$(mktemp /tmp/keyringXXXXXX.gpg)
cleanup() {
  rm -f "${keyring}"
}
trap cleanup EXIT

# We attempt the import twice because the first one will fail if the public key
# is not found. This isn't actually a failure for us, because we don't require
# the public (this may be stored separately). The second import will succeed
# because, in reality, the first import succeeded and it's a no-op.
gpg --no-default-keyring --keyring "${keyring}" --import "${private_key}" || \
  gpg --no-default-keyring --keyring "${keyring}" --import "${private_key}"

# Copy the packages into the root.
for pkg in "$@"; do
  ext=${pkg##*.}
  name=$(basename "${pkg}" ".${ext}")
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

  # The package may already exist, in which case we leave it alone.
  version=${version// /} # Trim whitespace.
  destdir="${root}/pool/${version}/binary-${arch}"
  target="${destdir}/${name}.${ext}"
  if [[ -f "${target}" ]]; then
    continue
  fi

  # Copy & sign the package.
  mkdir -p "${destdir}"
  cp -a "${pkg}" "${target}"
  chmod 0644 "${target}"
  if [[ "${ext}" == "deb" ]]; then
    dpkg-sig -g "--no-default-keyring --keyring ${keyring}" --sign builder "${target}"
  fi
done

# Build the package list.
declare arches=()
for dir in "${root}"/pool/*/binary-*; do
  name=$(basename "${dir}")
  arch=${name##binary-}
  arches+=("${arch}")
  repo_packages="${release}"/main/"${name}"
  mkdir -p "${repo_packages}"
  (cd "${root}" && apt-ftparchive --arch "${arch}" packages pool > "${repo_packages}"/Packages)
  (cd "${repo_packages}" && cat Packages | gzip > Packages.gz)
  (cd "${repo_packages}" && cat Packages | xz > Packages.xz)
done

# Build the release list.
cat > "${release}"/apt.conf <<EOF
APT {
  FTPArchive {
    Release {
      Architectures "${arches[@]}";
      Suite "${suite}";
      Components "main";
    };
  };
};
EOF
(cd "${release}" && apt-ftparchive -c=apt.conf release . > Release)
rm "${release}"/apt.conf

# Sign the release.
declare -r digest_opts=("--digest-algo" "SHA512" "--cert-digest-algo" "SHA512")
(cd "${release}" && rm -f Release.gpg InRelease)
(cd "${release}" && gpg --no-default-keyring --keyring "${keyring}" --clearsign "${digest_opts[@]}" -o InRelease Release)
(cd "${release}" && gpg --no-default-keyring --keyring "${keyring}" -abs "${digest_opts[@]}" -o Release.gpg Release)
