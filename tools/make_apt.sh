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
declare private_key
declare suite
declare root
private_key="$(readlink -e "$1")"
suite="$2"
root="$(readlink -m "$3")"
readonly private_key
readonly suite
readonly root
shift; shift; shift # For "$@" below.

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
# Using separate homedir allows us to install apt repositories multiple times
# using the same key. This is a limitation in GnuPG pre-2.1.
declare keyring
declare homedir
declare gpg_opts
keyring="$(mktemp /tmp/keyringXXXXXX.gpg)"
homedir="$(mktemp -d /tmp/homedirXXXXXX)"
gpg_opts=("--no-default-keyring" "--secret-keyring" "${keyring}" "--homedir" "${homedir}")
readonly keyring
readonly homedir
readonly gpg_opts
cleanup() {
  rm -rf "${keyring}" "${homedir}"
}
trap cleanup EXIT

# We attempt the import twice because the first one will fail if the public key
# is not found. This isn't actually a failure for us, because we don't require
# the public key (this may be stored separately). The second import will succeed
# because, in reality, the first import succeeded and it's a no-op.
gpg "${gpg_opts[@]}" --import "${private_key}" || \
  gpg "${gpg_opts[@]}" --import "${private_key}"

# Copy the packages into the root.
for pkg in "$@"; do
  if ! [[ -f "${pkg}" ]]; then
    continue
  fi
  ext=${pkg##*.}
  if [[ "${ext}" != "deb" ]]; then
    continue
  fi

  # Extract package information.
  name=$(basename "${pkg}" ".${ext}")
  arch=$(dpkg --info "${pkg}" | grep 'Architecture:' | cut -d':' -f2)
  version=$(dpkg --info "${pkg}" | grep 'Version:' | cut -d':' -f2)
  arch=${arch// /} # Trim whitespace.
  version=${version// /} # Ditto.
  destdir="${root}/pool/${version}/binary-${arch}"

  # Copy & sign the package.
  mkdir -p "${destdir}"
  cp -a -L "$(dirname "${pkg}")/${name}.deb" "${destdir}"
  cp -a -L "$(dirname "${pkg}")/${name}.changes" "${destdir}"
  chmod 0644 "${destdir}"/"${name}".*
  # We use [*] here to expand the gpg_opts array into a single shell-word.
  dpkg-sig -g "${gpg_opts[*]}" --sign builder "${destdir}/${name}.deb"
done

# Build the package list.
declare arches=()
for dir in "${root}"/pool/*/binary-*; do
  name=$(basename "${dir}")
  arch=${name##binary-}
  arches+=("${arch}")
  repo_packages="${release}"/main/"${name}"
  mkdir -p "${repo_packages}"
  (cd "${root}" && apt-ftparchive packages "${dir##${root}/}" > "${repo_packages}"/Packages)
  if ! [[ -s "${repo_packages}"/Packages ]]; then
    echo "Packages file is size zero." >&2
    exit 1
  fi
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
(cd "${release}" && gpg "${gpg_opts[@]}" --clearsign "${digest_opts[@]}" -o InRelease Release)
(cd "${release}" && gpg "${gpg_opts[@]}" -abs "${digest_opts[@]}" -o Release.gpg Release)
