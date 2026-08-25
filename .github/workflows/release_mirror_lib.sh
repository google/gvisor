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

# Shared release-artifact layout for .github/workflows/release_mirror.yml.
# Sourced, not executed; keeps the "wait" and "download" steps in agreement
# about exactly which objects make up a release.

declare -r RELEASES_URL="https://storage.googleapis.com/gvisor/releases"

# Architecture directory names for raw artifacts. These are derived by
# tools/make_release.sh from `file` output, and are also what
# g3doc/user_guide/install.md tells users to plug in from `uname -m`.
declare -ra ARCHS=(x86_64 aarch64)

# Raw artifacts to mirror, each with a sibling .sha512.
#
# Only the release tarball is mirrored. It already contains runsc,
# runsc-metric-server and containerd-shim-runsc-v1, and those standalone
# binaries are being retired. Debian packages are deliberately not mirrored
# either: they are served by the apt repository, which also provides the
# signed release metadata and the upgrade path that a release asset cannot.
declare -ra RAW_FILES=(
  gvisor.tar.bz2
)

# raw_url <version> <arch> <filename>
raw_url() {
  echo "${RELEASES_URL}/release/$1/$2/$3"
}

# asset_name <filename> <arch>
#
# GitHub release assets share one flat namespace, so per-architecture files
# have to carry the architecture in their name.
asset_name() {
  case "$1" in
    *.tar.bz2) echo "${1%.tar.bz2}-$2.tar.bz2" ;;
    *)         echo "$1-$2" ;;
  esac
}
