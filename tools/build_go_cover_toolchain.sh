#!/bin/bash

# Copyright 2026 The gVisor Authors.
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

# Builds the Go toolchain used by build_cover.sh to build coverage binaries and
# packs it into a tarball.
#
# The gVisor code coverage implementation uses internal packages, which the go
# command refuses to import unless patched. More details can be found here:
# https://github.com/golang/go/issues/76098.

set -x -e -o pipefail

dst=$(realpath "$1")
golang_patch=$(realpath "$2")
go_arch="$3"

arch="$(uname -m)"
case "$arch" in
    x86_64) host_go_arch="amd64" ;;
    aarch64) host_go_arch="arm64" ;;
    *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
esac
if [[ "$go_arch" != "$host_go_arch" ]]; then
  echo "Cannot build the ${go_arch} coverage toolchain on a ${arch} host" >&2
  exit 1
fi

mkdir .gocache
GOMODCACHE="$(pwd)/.gocache"
GOCACHE="$(pwd)/.gocache"
export GOMODCACHE GOCACHE

go_version=1.27.3
go_base_url="https://dl.google.com/go/go${go_version}"

mkdir go-bootstrap
curl -fsSL "${go_base_url}.linux-${go_arch}.tar.gz" | tar -xz -C go-bootstrap
GOROOT_BOOTSTRAP="$(pwd)/go-bootstrap/go"
export GOROOT_BOOTSTRAP

curl -fsSL "${go_base_url}.src.tar.gz" | tar -xz
(
  cd go
  patch -p1 < "$golang_patch"
  cd src
  ./make.bash
)

# Fixed metadata and no gzip timestamp make the tarball independent of when and
# where it was built.
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
  --exclude=go/pkg/obj -cf - go | gzip -n > "$dst"
