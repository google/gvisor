#!/bin/bash

# Copyright 2025 The gVisor Authors.
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

set -x -e -o pipefail

dst=$(realpath "$1")
gopath_zip="$2"
go_mod="$3"
go_sum="$4"
runsc_main_go="$5"
golang_patch=$(realpath "$6")
race="$7"

mkdir .gocache
GOMODCACHE="$(pwd)/.gocache"
GOCACHE="$(pwd)/.gocache"
export GOMODCACHE GOCACHE
(
  # The gVisor code coverate implementation uses internal packages. More details
  # can be found here: https://github.com/golang/go/issues/76098.
  curl -L https://go.dev/dl/go1.25.3.src.tar.gz | tar -xz
  cd go
  patch -p1 < "$golang_patch"
  cd src
  ./make.bash
)

goroot_dir="$(pwd)/go"
go_tool="$goroot_dir/bin/go"

gvisor_gopath="gopath"

unzip -q "$gopath_zip" -d "$gvisor_gopath"
cp "$go_mod" "$go_sum" "$gvisor_gopath/src/gvisor.dev/gvisor/"
mkdir -p "$gvisor_gopath/src/gvisor.dev/gvisor/runsc"
cp "$runsc_main_go" "$gvisor_gopath/src/gvisor.dev/gvisor/runsc/main.go"
cd "$gvisor_gopath/src/gvisor.dev/gvisor/"
export GOROOT="$goroot_dir"
go_opts=""
go_tags="kcov,opensource"
if [[ "$race" = true ]]; then
  go_opts="-race"
  go_tags="$go_tags,lockdep"
else
  # runsc has to be a self-contained binary to be able to run it in a minimal
  # mount namespace.
  export CGO_ENABLED=0
fi
# sleep, sync, syncevent use go:norace, which is not respected by coverage
# instrumentation. Race builds will be instrumented with atomic coverage (using
# sync/atomic.AddInt32), which will not work. We may be able to re-enable
# coverage on them when https://golang.org/issue/43007 is resolved.
gopkgs=$("$go_tool" list ./... | grep -E -v 'pkg/sentry/platform|pkg/ring0|pkg/coverage|pkg/sleep|pkg/sync|pkg/syncevent' | paste -sd,)
"$go_tool" build --tags "$go_tags" $go_opts -cover -coverpkg="$gopkgs" -covermode=atomic -o "$dst" runsc/main.go
