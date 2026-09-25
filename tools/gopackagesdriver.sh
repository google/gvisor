#!/usr/bin/env bash

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

export GOOS="${GOOS:-linux}"
if [[ -z "${GOARCH:-}" ]]; then
    host_arch="$(uname -m)" || exit 1
    case "$host_arch" in
        x86_64 | amd64) GOARCH=amd64 ;;
        aarch64 | arm64) GOARCH=arm64 ;;
        *) echo "Unsupported host architecture: $host_arch" >&2; exit 1 ;;
    esac
fi
export GOARCH

export GOPACKAGESDRIVER_BAZEL_BUILD_FLAGS="${GOPACKAGESDRIVER_BAZEL_BUILD_FLAGS:-} --platforms=@io_bazel_rules_go//go/toolchain:${GOOS}_${GOARCH}"

exec bazel run -- @io_bazel_rules_go//go/tools/gopackagesdriver "${@}"
