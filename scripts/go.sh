#!/bin/bash

# Copyright 2019 The gVisor Authors.
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

source $(dirname $0)/common.sh

# Build the go path.
build :gopath

# Build the synthetic branch.
tools/go_branch.sh

# Checkout the new branch.
git checkout go && git clean -f

go version

# Build everything.
go build ./...

# Push, if required.
if [[ -v KOKORO_GO_PUSH ]] && [[ "${KOKORO_GO_PUSH}" == "true" ]]; then
  if [[ -v KOKORO_GITHUB_ACCESS_TOKEN ]]; then
    git config --global credential.helper cache
    git credential approve <<EOF
protocol=https
host=github.com
username=$(cat "${KOKORO_KEYSTORE_DIR}/${KOKORO_GITHUB_ACCESS_TOKEN}")
password=x-oauth-basic
EOF
  fi
  git push origin go:go
fi
