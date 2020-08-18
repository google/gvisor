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

set -xeo pipefail

# Install all essential build tools.
while true; do
  if (apt-get update && apt-get install -y \
      make \
      git-core \
      build-essential \
      linux-headers-$(uname -r) \
      pkg-config); then
    break
  fi
  result=$?
  if [[ $result -ne 100 ]]; then
    exit $result
  fi
done

# Install a recent go toolchain.
if ! [[ -d /usr/local/go ]]; then
    wget https://dl.google.com/go/go1.13.5.linux-amd64.tar.gz
    tar -xvf go1.13.5.linux-amd64.tar.gz
    mv go /usr/local
fi

# Link the Go binary from /usr/bin; replacing anything there.
(cd /usr/bin && rm -f go && ln -fs /usr/local/go/bin/go go)
