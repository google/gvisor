#!/bin/bash

# Copyright 2025 The gVisor Authors.
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

ARCH="amd64"

if [[ "$(uname -m)" == "aarch64" ]]; then
        ARCH="arm64"
fi

wget "https://go.dev/dl/go1.24.1.linux-${ARCH}.tar.gz" && \
    tar -C /usr/local -xzf "go1.24.1.linux-${ARCH}.tar.gz" && \
    ln -s /usr/local/go/bin/go /usr/local/bin/go
