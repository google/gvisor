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

# Reinstall the latest containerd shim.
declare -r base="https://storage.googleapis.com/cri-containerd-staging/gvisor-containerd-shim"
declare -r latest=$(mktemp --tmpdir gvisor-containerd-shim-latest.XXXXXX)
declare -r shim_path=$(mktemp --tmpdir gvisor-containerd-shim.XXXXXX)
wget --no-verbose "${base}"/latest -O ${latest}
wget --no-verbose "${base}"/gvisor-containerd-shim-$(cat ${latest}) -O ${shim_path}
chmod +x ${shim_path}
sudo mv ${shim_path} /usr/local/bin/gvisor-containerd-shim

# Run the tests that require root.
install_runsc_for_test root
run_as_root //test/root:root_test --runtime=${RUNTIME}

