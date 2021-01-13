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

# Install all the shims.
#
# Note that containerd looks at the current executable directory
# in order to find the shim binary. So we need to check in order
# of preference. The local containerd installer will install to
# /usr/local, so we use that first.
if [[ -x /usr/local/bin/containerd ]]; then
  containerd_install_dir=/usr/local/bin
else
  containerd_install_dir=/usr/bin
fi
runfiles=.
if [[ -d "$0.runfiles" ]]; then
  runfiles="$0.runfiles"
fi
find -L "${runfiles}" -executable -type f -name containerd-shim-runsc-v1 -exec cp -L {} "${containerd_install_dir}" \;
