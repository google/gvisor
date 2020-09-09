#!/bin/sh -e

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

if [ "$1" != configure ]; then
  exit 0
fi

# Update docker configuration.
if [ -f /etc/docker/daemon.json ]; then
  runsc install
  if systemctl is-active -q docker; then
    systemctl restart docker || echo "unable to restart docker; you must do so manually." >&2
  fi
fi

# For containerd-based installers, we don't automatically update the
# configuration. If it uses a v2 shim, then it will find the package binaries
# automatically when provided the appropriate annotation.
