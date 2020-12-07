#!/bin/bash

# Copyright 2020 The gVisor Authors.
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

set -euo pipefail

# Enable ipv6 on loopback if it's not already enabled. Runsc doesn't enable ipv6
# loopback unless an ipv6 address was assigned to the container, which docker
# does not do by default.
if ! [[ $(ip -6 addr show dev lo) ]]; then
  ip addr add ::1 dev lo
fi

# The docker API doesn't provide for starting a container, running a command,
# and getting the exit status of the command in one go. The most straightforward
# way to do this is to verify the output of the command, so we output nothing on
# success and an error message on failure.
if ! out=$(/bin/ping6 -c 10 ::1); then
  echo "$out"
fi
