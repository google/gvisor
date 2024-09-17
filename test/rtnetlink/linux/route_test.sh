#!/bin/bash

# Copyright 2024 The gVisor Authors.
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
source "$(dirname "$0")/rtnetlink_test.sh"

# Create a new default route and a new route with a address.
ip netns add test
ip link add name veth1 type veth peer name eth0 netns test
ip netns exec test ip link set up dev lo
ip netns exec test ip link set up dev eth0
ip netns exec test ip addr add 192.168.11.2/24 dev eth0
ORIGINAL_ROUTES=$(ip netns exec test ip r)
ip netns exec test ip r add default via 192.168.11.1 dev eth0
ip netns exec test ip r list | grep "default via 192.168.11.1 dev eth0"
ip netns exec test ip r add 192.168.146.48/28 dev eth0
ip netns exec test ip r list | grep "192.168.146.48/28 dev eth0"
ip netns exec test ip route

# Replace the routes.
ip netns exec test ip r replace default via 192.168.11.2 dev eth0
ip netns exec test ip r list | grep "default via 192.168.11.2 dev eth0"

# Remove all routes that are add/modified above.
ip netns exec test ip r del default via 192.168.11.2 dev eth0
ip netns exec test ip r del 192.168.146.48/28
CURRENT_ROUTES=$(ip netns exec test ip r)

if [[ "$ORIGINAL_ROUTES" != "$CURRENT_ROUTES" ]]; then
  fail "unexpected routes are present"
  exit 1
fi
